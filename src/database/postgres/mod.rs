use std::env::var;

use crate::{
    database::{
        Database, types::{
            AdminUserInfoRequest, CaseAccess, CaseDetails, CaseInformation, Notes, UserInfo
        }
    },
    routes::{Error, client_modifier::BasicAuth}
};
use argon2::Config;
use chrono::{DateTime, Utc};
use hmac_crate::algorithms::hmac_sha_256::sha256;
use jwt::{constructor::TokenPieces, header::{Header, TokenType}, payload::Payload};
use sqlx::{
    Pool, Postgres, query
};
use subtle::ConstantTimeEq;
use tracing::{error, warn};
use tracing_log::log::info;
use uuid::Uuid;

///
/// `'Postgres'` DB implementation of the `'Database'` trait
/// 
impl Database for Pool<Postgres> {
    async fn user_exists(&self, username: &str) -> Result<bool, Error> {
        match sqlx::query(
            r#"
                SELECT user_handle
                FROM users
                WHERE user_handle = $1;
            "#
        )
        .bind(username)
        .fetch_optional(self)
        .await? {
            Some(_) => Ok(true),
            None => Ok(false)
        }
    }
    
    async fn insert_user(&self, user: UserInfo) -> Result<(), Error> {
        let salt = format!("{}{}", var("MASTER_KEY")?, Utc::now().timestamp());
        let config = Config::default();
        let hash = argon2::hash_encoded(user.password_id.as_bytes(), salt.as_bytes(), &config)?;
        let allowed_admins = var("DESIGNATED_ADMIN_USERS")?;
        let allowed_admins: Vec<&str> = allowed_admins.split(",").collect();
        let allowed_roles = var("ALLOWED_ROLE_TYPES")?;
        let allowed_roles: Vec<&str> = allowed_roles.split(",").collect();

        if !allowed_roles.contains(&user.user_role.as_str()) {
            return Err(Error::Unathorized);
        }
        if user.user_role == "admin" &&
            !allowed_admins.contains(&user.user_handle.as_str()) {
                return Err(Error::Unathorized);
            };
        if self.user_exists(&user.user_handle).await? {
            return Err(Error::UserExists);
        }
        match sqlx::query(
            "INSERT INTO users
                    (
                        user_id, user_handle, password_id,
                        user_role, created_at
                    ) VALUES (
                        $1, $2, $3, $4, $5
                    );"
        )
            .bind(Uuid::new_v4())
            .bind(user.user_handle)
            .bind(&hash)
            .bind(user.user_role)
            .bind(Utc::now().naive_utc())
            .execute(self)
            .await {
                Ok(_) => Ok(()),
                Err(error) => Err(error.into())
            }
    }

    async fn login_basic(&self, basic_auth: BasicAuth) -> Result<(String, Uuid), Error> {
        let user: Option<UserInfo> = match sqlx::query_as(
            "SELECT *
                FROM users
                WHERE user_handle = $1;"
            )
            .bind(&basic_auth.username)
            .fetch_optional(self)
            .await {
                Ok(user) => user, 
                Err(error) => return Err(error.into())
            };

        match user {
            Some(user) => {
                let time = Utc::now().timestamp();
                let header = Header::new("HS256".into(), TokenType::Jwt);
                let payload = Payload::new(user.user_id.to_string(), time + 7 * 24 * 3_600, "Graynote_auth_service".into(), Uuid::new_v4(), user.user_role, time - 1);
                let token = TokenPieces::new(header, payload);
                
                if !argon2::verify_encoded(&user.password_id, basic_auth.password.ok_or(Error::InvalidCredentials)?.as_bytes())? {
                    return Err(Error::InvalidCredentials)
                }

                let token_string = token.build_jwt(&var("MASTER_KEY")?)?;

                match self.login_user(token_string.clone()).await {
                    Ok(session_id) => Ok((token_string, session_id)),
                    Err(error) => Err(error)
                }
            },
            None => {
                argon2::verify_encoded("$NULLHASHjnlnnkn$", b"DO NOT VERIFY.")?;

                Err(Error::InvalidCredentials)
            }
        }
    }

    async fn insert_note(&self, note: &Notes) -> Result<(), Error> {
        let token = TokenPieces::try_from(note.token.as_str())?;

        if !self.is_access_granted(&note.session_id, &note.token,&Some(note.case_number), true).await?.0 {
            return Err(Error::Unathorized)
        };
        match query(
            r#"
                INSERT
                INTO notes (
                    note_id,
                    author_id,
                    note_text,
                    relevant_media,
                    entry_timestamp,
                    case_number
                ) VALUES (
                    $1, $2, $3, $4,
                    $5, $6
                );
                "#
        )
            .bind(Uuid::new_v4())
            .bind(token.get_payload().sub)
            .bind(note.note_text.as_str())
            .bind(&note.relevant_media)
            .bind(note.entry_timestamp)
            .bind(note.case_number)
            .execute(self)
            .await {
                Ok(_) => Ok(()),
                Err(error) => Err(Error::from(error))
            }
    }

    async fn insert_case_information(&self, case_access: CaseAccess) -> Result<Uuid, Error> {
        let case_number = Uuid::new_v4();
        let case_information = case_access.case_information;

        if !self.is_access_granted(&case_access.session_id, &case_access.token, &None, true).await?.0 {
            return Err(Error::Unathorized)
        };
        match query(
            r#"
                INSERT
                INTO cases (
                    case_number,
                    user_id,
                    suspect_name,
                    suspect_aliases,
                    suspect_description,
                    suspect_phone,
                    suspect_email,
                    suspect_ip,
                    victim_name,
                    victim_email,
                    victim_phone,
                    timestamp_case
                ) VALUES (
                    $1, $2, $3, $4, $5, $6, $7,
                    $8, $9, $10, $11, $12
                );
            "#
        )
            .bind(case_number)
            .bind(case_information.user_id)
            .bind(case_information.suspect_name)
            .bind(case_information.suspect_aliases)
            .bind(case_information.suspect_description)
            .bind(case_information.suspect_phone)
            .bind(case_information.suspect_email)
            .bind(case_information.suspect_ip)
            .bind(case_information.victim_name)
            .bind(case_information.victim_email)
            .bind(case_information.victim_phone)
            .bind(Utc::now())
            .execute(self)
            .await {
                Ok(_) => (),
                Err(error) => return Err(Error::from(error))
            }
        match query(
            r#"
                INSERT
                INTO user_access_control (
                    param_id,
                    user_id,
                    case_number
                ) VALUES (
                    $1, $2, $3
                );
            "#
        )
        .bind(Uuid::new_v4())
        .bind(case_information.user_id)
        .bind(case_number)
        .execute(self)
        .await {
            Ok(_) => Ok(case_number),
            Err(error) => Err(Error::from(error))
        }
    } 

    async fn get_case_information(&self, case_details: CaseDetails) -> Result<CaseInformation, Error> {
        let token = TokenPieces::try_from(case_details.token.as_str())?;

        if !self.is_access_granted(&case_details.session_id, &case_details.token,&Some(case_details.case_number), true).await?.0 {
            return Err(Error::Unathorized)
        };
        match sqlx::query_as(
            r#"
                SELECT c.case_number,
                    c.user_id,
                    c.suspect_name,
                    c.suspect_aliases,
                    c.suspect_description,
                    c.suspect_phone,
                    c.suspect_email,
                    c.suspect_ip,
                    c.victim_name,
                    c.victim_email,
                    c.victim_phone,
                    c.timestamp_case
                FROM cases c
                JOIN user_access_control uac
                    ON uac.case_number = c.case_number
                WHERE uac.user_id = $1::uuid
                AND c.case_number = $2::uuid;
            "#
        )
        .bind(token.get_payload().sub)
        .bind(case_details.case_number)
        .fetch_one(self)
        .await {
            Ok(data) => Ok(data),
            Err(error) => Err(Error::from(error))
        }
    }

    async fn get_case_notes(&self, case_details: CaseDetails) -> Result<Vec<Notes>, Error> {
        let token = TokenPieces::try_from(case_details.token.as_str())?;

        if !self.is_access_granted(&case_details.session_id, &case_details.token,&Some(case_details.case_number), true).await?.0 {
            return Err(Error::Unathorized)
        };
        match sqlx::query_as(
            r#"
                SELECT n.note_id,
                    n.author_id,
                    n.note_text,
                    n.relevant_media,
                    n.entry_timestamp,
                    n.case_number
                FROM notes n
                JOIN user_access_control uac
                    ON uac.case_number = n.case_number
                WHERE uac.user_id = $1::uuid
                    AND n.case_number = $2::uuid;
            "#
        )
            .bind(token.get_payload().sub)
            .bind(case_details.case_number)
            .fetch_all(self)
            .await {
                Ok(notes) => Ok(notes),
                Err(error) => Err(Error::from(error))
            }
    }

    async fn login_user(&self, token: String) -> Result<Uuid, Error> {
        let key_pieces = TokenPieces::try_from(token.as_str())?;
        let payload = key_pieces.get_payload();
        let Ok(user_id) = Uuid::try_parse(&payload.sub) else {
            return Err(Error::JwtError)
        };
        let expires_at = DateTime::from_timestamp_secs(Utc::now().timestamp() + 7 * 24 * 3600);
        let session_id = Uuid::new_v4();

        sqlx::query(
            r#"
                INSERT
                INTO auth_session (
                    session_id,
                    user_id,
                    token_hash,
                    expires_at
                ) VALUES (
                    $1, $2, $3, $4
                );
            "#
        )
        .bind(session_id)
        .bind(user_id)
        .bind(hex::encode(sha256(token.as_bytes().into())))
        .bind(expires_at)
        .execute(self)
        .await?;

        Ok(session_id)
    }

    async fn add_uac_member(
        &self, case_number: Uuid, token: String, session_id: String, target_user: Uuid
    ) -> Result<(), Error> {
        let admin_token = TokenPieces::try_from(token.as_str())?;
        
        if !self.is_access_granted(&session_id, &token, &Some(case_number), true).await?.0 ||
            admin_token.get_payload().role != "admin" {
            return Err(Error::Unathorized)
        };
        sqlx::query(
            r#"
                INSERT
                INTO user_access_control (
                    param_id,
                    user_id,
                    case_number
                ) VALUES (
                    $1, $2, $3
                );
            "#
        )
        .bind(Uuid::new_v4())
        .bind(target_user)
        .bind(case_number)
        .execute(self)
        .await?;

        Ok(())
    }

    async fn find_accessible_cases(&self, token: String, session_id: String) -> Result<Vec<CaseInformation>, Error> {
        let has_access = self.is_access_granted(&session_id, &token, &None, true).await;

        let Ok((true, pieces)) = has_access else {
            return Err(Error::Unathorized)
        };
        
        sqlx::query_as(
            r#"
            SELECT DISTINCT c.case_number,
                    c.user_id,
                    c.suspect_name,
                    c.suspect_aliases,
                    c.suspect_description,
                    c.suspect_phone,
                    c.suspect_email,
                    c.suspect_ip,
                    c.victim_name,
                    c.victim_email,
                    c.victim_phone,
                    c.timestamp_case
            FROM cases c
            JOIN user_access_control uac
                ON uac.case_number = c.case_number
            WHERE uac.user_id = $1;
            "#
        )
        .bind(pieces.get_payload().sub)
        .fetch_all(self)
        .await
        .map_err(Error::from)
    }

    async fn admin_get_user_info(&self, user_info: AdminUserInfoRequest) -> Result<UserInfo, Error> {
        let admin_token = self.is_access_granted(&user_info.admin_session_id.to_string(), &user_info.admin_token, &None, true).await?;
        
        if admin_token.1.get_payload().role != "admin" ||
            !admin_token.0 {
            return Err(Error::Unathorized)
        }

        match sqlx::query_as(
            r#"
                SELECT *
                FROM users
                WHERE user_handle =  $1;
            "#
        )
            .bind(user_info.user_handle)
            .fetch_optional(self)
            .await? {
                Some(user) => Ok(user),
                None => {
                    error!("User lookup failed");

                    Err(Error::UserNotFound)
                }
            }
    }

    async fn find_accessible_notes(&self, session_id: String, token: String) -> Result<Vec<Notes>, Error> {        
        let Ok((true, user)): Result<(bool, TokenPieces), Error> = self.is_access_granted(&session_id, &token, &None, true).await else {
            return Err(Error::Unathorized)
        };

        sqlx::query_as(
            r#"
            SELECT DISTINCT n.note_id,
                n.case_number,
                n.author_id,
                n.note_text,
                n.relevant_media,
                n.entry_timestamp
            FROM notes n
            JOIN user_access_control uac
                ON uac.case_number = n.case_number
            WHERE uac.user_id = $1;
            "#
        )
        .bind(user.get_payload().sub)
        .fetch_all(self)
        .await
        .map_err(Error::from)
    }

    async fn delete_invalid_token(&self, session_id: &String) -> Result<bool, Error> {
        match sqlx::query(
            r#"
                DELETE
                FROM auth_session
                WHERE session_id = $1;
            "#
        )
        .bind(session_id)
        .execute(self)
        .await {
            Ok(_) => Ok(true),
            Err(error) => Err(Error::from(error))
        }
    }

    async fn is_access_granted(&self, session_id: &String, token: &String, case_number: &Option<Uuid>, create_post: bool) -> Result<(bool, TokenPieces), Error> {
        info!("Checking if user is allowed to access requested resource...");
        let pieces = TokenPieces::try_from(token.as_str())?
            .verify_jwt(&var("MASTER_KEY")?, &token)?;
        let payload = pieces.get_payload();

        // For all events that depend on the timestamp, we want to get the exact timestamp.
        info!("Checking payload expiration date");
        if payload.exp <= Utc::now().timestamp() {
            error!("This token is expired as of {:?}.", DateTime::from_timestamp_secs(payload.exp));

            return Err(Error::JwtError)
        }
        
        info!("Checking if token is valid");
        if !payload.is_active {
            // Token is not valid, delete it to declutter the table.
            error!("Token not valid");

            self.delete_invalid_token(session_id).await?;

            return Err(Error::JwtError);
        }

        // Next check the database for our hashed token.
        info!("Checking database auth tables");
        let (token_hash,): (String,) = match sqlx::query_as(
            r#"
                SELECT au.token_hash
                FROM auth_session au
                LEFT JOIN user_access_control uac
                ON uac.user_id = au.user_id
                WHERE au.user_id = $1::uuid
                AND au.session_id = $2
                AND au.expires_at > NOW()
                AND ($3 IS NULL OR uac.case_number = $3)
                LIMIT 1;
            "#
        )
            .bind(Uuid::parse_str(&payload.sub)?)
            .bind(Uuid::parse_str(&session_id)?)
            .bind(case_number)
            .fetch_optional(self)
            .await {
                Ok(Some(id)) => id,
                Ok(None) => {
                    warn!("Query executed, nothing found");

                    (String::new(),)
                },
                Err(error) => {
                    error!("{error:?}");

                    return Err(Error::from(error));
                }
            };

        info!("Hex encoding hash");
        let bytes = hex::encode(sha256(token.as_bytes().into()));

        info!("Checking if hash integrity is good");
        if !bool::from(token_hash.as_bytes().ct_eq(bytes.as_bytes())) {
            warn!("Unauthorized token received");

            return Err(Error::Unathorized)
        }

        // Check if user is authorized to access the case
        info!("checking status");
        if create_post {
            // We want to maintain the exact time the request was officially "authorized" for documentation purposes.
            info!("Authorized at {}", Utc::now());

            Ok((true, pieces))
        } else {
            // Same as above, but for when an unauthorized attempt was made.
            error!("Unauthorized request at {}", Utc::now());

            Ok((false, pieces))
        }
    }
}