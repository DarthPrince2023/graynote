use std::{env::var, net::IpAddr};

use graynote_lib::types::{
    error::Error, structs::{
        AdminUserInfoRequest, AuthToken, CaseAccess, CaseDefinition, CaseInformation, CaseStatusUpdate, LogFormatter, NoteDetails, Notes, SessionInfo, UserInfo, basic_auth::BasicAuth
    }
};
use argon2::Config;
use chrono::{DateTime, Utc};
use hmac_crate::algorithms::hmac_sha_256::sha256;
use jwt::{constructor::TokenPieces, header::{Header, TokenType}, payload::Payload};
use sqlx::{
    Pool, Postgres, query
};
use subtle::ConstantTimeEq;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::database::Database;

const WEEKTIME_CALCULATION: i64 = 7 * 24 * 3_600;

///
/// `'Postgres'` DB implementation of the `'Database'` trait
/// 
impl Database for Pool<Postgres> {
    async fn user_exists(&self, username: &str, ip_address: IpAddr) -> Result<bool, Error> {
        let mut logger = LogFormatter::new(ip_address, "00000000-0000-0000-0000-000000000000".parse::<Uuid>()?);

        info!("{}", serde_json::to_string(&logger.with_message("Checking if user exists".into()).with_timestamp(Utc::now()))?);
        match sqlx::query(
            r#"
                SELECT username
                FROM users
                WHERE username = $1;
            "#
        )
        .bind(username)
        .fetch_optional(self)
        .await
        .map_err(|error| Error::from(&error))? {
            Some(_) => {
                warn!("{}", serde_json::to_string(&logger.with_message("User exists".into()).with_timestamp(Utc::now()))?);

                Ok(true)
            },
            None => {
                info!("{}", serde_json::to_string(&logger.with_message("User not found".into()).with_timestamp(Utc::now()))?);
                
                Ok(false)
            }
        }
    }
    
    async fn insert_user(&self, user: UserInfo, ip_address: IpAddr) -> Result<(), Error> {
        let mut logger = LogFormatter::new(ip_address, user.user_id());

        info!("{}", serde_json::to_string(&logger.with_message("Verifying user received".into()).with_timestamp(Utc::now()))?);
        if user.username().is_empty() ||
            user.password().is_empty() ||
            user.role().is_empty() {
                error!("{}", serde_json::to_string(&logger.with_message("Invalid payload received".into()).with_timestamp(Utc::now()))?);
                
                return Err(Error::InvalidCredentials);
        }

        let salt = format!("{}{}{}", var("MASTER_KEY")?, Utc::now().timestamp(), Uuid::new_v4());
        let config = Config::default();
        let hash = argon2::hash_encoded(user.password().as_bytes(), salt.as_bytes(), &config)?;
        let allowed_admins = var("DESIGNATED_ADMIN_USERS")?.to_lowercase();
        let allowed_admins: Vec<&str> = allowed_admins.split(",").collect();
        let allowed_roles = var("ALLOWED_ROLE_TYPES")?.to_lowercase();
        let allowed_roles: Vec<&str> = allowed_roles.split(",").collect();

        info!("{}", serde_json::to_string(&logger.with_message("Validating user role received against roles list".into()).with_timestamp(Utc::now()))?);
        if !allowed_roles.contains(&user.role().as_str()) {
            error!("{}", serde_json::to_string(&logger.with_message("Invalid role received".into()).with_timestamp(Utc::now()))?);
        
            return Err(Error::Unauthorized);
        }

        info!("{}", serde_json::to_string(&logger.with_message("Checking if role is admin and verifying against list of admins".into()).with_timestamp(Utc::now()))?);
        if user.role().to_lowercase() == "admin" &&
            !allowed_admins.contains(&user.username().to_lowercase().as_str()) {
                error!("{}", serde_json::to_string(&logger.with_message("Invalid admin creation attempt made".into()).with_timestamp(Utc::now()))?);
                
                return Err(Error::Unauthorized);
            };
        if self.user_exists(&user.username(), ip_address).await? {
            error!("{}", serde_json::to_string(&logger.with_message("Could not create user, handle in use".into()).with_timestamp(Utc::now()))?);

            return Err(Error::UserExists);
        }

        info!("{}", serde_json::to_string(&logger.with_message("Attempting to insert user into table".into()).with_timestamp(Utc::now()))?);
        sqlx::query(
            "INSERT INTO users
                    (
                        user_id, username, password,
                        user_role, created_at, entry_ip
                    ) VALUES (
                        $1, $2, $3, $4, $5, $6
                    );"
        )
            .bind(Uuid::new_v4())
            .bind(user.username())
            .bind(&hash)
            .bind(user.role())
            .bind(Utc::now().naive_utc())
            .bind(ip_address.to_string())
            .execute(self)
            .await
            .map_err(|error| Error::from(&error))?;

        Ok(())
    }

    async fn login_basic(&self, basic_auth: &BasicAuth, ip_address: IpAddr) -> Result<(TokenPieces, Uuid), Error> {
        let mut logger = LogFormatter::new(ip_address, "00000000-0000-0000-0000-000000000000".parse::<Uuid>()?);

        info!("{}", serde_json::to_string(&logger.with_message("Attempting authorization".into()).with_timestamp(Utc::now()))?);
        let user: Option<UserInfo> = sqlx::query_as(
            "SELECT *
                FROM users
                WHERE username = $1;"
            )
            .bind(&basic_auth.get_username())
            .fetch_optional(self)
            .await
            .map_err(|error| Error::from(&error))?;

        info!("{}", serde_json::to_string(&logger.with_message("Attempting to validate user authentication".into()).with_timestamp(Utc::now()))?);
        match user {
            Some(user) => {
                let time = Utc::now().timestamp();
                let header = Header::new("HS256".into(), TokenType::Jwt);
                let payload = Payload::new(user.user_id().to_string(), time + WEEKTIME_CALCULATION, "Graynote_auth_service".into(), Uuid::new_v4(), user.role(), time - 1, user.username());
                let token = TokenPieces::new(header, payload);

                if !argon2::verify_encoded(user.password().as_str(), basic_auth.get_password().as_ref().ok_or(Error::InvalidCredentials)?.as_bytes())? {
                    error!("{}", serde_json::to_string(&logger.with_message("Invalid credentials".into()).with_timestamp(Utc::now()))?);
                    
                    return Err(Error::InvalidCredentials)
                }

                match self.authorize_user(&token, ip_address).await {
                    Ok(session_id) => Ok((token, session_id)),
                    Err(error) => Err(error)
                }
            },
            None => {
                error!("{}", serde_json::to_string(&logger.with_message("Invalid credentials".into()).with_timestamp(Utc::now()))?);
                
                Err(Error::InvalidCredentials)
            }
        }
    }

    async fn authorize_user(&self, token: &TokenPieces, ip_address: IpAddr) -> Result<Uuid, Error> {
        let mut logger = LogFormatter::new(ip_address, token.get_payload().sub.parse::<Uuid>()?);
        let session_id = Uuid::new_v4();

        info!("{}", serde_json::to_string(&logger.with_message("Login successful, creating session".into()).with_timestamp(Utc::now()))?);
        sqlx::query(
            r#"
                INSERT
                INTO auth_session (
                    session_id,
                    user_id,
                    token_hash,
                    expires_at,
                    ip_address
                ) VALUES (
                    $1, $2, $3, $4, $5
                );
            "#
        )
        .bind(session_id)
        .bind(token.get_payload().sub)
        .bind(hex::encode(sha256(token.build_jwt(&var("MASTER_KEY")?)?.as_bytes().into())))
        .bind(token.get_payload().exp)
        .bind(ip_address.to_string())
        .execute(self)
        .await
        .map_err(|error| Error::from(&error))?;

        Ok(session_id)
    }

    async fn add_uac_member(
        &self, case_number: Option<Uuid>, note_number: Option<Uuid>, auth_token: &AuthToken, target_user: Uuid, ip_address: IpAddr
    ) -> Result<(), Error> {
        let mut logger = LogFormatter::new(ip_address, auth_token.token().get_payload().sub.parse::<Uuid>()?);

        info!("{}", serde_json::to_string(&logger.with_message("Attempting to validate admin for request".into()).with_timestamp(Utc::now()))?);
        self.is_access_granted(&auth_token, &None, &None, true, ip_address).await?;

        if let Some(case_number) = case_number {
            info!("{}", serde_json::to_string(&logger.with_message(format!("Adding user to UAC for case with identifier {case_number}")).with_timestamp(Utc::now()))?);
        }

        if let Some(note_number) = note_number {
            info!("{}", serde_json::to_string(&logger.with_message(format!("Adding user to UAC for note with identifier {note_number}")).with_timestamp(Utc::now()))?);
        }
        sqlx::query(
            r#"
                INSERT
                INTO user_access_control (
                    param_id,
                    user_id,
                    case_number,
                    note_id
                ) VALUES (
                    $1, $2, $3, $4
                );
            "#
        )
        .bind(Uuid::new_v4())
        .bind(target_user)
        .bind(case_number)
        .bind(note_number)
        .execute(self)
        .await
        .map_err(|error| Error::from(&error))?;

        Ok(())
    }

    async fn insert_note(&self, note: &Notes, ip_address: IpAddr) -> Result<(), Error> {
        let mut logger = LogFormatter::new(ip_address, note.auth_token().token().get_payload().sub.parse::<Uuid>()?);
        
        info!("{}", serde_json::to_string(&logger.with_message("Checking if user is authorized to insert note".into()).with_timestamp(Utc::now()))?);
        let note_details = &note.note_details();
        let pieces: TokenPieces = self.is_access_granted(&note.auth_token(),&Some(note_details.case_number()), &None, false, ip_address).await?;

        query(
            r#"
                INSERT
                INTO notes (
                    note_id,
                    author_id,
                    note_text,
                    relevant_media,
                    entry_timestamp,
                    case_number,
                    entry_ip
                ) VALUES (
                    $1, $2, $3, $4,
                    $5, $6, $7
                );
                "#
        )
            .bind(Uuid::new_v4())
            .bind(Uuid::parse_str(pieces.get_payload().sub.as_str())?)
            .bind(note_details.note_text())
            .bind(note_details.relevant_media())
            .bind(note_details.entry_timestamp())
            .bind(note_details.case_number())
            .bind(ip_address.to_string())
            .execute(self)
            .await
            .map_err(|error| Error::from(&error.into()))?;

        Ok(())
    }

    async fn insert_case_information(&self, case_definition: &CaseDefinition, ip_address: IpAddr) -> Result<Uuid, Error> {
        let case_number = Uuid::new_v4();
        let case_information = case_definition.case_information();
        let mut logger = LogFormatter::new(ip_address, case_definition.auth_token().token().get_payload().sub.parse::<Uuid>()?);

        info!("{}", serde_json::to_string(&logger.with_message(format!("Checking permissions for creating case with identifier of {case_number}")).with_timestamp(Utc::now()))?);
        self.is_access_granted(&case_definition.auth_token(), &None, &None, false, ip_address).await?;

        info!("{}", serde_json::to_string(&logger.with_message(format!("Attempting to create case with identifier {case_number}")).with_timestamp(Utc::now()))?);
        let (case_id,): (Uuid,) = sqlx::query_as(
            r#"WITH case_creation AS (
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
                        entry_ip,
                        timestamp_case
                    ) VALUES (
                        $1, $2, $3, $4, $5, $6,
                        $7, $8, $9, $10, $11, $12,
                        $13
                    )
                    RETURNING user_id, case_number
                )
                INSERT INTO user_access_control (
                    param_id,
                    user_id,
                    case_number
                ) 
                SELECT $13, user_id, case_number
                FROM case_creation;
            "#
        )
            .bind(case_number)
            .bind(case_definition.auth_token().token().get_payload().sub)
            .bind(case_information.suspect_name())
            .bind(case_information.suspect_aliases())
            .bind(case_information.suspect_description())
            .bind(case_information.suspect_phone())
            .bind(case_information.suspect_email())
            .bind(case_information.suspect_ip())
            .bind(case_information.victim_name())
            .bind(case_information.victim_email())
            .bind(case_information.victim_phone())
            .bind(Utc::now())
            .bind(Uuid::new_v4())
            .bind(ip_address.to_string())
            .fetch_one(self)
            .await
            .map_err(|error: sqlx::Error| Error::from(&error.into()))?;

        Ok(case_id)
    } 

    async fn get_case_information(&self, case_details: &CaseAccess, ip_address: IpAddr) -> Result<CaseInformation, Error> {
        let mut logger = LogFormatter::new(ip_address, case_details.auth_token().token().get_payload().sub.parse::<Uuid>()?);

        info!("{}", serde_json::to_string(&logger.with_message("Checking if user has access to view case".into()).with_timestamp(Utc::now()))?);
        let pieces: TokenPieces = self.is_access_granted(case_details.auth_token(),&Some(case_details.case_number()), &None, false, ip_address).await?;
        
        sqlx::query_as(
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
        .bind(pieces.get_payload().sub)
        .bind(case_details.case_number())
        .fetch_one(self)
        .await
        .map_err(|error| Error::from(&error.into()))
    }

    async fn get_case_notes(&self, case_access: &CaseAccess, ip_address: IpAddr) -> Result<Vec<NoteDetails>, Error> {
        let mut logger = LogFormatter::new(ip_address, case_access.auth_token().token().get_payload().sub.parse::<Uuid>()?);

        info!("{}", serde_json::to_string(&logger.with_message("Verifying is user is authorized to access requested resource".into()).with_timestamp(Utc::now()))?);
        let pieces: TokenPieces = self.is_access_granted(case_access.auth_token(), &Some(case_access.case_number()), &None, false, ip_address).await?;

        sqlx::query_as(
                r#"
                    SELECT n.note_id,
                        n.case_number,
                        n.author_id,
                        n.note_text,
                        n.relevant_media,
                        n.entry_timestamp
                    FROM notes n
                    JOIN user_access_control uac
                    ON uac.case_number = n.case_number
                    WHERE uac.user_id = $1::uuid
                    AND n.case_number = $2::uuid
                    ORDER BY n.entry_timestamp
                    DESC;
                "#
            )
            .bind(pieces.get_payload().sub.as_str())
            .bind(case_access.case_number())
            .fetch_all(self)
            .await
            .map_err(|error| Error::from(&error.into()))
    }

    async fn find_accessible_cases(&self, authorization_token: &AuthToken, ip_address: IpAddr) -> Result<Vec<CaseInformation>, Error> {
        let mut logger = LogFormatter::new(ip_address, authorization_token.token().get_payload().sub.parse::<Uuid>()?);

        info!("{}", serde_json::to_string(&logger.with_message("Verifying if user is authorized to access requested resource".into()).with_timestamp(Utc::now()))?);
        let has_access: TokenPieces = self.is_access_granted(authorization_token, &None, &None, false, ip_address).await?;

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
        .bind(has_access.get_payload().sub)
        .fetch_all(self)
        .await
        .map_err(|error| Error::from(&error.into()))
    }

    async fn admin_get_user_info(&self, user_info: AdminUserInfoRequest, ip_address: IpAddr) -> Result<Option<UserInfo>, Error> {
        let mut logger = LogFormatter::new(ip_address, user_info.admin_authorization().token().get_payload().sub.parse::<Uuid>()?);

        info!("{}", serde_json::to_string(&logger.with_message("Verifying admin access".into()).with_timestamp(Utc::now()))?);
        self.is_access_granted(&user_info.admin_authorization(), &None, &None, true, ip_address).await?;

        info!("{}", serde_json::to_string(&logger.with_message("Performing database lookup of user".into()).with_timestamp(Utc::now()))?);
        sqlx::query_as(
            r#"
                SELECT *
                FROM users
                WHERE username =  $1;
            "#
        )
            .bind(user_info.username())
            .fetch_optional(self)
            .await
            .map_err(|error| Error::from(&error.into()))
    }

    async fn find_accessible_notes(&self, authorization_token: &AuthToken, ip_address: IpAddr) -> Result<Vec<NoteDetails>, Error> {  
        let mut logger = LogFormatter::new(ip_address, authorization_token.token().get_payload().sub.parse::<Uuid>()?);

        info!("{}", serde_json::to_string(&logger.with_message("Verifying authorization for access".into()).with_timestamp(Utc::now()))?);    
        let user: TokenPieces = self.is_access_granted(authorization_token, &None, &None, false, ip_address).await?;

        info!("{}", serde_json::to_string(&logger.with_message("Retrieving accessible notes for user".into()).with_timestamp(Utc::now()))?);
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
        .map_err(|error| Error::from(&error.into()))
    }

    async fn delete_invalid_token(&self, session_id: Uuid, ip_address: IpAddr, user_id: Uuid) -> Result<(), Error> {
        let mut logger = LogFormatter::new(ip_address, user_id);

        info!("{}", serde_json::to_string(&logger.with_message("Deleting invalid token automatically, if it exists".into()).with_timestamp(Utc::now()))?);
        sqlx::query(
            r#"
                DELETE
                FROM auth_session
                WHERE session_id = $1;
            "#
        )
        .bind(session_id)
        .execute(self)
        .await
        .map_err(|error| Error::from(&error.into()))?;

        Ok(())
    }

    async fn admin_cycle_token(&self, admin_authorization: &AuthToken, session_id: Uuid, ip_address: IpAddr) -> Result<(), Error> {
        let mut logger = LogFormatter::new(ip_address, admin_authorization.token().get_payload().sub.parse::<Uuid>()?);

        info!("{}", serde_json::to_string(&logger.with_message("Verifying admin authorization request".into()).with_timestamp(Utc::now()))?);
        let _ = self.is_access_granted(&admin_authorization, &None, &None, true, ip_address).await?;

        info!("{}", serde_json::to_string(&logger.with_message("Deleting token, if it exists".into()).with_timestamp(Utc::now()))?);
        sqlx::query(
            r#"
                DELETE
                FROM auth_session
                WHERE session_id = $1;
            "#
        )
        .bind(session_id)
        .execute(self)
        .await
        .map_err(|error| Error::from(&error.into()))?;

        Ok(())
    }

    async fn is_access_granted(&self, auth_token: &AuthToken, case_number: &Option<Uuid>, note_number: &Option<Uuid>, admin_action: bool, ip_address: IpAddr) -> Result<TokenPieces, Error> {
        let master_key = var("MASTER_KEY")?;
        let token_string = auth_token.token().build_jwt(&master_key)?;
        let token = auth_token.token().verify_jwt(&master_key, &token_string)?;
        let payload = token.get_payload();
        let mut logger = LogFormatter::new(ip_address, auth_token.token().get_payload().sub.parse::<Uuid>()?);

        if admin_action && !is_admin_granted(auth_token.token().to_owned(), ip_address)? {
            error!("{}", serde_json::to_string(&logger.with_message("Unauthorized admin attempt".into()).with_timestamp(Utc::now()))?);

            return Err(Error::Unauthorized)
        }
        
        // For all events that depend on the timestamp, we want to get the exact timestamp.
        info!("{}", serde_json::to_string(&logger.with_message("Checking payload expiration date".into()).with_timestamp(Utc::now()))?);
        if payload.exp <= Utc::now().timestamp() {
            error!("{}", serde_json::to_string(&logger.with_message(format!("This token is expired as of {:?}.", DateTime::from_timestamp_secs(payload.exp))).with_timestamp(Utc::now()))?);

            return Err(Error::JwtError)
        }
        
        info!("{}", serde_json::to_string(&logger.with_message("Checking if token is valid".into()).with_timestamp(Utc::now()))?);
        if !payload.is_active {
            // Token is not valid, delete it to declutter the table.
            error!("{}", serde_json::to_string(&logger.with_message("Token not valid".into()).with_timestamp(Utc::now()))?);

            self.delete_invalid_token(auth_token.session_id(), ip_address, token.get_payload().sub.parse::<Uuid>()?).await?;

            return Err(Error::JwtError);
        }

        // Next check the database for our hashed token.
        info!("{}", serde_json::to_string(&logger.with_message("Checking database auth table".into()).with_timestamp(Utc::now()))?);
        let (token_hash,): (String,) = match sqlx::query_as(
            r#"
                SELECT au.token_hash
                FROM auth_session au
                LEFT JOIN user_access_control uac
                ON uac.user_id = au.user_id
                WHERE au.user_id = $1::uuid
                AND au.session_id = $2
                AND au.expires_at > NOW()
                AND (
                    ($3 IS NULL OR uac.case_number = $3)
                    AND
                    ($4 IS NULL OR uac.note_id = $4)
                )
                LIMIT 1;
            "#
        )
            .bind(Uuid::parse_str(&payload.sub)?)
            .bind(Uuid::parse_str(&auth_token.session_id().to_string())?)
            .bind(case_number)
            .bind(note_number)
            .fetch_optional(self)
            .await {
                Ok(Some(id)) => {
                    info!("{}", serde_json::to_string(&logger.with_message("User found for authorization".into()).with_timestamp(Utc::now()))?);

                    id
                },
                Ok(None) => {
                    info!("{}", serde_json::to_string(&logger.with_message("Query executed, nothing found".into()).with_timestamp(Utc::now()))?);
                    
                    (String::new(),)
                },
                Err(error) => {
                    let error = Error::from(&error.into());
                    error!("{}", serde_json::to_string(&logger.with_message("Unable to access requested".into()).with_timestamp(Utc::now()).with_error(Some(error.clone())))?);
                    
                    return Err(error);
                }
            };
        let bytes = hex::encode(sha256(token_string.as_bytes().into()));

        if !bool::from(token_hash.as_bytes().ct_eq(bytes.as_bytes())) {
            warn!("{}", serde_json::to_string(&logger.with_message("Unauthorized token received".into()).with_timestamp(Utc::now()))?);
    
            return Err(Error::Unauthorized)
        }

        // We want to maintain the exact time the request was officially "authorized" for documentation purposes.
        info!("{}", serde_json::to_string(&logger.with_message("Authorized".into()).with_timestamp(Utc::now()))?);
    
        Ok(token)
    }
    
    async fn admin_delete_user_account(&self, admin_authorization: &AuthToken, username: String, ip_address: IpAddr) -> Result<(), Error> {
        let mut logger = LogFormatter::new(ip_address, admin_authorization.token().get_payload().sub.parse::<Uuid>()?);

        info!("{}", serde_json::to_string(&logger.with_message("Checking permissions for deleting user account".into()).with_timestamp(Utc::now()))?);
        self.is_access_granted(&admin_authorization, &None, &None, true, ip_address).await?;

        sqlx::query(r#"
            WITH deleted_user AS (
                DELETE
                FROM users
                WHERE username = $1
                RETURNING user_id
            )
            deleted_session AS (
                DELETE
                FROM auth_session
                WHERE user_id IN (SELECT user_id FROM deleted_user)
            )
            deleted_user_access AS (
                DELETE
                FROM user_access_control
                WHERE user_id IN (SELECT user_id FROM deleted_user)
            );
        "#)
        .bind(username)
        .execute(self)
        .await
        .map_err(|error| Error::from(&error.into()))?;

        Ok(())
    }
    
    async fn delete_user_account(&self, authorization: &AuthToken, ip_address: IpAddr) -> Result<(), Error> {
        let mut logger = LogFormatter::new(ip_address, authorization.token().get_payload().sub.parse::<Uuid>()?);

        info!("{}", serde_json::to_string(&logger.with_message("Checking permissions for deleting user account".into()).with_timestamp(Utc::now()))?);
        self.is_access_granted(&authorization, &None, &None, false, ip_address).await?;

        sqlx::query(r#"
            WITH deleted_user AS (
                DELETE
                FROM users
                WHERE username = $1
                RETURNING user_id
            )
            deleted_session AS (
                DELETE
                FROM auth_session
                WHERE user_id IN (SELECT user_id FROM deleted_user)
            )
            deleted_user_access AS (
                DELETE
                FROM user_access_control
                WHERE user_id IN (SELECT user_id FROM deleted_user)
            );
        "#)
        .bind(authorization.token().get_payload().username())
        .execute(self)
        .await
        .map_err(|error| Error::from(&error.into()))?;

        Ok(())
    }
    
    async fn cycle_token(&self, authorization: &AuthToken, ip_address: IpAddr) -> Result<(), Error> {
        let mut logger = LogFormatter::new(ip_address, authorization.token().get_payload().sub.parse::<Uuid>()?);

        info!("{}", serde_json::to_string(&logger.with_message("Checking permissions to cycle token".into()).with_timestamp(Utc::now()))?);
        self.is_access_granted(&authorization, &None, &None, false, ip_address).await?;
        
        info!("{}", serde_json::to_string(&logger.with_message("Deleting token, if it exists".into()).with_timestamp(Utc::now()))?);
        sqlx::query(
            r#"
                DELETE
                FROM auth_session
                WHERE session_id = $1;
            "#
        )
        .bind(authorization.session_id())
        .execute(self)
        .await
        .map_err(|error| Error::from(&error.into()))?;

        Ok(())
    }
    
    async fn kill_sessions(&self, authorization: &AuthToken, ip_address: IpAddr) -> Result<(), Error> {
        let mut logger = LogFormatter::new(ip_address, authorization.token().get_payload().sub.parse::<Uuid>()?);

        info!("{}", serde_json::to_string(&logger.with_message("Checking permissions to cycle tokens".into()).with_timestamp(Utc::now()))?);
        self.is_access_granted(&authorization, &None, &None, false, ip_address).await?;
        
        info!("{}", serde_json::to_string(&logger.with_message("Deleting tokens".into()).with_timestamp(Utc::now()))?);
        sqlx::query(
            r#"
                DELETE
                FROM auth_session
                WHERE session_id != $1::uuid
                AND user_id = $2::uuid;
            "#
        )
        .bind(authorization.session_id())
        .bind(authorization.token().get_payload().sub.parse::<Uuid>()?)
        .execute(self)
        .await
        .map_err(|error| Error::from(&error.into()))?;

        Ok(())
    }
    
    async fn list_sessions(&self, authorization: &AuthToken, ip_address: IpAddr) -> Result<Vec<SessionInfo>, Error> {
        let mut logger = LogFormatter::new(ip_address, authorization.token().get_payload().sub.parse::<Uuid>()?);

        info!("{}", serde_json::to_string(&logger.with_message("Checking permissions to list active sessions".into()).with_timestamp(Utc::now()))?);
        self.is_access_granted(&authorization, &None, &None, false, ip_address).await?;
        
        sqlx::query_as(r#"
           WITH user_id_selected AS (
                SELECT user_id
                FROM users
                WHERE username = $1
            ) 
            SELECT session_id,
                expires_at,
                ip_address
            FROM auth_session
            WHERE user_id IN (SELECT user_id FROM user_id_selected);
        "#)
        .bind(authorization.token().get_payload().username())
        .fetch_all(self)
        .await
        .map_err(|error| Error::from(&error.into()))
    }
    
    async fn update_case_status(&self, case: CaseStatusUpdate, ip_address: IpAddr) -> Result<(), Error> {
        let mut logger = LogFormatter::new(ip_address, case.case().auth_token().token().get_payload().sub.parse::<Uuid>()?);

        info!("{}", serde_json::to_string(&logger.with_message("Checking permissions to update case status".into()).with_timestamp(Utc::now()))?);
        self.is_access_granted(&case.case().auth_token(), &None, &None, false, ip_address).await?;

        sqlx::query(r#"
            UPDATE cases
            SET case_status = $1
            WHERE case_number = $2;
        "#)
        .bind(serde_json::to_string(&case.status())?)
        .bind(case.case().case_number())
        .execute(self)
        .await
        .map_err(|error| Error::from(&error.into()))?;
    
        Ok(())
    }
}

pub fn is_admin_granted(authorization: TokenPieces, ip_address: IpAddr) -> Result<bool, Error> {
    let mut logger = LogFormatter::new(ip_address, authorization.get_payload().sub.parse::<Uuid>()?);
    let allowed_admins = var("DESIGNATED_ADMIN_USERS")?;
    let allowed_admins: Vec<&str> = allowed_admins.split(",").collect();

    if !allowed_admins.contains(&authorization.get_payload().username().as_str()) &&
            &authorization.get_payload().role != "admin" {
        error!("{}", serde_json::to_string(&logger.with_message("Unauthorized admin attempt".into()).with_timestamp(Utc::now()))?);

        return Err(Error::Unauthorized)
    };

    Ok(true)
}
