use std::env::var;

use crate::{
    database::{
        Database, types::{
            CaseAccess, CaseInformation, Notes, UserInfo
        }
    },
    routes::{Error, client_modifier::BasicAuth}
};
use chrono::{DateTime, Utc};
use hmac_crate::algorithms::hmac_sha_256::sha256;
use jwt::{constructor::TokenPieces, header::{Header, TokenType}, payload::Payload};
use sqlx::{
    Pool, Postgres, query
};
use uuid::Uuid;

///
/// `'Postgres'` DB implementation of the `'Database'` trait
/// 
impl Database for Pool<Postgres> {
    async fn user_exists(&self, username: &str) -> Result<bool, Error> {
        match sqlx::query_as(
            r#"
                SELECT user_handle
                FROM users
                WHERE user_handle = $1;
            "#
        )
        .bind(username)
        .fetch_optional(self)
        .await {
            Ok(Some(())) => return Ok(true),
            Ok(None) => return Ok(false),
            Err(error) => return Err(Error::from(error))
        }
    }
    
    async fn insert_user(&self, user: UserInfo) -> Result<(), Error> {
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
            .bind(hex::encode(sha256(user.password_id.as_bytes().to_vec())))
            .bind(user.user_role)
            .bind(Utc::now().naive_utc())
            .execute(self)
            .await {
                Ok(_) => return Ok(()),
                Err(error) => return Err(error.into())
            };
    }

    async fn login_basic(&self, basic_auth: BasicAuth) -> Result<String, Error> {
        let key = var("MASTER_KEY")?;
        let password_encrypt = match basic_auth.password {
            Some(password) => password,
            None => String::new()
        };
        let password_encrypt = sha256(password_encrypt.as_bytes().to_vec());
        let user: UserInfo = match sqlx::query_as(
            "SELECT *
                FROM users
                WHERE user_handle = $1
                AND password_id = $2;"
            )
            .bind(&basic_auth.username)
            .bind(hex::encode(&password_encrypt))
            .fetch_one(self)
            .await {
                Ok(user) => user, 
                Err(error) => return Err(Error::from(error))
            };
        let time = Utc::now().timestamp();
        let header = Header::new("HS256".into(), TokenType::Jwt);
        let payload = Payload::new(user.user_id.to_string(), time + 7 * 24 * 3_600, "Graynote_auth_service".into(), Uuid::new_v4(), user.user_role.into(), time - 1);
        let token = TokenPieces::new(header, payload);
        let token_string = token.build_jwt(&key)?;

        match self.login_user(token_string.clone()).await {
            Ok(()) => return Ok(token_string),
            Err(error) => return Err(Error::from(error))
        }
    }

    async fn insert_note(&self, note: Notes) -> Result<(), Error> {
        let note_id = Uuid::new_v4();
        let has_access = self.is_access_granted(note.token.clone(),Some(note.case_number), false).await.map_err(Error::from);
        let Ok(true) = has_access else {
            return Err(Error::Unathorized)
        };
        let token_pieces = TokenPieces::try_from(note.token.as_str())?;

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
            .bind(note_id)
            .bind(token_pieces.get_payload().sub)
            .bind(note.note_text)
            .bind(note.relevant_media)
            .bind(note.entry_timestamp)
            .bind(note.case_number)
            .execute(self)
            .await {
                Ok(_) => return Ok(()),
                Err(error) => return Err(Error::from(error))
            }
    }

    async fn insert_case_information(&self, case_access: CaseAccess) -> Result<Uuid, Error> {
        let token = case_access.token;
        let has_access = self.is_access_granted(token, None, true).await.map_err(Error::from);
        let Ok(true) = has_access else {
            return Err(Error::Unathorized)
        };
        let case_number = Uuid::new_v4();
        let case_information = case_access.case_information;

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
            Ok(_) => return Ok(case_number),
            Err(error) => return Err(Error::from(error))
        }
    } 

    async fn get_user_data(&self, username: &str, password: &str) -> Result<UserInfo, Error> {
        let password = sha256(password.as_bytes().into());

        match sqlx::query_as(
            r#"
                SELECT user_id,
                    user_handle,
                    password_id,
                    user_role,
                    created_at
                FROM users
                WHERE user_handle = $1
                AND password_id = $2;
            "#
        )
        .bind(username)
        .bind(hex::encode(password))
        .fetch_one(self)
        .await {
            Ok(user) => return Ok(user),
            Err(error) => return Err(Error::from(error))
        }
    }

    async fn get_case_information(&self, case_number: Uuid, token: String) -> Result<CaseInformation, Error> {
        let has_access = self.is_access_granted(token.clone(),Some(case_number), false).await.map_err(Error::from);
        println!("ACCESS => {has_access:?}");
        let Ok(true) = has_access else {
            return Err(Error::Unathorized)
        };
        println!("Authorized");
        let token_pieces = TokenPieces::try_from(token.as_str())?;
        let user_id: Uuid = token_pieces.get_payload().sub.parse()?;
        println!("User => {user_id:?}");

        let result: CaseInformation = match sqlx::query_as(
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
        .bind(user_id)
        .bind(case_number)
        .fetch_one(self)
        .await {
            Ok(data) => data,
            Err(error) => {
                println!("ERROR => {error:?}");

                return Err(Error::from(error));
            }
        };
        println!("CASE => {result:?}");

        Ok(result)
    }

    async fn get_case_notes(&self, case_number: Uuid, token: String) -> Result<Vec<Notes>, Error> {
        let has_access = self.is_access_granted(token.clone(),Some(case_number), false).await.map_err(Error::from);
        let Ok(true) = has_access else {
            return Err(Error::Unathorized)
        };
        let token_pieces = TokenPieces::try_from(token.as_str())?;
        let user_id: Uuid = token_pieces.get_payload().sub.parse()?;
        
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
            .bind(user_id)
            .bind(case_number)
            .fetch_all(self)
            .await {
                Ok(notes) => return Ok(notes),
                Err(error) => return Err(Error::from(error))
            };
    }

    async fn login_user(&self, token: String) -> Result<(), Error> {
        let key_pieces = TokenPieces::try_from(token.as_str())?;
        let user_id = key_pieces.get_payload().sub;
        let user_id = Uuid::try_parse(user_id.as_str())?;
        let token_hash = sha256(token.as_bytes().to_vec());
        let expires_at = Utc::now().timestamp() + 7 * 24 * 3600;
        let expires_at = DateTime::from_timestamp_secs(expires_at);

        sqlx::query(
            r#"
                INSERT
                INTO auth_session (
                    user_id,
                    token_hash,
                    expires_at
                ) VALUES (
                    $1, $2, $3
                );
            "#
        )
        .bind(user_id)
        .bind(hex::encode(token_hash))
        .bind(expires_at)
        .execute(self)
        .await
        .map_err(Error::from)?;

        Ok(())
    }

    async fn add_uac_member(
        &self, case_number: Uuid, token: String, target_user: Uuid
    ) -> Result<(), Error> {
        self.is_access_granted(token.clone(), Some(case_number), false).await?;

        let admin_token = TokenPieces::try_from(token.as_str())?;
        
        if admin_token.get_payload().role != "admin" {
            return Err(Error::Unathorized);
        }
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
        .await
        .map_err(Error::from)?;

        Ok(())
    }

    async fn find_accessible_cases(&self, token: String) -> Result<Vec<CaseInformation>, Error> {
        let has_access = self.is_access_granted(token.clone(), None, false).await;

        let Ok(true) = has_access else {
            return Err(Error::Unathorized)
        };

        let token_pieces = TokenPieces::try_from(token.as_str())?;
        
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
        .bind(token_pieces.get_payload().sub)
        .fetch_all(self)
        .await
        .map_err(Error::from)
    }

    async fn find_accessible_notes(&self, token: String) -> Result<Vec<Notes>, Error> {
        let has_access = self.is_access_granted(token.clone(), None, false).await;
        
        let Ok(true) = has_access else {
            return Err(Error::Unathorized)
        };

        let token_pieces = TokenPieces::try_from(token.as_str())?;

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
        .bind(token_pieces.get_payload().sub)
        .fetch_all(self)
        .await
        .map_err(Error::from)
    }

    async fn delete_invalid_token(&self, token: String) -> Result<bool, Error> {
        let token = sha256(token.as_bytes().to_vec());

        match sqlx::query(
            r#"
                DELETE
                FROM auth_session
                WHERE token_hash = $1;
            "#
        )
        .bind(hex::encode(token))
        .execute(self)
        .await {
            Ok(_) => return Ok(true),
            Err(error) => return Err(Error::from(error))
        }
    }

    async fn is_access_granted(&self, token: String, case_number: Option<Uuid>, create_post: bool) -> Result<bool, Error> {
        let key = var("MASTER_KEY")?;
        let token_pieces = TokenPieces::try_from(token.as_str())?;
        let verified = token_pieces.verify_jwt(&key, &token)?;
        let payload = verified.get_payload();
        let is_valid = payload.is_active;
        let token_hash = sha256(token.as_bytes().to_vec());
        println!("IS VALID => {is_valid}");
        if !is_valid {
            self.delete_invalid_token(token).await?;

            return Err(Error::JwtError);
        }

        // Next check the database for our hashed token.
        let (user_id,): (Option<Uuid>,) = match sqlx::query_as(
            r#"
                SELECT user_id
                FROM auth_session au
                WHERE au.user_id = $1
                AND au.token_hash = $2;
            "#
        )
            .bind(Uuid::parse_str(&payload.sub)?)
            .bind(hex::encode(token_hash))
            .fetch_optional(self)
            .await? {
                Some(id) => id,
                None => {
                    println!("BROKE HERE 1");
                    
                    return Err(Error::InvalidCredentials)
                }
            };

        // Check if user is authorized to access the case
        if create_post {
            return Ok(true)
        }

        match sqlx::query(
            r#"
                SELECT 1
                FROM user_access_control uac
                WHERE uac.user_id = $1
                AND $2 IS NULL OR uac.case_number = $2
                LIMIT 1;
            "#
        )
            .bind(user_id)
            .bind(case_number)
            .fetch_optional(self)
            .await? {
                Some(_) => return Ok(true),
                None => return Err(Error::InvalidCredentials)
            };
    }
}