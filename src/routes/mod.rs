use dotenvy::Error as DotEnvError;
use jwt::errors::Error as JwtError;
use reqwest::{
    Client, Error as ClientError
};
use serde::{Deserialize, Serialize};
use serde_json::Error as JsonError;
use sqlx::{
    Postgres, Pool, Error as SqlxError,
    postgres::PgPoolOptions
};
use tracing_log::log::info;
use tracing_subscriber::{EnvFilter, fmt};
use std::{
    env::{
        VarError, var
    },
    fmt::Display,
    str::ParseBoolError
};
use uuid::Error as UuidError;

pub mod client_modifier;
pub mod post;

///
/// Shared state we use in the service for handling things like persistent database connectivity.
///
#[derive(Debug, Clone)]
pub struct SharedState {
    pub postgres_pool: Pool<Postgres>,
    pub client: Client,
    pub key: String
}

impl SharedState {
    ///
    /// instantiate a new shared state instance for our service
    /// 
    pub async fn new() -> Result<Self, Error> {
        Self::init_tracing();

        // Attempt to get a postgres connection
        info!("Retrieving necessary environment variables");
        let url = &var("DATABASE_URL")?;
        let key = var("MASTER_KEY")?;
        let use_https_strict_rule: bool = var("RESTRICT_HTTPS_ONLY")?.parse()?;
        
        info!("Trying to connect to Database");
        let postgres_pool = PgPoolOptions::new()
            .min_connections(1)
            .max_connections(10)
            .connect(url)
            .await?;

        // Get a request sender
        info!("Construction HTTP request client");
        let client = reqwest::ClientBuilder::new()
            .https_only(use_https_strict_rule)
            .build()?;

        Ok(
            Self {
                postgres_pool,
                client,
                key
            }
        )
    }

    pub fn init_tracing() {
        let tracing_filter = EnvFilter::try_from_default_env()
            .unwrap_or(EnvFilter::new("info"));
        fmt()
            .with_env_filter(tracing_filter)
            .init();
    }
}

///
/// Declare custom `'Error'` enum type for handling errors in the codebase
/// 
#[derive(Debug, Deserialize, Serialize)]
pub enum Error {
    EnvError,
    DatabaseError,
    UserNotFound,
    ClientError,
    BooleanParseError,
    JwtError,
    InvalidCredentials,
    UserExists,
    UuidError,
    Unathorized,
    JsonParseError
}

impl From<JsonError> for Error {
    fn from(_: JsonError) -> Self {
        Self::JsonParseError
    }
}

impl From<UuidError> for Error {
    fn from(_: UuidError) -> Self {
        Self::UuidError
    }
}

///
/// Convert from `'JwtError'` to Error
///
impl From<JwtError> for Error {
    fn from(_: JwtError) -> Self {
        Self::JwtError
    }
}

///
/// Convert from `'ParseErrorBool'` for our custom `'Error'` type
/// 
impl From<ParseBoolError> for Error {
    fn from(_: ParseBoolError) -> Self {
        Self::BooleanParseError
    }
}

///
/// Convert from `'ClientError'` for our custom `'Error'` type
/// 
impl From<ClientError> for Error {
    fn from(_: ClientError) -> Self {
        Self::ClientError
    }
}

///
/// Convert from `'DotEnvError'` for our custom `'Error'` type
/// 
impl From<DotEnvError> for Error {
    fn from(_: DotEnvError) -> Self {
        Self::EnvError
    }
}

///
/// Convert from `'VarError'` for our custom `'Error'` type
/// 
impl From<VarError> for Error {
    fn from(_: VarError) -> Self {
        Self::EnvError
    }
}

///
/// Convert from `'SqlxError'` for our custom `'Error'` type
///
impl From<SqlxError> for Error {
    fn from(_: SqlxError) -> Self {
        Self::DatabaseError
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BooleanParseError => write!(f, "Could not parse boolean value"),
            Self::EnvError => write!(f, "Environment error"),
            Self::ClientError => write!(f, "Client error"),
            Self::UserNotFound => write!(f, "User identified by information could not be verified."),
            Self::DatabaseError => write!(f, "Database error has occurred"),
            Self::JwtError => write!(f, "Token could not be verified."),
            Self::InvalidCredentials => write!(f, "Could not login; invalid credentials provided."),
            Self::UserExists => write!(f, "Could not create user, username exists."),
            Self::UuidError => write!(f, "Could not parse UUID"),
            Self::Unathorized => write!(f, "Unauthorized"),
            Self::JsonParseError => write!(f, "Unable to parse JSON data")
        }
    }
}
