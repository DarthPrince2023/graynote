use axum_server::tls_rustls::RustlsConfig;
use chrono::Utc;
use reqwest::Client;
use sqlx::{
    Postgres, Pool, postgres::PgPoolOptions
};
use tracing::warn;
use tracing_log::log::info;
use tracing_subscriber::{EnvFilter, fmt};
use std::{collections::HashMap, env::var};
use graynote_lib::types::error::Error;

use crate::routes::rate_limiter::RateLimiter;

pub mod post;
pub mod rate_limiter;

///
/// Shared state we use in the service for handling things like persistent database connectivity.
///
#[derive(Debug, Clone)]
pub struct SharedState {
    pub postgres_pool: Pool<Postgres>,
    pub client: Client,
    pub key: String,
    pub user_rates: HashMap<String, RateLimiter>,
    pub rustls_config: RustlsConfig
}

impl SharedState {
    ///
    /// instantiate a new shared state instance for our service
    /// 
    pub async fn new() -> Result<Self, Error> {
        // Attempt to get a postgres connection
        info!("Retrieving necessary environment variables");
        let data_base_type = var("DATABASE_TYPE")?;
        let database_user = var("DATABASE_USER")?;
        let database_password = var("DATABASE_PASSWORD")?;
        let database_host = var("DATABASE_HOST")?;
        let database_schema = var("DATABASE_SCHEMA")?;
        let url_value = var("DATABASE_URL")?;
        let mut url = String::new();

        if let Some(_) = url_value.is_empty().then(|| {
            warn!("DATABASE_URL environment variable is not set, falling back to constructing URL from other environment variables at {}", Utc::now());
        }) {
            info!("DATABASE_URL environment variable is not set, falling back to constructing URL from other environment variables at {}", Utc::now());

            url.push_str(&format!("{data_base_type}://{database_user}:{database_password}@{database_host}:5432/{database_schema}"));
        } else {
            info!("DATABASE_URL environment variable is set, using it to connect to database at {}", Utc::now());

            url.push_str(&url_value);
        }

        let key = var("MASTER_KEY")?;
        let use_https_strict_rule: bool = var("RESTRICT_HTTPS_ONLY")?.parse()?;
        let user_rates = HashMap::new();

        info!("Trying to create Rustls Configuration using provided certificates");
        let rustls_config = RustlsConfig::from_pem_file(
            "/ssl_certificates/graynote_cert.pem",
            "/ssl_certificates/graynote_key.pem"
        )
        .await?;
        
        info!("Trying to connect to Database");
        let postgres_pool = PgPoolOptions::new()
            .min_connections(1)
            .max_connections(10)
            .connect(&url)
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
                key,
                user_rates,
                rustls_config
            }
        )
    }

    pub async fn use_request_token(&mut self, username: String) -> bool {
        let default_rate_limiter = RateLimiter::new();
        let rate_limiter = self.user_rates.get(&username);

        if let Some(rate_limiter) = rate_limiter {
            return rate_limiter.try_acquire().await
        } else {
            self.user_rates.insert(username.clone(), default_rate_limiter.clone());

            info!("Created new rate limiter for user {} at {}", username, Utc::now());

            return default_rate_limiter.try_acquire().await
        }
    }

    pub fn init_tracing() {
        let tracing_filter = EnvFilter::try_from_default_env()
            .unwrap_or(EnvFilter::new("info"));
        fmt()
            .with_env_filter(tracing_filter)
            .init();
    }
}
