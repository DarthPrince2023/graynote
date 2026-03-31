use axum_server::tls_rustls::RustlsConfig;
use reqwest::Client;
use sqlx::{
    Postgres, Pool, postgres::PgPoolOptions
};
use tracing_log::log::info;
use tracing_subscriber::{EnvFilter, fmt};
use std::env::var;
use graynote_lib::types::error::Error;

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
    pub async fn new() -> Result<(Self, RustlsConfig), Error> {
        // Attempt to get a postgres connection
        info!("Retrieving necessary environment variables");
        let url = &var("DATABASE_URL")?;
        let key = var("MASTER_KEY")?;
        let use_https_strict_rule: bool = var("RESTRICT_HTTPS_ONLY")?.parse()?;

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
            .connect(url)
            .await?;

        // Get a request sender
        info!("Construction HTTP request client");
        let client = reqwest::ClientBuilder::new()
            .https_only(use_https_strict_rule)
            .build()?;

        Ok(
            (Self {
                postgres_pool,
                client,
                key
            }, rustls_config)
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
