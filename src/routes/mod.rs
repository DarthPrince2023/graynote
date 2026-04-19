use axum_server::tls_rustls::RustlsConfig;
use chrono::Utc;
use colored::Colorize;
use moka::{
    future::{Cache, CacheBuilder}, policy::EvictionPolicy
};
use reqwest::Client;
use sqlx::{Postgres, Pool, postgres::PgPoolOptions};
use tokio::sync::Mutex;
use tracing::{warn, info};
use tracing_subscriber::{EnvFilter, fmt};
use uuid::Uuid;
use std::{collections::HashMap, env::var, fs::OpenOptions, net::IpAddr, sync::Arc, time::Duration};
use graynote_lib::types::{error::Error, structs::{CaseInformation, NoteDetails, UserAccessControlPolicy}};

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
    pub user_rates: Arc<Mutex<HashMap<(String, IpAddr), RateLimiter>>>,
    pub rustls_config: RustlsConfig,
    pub username_cache: Cache<String, Uuid>,
    pub case_information_cache: Cache<Uuid, CaseInformation>,
    pub note_details_cache: Cache<Uuid, NoteDetails>,
    pub case_details_cache: Cache<Uuid, (CaseInformation, Vec<NoteDetails>)>,
    pub user_access_control_policy_cache: Cache<Uuid, UserAccessControlPolicy>
}

impl SharedState {
    ///
    /// instantiate a new shared state instance for our service
    /// 
    pub async fn new() -> Result<Self, Error> {
        let username_cache: Cache<String, Uuid> = CacheBuilder::new(75_000)
            .name("username_cache")
            .eviction_policy(EvictionPolicy::tiny_lfu())
            .initial_capacity(50_000)
            .max_capacity(75_000)
            .time_to_live(Duration::from_secs(3_600 * 24))
            .time_to_idle(Duration::from_secs(3_600 * 6))
            .build();

        let case_information_cache: Cache<Uuid, CaseInformation> = CacheBuilder::new(50_000)
            .name("case_information_cache")
            .eviction_policy(EvictionPolicy::tiny_lfu())
            .initial_capacity(25_000)
            .max_capacity(50_000)
            .time_to_live(Duration::from_secs(3_600 * 24))
            .time_to_idle(Duration::from_secs(3_600 * 6))
            .build();

        let note_details_cache: Cache<Uuid, NoteDetails> = CacheBuilder::new(50_000)
            .name("note_details_cache")
            .eviction_policy(EvictionPolicy::tiny_lfu())
            .initial_capacity(25_000)
            .max_capacity(50_000)
            .time_to_live(Duration::from_secs(3_600 * 24))
            .time_to_idle(Duration::from_secs(3_600 * 6))
            .build();

        let user_access_control_policy_cache: Cache<Uuid, UserAccessControlPolicy> = CacheBuilder::new(50_000)
            .name("user_access_control_policy_cache")
            .eviction_policy(EvictionPolicy::tiny_lfu())
            .initial_capacity(25_000)
            .max_capacity(50_000)
            .time_to_live(Duration::from_secs(3_600 * 24))
            .time_to_idle(Duration::from_secs(3_600 * 6))
            .build();

        let case_details_cache: Cache<Uuid, (CaseInformation, Vec<NoteDetails>)> = CacheBuilder::new(25_000)
            .name("case_details_cache")
            .eviction_policy(EvictionPolicy::tiny_lfu())
            .initial_capacity(15_000)
            .max_capacity(25_000)
            .time_to_live(Duration::from_secs(3_600 * 24))
            .time_to_idle(Duration::from_secs(3_600 * 6))
            .build();

        // Attempt to get a postgres connection
        Self::init_tracing()?;

        info!("Retrieving necessary environment variables");
        let data_base_type = var("DATABASE_TYPE")?;
        let database_user = var("DATABASE_USER")?;
        let database_password = var("DATABASE_PASSWORD")?;
        let database_host = var("DATABASE_HOST")?;
        let database_schema = var("DATABASE_SCHEMA")?;
        let url_value = var("DATABASE_URL")?;
        let mut url = String::new();

        if url_value.is_empty().then(|| {
            warn!("{}", format!("DATABASE_URL environment variable is not set, falling back to constructing URL from other environment variables at {}", Utc::now()).purple());
        }).is_some() {
            info!("{}", format!("DATABASE_URL environment variable is not set, falling back to constructing URL from other environment variables at {}", Utc::now()).purple());

            url.push_str(&format!("{data_base_type}://{database_user}:{database_password}@{database_host}:5432/{database_schema}"));
        } else {
            info!("{}", format!("DATABASE_URL environment variable is set, using it to connect to database at {}", Utc::now()).purple());

            url.push_str(&url_value);
        }

        let key = var("MASTER_KEY")?;
        let use_https_strict_rule: bool = var("RESTRICT_HTTPS_ONLY")?.parse()?;
        let user_rates = Arc::new(Mutex::new(HashMap::new()));

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
            .await
            .map_err(|error| Error::from(&error.into()))?;

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
                username_cache,
                case_information_cache,
                note_details_cache,
                case_details_cache,
                user_access_control_policy_cache,
                rustls_config
            }
        )
    }

    pub async fn use_request_token(&mut self, username: String, ip_address: IpAddr) -> bool {
        let default_rate_limiter = RateLimiter::default();
        let mut user_rates_lock = self.user_rates.lock().await;
        let rate_limiter = user_rates_lock.get(&(username.clone(), ip_address));

        if let Some(rate_limiter) = rate_limiter {
            return rate_limiter.try_acquire().await
        } else {
            user_rates_lock.insert((username, ip_address), default_rate_limiter.clone());

            return default_rate_limiter.try_acquire().await
        }
    }

    pub fn init_tracing() -> Result<(), Error> {
        let tracing_filter = EnvFilter::try_from_default_env()
            .unwrap_or(EnvFilter::new("info"));
        let log_file = OpenOptions::new()
            .append(true)
            .create(true)
            .open("/usr/local/bin/trace/trace.log")?;
        fmt()
            .with_env_filter(tracing_filter)
            .with_writer(log_file)
            .with_ansi(false)
            .with_target(false)
            .compact()
            .init();

        Ok(())
    }
}
