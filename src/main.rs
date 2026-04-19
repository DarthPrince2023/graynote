use std::net::SocketAddr;

use axum::{Router, http::HeaderValue, routing::post};
use axum_client_ip::ClientIpSource;
use chrono::Utc;
use colored::Colorize;
use reqwest::{Method, header::CONTENT_TYPE};
use tower_http::cors::CorsLayer;
use tracing::{info, error};

use crate::routes::{SharedState, post as PostRoutes};

pub mod routes;
pub mod database;

#[tokio::main]
async fn main() {
    // Get a new shared state instance, or return error on failure
    let state = match SharedState::new().await {
        Ok(state) => state,
        Err(error) => {
            error!("Could not create shared state => {error:?}");

            return;
        }
    };

    info!("Attempting to build Router at {}", Utc::now().to_string().purple());
    let allowed_origin = match HeaderValue::try_from("*") {
        Ok(origin) => origin,
        Err(error) => {
            error!("Could not get HeaderValue from provided input => {error}");

            return;
        }
    };
    let cors = CorsLayer::new()
        .allow_headers([CONTENT_TYPE])
        .allow_origin(allowed_origin)
        .allow_methods(Method::POST);
    let connect_info = ClientIpSource::ConnectInfo;
    let router = Router::new()
        .route("/v1/auth/user/create", post(PostRoutes::create_user))
        .route("/v1/auth/user/login", post(PostRoutes::basic_login))
        .route("/v1/auth/user/delete", post(PostRoutes::delete_user))
        .route("/v1/auth/user/sessions", post(PostRoutes::kill_user_sessions))
        .route("/v1/auth/user/logout", post(PostRoutes::cycle_session))
        .route("/v1/auth/user/sessions/list", post(PostRoutes::list_sessions))
        .route("/v1/admin/user_access_control/policies/create", post(PostRoutes::add_uac_member))
        .route("/v1/admin/user/delete", post(PostRoutes::admin_delete_user))
        .route("/v1/admin/user/inquire", post(PostRoutes::fetch_user_info_admin))
        .route("/v1/admin/user/session/kill", post(PostRoutes::admin_cycle_session))
        .route("/v1/admin/user_access_control/policies/fetch", post(PostRoutes::get_user_access_control_policies))
        .route("/v1/admin/user_access_control/policies/revoke", post(PostRoutes::revoke_user_access_control_policy))
        .route("/v1/case/create", post(PostRoutes::new_case))
        .route("/v1/case/find/all", post(PostRoutes::find_accessible_cases))
        .route("/v1/case/fetch", post(PostRoutes::get_case_information))
        .route("/v1/case/details/fetch", post(PostRoutes::get_case_details))
        .route("/v1/case/notes", post(PostRoutes::get_case_notes))
        .route("/v1/case/notes/add", post(PostRoutes::insert_note))
        .route("/v1/case/notes/fetch", post(PostRoutes::fetch_note))
        .route("/v1/case/notes/find/all", post(PostRoutes::find_accessible_notes))
        .with_state(state.clone())
        .layer(cors)
        .layer(connect_info.into_extension());

    info!("Attempting to create TCP listener at {}", Utc::now().to_string().purple());
    let listener = SocketAddr::from(([0, 0, 0, 0], 8443));

    info!("Serving listener at {}", Utc::now().to_string().purple());
    let _ = axum_server::bind_rustls(listener, state.rustls_config)
        .serve(router.into_make_service_with_connect_info::<SocketAddr>())
        .await;
}
