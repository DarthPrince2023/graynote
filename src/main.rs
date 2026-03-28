extern crate argon2;
use axum::{Router, routing::post};
use tokio::net::TcpListener;

use crate::routes::{SharedState, post as PostRoutes};

pub mod routes;
pub mod database;

#[tokio::main]
async fn main() {
    // Get a new shared state instance, or return error on failure
    let state = match SharedState::new().await {
        Ok(state) => state,
        Err(error) => panic!("Could not create shared state => {error:?}")
    };
    let router = Router::new()
        .route("/add_user", post(PostRoutes::create_user))
        .route("/login", post(PostRoutes::basic_login))
        .route("/admin/add_uac_member", post(PostRoutes::add_uac_member))
        .route("/admin/user/inquire", post(PostRoutes::fetch_user_info_admin))
        .route("/case/create", post(PostRoutes::new_case))
        .route("/case/fetch", post(PostRoutes::get_case_information))
        .route("/case/notes", post(PostRoutes::get_case_notes))
        .route("/case/notes/add", post(PostRoutes::insert_note))
        .route("/case/find/all", post(PostRoutes::find_accessible_cases))
        .route("/case/notes/find/all", post(PostRoutes::find_accessible_notes))
        .with_state(state);
    let listener = TcpListener::bind("0.0.0.0:8080").await.expect("TcpListener");
    let _ = axum::serve(listener, router.into_make_service()).await;
}
