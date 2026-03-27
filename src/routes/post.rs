use axum::{
    Json, extract::State, http::StatusCode,
    response::IntoResponse
};
use serde_json::json;
use tracing_log::log::info;

use crate::{
    database::{
        Database, types::{AuthToken, CaseAccess, CaseDetails, Notes, UserAccessManagement, UserInfo}
    },
    routes::{
        SharedState, client_modifier::BasicAuth
    }
};

pub async fn create_user(State(state): State<SharedState>, Json(user): Json<UserInfo>) -> impl IntoResponse {
    match state.postgres_pool.insert_user(user).await {
        Ok(()) => (StatusCode::CREATED, json!({"message": "User added."}).to_string()),
        Err(error) => (StatusCode::INTERNAL_SERVER_ERROR, json!({"message": error}).to_string())
    }
}

pub async fn basic_login(State(state): State<SharedState>, Json(basic_auth): Json<BasicAuth>) -> impl IntoResponse {
    match state.postgres_pool.login_basic(basic_auth).await {
        Ok(token) => return (StatusCode::OK, json!({"message": "Logged in successfully.", "token": token.0, "session_id": token.1}).to_string()),
        Err(error) => return (StatusCode::INTERNAL_SERVER_ERROR, json!({"message": "Failed to authenticate user", "error": error}).to_string())
    }
}

pub async fn get_case_information(State(shared_state): State<SharedState>, Json(case): Json<CaseDetails>) -> impl IntoResponse {
    let case_info = match shared_state.postgres_pool.get_case_information(case).await {
        Ok(case_info) => case_info,
        Err(_) => return (
                StatusCode::UNAUTHORIZED,
                json!({"message":"You are not authorized to access the requested resource."}).to_string()
            )
    };
    let Ok(case_info) = serde_json::to_string(&case_info) else {
        return (StatusCode::INTERNAL_SERVER_ERROR, json!({"message": "Could not build response message"}).to_string())
    };

    return (StatusCode::OK, case_info)
}

pub async fn get_case_notes(State(shared_state): State<SharedState>, Json(case): Json<CaseDetails>) -> impl IntoResponse {
    let case_notes = match shared_state.postgres_pool.get_case_notes(case).await {
        Ok(case_notes) => case_notes,
        Err(_) => return (
                StatusCode::UNAUTHORIZED,
                json!({"message": "You are not authorized to access the requested resource."}).to_string()
            )
    };
    let Ok(case_notes) = serde_json::to_string(&case_notes) else {
        return (StatusCode::INTERNAL_SERVER_ERROR, json!({"message": "Could not build response message."}).to_string())
    };

    return (StatusCode::OK, case_notes)
}

pub async fn find_accessible_cases(State(shared_state): State<SharedState>, Json(token): Json<AuthToken>) -> impl IntoResponse {
    let cases = match shared_state.postgres_pool.find_accessible_cases(token.token, token.session_id).await {
        Ok(cases) => cases,
        Err(_) => return (
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"message": "Could not retrieve cases for user"}).to_string()
        )
    };
    let Ok(cases) = serde_json::to_string(&cases) else {
        return (StatusCode::INTERNAL_SERVER_ERROR, json!({"message": "Unable to serialize cases"}).to_string())
    };

    return (StatusCode::OK, cases)
}

pub async fn find_accessible_notes(State(shared_state): State<SharedState>, Json(token): Json<AuthToken>) -> impl IntoResponse {
    let notes = match shared_state.postgres_pool.find_accessible_notes(token.session_id, token.token).await {
        Ok(notes) => notes,
        Err(_) => return (
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"message": "Could not fetch notes for user"}).to_string()
        )
    };
    let Ok(notes_string) = serde_json::to_string(&notes) else {
        return (StatusCode::INTERNAL_SERVER_ERROR, json!({"message": "No accessible notes found for provided user"}).to_string())
    };

    return (StatusCode::OK, notes_string)
}

pub async fn add_uac_member(State(shared_state): State<SharedState>, Json(uac_management): Json<UserAccessManagement>) -> impl IntoResponse {
    info!("Adding access for case to user");
    match shared_state.postgres_pool.add_uac_member(uac_management.case_number, uac_management.token, uac_management.session_id, uac_management.target_user).await {
        Ok(()) => return (
            StatusCode::CREATED,
            json!({"message":"Added user access to case"}).to_string()
        ),
        Err(_) => return (
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({"message":"Could not grant access for user"}).to_string()
        )
    };
}

pub async fn insert_note(State(shared_state): State<SharedState>, Json(note): Json<Notes>) -> impl IntoResponse {
    info!("Adding note to case...");
    match shared_state.postgres_pool.insert_note(note).await {
        Ok(()) => return (
            StatusCode::CREATED,
            "Added note to case"
        ),
        Err(_) => return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unable to create note for case due to error"
        )
    };
}

pub async fn new_case(State(shared_state): State<SharedState>, Json(case): Json<CaseAccess>) -> impl IntoResponse {
    match shared_state.postgres_pool.insert_case_information(case).await  {
        Ok(case_number) => return (
                StatusCode::CREATED,
                json!({
                    "message": "Case created",
                    "case_number": case_number
                })
                .to_string()
            ),
        Err(error) => return (
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({
                    "message": "Error filing case",
                    "error": error.to_string()
                })
                .to_string()
            )
    };
}


