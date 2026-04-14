use axum::{Json, extract::State};
use chrono::Utc;
use graynote_lib::types::{
    error::Error, structs::{
        AdminUserInfoRequest, AuthToken, BasicAuth,
        CaseAccess, CaseDetails, CaseInformation,
        NoteDetails, Notes, UserAccessManagement,
        UserInfo
    }
};
use jwt::TokenPieces;
use serde_json::{Value, json};
use tracing::info;

use crate::{database::Database, routes::SharedState};

#[tracing::instrument(skip(state), name = "RATE LIMIT CHECK")]
pub async fn rate_limit_check(mut state: SharedState, token: String) -> Result<(), Error> {
    info!("Extracting token pieces to check rate limit at {}", Utc::now());
    let payload = TokenPieces::try_from(token.as_str())?;
    let username = payload.get_payload().username;

    info!("Rate limit checking at {}", Utc::now());
    if !state.use_request_token(username).await {
        return Err(Error::RateLimitExceeded);
    }

    Ok(())
}

#[tracing::instrument(skip(state, user), name = "CREATE USER")]
pub async fn create_user(State(mut state): State<SharedState>, Json(user): Json<UserInfo>) -> Result<Json<Value>, Error> {
    // Since we have the username, we can perform a simple rate limit check, before attempting to create user.
    info!("Rate limit checking at {}", Utc::now());
    if !state.use_request_token(user.user_handle.clone()).await {
        return Err(Error::RateLimitExceeded);
    }

    info!("Attempting to creater user at {}", Utc::now());
    state.postgres_pool.insert_user(user).await?;

    info!("Created user successfully at {}", Utc::now());
    
    Ok(Json(json!({"message": "User added."})))
}

#[tracing::instrument(skip(state, basic_auth), name = "BASIC AUTHENTICATION")]
pub async fn basic_login(State(mut state): State<SharedState>, Json(basic_auth): Json<BasicAuth>) -> Result<Json<Value>, Error> {
    info!("Rate limit checking at {}", Utc::now());
    if !state.use_request_token(basic_auth.username.clone()).await {
        return Err(Error::RateLimitExceeded);
    }

    info!("Attempting login authorization at {}", Utc::now());
    let token = state.postgres_pool.login_basic(&basic_auth).await?;

    info!("User login request authorized at {}", Utc::now());

    Ok(Json(json!({"message": "Logged in successfully.", "token": token.0, "session_id": token.1})))
}

#[tracing::instrument(skip(shared_state, case), name = "GET CASE INFORMATION")]
pub async fn get_case_information(State(shared_state): State<SharedState>, Json(case): Json<CaseDetails>) -> Result<Json<CaseInformation>, Error> {
    // We do not have the username at this point,
    //  so we will just perform a rate limit check using the token, and if it fails, we will return an error.
    // If it succeeds, we will attempt to retrieve the case information.
    info!("Rate limit checking at {}", Utc::now());
    rate_limit_check(shared_state.clone(), case.token.clone()).await?;

    info!("Attempting to retrieve information about case at {}", Utc::now());
    let case_info = shared_state.postgres_pool.get_case_information(&case).await?;

    info!("Retrieved information for case {} at {} for {}", case.case_number, Utc::now(), case_info.user_id);

    Ok(Json(case_info))
}

#[tracing::instrument(skip(shared_state, case), name = "GET CASE NOTES")]
pub async fn get_case_notes(State(shared_state): State<SharedState>, Json(case): Json<CaseDetails>) -> Result<Json<Vec<NoteDetails>>, Error> {
    info!("Rate limit checking at {}", Utc::now());
    rate_limit_check(shared_state.clone(), case.token.clone()).await?;

    info!("Attempting to retrieve notes for case {} at {}", case.case_number, Utc::now());
    let case_notes = shared_state.postgres_pool.get_case_notes(&case).await?;
    
    info!("Retrieved notes for case {} at {}", case.case_number, Utc::now());
    
    Ok(Json(case_notes))
}

#[tracing::instrument(skip(shared_state, token), name = "FIND ACCESSIBLE CASES")]
pub async fn find_accessible_cases(State(shared_state): State<SharedState>, Json(token): Json<AuthToken>) -> Result<Json<Vec<CaseInformation>>, Error> {
    info!("Rate limit checking at {}", Utc::now());
    rate_limit_check(shared_state.clone(), token.token.clone()).await?;

    info!("Retrieving accessible cases for given user");
    let cases = shared_state.postgres_pool.find_accessible_cases(token.token, token.session_id).await?;

    info!("Retrieved accessible cases");
    
    Ok(Json(cases))
}

#[tracing::instrument(skip(shared_state, token), name = "GET ACCESSIBLE NOTES")]
pub async fn find_accessible_notes(State(shared_state): State<SharedState>, Json(token): Json<AuthToken>) -> Result<Json<Vec<NoteDetails>>, Error> {
    info!("Rate limit checking at {}", Utc::now());
    rate_limit_check(shared_state.clone(), token.token.clone()).await?;
    
    info!("Retrieving accessible notes for given user at {}", Utc::now());
    let notes = shared_state.postgres_pool.find_accessible_notes(token.session_id, token.token).await?;
    
    info!("Retrieved notes for given user at {}", Utc::now());

    Ok(Json(notes))
}

#[tracing::instrument(skip(shared_state, admin_request), name = "GET USER INFORMATION")]
pub async fn fetch_user_info_admin(State(shared_state): State<SharedState>, Json(admin_request): Json<AdminUserInfoRequest>) -> Result<Json<Value>, Error> {
    info!("Rate limit checking at {}", Utc::now());
    rate_limit_check(shared_state.clone(), admin_request.admin_token.clone()).await?;

    info!("Attempting to retrieve user information at {}", Utc::now());
    let user_info = shared_state.postgres_pool.admin_get_user_info(admin_request).await?;
    
    info!("Successfully retrieved user info at {}", Utc::now());

    Ok(Json(json!({"message": "Retrieval success", "user": user_info})))
}

#[tracing::instrument(skip(shared_state, uac_management), name = "ADD MEMBER USER ACCESS CONTROL")]
pub async fn add_uac_member(State(shared_state): State<SharedState>, Json(uac_management): Json<UserAccessManagement>) -> Result<Json<Value>, Error> {
    info!("Rate limit checking at {}", Utc::now());
    rate_limit_check(shared_state.clone(), uac_management.token.clone()).await?;
    
    info!("Adding access for case {} to user at {}", uac_management.case_number, Utc::now());
    let () = shared_state.postgres_pool.add_uac_member(uac_management.case_number, uac_management.token, uac_management.session_id, uac_management.target_user).await?;
    
    info!("Granted access for user {} at {}", uac_management.target_user, Utc::now());

    Ok(Json(json!({"message":"Added user access to case"})))
}

#[tracing::instrument(skip(shared_state, note), name = "ADD NOTE TO CASE")]
pub async fn insert_note(State(shared_state): State<SharedState>, Json(note): Json<Notes>) -> Result<Json<Value>, Error> {
    info!("Rate limit checking at {}", Utc::now());
    rate_limit_check(shared_state.clone(), note.token.clone()).await?;

    info!("Adding note to case...");
    let () = shared_state.postgres_pool.insert_note(&note).await?;

    if let Some(author_id) = note.note_details.author_id {
        info!("Note added to case by {author_id} at {}.", Utc::now());
    } else {
        info!("Note added to case by unknown author at {}.", Utc::now());
    }

    Ok(Json(json!({"message": "Added note to case"})))
}

#[tracing::instrument(skip(shared_state, case), name = "FILE NEW CASE")]
pub async fn new_case(State(shared_state): State<SharedState>, Json(case): Json<CaseAccess>) -> Result<Json<Value>, Error> {
    info!("Rate limit checking at {}", Utc::now());
    rate_limit_check(shared_state.clone(), case.token.clone()).await?;

    info!("Attempting to create new case");
    let case_number =  shared_state.postgres_pool.insert_case_information(case).await?;

    info!("Case creation authorized at {} for case {case_number}", Utc::now());

    Ok(Json(json!({ "message": "Case created", "case_number": case_number })))
}
