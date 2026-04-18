use std::net::IpAddr;

use axum::{Json, extract::State};
use axum_client_ip::ClientIp;
use chrono::Utc;
use dotenvy::var;
use graynote_lib::types::{
    error::Error, structs::{
        AdminDeleteUser, AdminTokenCycleRequest, AdminUserInfoRequest, AuthToken, Authorization, BasicAuth, CaseAccess, CaseDefinition, CaseInformation, CaseStatusUpdate, LogFormatter, NoteDetails, Notes, UserInfo, UserAccessControl
    }
};
use serde_json::{Value, json};
use tracing::{error, info};
use uuid::Uuid;

use crate::{database::Database, routes::SharedState};

#[tracing::instrument(skip(state, authorization_token, ip), name = "RATE LIMIT CHECK")]
pub async fn rate_limit_check(mut state: SharedState, authorization_token: &AuthToken, ip: IpAddr) -> Result<(), Error> {
    let username = authorization_token
        .token()
        .get_payload()
        .username();

    if !state.use_request_token(username, ip).await {
        return Err(Error::RateLimitExceeded);
    }

    Ok(())
}

#[tracing::instrument(skip(shared_state, admin_request, ip), name = "GET USER INFORMATION")]
pub async fn fetch_user_info_admin(State(shared_state): State<SharedState>, ClientIp(ip): ClientIp, Json(admin_request): Json<AdminUserInfoRequest>) -> Result<Json<Value>, Error> {
    let request_id = Uuid::new_v4();
    let mut logger = LogFormatter::new(ip, admin_request.admin_authorization().token().get_payload().sub.parse::<Uuid>()?, request_id);

    info!("{}", serde_json::to_string(&logger.with_message("Rate limit checking".into()).with_timestamp(Utc::now()))?);
    rate_limit_check(shared_state.clone(), &admin_request.admin_authorization(), ip).await?;

    info!("{}", serde_json::to_string(&logger.with_message("Attempting to retrieve user information".into()).with_timestamp(Utc::now()))?);
    let user_info = shared_state.postgres_pool.admin_get_user_info(admin_request, ip, request_id).await?;
    
    info!("{}", serde_json::to_string(&logger.with_message("Successfully retrieved user info".into()).with_timestamp(Utc::now()))?);
    
    Ok(Json(json!({"message": "Retrieval success", "user": user_info})))
}

#[tracing::instrument(skip(shared_state, user_access_control, ip), name = "ADD MEMBER USER ACCESS CONTROL")]
pub async fn add_uac_member(State(shared_state): State<SharedState>, ClientIp(ip): ClientIp, Json(user_access_control): Json<UserAccessControl>) -> Result<Json<Value>, Error> {
    let request_id = Uuid::new_v4();
    let mut logger = LogFormatter::new(ip, user_access_control.get_token().token().get_payload().sub.parse::<Uuid>()?, request_id);

    info!("{}", serde_json::to_string(&logger.with_message("Rate limit checking".into()).with_timestamp(Utc::now()))?);
    rate_limit_check(shared_state.clone(), &user_access_control.get_token(), ip).await?;
    
    info!("{}", serde_json::to_string(&logger.with_message("Adding access for case".into()).with_timestamp(Utc::now()))?);
    let () = shared_state.postgres_pool.add_uac_member(user_access_control, ip, request_id).await?;
    
    info!("{}", serde_json::to_string(&logger.with_message("Granted access for user".into()).with_timestamp(Utc::now()))?);

    Ok(Json(json!({"message":"Added user access to case"})))
}



#[tracing::instrument(skip(shared_state, user, ip), name = "ADMIN DELETE USER ACCOUNT")]
pub async fn admin_delete_user(State(shared_state): State<SharedState>, ClientIp(ip): ClientIp, Json(user): Json<AdminDeleteUser>) -> Result<Json<Value>, Error> {
    let request_id = Uuid::new_v4();
    let mut logger = LogFormatter::new(ip, user.admin_authorization().token().get_payload().sub.parse::<Uuid>()?, request_id);

    info!("{}", serde_json::to_string(&logger.with_message("Rate limit checking".into()).with_timestamp(Utc::now()))?);
    rate_limit_check(shared_state.clone(), &user.admin_authorization(), ip).await?;

    info!("{}", serde_json::to_string(&logger.with_message("Attempting to delete user (ADMIN)".into()).with_timestamp(Utc::now()))?);
    let () =  shared_state.postgres_pool.admin_delete_user_account(user, ip, request_id).await?;

    info!("{}", serde_json::to_string(&logger.with_message("Admin user delete request processed".into()).with_timestamp(Utc::now()))?);

    Ok(Json(json!({ "message": "User deleted" })))
}

#[tracing::instrument(skip(state, session, ip), name = "CYCLE SESSION")]
pub async fn admin_cycle_session(State(mut state): State<SharedState>, ClientIp(ip): ClientIp, Json(session): Json<AdminTokenCycleRequest>) -> Result<Json<Value>, Error> {
    let request_id = Uuid::new_v4();
    let mut logger = LogFormatter::new(ip, session.admin_authorization().token().get_payload().sub.parse::<Uuid>()?, request_id);

    info!("{}", serde_json::to_string(&logger.with_message("Rate limit checking".into()).with_timestamp(Utc::now()))?);
    if !state.use_request_token(session.admin_authorization().token().get_payload().username(), ip).await {
        return Err(Error::RateLimitExceeded);
    }

    info!("{}", serde_json::to_string(&logger.with_message("Cycling token request".into()).with_timestamp(Utc::now()))?);
    state.postgres_pool.admin_cycle_token(session, ip, request_id).await?;

    info!("{}", serde_json::to_string(&logger.with_message("Successfully cycled token".into()).with_timestamp(Utc::now()))?);

    Ok(Json(json!({"message": "Token cycled."})))
}

#[tracing::instrument(skip(state, user, ip), name = "CREATE USER")]
pub async fn create_user(State(mut state): State<SharedState>, ClientIp(ip): ClientIp, Json(user): Json<UserInfo>) -> Result<Json<Value>, Error> {
    // Since we have the username, we can perform a simple rate limit check, before attempting to create user.
    let request_id = Uuid::new_v4();
    let mut logger = LogFormatter::new(ip, "00000000-0000-0000-0000-000000000000".parse::<Uuid>()?, request_id);

    info!("{}", serde_json::to_string(&logger.with_message("Rate limit checking (User ID in this is not actually available).".into()).with_timestamp(Utc::now()))?);
    if !state.use_request_token(user.username(), ip).await {
        return Err(Error::RateLimitExceeded);
    }

    info!("{}", serde_json::to_string(&logger.with_message("Attempting to creater user".into()).with_timestamp(Utc::now()))?);
    state.postgres_pool.insert_user(user, ip, request_id).await?;

    info!("{}", serde_json::to_string(&logger.with_message("Created user successfully".into()).with_timestamp(Utc::now()))?);

    Ok(Json(json!({"message": "User added."})))
}

#[tracing::instrument(skip(state, basic_auth, ip), name = "BASIC AUTHENTICATION")]
pub async fn basic_login(State(mut state): State<SharedState>, ClientIp(ip): ClientIp, Json(basic_auth): Json<BasicAuth>) -> Result<Json<Value>, Error> {
    let request_id = Uuid::new_v4();
    let mut logger = LogFormatter::new(ip, "00000000-0000-0000-0000-000000000000".parse::<Uuid>()?, request_id);

    info!("{}", serde_json::to_string(&logger.with_message("Rate limit checking (User ID in this is not actually available).".into()).with_timestamp(Utc::now()))?);
    if !state.use_request_token(basic_auth.get_username().into(), ip).await {
        return Err(Error::RateLimitExceeded);
    }

    info!("{}", serde_json::to_string(&logger.with_message("Attempting login authorization".into()).with_timestamp(Utc::now()))?);
    let token = state.postgres_pool.login_basic(&basic_auth, ip, request_id).await?;

    info!("{}", serde_json::to_string(&logger.with_message("User login request authorized".into()).with_timestamp(Utc::now()))?);
    
    Ok(Json(json!({"message": "Logged in successfully.", "token": token.0.build_jwt(&var("MASTER_KEY")?)?, "session_id": token.1})))
}

#[tracing::instrument(skip(shared_state, authorization, ip), name = "DELETE USER ACCOUNT")]
pub async fn delete_user(State(shared_state): State<SharedState>, ClientIp(ip): ClientIp, Json(authorization): Json<Authorization>) -> Result<Json<Value>, Error> {
    let request_id = Uuid::new_v4();
    let mut logger = LogFormatter::new(ip, authorization.authorization().token().get_payload().sub.parse::<Uuid>()?, request_id);

    info!("{}", serde_json::to_string(&logger.with_message("Rate limit checking".into()).with_timestamp(Utc::now()))?);
    rate_limit_check(shared_state.clone(), &authorization.authorization(), ip).await?;

    info!("{}", serde_json::to_string(&logger.with_message("Attempting to delete user (USER REQUEST)".into()).with_timestamp(Utc::now()))?);
    let () = shared_state.postgres_pool.delete_user_account(&authorization.authorization(), ip, request_id).await?;

    info!("{}", serde_json::to_string(&logger.with_message("User delete request processed".into()).with_timestamp(Utc::now()))?);

    Ok(Json(json!({ "message": "User deleted" })))
}

#[tracing::instrument(skip(shared_state, authorization, ip), name = "CYCLE TOKEN")]
pub async fn cycle_session(State(shared_state): State<SharedState>, ClientIp(ip): ClientIp, Json(authorization): Json<Authorization>) -> Result<Json<Value>, Error> {
    let request_id = Uuid::new_v4();
    let mut logger = LogFormatter::new(ip, authorization.authorization().token().get_payload().sub.parse::<Uuid>()?, request_id);

    info!("{}", serde_json::to_string(&logger.with_message("Rate limit checking".into()).with_timestamp(Utc::now()))?);
    rate_limit_check(shared_state.clone(), &authorization.authorization(), ip).await?;

    info!("{}", serde_json::to_string(&logger.with_message("Trying to cycle token for user".into()).with_timestamp(Utc::now()))?);
    let () = shared_state.postgres_pool.cycle_token(&authorization.authorization(), ip, request_id).await?;

    info!("{}", serde_json::to_string(&logger.with_message("Token cycled for user".into()).with_timestamp(Utc::now()))?);

    Ok(Json(json!({ "message": "Token cycled" })))
}

#[tracing::instrument(skip(shared_state, authorization, ip), name = "KILL SESSIONS FOR USER")]
pub async fn kill_user_sessions(State(shared_state): State<SharedState>, ClientIp(ip): ClientIp, Json(authorization): Json<Authorization>) -> Result<Json<Value>, Error> {
    let request_id = Uuid::new_v4();
    let mut logger = LogFormatter::new(ip, authorization.authorization().token().get_payload().sub.parse::<Uuid>()?, request_id);

    info!("{}", serde_json::to_string(&logger.with_message("Rate limit checking".into()).with_timestamp(Utc::now()))?);
    rate_limit_check(shared_state.clone(), &authorization.authorization(), ip).await?;

    info!("{}", serde_json::to_string(&logger.with_message("Trying to delete all user sessions except current".into()).with_timestamp(Utc::now()))?);
    let () = shared_state.postgres_pool.kill_sessions(&authorization.authorization(), ip, request_id).await?;

    info!("{}", serde_json::to_string(&logger.with_message("Sessions terminated for user".into()).with_timestamp(Utc::now()))?);

    Ok(Json(json!({ "message": "Sessions terminated successfully" })))
}

#[tracing::instrument(skip(shared_state, authorization, ip), name = "LIST SESSIONS FOR USER")]
pub async fn list_sessions(State(shared_state): State<SharedState>, ClientIp(ip): ClientIp, Json(authorization): Json<Authorization>) -> Result<Json<Value>, Error> {
    let request_id = Uuid::new_v4();
    let mut logger = LogFormatter::new(ip, authorization.authorization().token().get_payload().sub.parse::<Uuid>()?, request_id);

    info!("{}", serde_json::to_string(&logger.with_message("Rate limit checking".into()).with_timestamp(Utc::now()))?);
    rate_limit_check(shared_state.clone(), &authorization.authorization(), ip).await?;

    info!("{}", serde_json::to_string(&logger.with_message("Trying to fetch sessions".into()).with_timestamp(Utc::now()))?);
    let result = shared_state.postgres_pool.list_sessions(&authorization.authorization(), ip, request_id).await;
    let Ok(sessions) = result else {
        let error = result.unwrap_err();
        error!("{}", serde_json::to_string(&logger.with_message("Could not fetch sessions".into()).with_timestamp(Utc::now()).with_error(Some(error.clone())))?);
        
        return Err(error)
    };

    info!("{}", serde_json::to_string(&logger.with_message("Successfully retrieved sessions".into()).with_timestamp(Utc::now()))?);

    Ok(Json(json!({ "message": "Successfully retrieved sessions", "sessions": sessions })))
}

#[tracing::instrument(skip(shared_state, case, ip), name = "FILE NEW CASE")]
pub async fn new_case(State(shared_state): State<SharedState>, ClientIp(ip): ClientIp, Json(case): Json<CaseDefinition>) -> Result<Json<Value>, Error> {
    let request_id = Uuid::new_v4();
    let mut logger = LogFormatter::new(ip, case.auth_token().token().get_payload().sub.parse::<Uuid>()?, request_id);

    info!("{}", serde_json::to_string(&logger.with_message("Rate limit checking".into()).with_timestamp(Utc::now()))?);
    rate_limit_check(shared_state.clone(), &case.auth_token(), ip).await?;

    info!("{}", serde_json::to_string(&logger.with_message("Attempting to create new case".into()).with_timestamp(Utc::now()))?);
    let case_number =  shared_state.postgres_pool.insert_case_information(&case, ip, request_id).await?;

    info!("{}", serde_json::to_string(&logger.with_message("Case creation authorized".into()).with_timestamp(Utc::now()))?);

    Ok(Json(json!({ "message": "Case created", "case_number": case_number })))
}

#[tracing::instrument(skip(shared_state, token, ip), name = "FIND ACCESSIBLE CASES")]
pub async fn find_accessible_cases(State(shared_state): State<SharedState>,ClientIp(ip): ClientIp, Json(token): Json<Authorization>) -> Result<Json<Vec<CaseInformation>>, Error> {
    let request_id = Uuid::new_v4();
    let mut logger = LogFormatter::new(ip, token.authorization().token().get_payload().sub.parse::<Uuid>()?, request_id);

    info!("{}", serde_json::to_string(&logger.with_message("Rate limit checking".into()).with_timestamp(Utc::now()))?);
    rate_limit_check(shared_state.clone(), &token.authorization(), ip).await?;

    info!("{}", serde_json::to_string(&logger.with_message("Retrieving accessible cases".into()).with_timestamp(Utc::now()))?);
    let cases = shared_state.postgres_pool.find_accessible_cases(&token.authorization(), ip, request_id).await?;

    info!("{}", serde_json::to_string(&logger.with_message("Retrieved accessible cases".into()).with_timestamp(Utc::now()))?);
    
    Ok(Json(cases))
}

#[tracing::instrument(skip(shared_state, case_status, ip), name = "UPDATE CASE STATUS")]
pub async fn update_case_status(State(shared_state): State<SharedState>, ClientIp(ip): ClientIp, Json(case_status): Json<CaseStatusUpdate>) -> Result<Json<Value>, Error> {
    let request_id = Uuid::new_v4();
    let mut logger = LogFormatter::new(ip, case_status.case().auth_token().token().get_payload().sub.parse::<Uuid>()?, request_id);
    let logger = logger
        .with_case_number(Some(case_status.case().case_number()));

    info!("{}", serde_json::to_string(&logger.with_message("Rate limit checking".into()).with_timestamp(Utc::now()))?);
    rate_limit_check(shared_state.clone(), &case_status.case().auth_token(), ip).await?;

    info!("{}", serde_json::to_string(&logger.with_message("Attempting to update status of case".into()).with_timestamp(Utc::now()))?);
    let () = shared_state.postgres_pool.update_case_status(case_status.clone(), ip, request_id).await?;
    
    info!("{}", serde_json::to_string(&logger.with_message(format!("Updated case status to '{}'", serde_json::to_string(&case_status.status())?)).with_timestamp(Utc::now()))?);

    Ok(Json(json!({ "message": "Case status updated successfully" })))
}

#[tracing::instrument(skip(shared_state, case, ip), name = "GET CASE INFORMATION")]
pub async fn get_case_information(State(shared_state): State<SharedState>, ClientIp(ip): ClientIp, Json(case): Json<CaseAccess>) -> Result<Json<CaseInformation>, Error> {
    let request_id = Uuid::new_v4();
    let mut logger = LogFormatter::new(ip, case.auth_token().token().get_payload().sub.parse::<Uuid>()?, request_id);
    let logger = logger
        .with_case_number(Some(case.case_number()));

    // We do not have the username at this point,
    //  so we will just perform a rate limit check using the token, and if it fails, we will return an error.
    // If it succeeds, we will attempt to retrieve the case information.
    info!("{}", serde_json::to_string(&logger.with_message("Rate limit checking".into()).with_timestamp(Utc::now()))?);
    rate_limit_check(shared_state.clone(), case.auth_token(), ip).await?;

    info!("{}", serde_json::to_string(&logger.with_message("Attempting to retrieve information about case".into()).with_timestamp(Utc::now()))?);
    let case_info = shared_state.postgres_pool.get_case_information(&case, ip, request_id).await?;

    info!("{}", serde_json::to_string(&logger.with_message("Retrieved information for case".into()).with_timestamp(Utc::now()))?);

    Ok(Json(case_info))
}

#[tracing::instrument(skip(shared_state, case, ip), name = "GET CASE NOTES")]
pub async fn get_case_notes(State(shared_state): State<SharedState>, ClientIp(ip): ClientIp, Json(case): Json<CaseAccess>) -> Result<Json<Vec<NoteDetails>>, Error> {
    let request_id = Uuid::new_v4();
    let mut logger = LogFormatter::new(ip, case.auth_token().token().get_payload().sub.parse::<Uuid>()?, request_id);
    let logger = logger
        .with_case_number(Some(case.case_number()));

    info!("{}", serde_json::to_string(&logger.with_message("Rate limit checking".into()).with_timestamp(Utc::now()))?);
    rate_limit_check(shared_state.clone(), case.auth_token(), ip).await?;

    info!("{}", serde_json::to_string(&logger.with_message("Attempting to retrieve notes for case".into()).with_timestamp(Utc::now()))?);
    let case_notes = shared_state.postgres_pool.get_case_notes(&case, ip, request_id).await?;
    
    info!("{}", serde_json::to_string(&logger.with_message("Retrieved notes for case".into()).with_timestamp(Utc::now()))?);
    
    Ok(Json(case_notes))
}

#[tracing::instrument(skip(shared_state, token, ip), name = "GET ACCESSIBLE NOTES")]
pub async fn find_accessible_notes(State(shared_state): State<SharedState>, ClientIp(ip): ClientIp, Json(token): Json<Authorization>) -> Result<Json<Vec<NoteDetails>>, Error> {
    let request_id = Uuid::new_v4();
    let mut logger = LogFormatter::new(ip, token.authorization().token().get_payload().sub.parse::<Uuid>()?, request_id);

    info!("{}", serde_json::to_string(&logger.with_message("Rate limit checking".into()).with_timestamp(Utc::now()))?);
    rate_limit_check(shared_state.clone(), &token.authorization(), ip).await?;
    
    info!("{}", serde_json::to_string(&logger.with_message("Retrieving accessible notes".into()).with_timestamp(Utc::now()))?);
    let notes = shared_state.postgres_pool.find_accessible_notes(&token.authorization(), ip, request_id).await?;
    
    info!("{}", serde_json::to_string(&logger.with_message("Retrieved notes".into()).with_timestamp(Utc::now()))?);

    Ok(Json(notes))
}

#[tracing::instrument(skip(shared_state, note, ip), name = "ADD NOTE TO CASE")]
pub async fn insert_note(State(shared_state): State<SharedState>, ClientIp(ip): ClientIp, Json(note): Json<Notes>) -> Result<Json<Value>, Error> {
    let request_id = Uuid::new_v4();
    let mut logger = LogFormatter::new(ip, note.auth_token().token().get_payload().sub.parse::<Uuid>()?, request_id);
    let logger = logger
        .with_case_number(Some(note.note_details().case_number()))
        .with_note_id(Some(note.note_id()));

    info!("{}", serde_json::to_string(&logger.with_message("Rate limit checking".into()).with_timestamp(Utc::now()))?);
    rate_limit_check(shared_state.clone(), &note.auth_token(), ip).await?;

    info!("{}", serde_json::to_string(&logger.with_message("Adding note to case".into()).with_timestamp(Utc::now()))?);
    let () = shared_state.postgres_pool.insert_note(&note, ip, request_id).await?;

    info!("{}", serde_json::to_string(&logger.with_message("Note added to case".into()).with_timestamp(Utc::now()))?);

    Ok(Json(json!({"message": "Added note to case"})))
}
