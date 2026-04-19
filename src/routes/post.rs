use std::net::IpAddr;

use axum::{Json, extract::State};
use axum_client_ip::ClientIp;
use chrono::Utc;
use dotenvy::var;
use graynote_lib::types::{
    error::Error, structs::{
        AdminDeleteUser, AdminTokenCycleRequest, AdminUserInfoRequest, AuthToken, Authorization, BasicAuth, CaseAccess, CaseDefinition, CaseInformation, CaseStatusUpdate, DeleteUacPolicy, LogFormatter, NoteContext, NoteDetails, UserAccessControlDefinition, UserAccessControlFilter, UserAccessControlPolicy, UserInfo
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
pub async fn add_uac_member(State(shared_state): State<SharedState>, ClientIp(ip): ClientIp, Json(user_access_control): Json<UserAccessControlDefinition>) -> Result<Json<Value>, Error> {
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

    info!("{}", serde_json::to_string(&logger.with_message("Checking cache for username".into()).with_timestamp(Utc::now()))?);
    let exists = state.username_cache.entry(user.username()).or_insert(Uuid::new_v4()).await.is_fresh();

    info!("{}", serde_json::to_string(&logger.with_message("Attempting to creater user".into()).with_timestamp(Utc::now()))?);
    state.postgres_pool.insert_user(user, ip, request_id, exists).await?;

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
    let user_id = case.auth_token().token().get_payload().sub.parse::<Uuid>()?;
    let mut logger = LogFormatter::new(ip, user_id, request_id);
    let logger = logger
        .with_case_number(Some(case.case_number()));

    // We do not have the username at this point,
    //  so we will just perform a rate limit check using the token, and if it fails, we will return an error.
    // If it succeeds, we will attempt to retrieve the case information.
    info!("{}", serde_json::to_string(&logger.with_message("Rate limit checking".into()).with_timestamp(Utc::now()))?);
    rate_limit_check(shared_state.clone(), case.auth_token(), ip).await?;

    info!("{}", serde_json::to_string(&logger.with_message("Checking if user has access to case to fetch information".into()).with_timestamp(Utc::now()))?);
    let user_access_control = UserAccessControlDefinition::new(user_id, Some(case.case_number()), None, case.auth_token().clone())?;
    shared_state.postgres_pool.is_access_granted(&user_access_control, false, ip, request_id).await?;

    info!("{}", serde_json::to_string(&logger.with_message("Checking cache for case information".into()).with_timestamp(Utc::now()))?);
    let case_info_existed = shared_state.case_details_cache.contains_key(&case.case_number());

    if !case_info_existed {
        info!("{}", serde_json::to_string(&logger.with_message("Fetching cache for case information".into()).with_timestamp(Utc::now()))?);
        let case_information = shared_state.case_information_cache.entry(case.case_number()).or_default().await.into_value();

        info!("{}", serde_json::to_string(&logger.with_message("Retrieved information for case".into()).with_timestamp(Utc::now()))?);

        Ok(Json(case_information))
    } else {
        info!("{}", serde_json::to_string(&logger.with_message("Attempting to retrieve information about case".into()).with_timestamp(Utc::now()))?);
        let case_information = shared_state.postgres_pool.get_case_information(&case, ip, request_id).await?;

        info!("{}", serde_json::to_string(&logger.with_message("Caching information about case".into()).with_timestamp(Utc::now()))?);
        shared_state.case_information_cache.insert(case_information.case_number(), case_information.clone()).await;

        Ok(Json(case_information))
    }

    
}

#[tracing::instrument(skip(shared_state, case, ip), name = "GET CASE NOTES")]
pub async fn get_case_notes(State(shared_state): State<SharedState>, ClientIp(ip): ClientIp, Json(case): Json<CaseAccess>) -> Result<Json<Vec<NoteDetails>>, Error> {
    let request_id = Uuid::new_v4();
    let user_id = case.auth_token().token().get_payload().sub.parse::<Uuid>()?;
    let mut logger = LogFormatter::new(ip, user_id, request_id);
    let logger = logger
        .with_case_number(Some(case.case_number()));

    info!("{}", serde_json::to_string(&logger.with_message("Rate limit checking".into()).with_timestamp(Utc::now()))?);
    rate_limit_check(shared_state.clone(), case.auth_token(), ip).await?;
    
    info!("{}", serde_json::to_string(&logger.with_message("Checking if user has access to case to retrieve notes".into()).with_timestamp(Utc::now()))?);
    let user_access_control = UserAccessControlDefinition::new(user_id, Some(case.case_number()), None, case.auth_token().clone())?;
    shared_state.postgres_pool.is_access_granted(&user_access_control, false, ip, request_id).await?;

    info!("{}", serde_json::to_string(&logger.with_message("Checking cache for case notes".into()).with_timestamp(Utc::now()))?);
    let notes_exist = shared_state.case_details_cache.contains_key(&case.case_number());

    if notes_exist {
        info!("{}", serde_json::to_string(&logger.with_message("Note found in cache".into()).with_timestamp(Utc::now()))?);
        
        let notes = shared_state.case_details_cache.entry(case.case_number()).or_default().await.into_value().1;
        
        info!("{}", serde_json::to_string(&logger.with_message("Retrieved notes for case".into()).with_timestamp(Utc::now()))?);
    
        Ok(Json(notes))
    } else {
        info!("{}", serde_json::to_string(&logger.with_message("No notes found in cache for case, attempting to retrieve notes for case from database".into()).with_timestamp(Utc::now()))?);
        
        let case_details = shared_state.postgres_pool.get_case_details(&case, ip, request_id).await?;
        shared_state.case_details_cache.insert(case.case_number(), case_details.clone()).await;
        
        info!("{}", serde_json::to_string(&logger.with_message("Retrieved notes for case".into()).with_timestamp(Utc::now()))?);
    
        Ok(Json(case_details.1))
    }
}

#[tracing::instrument(skip(shared_state, request, ip), name = "GET USER ACCESS CONTROL POLICIES")]
pub async fn get_user_access_control_policies(State(shared_state): State<SharedState>, ClientIp(ip): ClientIp, Json(request): Json<UserAccessControlFilter>) -> Result<Json<Vec<UserAccessControlPolicy>>, Error> {
    let request_id = Uuid::new_v4();
    let user_id = request.authorization().token().get_payload().sub.parse::<Uuid>()?;
    let mut logger = LogFormatter::new(ip, user_id, request_id);

    info!("{}", serde_json::to_string(&logger.with_message("Rate limit checking".into()).with_timestamp(Utc::now()))?);
    rate_limit_check(shared_state.clone(), &request.authorization(), ip).await?;

    info!("{}", serde_json::to_string(&logger.with_message("Checking if user has access to get policies".into()).with_timestamp(Utc::now()))?);
    let user_access_control = UserAccessControlDefinition::new(user_id, None, None, request.authorization())?;
    shared_state.postgres_pool.is_access_granted(&user_access_control, false, ip, request_id).await?;

    if shared_state.case_details_cache.entry_count() > 0 {
        info!("{}", serde_json::to_string(&logger.with_message("Retrieving cached policies".into()).with_timestamp(Utc::now()))?);
        let mut uac_policies: Vec<UserAccessControlPolicy> = Vec::new();
        shared_state.user_access_control_policy_cache.into_iter().for_each(|policy| uac_policies.push(policy.1));

        info!("{}", serde_json::to_string(&logger.with_message("Retrieved cached policies".into()).with_timestamp(Utc::now()))?);

        Ok(Json(uac_policies))
    } else {
        info!("{}", serde_json::to_string(&logger.with_message("Policies not found in cache, checking database".into()).with_timestamp(Utc::now()))?);
        let details = shared_state.postgres_pool.get_uac_policies(request, ip, request_id).await?;

        for policy in details.clone() {
            let Some(policy_id) = policy.policy_id() else {
                error!("{}", serde_json::to_string(&logger.with_message("Policy ID unavailable".into()).with_timestamp(Utc::now()))?);

                return Err(Error::DatabaseError)
            };

            shared_state.user_access_control_policy_cache.insert(policy_id, policy.clone()).await;
        }

        info!("{}", serde_json::to_string(&logger.with_message("Fetched case details".into()).with_timestamp(Utc::now()))?);

        Ok(Json(details))
    }
}

#[tracing::instrument(skip(shared_state, request, ip), name = "REVOKE USER ACCESS CONTROL POLICY")]
pub async fn revoke_user_access_control_policy(State(shared_state): State<SharedState>, ClientIp(ip): ClientIp, Json(request): Json<DeleteUacPolicy>) -> Result<Json<Value>, Error> {
    let request_id = Uuid::new_v4();
    let user_id = request.auth_token().token().get_payload().sub.parse::<Uuid>()?;
    let mut logger = LogFormatter::new(ip, user_id, request_id);

    info!("{}", serde_json::to_string(&logger.with_message("Rate limit checking".into()).with_timestamp(Utc::now()))?);
    rate_limit_check(shared_state.clone(), &request.auth_token(), ip).await?;

    let () = shared_state.postgres_pool.delete_uac_policy(&request.auth_token(), request.policy_id(), ip, request_id).await?;

    shared_state.user_access_control_policy_cache.remove(&request.policy_id()).await;

    info!("{}", serde_json::to_string(&logger.with_message("Revoked policy".into()).with_timestamp(Utc::now()))?);

    Ok(Json(json!({ "message": "Revoked policy" })))
}

#[tracing::instrument(skip(shared_state, request, ip), name = "GET CASE DETAILS")]
pub async fn get_case_details(State(shared_state): State<SharedState>, ClientIp(ip): ClientIp, Json(request): Json<CaseAccess>) -> Result<Json<Value>, Error> {
    let request_id = Uuid::new_v4();
    let user_id = request.auth_token().token().get_payload().sub.parse::<Uuid>()?;
    let mut logger = LogFormatter::new(ip, user_id, request_id);

    info!("{}", serde_json::to_string(&logger.with_message("Rate limit checking".into()).with_timestamp(Utc::now()))?);
    rate_limit_check(shared_state.clone(), &request.auth_token(), ip).await?;

    info!("{}", serde_json::to_string(&logger.with_message("Checking if user has access to case".into()).with_timestamp(Utc::now()))?);
    let user_access_control = UserAccessControlDefinition::new(user_id, Some(request.case_number()), None, request.auth_token().clone())?;
    shared_state.postgres_pool.is_access_granted(&user_access_control, false, ip, request_id).await?;

    if shared_state.case_details_cache.contains_key(&request.case_number()) {
        info!("{}", serde_json::to_string(&logger.with_message("Case details found in cache".into()).with_timestamp(Utc::now()))?);
        let case_details = shared_state.case_details_cache.entry(request.case_number().clone()).or_default().await.into_value();

        info!("{}", serde_json::to_string(&logger.with_message("Fetched case details".into()).with_timestamp(Utc::now()))?);

        Ok(Json(json!({"message": "Retrieved case details", "details": case_details })))
    } else {
        info!("{}", serde_json::to_string(&logger.with_message("Case details not found in cache, checking database".into()).with_timestamp(Utc::now()))?);
        let details = shared_state.postgres_pool.get_case_details(&request, ip, request_id).await?;
        
        shared_state.case_details_cache.insert(request.case_number(), details.clone()).await;

        info!("{}", serde_json::to_string(&logger.with_message("Fetched case details".into()).with_timestamp(Utc::now()))?);

        Ok(Json(json!({ "message": "Retrieved case details", "details": details })))
    }
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
pub async fn insert_note(State(shared_state): State<SharedState>, ClientIp(ip): ClientIp, Json(note): Json<NoteContext>) -> Result<Json<Value>, Error> {
    let request_id = Uuid::new_v4();
    let mut logger = LogFormatter::new(ip, note.auth_token().token().get_payload().sub.parse::<Uuid>()?, request_id);
    let logger = logger
        .with_case_number(Some(note.note_details().case_number()))
        .with_note_id(note.note_id());

    info!("{}", serde_json::to_string(&logger.with_message("Rate limit checking".into()).with_timestamp(Utc::now()))?);
    rate_limit_check(shared_state.clone(), &note.auth_token(), ip).await?;

    info!("{}", serde_json::to_string(&logger.with_message("Adding note to case".into()).with_timestamp(Utc::now()))?);
    let () = shared_state.postgres_pool.insert_note(&note, ip, request_id).await?;

    info!("{}", serde_json::to_string(&logger.with_message("Note added to case".into()).with_timestamp(Utc::now()))?);

    Ok(Json(json!({"message": "Added note to case"})))
}


#[tracing::instrument(skip(shared_state, data, ip), name = "FETCH CASE NOTE")]
pub async fn fetch_note(State(shared_state): State<SharedState>, ClientIp(ip): ClientIp, Json(data): Json<NoteContext>) -> Result<Json<Value>, Error> {
    let request_id = Uuid::new_v4();
    let user_id = data.auth_token().token().get_payload().sub.parse::<Uuid>()?;
    let mut logger = LogFormatter::new(ip, user_id, request_id);

    info!("{}", serde_json::to_string(&logger.with_message("Rate limit checking".into()).with_timestamp(Utc::now()))?);
    rate_limit_check(shared_state.clone(), &data.auth_token(), ip).await?;

    info!("{}", serde_json::to_string(&logger.with_message("Checking if user has access to note".into()).with_timestamp(Utc::now()))?);
    let user_access_control = UserAccessControlDefinition::new(user_id, None, data.note_id(), data.auth_token())?;
    shared_state.postgres_pool.is_access_granted(&user_access_control, false, ip, request_id).await?;

    info!("{}", serde_json::to_string(&logger.with_message("Checking if note is in cache".into()).with_timestamp(Utc::now()))?);
    let Some(note_id) = data.note_id() else {
        let error = Error::ValueNotFound("note_id".into());
        error!("{}", serde_json::to_string(&logger.with_message("Could not parse data".into()).with_timestamp(Utc::now()).with_error(Some(error.clone())))?);

        return Err(error)
    };

    if shared_state.note_details_cache.contains_key(&note_id) {
        info!("{}", serde_json::to_string(&logger.with_message("Note found in cache".into()).with_timestamp(Utc::now()))?);
        let note_details = shared_state.note_details_cache.entry(note_id).or_default().await.into_value();

        info!("{}", serde_json::to_string(&logger.with_message("Fetched note".into()).with_timestamp(Utc::now()))?);

        Ok(Json(json!({"message": "Retrieved note", "note": note_details })))
    } else {
        info!("{}", serde_json::to_string(&logger.with_message("Note not found in cache, checking database".into()).with_timestamp(Utc::now()))?);
        let note_details = shared_state.postgres_pool.fetch_note(&data, ip, request_id).await?;
        let Some(details) = note_details.clone() else {
            error!("{}", serde_json::to_string(&logger.with_message("Note not found in cache, checking database".into()).with_timestamp(Utc::now()))?);

            return Err(Error::DatabaseError)
        };
        shared_state.note_details_cache.insert(note_id, details).await;

        info!("{}", serde_json::to_string(&logger.with_message("Fetched note".into()).with_timestamp(Utc::now()))?);

        Ok(Json(json!({"message": "Retrieved note", "note": note_details })))
    }
}
