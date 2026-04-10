use axum::{
    Json, extract::State, http::StatusCode,
    response::IntoResponse
};
use chrono::Utc;
use graynote_lib::types::structs::{
    AdminUserInfoRequest, AuthToken,
    BasicAuth, CaseAccess, CaseDetails,
    Notes, UserAccessManagement, UserInfo
};
use jwt::TokenPieces;
use serde_json::json;
use tracing::{error, info};

use crate::{database::Database, routes::SharedState};

#[tracing::instrument(skip(state), name = "RATE LIMIT CHECK")]
pub async fn rate_limit_check(mut state: SharedState, token: String) -> impl IntoResponse {
    info!("Extracting token pieces to check rate limit at {}", Utc::now());
    let payload = match TokenPieces::try_from(token.as_str()) {
        Ok(payload) => payload,
        Err(_) => {
            error!("Invalid credentials at {}", Utc::now());
            return (StatusCode::BAD_REQUEST, json!({"message": "Invalid credentials"}).to_string());
        }
    };
    let username = payload.get_payload().username;

    info!("Rate limit checking at {}", Utc::now());
    if !state.use_request_token(username).await {
        return (StatusCode::TOO_MANY_REQUESTS, json!({"message": "Rate limit exceeded"}).to_string());
    }

    (StatusCode::OK, json!({"message": "Rate limit check passed"}).to_string())
}

#[tracing::instrument(skip(state, user), name = "CREATE USER")]
pub async fn create_user(State(mut state): State<SharedState>, Json(user): Json<UserInfo>) -> impl IntoResponse {
    // Since we have the username, we can perform a simple rate limit check, before attempting to create user.
    info!("Rate limit checking at {}", Utc::now());
    if !state.use_request_token(user.user_handle.clone()).await {
        return (StatusCode::TOO_MANY_REQUESTS, json!({"message": "Rate limit exceeded"}).to_string());
    }

    info!("Attempting to creater user at {}", Utc::now());
    match state.postgres_pool.insert_user(user).await {
        Ok(()) => {
            info!("Created user successfully at {}", Utc::now());

            (StatusCode::CREATED, json!({"message": "User added."}).to_string())
        },
        Err(error) => {
            error!("Unable to create user at {}", Utc::now());

            (StatusCode::INTERNAL_SERVER_ERROR, json!({"message": error}).to_string())
        }
    }
}

#[tracing::instrument(skip(state, basic_auth), name = "BASIC AUTHENTICATION")]
pub async fn basic_login(State(mut state): State<SharedState>, Json(basic_auth): Json<BasicAuth>) -> impl IntoResponse {
    // Since we have the username, we can perform a simple rate limit check before attempting to authorize login.
    info!("Rate limit checking at {}", Utc::now());
    if !state.use_request_token(basic_auth.username.clone()).await {
        return (StatusCode::TOO_MANY_REQUESTS, json!({"message": "Rate limit exceeded"}).to_string());
    }

    info!("Attempting login authorization at {}", Utc::now());
    match state.postgres_pool.login_basic(&basic_auth).await {
        Ok(token) => {
            info!("User login request authorized at {}", Utc::now());

            (StatusCode::OK, json!({"message": "Logged in successfully.", "token": token.0, "session_id": token.1}).to_string())
        },
        Err(error) => {
            error!("Unable to login at {}", Utc::now());

            (StatusCode::INTERNAL_SERVER_ERROR, json!({"message": "Failed to authenticate user", "error": error}).to_string())
        }
    }
}

#[tracing::instrument(skip(shared_state, case), name = "GET CASE INFORMATION")]
pub async fn get_case_information(State(shared_state): State<SharedState>, Json(case): Json<CaseDetails>) -> impl IntoResponse {
    // We do not have the username at this point,
    //  so we will just perform a rate limit check using the token, and if it fails, we will return an error.
    // If it succeeds, we will attempt to retrieve the case information.
    info!("Rate limit checking at {}", Utc::now());
    let _ = rate_limit_check(shared_state.clone(), case.token.clone()).await;

    info!("Attempting to retrieve information about case at {}", Utc::now());
    let case_info = match shared_state.postgres_pool.get_case_information(&case).await {
        Ok(case_info) => {
            info!("Retrieved information for case {} at {} for {}", case.case_number, Utc::now(), case_info.user_id);

            case_info
        },
        Err(_) => {
            error!("Unauthorized access attempt for resource at {}", Utc::now());

            return (StatusCode::UNAUTHORIZED,json!({"message":"You are not authorized to access the requested resource."}).to_string())
        }
    };

    info!("Attempting to serialize retrieved case information at {} for case {}", Utc::now(), case_info.case_number);
    let Ok(case_info) = serde_json::to_string(&case_info) else {
        error!("Unable to serialize retrieved case data at {}", Utc::now());

        return (StatusCode::INTERNAL_SERVER_ERROR, json!({"message": "Could not build response message"}).to_string())
    };

    (StatusCode::OK, case_info)
}

#[tracing::instrument(skip(shared_state, case), name = "GET CASE NOTES")]
pub async fn get_case_notes(State(shared_state): State<SharedState>, Json(case): Json<CaseDetails>) -> impl IntoResponse {
    // We do not have the username at this point,
    //  so we will just perform a rate limit check using the token, and if it fails, we will return an error.
    // If it succeeds, we will attempt to retrieve the case information.
    info!("Rate limit checking at {}", Utc::now());
    let _ = rate_limit_check(shared_state.clone(), case.token.clone()).await;

    info!("Attempting to retrieve notes for case {} at {}", case.case_number, Utc::now());
    match shared_state.postgres_pool.get_case_notes(&case).await {
        Ok(case_notes) => {
            info!("Retrieved notes for case {} at {}", case.case_number, Utc::now());

            return (
                StatusCode::OK,
                json!({"message": "Retrieved notes", "notes": case_notes}).to_string()
            )
        },
        Err(_) => {
            error!("Unable to retrieve notes for requested case {} at {}", case.case_number, Utc::now());

            return (
                StatusCode::UNAUTHORIZED,
                json!({"message": "You are not authorized to access the requested resource."}).to_string()
            )
        }
    }
}

#[tracing::instrument(skip(shared_state, token), name = "FIND ACCESSIBLE CASES")]
pub async fn find_accessible_cases(State(shared_state): State<SharedState>, Json(token): Json<AuthToken>) -> impl IntoResponse {
    // We do not have the username at this point,
    //  so we will just perform a rate limit check using the token, and if it fails, we will return an error.
    // If it succeeds, we will attempt to retrieve the case information.
    info!("Rate limit checking at {}", Utc::now());
    let _ = rate_limit_check(shared_state.clone(), token.token.clone()).await;

    info!("Retrieving accessible cases for given user");
    let cases = match shared_state.postgres_pool.find_accessible_cases(token.token, token.session_id).await {
        Ok(cases) => {
            info!("Cases retrieved successfully at {}", Utc::now());

            cases
        },
        Err(_) => {
            error!("Unable to retrieve cases at {}", Utc::now());

            return (StatusCode::INTERNAL_SERVER_ERROR, json!({"message": "Could not retrieve cases for user"}).to_string())
        }
    };
    let Ok(cases) = serde_json::to_string(&cases) else {
        error!("Unable to serialize retrieved cases");

        return (StatusCode::INTERNAL_SERVER_ERROR, json!({"message": "Unable to serialize cases"}).to_string())
    };
    (StatusCode::OK, cases)
}

#[tracing::instrument(skip(shared_state, token), name = "GET ACCESSIBLE NOTES")]
pub async fn find_accessible_notes(State(shared_state): State<SharedState>, Json(token): Json<AuthToken>) -> impl IntoResponse {
    // We do not have the username at this point,
    //  so we will just perform a rate limit check using the token, and if it fails, we will return an error.
    // If it succeeds, we will attempt to retrieve the case information.
    info!("Rate limit checking at {}", Utc::now());
    let _ = rate_limit_check(shared_state.clone(), token.token.clone()).await;
    
    info!("Retrieving accessible notes for given user at {}", Utc::now());
    let notes = match shared_state.postgres_pool.find_accessible_notes(token.session_id, token.token).await {
        Ok(notes) => {
            info!("Retrieved notes for given user at {}", Utc::now());

            notes
        },
        Err(_) => {
            error!("Unable to retrieve notes for user at {}", Utc::now());

            return (StatusCode::INTERNAL_SERVER_ERROR, json!({"message": "Could not fetch notes for user"}).to_string())
        }
    };

    info!("Attempting to serialize retrieved notes at {}", Utc::now());
    let Ok(notes_string) = serde_json::to_string(&notes) else {
        error!("Unable to serialize retrieved notes at {}", Utc::now());

        return (StatusCode::INTERNAL_SERVER_ERROR, json!({"message": "No accessible notes found for provided user"}).to_string())
    };

    (StatusCode::OK, notes_string)
}

#[tracing::instrument(skip(shared_state, admin_request), name = "GET USER INFORMATION")]
pub async fn fetch_user_info_admin(State(shared_state): State<SharedState>, Json(admin_request): Json<AdminUserInfoRequest>) -> impl IntoResponse {
    // We do not have the username at this point,
    //  so we will just perform a rate limit check using the token, and if it fails, we will return an error.
    // If it succeeds, we will attempt to retrieve the case information.
    info!("Rate limit checking at {}", Utc::now());
    let _ = rate_limit_check(shared_state.clone(), admin_request.admin_token.clone()).await;

    info!("Attempting to retrieve user information at {}", Utc::now());
    match shared_state.postgres_pool.admin_get_user_info(admin_request).await {
        Ok(user) => {
            info!("Successfully retrieved user info at {}", Utc::now());

            (StatusCode::OK, json!({"message": "Retrieval success", "user": user}).to_string())
        },
        Err(error_message) => {
            error!("Could not fetch user information => {error_message} at {}", Utc::now());

            (StatusCode::UNAUTHORIZED, json!({"message": "Could not look up user information"}).to_string())
        }
    }
}

#[tracing::instrument(skip(shared_state, uac_management), name = "ADD MEMBER USER ACCESS CONTROL")]
pub async fn add_uac_member(State(shared_state): State<SharedState>, Json(uac_management): Json<UserAccessManagement>) -> impl IntoResponse {
    // We do not have the username at this point,
    //  so we will just perform a rate limit check using the token, and if it fails, we will return an error.
    // If it succeeds, we will attempt to retrieve the case information.
    info!("Rate limit checking at {}", Utc::now());
    let _ = rate_limit_check(shared_state.clone(), uac_management.token.clone()).await;
    
    info!("Adding access for case {} to user at {}", uac_management.case_number, Utc::now());
    match shared_state.postgres_pool.add_uac_member(uac_management.case_number, uac_management.token, uac_management.session_id, uac_management.target_user).await {
        Ok(()) => {
            info!("Granted access for user {} at {}", uac_management.target_user, Utc::now());

            (StatusCode::CREATED, json!({"message":"Added user access to case"}).to_string())
        },
        Err(error) => {
            error!("Could not grant access to resource at {}; error occurred => {error:?}", Utc::now());

            (StatusCode::INTERNAL_SERVER_ERROR, json!({"message":"Could not grant access for user"}).to_string())
        }
    }
}

#[tracing::instrument(skip(shared_state, note), name = "ADD NOTE TO CASE")]
pub async fn insert_note(State(shared_state): State<SharedState>, Json(note): Json<Notes>) -> impl IntoResponse {
    // We do not have the username at this point,
    //  so we will just perform a rate limit check using the token, and if it fails, we will return an error.
    // If it succeeds, we will attempt to retrieve the case information.
    info!("Rate limit checking at {}", Utc::now());
    let _ = rate_limit_check(shared_state.clone(), note.token.clone()).await;

    info!("Adding note to case...");
    match shared_state.postgres_pool.insert_note(&note).await {
        Ok(()) => {
            info!("Note added to case by {} at {}.", note.note_details.author_id.expect("Author ID"), Utc::now());

            (StatusCode::CREATED,json!({"message": "Added note to case"}).to_string())
        },
        Err(error_message) => {
            error!("Attempted note insertion at {}; error occurred => {error_message}", Utc::now());

            (StatusCode::INTERNAL_SERVER_ERROR, json!({"message": "Unable to create note for case due to error"}).to_string())
        }
    }
}

#[tracing::instrument(skip(shared_state, case), name = "FILE NEW CASE")]
pub async fn new_case(State(shared_state): State<SharedState>, Json(case): Json<CaseAccess>) -> impl IntoResponse {
    // We do not have the username at this point,
    //  so we will just perform a rate limit check using the token, and if it fails, we will return an error.
    // If it succeeds, we will attempt to retrieve the case information.
    info!("Rate limit checking at {}", Utc::now());
    let _ = rate_limit_check(shared_state.clone(), case.token.clone()).await;

    info!("Attempting to create new case");
    match shared_state.postgres_pool.insert_case_information(case).await  {
        Ok(case_number) => {
            info!("Case creation authorized at {} for case {case_number}", Utc::now());

            (StatusCode::CREATED, json!({ "message": "Case created", "case_number": case_number }).to_string())
        },
        Err(error) => {
            error!("Unauthorized case creation attempt at {}; error occurred => {error}", Utc::now());

            (StatusCode::INTERNAL_SERVER_ERROR, json!({ "message": "Error filing case", "error": error.to_string() }).to_string())
        },
    }
}
