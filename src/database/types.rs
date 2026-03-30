use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

///
/// `'AdminUserInfoRequest'`
/// 
/// --- FIELDS ---
/// `user_handle` = the username of the user to look up
/// `admin_session_id` = a valid admin session ID
/// `admin_token` = a valid admin session token
/// 
/// The purpose of this type is to allow an admin lookup request of a user
/// by username
/// 
#[derive(Debug, Deserialize, Serialize, FromRow, Default)]
pub struct AdminUserInfoRequest {
    pub user_handle: String,
    pub admin_session_id: Uuid,
    pub admin_token: String,
}

///
/// This object stores the information of a given user, everything necessary to identify a user across sessions.
/// 
/// Fields
/// 
/// `user_id`: The ID of the user in the database
/// 
/// `user_handle`: The identifying "username" of a given user
/// 
/// `password_id`: The password of a user. Skipped when retrieving user info for security.
/// 
/// `user_role`: What role this user is assigned when accessing information from the service: ['viewer', 'investigator', 'admin']
/// 
/// `created_at`: The Chrono `'Datetime'` UTC timestamp for when a user was originally created in the database. Used in creating tokens.
///
#[derive(Debug, Deserialize, Serialize, FromRow, Default)]
pub struct UserInfo {
    #[serde(skip_deserializing)]
    pub user_id: Uuid,
    pub user_handle: String,
    #[serde(skip_serializing)]
    pub password_id: String,
    pub user_role: String,
    #[serde(skip_deserializing)]
    pub created_at: DateTime<Utc>
}

impl UserInfo {
    #[allow(unused)]
    pub fn new(
        user_id: Uuid,
        user_handle: String,
        password_id: String,
        user_role: String,
        created_at: DateTime<Utc>
    ) -> Self {
        Self {
            user_id,
            user_handle,
            password_id,
            user_role,
            created_at
        }
    }

    pub fn with_user_id(&mut self, user_id: Uuid) -> &mut Self {
        self.user_id = user_id;

        self
    }

    pub fn with_created_at(&mut self, created_at: DateTime<Utc>) -> &mut Self {
        self.created_at = created_at;

        self
    }

    pub fn with_role(&mut self, role: String) -> &mut Self {
        self.user_role = role;

        self
    }

    pub fn with_username(&mut self, username: String) -> &mut Self {
        self.user_handle = username;

        self
    }

    pub fn with_password(&mut self, password: String) -> &mut Self {
        self.password_id = password;

        self
    }
}


/// `'CaseInformation'` is a type that we can pull from the database regarding a case. 
#[derive(Debug, Deserialize, Serialize, FromRow)]
pub struct CaseInformation {
    #[serde(skip)]
    pub case_number: Uuid,
    pub user_id: Uuid,
    pub suspect_name: Option<String>,
    pub suspect_aliases: Vec<String>,
    pub suspect_description: Option<String>,
    pub suspect_phone: Option<String>,
    pub suspect_email: Option<String>,
    pub suspect_ip: Option<String>,
    pub victim_name: String,
    pub victim_email: Option<String>,
    pub victim_phone: Option<String>,
    #[serde(skip)]
    pub timestamp_case: Option<DateTime<Utc>>
}

impl Default for CaseInformation {
    fn default() -> Self {
        Self {
            case_number: Uuid::default(),
            user_id: Uuid::default(),
            suspect_name: None,
            suspect_aliases: Vec::new(),
            suspect_description: None,
            suspect_email: None,
            suspect_phone: None,
            suspect_ip: None,
            victim_name: String::new(),
            victim_phone: None,
            victim_email: None,
            timestamp_case: Some(Utc::now())
        }
    }
}

#[derive(Debug, FromRow, Deserialize, Serialize)]
pub struct CaseAccess {
    pub case_information: CaseInformation,
    pub session_id: String,
    pub token: String
}

#[derive(Debug, FromRow, Deserialize, Serialize)]
pub struct UserAccessManagement {
    pub session_id: String,
    pub token: String,  
    pub case_number: Uuid,
    pub target_user: Uuid
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CaseDetails {
    pub case_number: Uuid,
    pub token: String,
    pub session_id: String
}

///
/// Token type for routing logic implementing the JSON payload routes only accepting a token
/// 
#[derive(Debug, Deserialize, Serialize)]
pub struct AuthToken {
    pub token: String,
    pub session_id: String
}

///
/// Type for abstracting away case info (ie getting case info, getting notes)
///
#[derive(Debug, Deserialize, Serialize)]
pub struct CaseDefinition {
    pub case_number: Uuid,
    pub token: String
}

///
/// The `'Notes'` type is used for getting notes relevant to a case and/or it's relevant evidence
///
#[derive(Debug, Deserialize, Serialize)]
pub struct Notes {
    #[serde(skip_deserializing)]
    pub note_id: Uuid,
    pub note_details: NoteDetails,
    #[serde(skip_serializing)]
    pub token: String,
    #[serde(skip_serializing)]
    pub session_id: String,
}

#[derive(Debug, Deserialize, FromRow, Serialize, Default)]
pub struct NoteDetails {
    pub case_number: Uuid,
    pub author_id: Option<Uuid>,
    pub note_text: String,
    pub relevant_media: Vec<String>,
    #[serde(skip_deserializing)]
    pub entry_timestamp: Option<DateTime<Utc>>
}

impl Default for Notes {
    fn default() -> Self {
        Self {
            note_id: Uuid::default(),
            note_details: NoteDetails::default(),
            token: String::new(),
            session_id: String::new(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct BasicLoginFlow {
    pub username: String,
    pub password: String
}

#[derive(Debug, FromRow, Deserialize, Serialize, Clone)]
pub struct UserAccessControl {
    #[serde(skip)]
    param_id: Uuid,
    user_id: Uuid,
    case_number: Option<Uuid>,
    note_id: Option<Uuid>,
    #[serde(skip)]
    token: String
}

impl UserAccessControl {
    pub fn new(user_id: Uuid, case_number: Option<Uuid>, note_id: Option<Uuid>) -> Self {
        Self {
            param_id: Uuid::new_v4(),
            user_id,
            case_number,
            note_id,
            token: String::new()
        }
    }

    pub fn get_param_id(&self) -> Uuid {
        self.param_id
    }

    pub fn get_user_id(&self) -> Uuid {
        self.user_id
    }

    pub fn get_case_number(&self) -> Option<Uuid> {
        self.case_number
    }

    pub fn get_note_id(&self) -> Option<Uuid> {
        self.note_id
    }

    pub fn get_token(&self) -> &String {
        &self.token
    }
}
