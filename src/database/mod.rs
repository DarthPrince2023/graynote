use jwt::TokenPieces;
use uuid::Uuid;
use crate::{database::types::{AdminUserInfoRequest, CaseAccess, CaseDetails, CaseInformation, Notes, UserInfo}, routes::{Error, client_modifier::BasicAuth}};
use std::future::Future;

pub mod postgres;
pub mod types;

///
/// `'Database'` trait allows us to implement this for different DB connector/interface types.
/// 
/// Trait methods:
///     user_exists -> Checks whether a user exists or not
/// 
///     get_user_data -> Gets information about a user, such as for checking if a user is already signed in,
/// by presenting a username to get the data about a user, including checking if a presented optional JWT is active
/// for the requested user
/// 
///     get_case_information -> This gets any information about a case that's relevant based on the case number
/// we use relational logic in the DB handling to do this efficiently
/// 
///     get_case_notes -> This allows us to retrieve only the notes relative to a case via case number
/// 
///     insert_user -> Creates a new user with one new valid token (returned when you interact with the auth endpoints,
/// if successful)
/// 
///     insert_case_information -> Creates a new row for a specific case, returns information that allows a user to
/// identify the case for later reference
/// 
///     insert_note -> Creates a new row in the notes table associated with a given case
/// 
///     add_uac_member -> Grants access to a case by referencing the username of the user being given
/// permission to access the case info
/// 
///     These methods will be protected via a custom UAC implementing token checks.
///
pub trait Database {
    fn user_exists(&self, username: &str) -> impl Future<Output = Result<bool, Error>> + Send;
    fn get_case_information(&self, case_details: CaseDetails) -> impl Future<Output = Result<CaseInformation, Error>> + Send;
    fn admin_get_user_info(&self, user_info: AdminUserInfoRequest) -> impl Future<Output = Result<UserInfo, Error>> + Send;
    fn get_case_notes(&self, case_details: CaseDetails) -> impl Future<Output = Result<Vec<Notes>, Error>> + Send;
    fn login_basic(&self, basic_auth: BasicAuth) -> impl Future<Output = Result<(String, Uuid), Error>> + Send;
    fn insert_user(&self, user: UserInfo) -> impl Future<Output = Result<(), Error>> + Send;
    fn insert_case_information(&self, case_access: CaseAccess) -> impl Future<Output = Result<Uuid, Error>> + Send;
    fn insert_note(&self, note: &Notes) -> impl Future<Output = Result<(), Error>> + Send;
    fn login_user(&self, token: String) -> impl Future<Output = Result<Uuid, Error>> + Send;
    fn add_uac_member(&self, case_number: Uuid, token: String, session_id: String, target_user: Uuid) -> impl Future<Output = Result<(), Error>> + Send;
    fn find_accessible_cases(&self, token: String, session_id: String) -> impl Future<Output = Result<Vec<CaseInformation>, Error>> + Send;
    fn find_accessible_notes(&self, session_id: String, token: String) -> impl Future<Output = Result<Vec<Notes>, Error>> + Send;
    fn is_access_granted(&self, session_id: &String, token: &String, case_number: &Option<Uuid>, create_post: bool) -> impl Future<Output = Result<(bool, TokenPieces), Error>> + Send;
    fn delete_invalid_token(&self, token: &String) -> impl Future<Output = Result<bool, Error>> + Send;
} 