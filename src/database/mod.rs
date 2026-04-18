pub mod postgres;

use std::{future::Future, net::IpAddr};
use graynote_lib::types::{
    error::Error, structs::{
        AdminDeleteUser, AdminTokenCycleRequest, AdminUserInfoRequest, AuthToken, BasicAuth, CaseAccess, CaseDefinition, CaseInformation, CaseStatusUpdate, NoteDetails, Notes, SessionInfo, UserAccessControl, UserInfo
    }
};
use jwt::TokenPieces;
use uuid::Uuid;

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
    fn user_exists(&self, username: &str, ip_address: IpAddr, request_id: Uuid) -> impl Future<Output = Result<bool, Error>> + Send;
    fn get_case_information(&self, case_access: &CaseAccess, ip_address: IpAddr, request_id: Uuid) -> impl Future<Output = Result<CaseInformation, Error>> + Send;
    fn admin_get_user_info(&self, user_info: AdminUserInfoRequest, ip_address: IpAddr, request_id: Uuid) -> impl Future<Output = Result<Option<UserInfo>, Error>> + Send;
    fn get_case_notes(&self, case_access: &CaseAccess, ip_address: IpAddr, request_id: Uuid) -> impl Future<Output = Result<Vec<NoteDetails>, Error>> + Send;
    fn login_basic(&self, basic_auth: &BasicAuth, ip_address: IpAddr, request_id: Uuid) -> impl Future<Output = Result<(TokenPieces, Uuid), Error>> + Send;
    fn insert_user(&self, user: UserInfo, ip_address: IpAddr, request_id: Uuid) -> impl Future<Output = Result<(), Error>> + Send;
    fn insert_case_information(&self, case_definition: &CaseDefinition, ip_address: IpAddr, request_id: Uuid) -> impl Future<Output = Result<Uuid, Error>> + Send;
    fn insert_note(&self, note: &Notes, ip_address: IpAddr, request_id: Uuid) -> impl Future<Output = Result<(), Error>> + Send;
    fn authorize_user(&self, authorization_token: &TokenPieces, ip_address: IpAddr, request_id: Uuid) -> impl Future<Output = Result<Uuid, Error>> + Send;
    fn add_uac_member(&self, user_access_control: UserAccessControl, ip_address: IpAddr, request_id: Uuid) -> impl Future<Output = Result<(), Error>> + Send;
    fn find_accessible_cases(&self, authorization_token: &AuthToken, ip_address: IpAddr, request_id: Uuid) -> impl Future<Output = Result<Vec<CaseInformation>, Error>> + Send;
    fn find_accessible_notes(&self, authorization_token: &AuthToken, ip_address: IpAddr, request_id: Uuid) -> impl Future<Output = Result<Vec<NoteDetails>, Error>> + Send;
    fn is_access_granted(&self, user_access_control: &UserAccessControl, admin_action: bool, ip_address: IpAddr, request_id: Uuid) -> impl Future<Output = Result<TokenPieces, Error>> + Send;
    fn delete_invalid_token(&self, session_id: Uuid, ip_address: IpAddr, user_id: Uuid, request_id: Uuid) -> impl Future<Output = Result<(), Error>> + Send;
    fn admin_cycle_token(&self, admin_token_cycle_request: AdminTokenCycleRequest, ip_address: IpAddr, request_id: Uuid) -> impl Future<Output = Result<(), Error>> + Send;
    fn admin_delete_user_account(&self, admin_delete_user: AdminDeleteUser, ip_address: IpAddr, request_id: Uuid) -> impl Future<Output = Result<(), Error>> + Send;
    fn delete_user_account(&self, authorization: &AuthToken, ip_address: IpAddr, request_id: Uuid) -> impl Future<Output = Result<(), Error>> + Send;
    fn cycle_token(&self, authorization: &AuthToken, ip_address: IpAddr, request_id: Uuid) -> impl Future<Output = Result<(), Error>> + Send;
    fn kill_sessions(&self, authorization: &AuthToken, ip_address: IpAddr, request_id: Uuid) -> impl Future<Output = Result<(), Error>> + Send;
    fn list_sessions(&self, authorization: &AuthToken, ip_address: IpAddr, request_id: Uuid) -> impl Future<Output = Result<Vec<SessionInfo>, Error>> + Send;
    fn update_case_status(&self, case: CaseStatusUpdate, ip_address: IpAddr, request_id: Uuid) -> impl Future<Output = Result<(), Error>> + Send;
}