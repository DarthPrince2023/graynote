### GRAYNOTE API DOCUMENTATION ###

## Gray Note is a secure authentication first based case access management digital locker ##

# DESCRIPTION, ENDPOINTS, VERB, EXPECTED PAYLOAD #

Create a user
    `/add_user`
    POST
    {
        user_handle: String - Desired username for new user.
        password_id: String - Desired password for new user.
        user_role: String, - Roles defined in environment variable `ALLOWED_ROLE_TYPES`.
    }

Authenticate a user
    `/login`
    POST
    {
        username: String - Username identifier for login request.
        password: String - Plaintext password for login request.
    }

    Grant permission to access a resource to a user
    `/admin/add_uac_member`
    POST
    {
        session_id: Uuid - Admin authorization session ID.
        token: String - Admin authorization token.
        case_number: Uuid - Case number to grant access to.
        target_user: Uuid - Desired user to grant permission to.
    }

    Retrieve information about a user
    `/admin/user/inquire`
    POST
    {
        user_handle: String - Username for a given user.
        admin_session_id: Uuid - Authorization session ID for user.
        admin_token: String - Authorization token for admin.
    }

    File a new case in the system
    `/case/create`
    POST
    {
        case_information: {
  		    user_id: Uuid - ID of investigator or admin filing a case.
  		    suspect_name: Optional String - Name of suspect for file.
  		    suspect_aliases: array of strings - Aliases of suspect for file.
  		    suspect_description: Optional String - A description of the suspect for file, if provided.
  		    suspect_phone: Optional String - phone number of suspect, if provided.
  		    suspect_email: Optional String - email of the suspect, if provided.
  		    suspect_ip: Optional String - IP address of the suspect, if provided.
  		    victim_name: String - name of the impacted party.
            victim_email: Optional String - Contact email address for complaintant, if provided.
            victim_phone: Optional String - Contact phone number for complaintant, if provided.
	    },
	    session_id: Uuid - session identifier for investigator or admin filing the case.
        token: String - session token for investigator or admin filing the case.
    }

    Retrieve information about a case
    `/case/fetch`
    POST
    {
        case_number: Uuid - Case number identifier to retrieve.
        token: String - Authorization session token for investigator with access or admin
        session_id: Uuid - Authorization session ID for investigator with access or admin
    }

    Retrieve notes relevant to a case
    `/case/notes`
    POST
    {
        case_number: Uuid - Case number identifier for case to retrieve notes for.
        token: String - Authorization session token for investigator with access or admin.
        session_id: Uuid - Authorization session identifier for investigator with access or admin.
    }

    Add a new relevant note to case file
    `/case/notes/add`
    POST
    {
        note_details: NoteDetails (Described below)
        token: String - Authorization session token for investigator with access or admin.
        session_id: Uuid - Authorization session identifier for investigator with access or admin.
    }

    `NoteDetails`:
        case_number: Uuid - Case number for which case this note is relevant.
        user_id: Optional Uuid - you are not required to include this in your payload.
        note_text: String - Textual description for note.
        relevant_media: array of strings - Relevant media source for note.

    Find all accessible cases for a user
    `/case/find/all`
    POST
    {
        token: String - Authorization session token for authorized investigator or admin
        session_id: Uuid - Authorization session identifier for authorized investigator or admin
    }

    Find all accessible notes for a user
    `/case/notes/find/all`
    POST
    {
        token: String - Authorization session token for authorized investigator or admin
        session_id: Uuid - Authorization session identifier for authorized investigator or admin
    }