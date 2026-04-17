CREATE TYPE case_status AS ENUM (
    'OPEN',
    'CLOSED',
    'IN_REVIEW'
);

-- Users table
CREATE TABLE IF NOT EXISTS users (
    user_id UUID PRIMARY KEY NOT NULL,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    user_role TEXT,
    entry_ip TEXT,
    created_at TIMESTAMPTZ DEFAULT now()
);

-- Cases table
CREATE TABLE IF NOT EXISTS cases (
    case_number UUID PRIMARY KEY,
    user_id UUID NOT NULL,
    suspect_name TEXT,
    suspect_aliases TEXT[],
    suspect_description TEXT,
    suspect_phone TEXT,
    suspect_email TEXT,
    suspect_ip TEXT,
    victim_name TEXT NOT NULL,
    victim_email TEXT,
    victim_phone TEXT,
    token TEXT,
    timestamp_case TIMESTAMPTZ DEFAULT now(),
    case_status case_status,
    entry_ip TEXT,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- Notes table
CREATE TABLE IF NOT EXISTS notes (
    note_id UUID PRIMARY KEY,
    case_number UUID NOT NULL,
    author_id UUID,
    note_text TEXT NOT NULL,
    relevant_media TEXT [],
    entry_timestamp TIMESTAMPTZ DEFAULT now(),
    entry_ip TEXT,
    FOREIGN KEY (case_number) REFERENCES cases(case_number)
);

-- UAC table, flexible by design.
-- With the UAC table, you can grant access to certain cases, notes, or just store tokens for users.
-- Store the token signature, so we don't have any replication issues.
CREATE TABLE IF NOT EXISTS user_access_control (
    param_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    case_number UUID,
    note_id UUID
);

-- Auth session table
CREATE TABLE IF NOT EXISTS auth_session (
    session_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL,
    token_hash TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    ip_address TEXT NOT NULL
);
