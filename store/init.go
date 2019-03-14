package store

const (
	sessionSchema = `
create table if not exists dim_resolutions (
    id INTEGER PRIMARY KEY,
    resolution TEXT NOT NULL
);

create table if not exists fact_sessions (
    id INTEGER PRIMARY KEY,
    resolution_id INTEGER references dim_resolutions(id) NOT NULL,
    navigated_time INTEGER NOT NULL,
    loaded_time INTEGER NOT NULL,
    terminated_time INTEGER NOT NULL,
    amount_of_actions INTEGER NOT NULL,
    error TEXT
);
`
	consoleSchema = `
create table if not exists dim_console_messages (
    id INTEGER PRIMARY KEY,
    message TEXT NOT NULL
);

create table if not exists dim_javascript_origin (
    id INTEGER PRIMARY KEY,
    func TEXT NOT NULL,
    column INTEGER NOT NULL,
    line INTEGER NOT NULL
);

create table if not exists fact_console_output (
    session_id INTEGER references fact_sessions(id) NOT NULL,
    seq INTEGER NOT NULL,
    javascript_origin_id INTEGER NOT NULL,
    msg_id INTEGER references dim_console_messages(id) NOT NULL
);`

	screenshotSchema = `
create table if not exists fact_screenshots (
    session_id INTEGER references fact_sessions(id) NOT NULL,
    time_taken INTEGER NOT NULL,
    path TEXT NOT NULL
);`

	actionSchema = `
create table if not exists dim_hosts (
    id INTEGER PRIMARY KEY,
    domain TEXT NOT NULL,
    tld TEXT NOT NULL,
    ipv4 TEXT NOT NULL,
    nameservers TEXT NOT NULL
);

create table if not exists dim_errors (
    id INTEGER PRIMARY KEY,
    error TEXT NOT NULL
);

create table if not exists dim_methods (
    id INTEGER PRIMARY KEY,
    method TEXT NOT NULL
);

create table if not exists dim_protocols (
    id INTEGER PRIMARY KEY,
    protocol TEXT NOT NULL
);

create table if not exists dim_initiators (
    id INTEGER PRIMARY KEY,
    initiator TEXT NOT NULL
);

create table if not exists fact_actions (
    id INTEGER PRIMARY KEY,
    parent_id INTEGER references fact_actions(id),
    session_id INTEGER references fact_sessions(id) NOT NULL,
    method_id INTEGER references dim_methods(id) NOT NULL,
    protocol_id INTEGER references dim_procols(id),
    host_id INTEGER references dim_hosts(id),
    initiator_id INTEGER references dim_initiators(id) NOT NULL,
    status_code INTEGER,
    error_id INTEGER references dim_errors(id)
);`

	urlSchema = `
create table if not exists dim_url_schemes (
    id INTEGER PRIMARY KEY,
    scheme TEXT NOT NULL
);

create table if not exists dim_url_users (
    id INTEGER PRIMARY KEY,
    user TEXT NOT NULL
);

create table if not exists dim_url_hosts (
    id INTEGER PRIMARY KEY,
    host TEXT NOT NULL
);

create table if not exists dim_url_paths (
    id INTEGER PRIMARY KEY,
    path TEXT NOT NULL
);

create table if not exists dim_url_fragments (
    id INTEGER PRIMARY KEY,
    fragment TEXT NOT NULL
);

create table if not exists dim_url_raw_queries (
    id INTEGER PRIMARY KEY,
    query TEXT NOT NULL
);

create table if not exists fact_urls (
    action_id INTEGER references fact_actions(id) NOT NULL,
    scheme_id INTEGER references dim_url_schemes(id) NOT NULL,
    user_id INTEGER references dim_url_users(id),
    host_id INTEGER references dim_url_hosts(id) NOT NULL,
    path_id INTEGER references dim_url_paths(id) NOT NULL,
    fragment_id INTEGER references dim_url_fragments(id),
    raw_query_id INTEGER references dim_url_raw_queries(id),
    url TEXT NOT NULL
);`

	headerSchema = `
create table if not exists dim_header_keys (
    id INTEGER PRIMARY KEY,
    key TEXT NOT NULL
);

create table if not exists dim_header_keyvalues (
    id INTEGER PRIMARY KEY,
    key_id INTEGER references dim_header_keys(id) NOT NULL,
    value TEXT NOT NULL
);

create table if not exists fact_response_headers (
    action_id INTEGER references fact_action(id) NOT NULL,
    header_keyvalue_id INTEGER references dim_header_keyvalues(id) NOT NULL
);

create table if not exists fact_request_headers (
    action_id INTEGER references fact_action(id) NOT NULL,
    header_keyvalue_id INTEGER references dim_header_keyvalues(id) NOT NULL
);`

	securitySchema = `
create table if not exists dim_protocols (
    id INTEGER PRIMARY KEY,
    protocol TEXT NOT NULL
);

create table if not exists dim_issuers (
    id INTEGER PRIMARY KEY,
    issuer TEXT NOT NULL
);

create table if not exists dim_key_exchanges (
    id INTEGER PRIMARY KEY,
    key_exchange TEXT NOT NULL
);

create table if not exists dim_ciphers (
    id INTEGER PRIMARY KEY,
    cipher TEXT NOT NULL
);

create table if not exists dim_san_lists (
    id INTEGER PRIMARY KEY,
    list TEXT NOT NULL
);

create table if not exists fact_security_details (
    action_id INTEGER references fact_action(id) NOT NULL,
    protocol_id INTEGER references dim_procols(id) NOT NULL,
    key_exchange_id INTEGER references dim_key_exchanges(id) NOT NULL,
    issuer_id INTEGER references dim_issuer(id) NOT NULL,
    cipher_id INTEGER references dim_cipher(id) NOT NULL,
    san_list_id INTEGER references dim_san_lists(id) NOT NULL,
    subject_name TEXT NOT NULL,
    valid_from INTEGER NOT NULL,
    valid_to INTEGER NOT NULL
);`

	bodySchema = `
create table if not exists dim_mime_types (
    id INTEGER PRIMARY KEY,
    mime_type TEXT NOT NULL
);

create table if not exists fact_bodies (
    action_id INTEGER references fact_action(id) NOT NULL,
    browser_mime_id INTEGER references dim_mime_types(id) NOT NULL,
    determined_mime_id INTEGER references dim_mime_types(id) NOT NULL,
    hash256 TEXT NOT NULL,
    org_size INTEGER NOT NULL,
    comp_size INTEGER,
    path TEXT
);`

	postDataSchema = `
create table if not exists fact_post_data (
    action_id INTEGER references fact_action(id) NOT NULL,
    data TEXT NOT NULL
);`

	initiatorStackSchema = `
create table if not exists fact_initiator_stack (
    action_id INTEGER references fact_action(id) NOT NULL,
    col INTEGER NOT NULL,
    line INTEGER NOT NULL,
    func TEXT
);`

	urlStoreSchema = `
create table if not exists url_visits (
    id INTEGER PRIMARY KEY,
    url TEXT NOT NULL,
    last_visit INTEGER
);`
)
