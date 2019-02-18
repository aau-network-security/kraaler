create table dim_initiators (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL
);

create table dim_protocols (
    id INTEGER PRIMARY KEY,
    protocol TEXT NOT NULL
);

create table dim_schemes (
    id INTEGER PRIMARY KEY,
    scheme TEXT NOT NULL,
    protocol_id INTEGER references dim_procols(id) NOT NULL
);

create table dim_paths (
    id INTEGER PRIMARY KEY,
    path TEXT NOT NULL
);

create table dim_hosts (
    id INTEGER PRIMARY KEY,
    domain TEXT NOT NULL,
    tld TEXT NOT NULL,
    ipv4 TEXT NOT NULL
);

create table dim_errors (
    id INTEGER PRIMARY KEY,
    error TEXT NOT NULL
);

create table dim_methods (
    id INTEGER PRIMARY KEY,
    method TEXT NOT NULL
);

create table fact_actions (
    id INTEGER PRIMARY KEY,
    parent_id INTEGER references fact_action(id),
    method_id INTEGER references dim_methods(id) NOT NULL,
    scheme_id INTEGER references dim_scheme(id) NOT NULL,
    path_id INTEGER references dim_paths(id) NOT NULL,
    host_id INTEGER references dim_hosts(id) NOT NULL,
    status_code INTEGER,
    error_id INTEGER references dim_errors(id)
);

create table dim_header_keys (
    id INTEGER PRIMARY KEY,
    key TEXT NOT NULL
);

create table dim_header_keyvalues (
    id INTEGER PRIMARY KEY,
    key_id INTEGER references dim_header_keys(id) NOT NULL,
    value TEXT NOT NULL
);

create table fact_response_headers (
    action_id INTEGER references fact_action(id) NOT NULL,
    header_keyvalue_id INTEGER references dim_header_keyvalues(id) NOT NULL
);

create table fact_request_headers (
    action_id INTEGER references fact_action(id) NOT NULL,
    header_keyvalue_id INTEGER references dim_header_keyvalues(id) NOT NULL
);

create table fact_action_timings (
    action_id INTEGER references fact_action(id) NOT NULL,
    start_datetime NUMERIC NOT NULL,
    end_datetime NUMERIC NOT NULL,
    connect_start_time NUMERIC,
    connect_end_time NUMERIC,
    send_start_time NUMERIC,
    send_end_time NUMERIC,
    push_start_time NUMERIC,
    push_end_time NUMERIC
);

create table dim_issuers (
    id INTEGER PRIMARY KEY,
    issuer TEXT NOT NULL
);

create table dim_key_exchanges (
    id INTEGER PRIMARY KEY,
    key_exchange TEXT NOT NULL
);

create table dim_ciphers (
    id INTEGER PRIMARY KEY,
    cipher TEXT NOT NULL
);

create table dim_san_lists (
    id INTEGER PRIMARY KEY,
    list TEXT NOT NULL
);

create table fact_security_details (
    action_id INTEGER references fact_action(id) NOT NULL,
    protocol_id INTEGER references dim_procols(id) NOT NULL,
    key_exchange_id INTEGER references dim_key_exchanges(id) NOT NULL,
    issuer_id INTEGER references dim_issuer(id) NOT NULL,
    cipher_id INTEGER references dim_cipher(id) NOT NULL,
    san_list_id INTEGER references dim_san_lists(id) NOT NULL,
    subject_name TEXT NOT NULL,
    valid_from NUMERIC NOT NULL,
    valid_to NUMERIC NOT NULL
);

create table dim_mime_types (
    id INTEGER PRIMARY KEY,
    mime_type TEXT NOT NULL
);

create table fact_bodies (
    action_id INTEGER references fact_action(id) NOT NULL,
    path TEXT NOT NULL,
    mime_id INTEGER references dim_mime_types(id) NOT NULL,
    hash256 TEXT NOT NULL
);

create table dim_resolutions (
    id INTEGER PRIMARY KEY,
    resolution TEXT NOT NULL
);

create table fact_screenshots (
    action_id INTEGER references fact_action(id) NOT NULL,
    is_mobile BOOLEAN NOT NULL,
    resolution_id INTEGER references dim_resolutions(id) NOT NULL,
    path TEXT NOT NULL
);

create table fact_post_data (
    action_id INTEGER references fact_action(id) NOT NULL,
    data TEXT NOT NULL
)

create table fact_console_output (
    action_id INTEGER references fact_action(id),
    seq INTEGER NOT NULL,
    message TEXT NOT NULL
);
