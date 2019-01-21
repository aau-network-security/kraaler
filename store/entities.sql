create table dim_initiators (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL
);

create table dim_schemes (
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL,
    protocol TEXT NOT NULL
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

create table fact_action (
    id INTEGER PRIMARY KEY,
    status_code INTEGER,
    parent_id INTEGER references fact_action(id),
    scheme_id INTEGER references dim_scheme(id) NOT NULL,
    host_id INTEGER references dim_hosts(id) NOT NULL,
    error_id INTEGER references dim_errors(id),
    body_id INTEGER references dim_bodies(id),
    start_time NUMERIC NOT NULL,
    end_time NUMERIC NOT NULL
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

create table fact_action_headers (
    action_id INTEGER references fact_action(id) NOT NULL,
    is_response BOOLEAN NOT NULL,
    header_keyvalue_id INTEGER references dim_header_keyvalues(id) NOT NULL
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

create table fact_console_output (
    action_id INTEGER references fact_action(id),
    seq INTEGER NOT NULL,
    message TEXT NOT NULL
);
