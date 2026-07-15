CREATE TABLE IF NOT EXISTS captures (
    id TEXT PRIMARY KEY,
    method TEXT NOT NULL CHECK (method IN ('POST', 'PUT', 'PATCH')),
    path TEXT NOT NULL,
    query_json TEXT NOT NULL,
    headers_json TEXT NOT NULL,
    content_type TEXT NOT NULL,
    body_kind TEXT NOT NULL CHECK (
        body_kind IN ('empty', 'json', 'malformed-json', 'form', 'text', 'binary-base64')
    ),
    body_text TEXT NOT NULL,
    body_bytes INTEGER NOT NULL CHECK (body_bytes >= 0 AND body_bytes <= 131072),
    source_ip TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS captures_created_idx ON captures (created_at, id);
CREATE INDEX IF NOT EXISTS captures_method_created_idx ON captures (method, created_at);

CREATE TABLE IF NOT EXISTS hookbox_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
