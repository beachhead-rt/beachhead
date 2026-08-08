-- src/beachhead/core/store/migrations/001_init.sql
-- Beachhead core/store slice 1 schema. Forward-only. user_version is set by the
-- migration runner from this file's NNN_ prefix, not here.

CREATE TABLE engagement (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    started_at  TEXT NOT NULL,
    scope_hash  TEXT NOT NULL
);

CREATE TABLE runs (
    id           TEXT PRIMARY KEY,
    module       TEXT NOT NULL,
    phase        TEXT NOT NULL,
    mode         TEXT NOT NULL CHECK (mode IN ('dry', 'live')),
    operator     TEXT NOT NULL,
    started_at   TEXT NOT NULL,
    finished_at  TEXT,
    status       TEXT NOT NULL CHECK (status IN ('running', 'ok', 'error'))
);

CREATE TABLE artifacts (
    id           TEXT PRIMARY KEY,
    type         TEXT NOT NULL,
    azure_id     TEXT NOT NULL,
    scope        TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    expires_at   TEXT,
    description  TEXT,
    run_id       TEXT REFERENCES runs(id)
);

CREATE TABLE audit_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT NOT NULL,
    operator  TEXT NOT NULL,
    action    TEXT NOT NULL,
    target    TEXT NOT NULL,
    mode      TEXT NOT NULL,
    result    TEXT NOT NULL,
    run_id    TEXT REFERENCES runs(id)
);
