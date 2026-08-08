-- 002_expand_tables.sql — resources, findings, attack_paths
-- Adds the remaining framework tables on top of 001_init.

CREATE TABLE resources (
    resource_id         TEXT PRIMARY KEY,
    type                TEXT NOT NULL,
    name                TEXT NOT NULL DEFAULT '',
    properties_summary  TEXT NOT NULL DEFAULT '',
    run_id              TEXT NOT NULL REFERENCES runs(id),
    collected_at        TEXT NOT NULL
);

CREATE TABLE findings (
    id           TEXT PRIMARY KEY,
    kind         TEXT NOT NULL,
    resource_id  TEXT,
    reference    TEXT NOT NULL,
    redacted     INTEGER NOT NULL DEFAULT 0,
    details_json TEXT NOT NULL DEFAULT '{}',
    run_id       TEXT NOT NULL REFERENCES runs(id),
    collected_at TEXT NOT NULL
);

CREATE TABLE attack_paths (
    id             TEXT PRIMARY KEY,
    source_id      TEXT NOT NULL,
    target_id      TEXT NOT NULL,
    edges_json     TEXT NOT NULL DEFAULT '[]',
    technique_ids  TEXT NOT NULL DEFAULT '[]',
    score          REAL NOT NULL DEFAULT 0.0,
    description    TEXT NOT NULL DEFAULT '',
    run_id         TEXT NOT NULL REFERENCES runs(id),
    collected_at   TEXT NOT NULL
);
