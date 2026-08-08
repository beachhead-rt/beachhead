-- 009_remove_dry_mode.sql — remove dry mode; only live mode exists now.
-- SQLite cannot ALTER constraints, so recreate the runs table without the
-- mode column (it was always 'live').

CREATE TABLE runs_new (
    id           TEXT PRIMARY KEY,
    module       TEXT NOT NULL,
    phase        TEXT NOT NULL,
    operator     TEXT NOT NULL,
    started_at   TEXT NOT NULL,
    finished_at  TEXT,
    status       TEXT NOT NULL CHECK (status IN ('running', 'ok', 'error'))
);

INSERT INTO runs_new (id, module, phase, operator, started_at, finished_at, status)
    SELECT id, module, phase, operator, started_at, finished_at, status FROM runs;

DROP TABLE runs;
ALTER TABLE runs_new RENAME TO runs;

-- audit_log keeps the mode column but the CHECK is gone; existing rows stay
-- as-is and new rows will always be 'live'.
CREATE TABLE audit_log_new (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT NOT NULL,
    operator  TEXT NOT NULL,
    action    TEXT NOT NULL,
    target    TEXT NOT NULL,
    mode      TEXT NOT NULL DEFAULT 'live',
    result    TEXT NOT NULL,
    run_id    TEXT REFERENCES runs(id)
);

INSERT INTO audit_log_new (id, ts, operator, action, target, mode, result, run_id)
    SELECT id, ts, operator, action, target, mode, result, run_id FROM audit_log;

DROP TABLE audit_log;
ALTER TABLE audit_log_new RENAME TO audit_log;
