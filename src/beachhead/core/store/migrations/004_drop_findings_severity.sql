-- Remove the severity column from findings.  Uses the table-rebuild
-- pattern so it works whether the column is present or not (the DDL
-- in 002 was edited mid-development).

CREATE TABLE findings_new (
    id           TEXT PRIMARY KEY,
    kind         TEXT NOT NULL,
    resource_id  TEXT,
    reference    TEXT NOT NULL,
    redacted     INTEGER NOT NULL DEFAULT 0,
    details_json TEXT NOT NULL DEFAULT '{}',
    run_id       TEXT NOT NULL REFERENCES runs(id),
    collected_at TEXT NOT NULL
);

INSERT INTO findings_new (id, kind, resource_id, reference, redacted,
                          details_json, run_id, collected_at)
SELECT id, kind, resource_id, reference, redacted,
       details_json, run_id, collected_at
FROM findings;

DROP TABLE findings;
ALTER TABLE findings_new RENAME TO findings;

CREATE UNIQUE INDEX IF NOT EXISTS uix_findings_natural
    ON findings (kind, COALESCE(resource_id, ''), reference);
