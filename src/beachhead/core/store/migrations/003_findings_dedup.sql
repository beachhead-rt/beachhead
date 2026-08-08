-- Deduplicate existing findings rows, keeping the most recent per
-- (kind, resource_id, reference) triple, then add a unique index so
-- re-runs upsert instead of inserting duplicates.

DELETE FROM findings
WHERE id NOT IN (
    SELECT id FROM (
        SELECT id,
               ROW_NUMBER() OVER (
                   PARTITION BY kind, COALESCE(resource_id, ''), reference
                   ORDER BY collected_at DESC
               ) AS rn
        FROM findings
    )
    WHERE rn = 1
);

CREATE UNIQUE INDEX IF NOT EXISTS uix_findings_natural
    ON findings (kind, COALESCE(resource_id, ''), reference);
