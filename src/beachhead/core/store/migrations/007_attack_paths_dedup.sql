-- Deduplicate existing attack_paths rows, keeping the most recent per
-- (source_id, target_id, description) triple, then add a unique index so
-- re-runs upsert instead of inserting duplicates.

DELETE FROM attack_paths
WHERE id NOT IN (
    SELECT id FROM (
        SELECT id,
               ROW_NUMBER() OVER (
                   PARTITION BY source_id, target_id, description
                   ORDER BY collected_at DESC
               ) AS rn
        FROM attack_paths
    )
    WHERE rn = 1
);

CREATE UNIQUE INDEX IF NOT EXISTS uix_attack_paths_natural
    ON attack_paths (source_id, target_id, description);
