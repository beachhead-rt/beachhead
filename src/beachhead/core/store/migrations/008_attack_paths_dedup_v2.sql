-- Tighten attack_paths uniqueness to (source_id, target_id) so re-runs
-- with different descriptions (e.g. admin status change) replace instead
-- of creating duplicates.  Keep the most recent row per pair.

DROP INDEX IF EXISTS uix_attack_paths_natural;

DELETE FROM attack_paths
WHERE id NOT IN (
    SELECT id FROM (
        SELECT id,
               ROW_NUMBER() OVER (
                   PARTITION BY source_id, target_id
                   ORDER BY collected_at DESC
               ) AS rn
        FROM attack_paths
    )
    WHERE rn = 1
);

CREATE UNIQUE INDEX IF NOT EXISTS uix_attack_paths_src_tgt
    ON attack_paths (source_id, target_id);
