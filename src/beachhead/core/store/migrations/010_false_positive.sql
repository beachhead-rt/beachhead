-- Add false_positive flag to findings and attack_paths tables.
-- Operator triage decisions: marked items are hidden from default views
-- but preserved for audit trail and optional display.

ALTER TABLE findings ADD COLUMN false_positive INTEGER NOT NULL DEFAULT 0;
ALTER TABLE attack_paths ADD COLUMN false_positive INTEGER NOT NULL DEFAULT 0;
