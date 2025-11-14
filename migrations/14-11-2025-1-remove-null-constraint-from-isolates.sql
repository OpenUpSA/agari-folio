-- Remove null constraint from isolate_id column

ALTER TABLE isolates 
ALTER COLUMN isolate_id DROP NOT NULL;