-- Isolates table modifications for November 14, 2025

-- drop isolate_id column
ALTER TABLE isolates 
DROP COLUMN isolate_id;

-- Add row number column to track TSV row position
ALTER TABLE isolates 
ADD COLUMN tsv_row INT;

-- Add error and status columns for validation tracking
ALTER TABLE isolates 
ADD COLUMN error JSONB,
ADD COLUMN status VARCHAR(50);