-- Add error and status columns to isolates table
ALTER TABLE isolates 
ADD COLUMN error JSONB,
ADD COLUMN status VARCHAR(50);

