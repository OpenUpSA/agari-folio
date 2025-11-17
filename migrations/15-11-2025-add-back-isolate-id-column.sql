-- Add isolate_id column to isolates table
ALTER TABLE isolates 
ADD COLUMN isolate_id UUID;
