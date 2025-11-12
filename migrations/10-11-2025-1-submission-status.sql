-- Add status column to submissions table
ALTER TABLE submissions 
ADD COLUMN status VARCHAR(50) DEFAULT 'draft';

-- Add index for better performance
CREATE INDEX IF NOT EXISTS idx_submissions_status ON submissions(status);