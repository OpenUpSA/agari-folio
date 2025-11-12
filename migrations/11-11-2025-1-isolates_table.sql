-- Migration: Create isolates table
-- Date: 2025-11-11
-- Description: Create table to store isolate data linked to submissions and FASTA files

CREATE TABLE IF NOT EXISTS isolates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    submission_id UUID NOT NULL REFERENCES submissions(id) ON DELETE CASCADE,
    isolate_id VARCHAR(255) NOT NULL,
    object_id UUID,
    isolate_data JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE NULL
);

-- Create indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_isolates_submission_id ON isolates(submission_id);
CREATE INDEX IF NOT EXISTS idx_isolates_isolate_id ON isolates(isolate_id);
CREATE INDEX IF NOT EXISTS idx_isolates_object_id ON isolates(object_id);

-- Create unique constraint on submission_id + isolate_id to prevent duplicates
CREATE UNIQUE INDEX IF NOT EXISTS idx_isolates_submission_isolate_unique 
ON isolates(submission_id, isolate_id);

-- Add GIN index for JSONB data column for efficient JSON queries
CREATE INDEX IF NOT EXISTS idx_isolates_data_gin ON isolates USING GIN (isolate_data);

-- Create trigger to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_isolates_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trigger_isolates_updated_at
    BEFORE UPDATE ON isolates
    FOR EACH ROW
    EXECUTE FUNCTION update_isolates_updated_at();

-- Add comments for documentation
COMMENT ON TABLE isolates IS 'Stores individual isolate data linked to submissions and FASTA files';
COMMENT ON COLUMN isolates.id IS 'Primary key UUID';
COMMENT ON COLUMN isolates.submission_id IS 'Foreign key to submissions table';
COMMENT ON COLUMN isolates.isolate_id IS 'Identifier for the isolate (e.g., sample_id from TSV)';
COMMENT ON COLUMN isolates.object_id IS 'UUID reference to the FASTA file object in MinIO storage';
COMMENT ON COLUMN isolates.isolate_data IS 'JSONB column containing isolate metadata and analysis data';
COMMENT ON COLUMN isolates.created_at IS 'Timestamp when isolate record was created';
COMMENT ON COLUMN isolates.updated_at IS 'Timestamp when isolate record was last updated';
COMMENT ON COLUMN isolates.deleted_at IS 'Timestamp when isolate record was soft-deleted';