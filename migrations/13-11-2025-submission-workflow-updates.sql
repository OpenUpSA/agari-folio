-- Migration: Submission workflow updates
-- Date: 13-11-2025

-- ================================
-- 1. Add status and error columns to submissions table
-- ================================
ALTER TABLE submissions 
ADD COLUMN IF NOT EXISTS status VARCHAR(50) DEFAULT 'draft',
ADD COLUMN IF NOT EXISTS error JSONB;

-- Add index for better performance
CREATE INDEX IF NOT EXISTS idx_submissions_status ON submissions(status);

-- ================================
-- 2. Create isolates table
-- ================================
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

-- ================================
-- 3. Create submission_files table
-- ================================
CREATE TABLE IF NOT EXISTS submission_files (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    submission_id UUID NOT NULL REFERENCES submissions(id) ON DELETE CASCADE,
    isolate_id UUID REFERENCES isolates(id) ON DELETE SET NULL,
    filename VARCHAR(255) NOT NULL,
    file_type VARCHAR(50) NOT NULL CHECK (file_type IN ('tsv', 'fasta')),
    object_id UUID,
    file_size BIGINT,
    md5_hash VARCHAR(32),
    is_split BOOLEAN DEFAULT FALSE,
    parent_file_id UUID REFERENCES submission_files(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_submission_files_submission ON submission_files(submission_id);
CREATE INDEX IF NOT EXISTS idx_submission_files_type ON submission_files(file_type);
CREATE INDEX IF NOT EXISTS idx_submission_files_isolate ON submission_files(isolate_id);
CREATE INDEX IF NOT EXISTS idx_submission_files_object ON submission_files(object_id);

-- ================================
-- Documentation Comments
-- ================================

-- Submissions table comments
COMMENT ON COLUMN submissions.status IS 'Current status of the submission (draft, validated, error, finalised, published)';

-- Isolates table comments
COMMENT ON TABLE isolates IS 'Stores individual isolate data linked to submissions and FASTA files';
COMMENT ON COLUMN isolates.id IS 'Primary key UUID';
COMMENT ON COLUMN isolates.submission_id IS 'Foreign key to submissions table';
COMMENT ON COLUMN isolates.isolate_id IS 'Identifier for the isolate (e.g., sample_id from TSV)';
COMMENT ON COLUMN isolates.object_id IS 'UUID reference to the FASTA file object in MinIO storage';
COMMENT ON COLUMN isolates.isolate_data IS 'JSONB column containing isolate metadata and analysis data';

-- Submission files table comments
COMMENT ON TABLE submission_files IS 'Tracks uploaded files associated with submissions and isolates';
COMMENT ON COLUMN submission_files.id IS 'Primary key UUID';
COMMENT ON COLUMN submission_files.submission_id IS 'Foreign key to submissions table';
COMMENT ON COLUMN submission_files.isolate_id IS 'Foreign key to isolates table (optional)';
COMMENT ON COLUMN submission_files.filename IS 'Original filename of the uploaded file';
COMMENT ON COLUMN submission_files.file_type IS 'Type of file (tsv or fasta)';
COMMENT ON COLUMN submission_files.object_id IS 'UUID reference to the file object in MinIO storage';
COMMENT ON COLUMN submission_files.file_size IS 'Size of the file in bytes';
COMMENT ON COLUMN submission_files.md5_hash IS 'MD5 hash of the file content for integrity checking';
COMMENT ON COLUMN submission_files.is_split IS 'Whether this file was created by splitting a larger file';
COMMENT ON COLUMN submission_files.parent_file_id IS 'Reference to the original file if this is a split file';
