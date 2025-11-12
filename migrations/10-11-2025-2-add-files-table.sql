-- Create submission_files table for tracking uploaded files
CREATE TABLE IF NOT EXISTS submission_files (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
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

CREATE INDEX IF NOT EXISTS idx_submission_files_submission ON submission_files(submission_id);
CREATE INDEX IF NOT EXISTS idx_submission_files_type ON submission_files(file_type);