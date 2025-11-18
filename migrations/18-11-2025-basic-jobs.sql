-- Simple job queue table
-- Date: 18-11-2025

-- Job status enum
CREATE TYPE job_status AS ENUM ('pending', 'in_progress', 'done', 'failed');

-- Simple Job table
CREATE TABLE jobs (
    id SERIAL PRIMARY KEY,
    status job_status NOT NULL DEFAULT 'pending',
    payload JSONB,
    retry_count INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT now(),
    updated_at TIMESTAMP DEFAULT now()
);

-- Simple index for finding pending jobs
CREATE INDEX idx_jobs_pending ON jobs(status, created_at) WHERE status = 'pending';

-- Comment
COMMENT ON TABLE jobs IS 'Basic job queue - starting simple';