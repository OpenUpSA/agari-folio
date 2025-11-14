-- Migration: Remove study_id and analysis_id, add user_id as UUID

ALTER TABLE submissions 
DROP COLUMN IF EXISTS study_id,
DROP COLUMN IF EXISTS analysis_id,
ADD COLUMN user_id UUID;

