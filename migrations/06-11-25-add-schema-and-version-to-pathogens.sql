-- Migration: Add schema and schema_version columns to pathogens table
-- Date: 2025-11-06

ALTER TABLE pathogens 
ADD COLUMN IF NOT EXISTS schema VARCHAR(255) NULL;

ALTER TABLE pathogens 
ADD COLUMN IF NOT EXISTS schema_version INT NULL;

CREATE INDEX IF NOT EXISTS idx_pathogens_schema_version ON pathogens(schema_version);