-- Migration: Remove schema column and update schema_version to UUID foreign key
-- Date: 16-11-2025

BEGIN;

-- First, add the new schema_id column as UUID
ALTER TABLE pathogens 
ADD COLUMN schema_id UUID;

-- Update the schema_id with values from the schemas table
-- This assumes there's a mapping between the old schema column and schema names/versions
UPDATE pathogens 
SET schema_id = s.id 
FROM schemas s 
WHERE pathogens.schema_version = s.version;

-- Drop the old schema column
ALTER TABLE pathogens 
DROP COLUMN schema;

-- Drop the old schema_version column
ALTER TABLE pathogens 
DROP COLUMN schema_version;

-- Add foreign key constraint
ALTER TABLE pathogens 
ADD CONSTRAINT fk_pathogen_schema 
FOREIGN KEY (schema_id) REFERENCES schemas(id);

COMMIT;