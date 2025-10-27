-- Create templates table
CREATE TABLE IF NOT EXISTS templates (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    pathogen_id UUID NOT NULL REFERENCES pathogens(id) ON DELETE CASCADE,
    schema_version INTEGER NOT NULL,
    minio_object_id VARCHAR(255) NOT NULL,
    filename VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP WITH TIME ZONE NULL,
    UNIQUE(pathogen_id, schema_version)
);


CREATE INDEX IF NOT EXISTS idx_templates_pathogen ON templates(pathogen_id);
CREATE INDEX IF NOT EXISTS idx_templates_schema_version ON templates(schema_version);


CREATE TRIGGER update_templates_updated_at
    BEFORE UPDATE ON templates
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();


COMMENT ON TABLE templates IS 'Templates table containing spreadsheet template files for data preparation';
