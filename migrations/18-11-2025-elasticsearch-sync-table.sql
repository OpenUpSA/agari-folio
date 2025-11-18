CREATE TABLE IF NOT EXISTS elasticsearch_sync (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    isolate_id UUID NOT NULL REFERENCES isolates(id) ON DELETE CASCADE,
    isolate_version_hash VARCHAR(64) NOT NULL,
    index_status VARCHAR(20) NOT NULL DEFAULT 'pending', 
    -- 'pending', 'indexed', 'failed', 'stale'
    indexed_at TIMESTAMP,
    error_message TEXT,
    retry_count INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_es_sync_isolate ON elasticsearch_sync(isolate_id);
CREATE INDEX IF NOT EXISTS idx_es_sync_status ON elasticsearch_sync(index_status);
CREATE INDEX IF NOT EXISTS idx_es_sync_stale ON elasticsearch_sync(isolate_id, isolate_version_hash);

-- Unique constraint to prevent duplicate tracking
CREATE UNIQUE INDEX IF NOT EXISTS idx_es_sync_isolate_unique ON elasticsearch_sync(isolate_id);

-- Comments
COMMENT ON TABLE elasticsearch_sync IS 'Tracks Elasticsearch indexing status for isolates';
COMMENT ON COLUMN elasticsearch_sync.isolate_version_hash IS 'SHA256 hash of isolate data when marked for indexing';
COMMENT ON COLUMN elasticsearch_sync.index_status IS 'pending=needs indexing, indexed=successfully indexed, failed=indexing failed, stale=isolate changed since indexing';