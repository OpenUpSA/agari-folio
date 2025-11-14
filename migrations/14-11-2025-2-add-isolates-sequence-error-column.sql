-- Migration: Add seq_error column to isolates table

ALTER TABLE isolates 
ADD COLUMN seq_error JSONB NULL;