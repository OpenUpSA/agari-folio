#!/bin/bash

DB_USER="${DB_USER:-admin}"
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5434}"
DB_NAME="${DB_NAME:-folio}"
export PGPASSWORD="${DB_PASSWORD:-folio-db-pass-123}"

FILES=(
    "migrations/06-11-25-add-schema-and-version-to-pathogens.sql"
    "migrations/13-11-2025-submission-workflow-updates.sql"
    "migrations/14-11-2025-isolates-table.sql"
)

for file in "${FILES[@]}"; do
    echo "Running $file..."
    psql -U "$DB_USER" -h "$DB_HOST" -p "$DB_PORT" -d "$DB_NAME" < "$file"
done