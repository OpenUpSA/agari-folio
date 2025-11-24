#!/bin/bash
set -euo pipefail

DB_USER="${DB_USER:-admin}"
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-5434}"
DB_NAME="${DB_NAME:-folio}"
export PGPASSWORD="${DB_PASSWORD:-folio-db-pass-123}"

FILES=(
    "migrations/06-11-25-add-schema-and-version-to-pathogens.sql"
    "migrations/13-11-2025-submission-workflow-updates.sql"
    "migrations/14-11-2025-isolates-table.sql"
    "migrations/14-11-2025-2-add-isolates-sequence-error-column.sql"
    "migrations/14-11-2025-3-submissions-table-work.sql"
    "migrations/15-11-2025-add-back-isolate-id-column.sql"
    "migrations/16-11-2025-schemas-table.sql"
    "migrations/16-11-2025-2-drop-submission-log-table.sql"
    "migrations/16-11-2025-3-remove-schema-name-column-from-pathogen-table.sql"
    "migrations/18-11-2025-basic-jobs.sql"
)

for file in "${FILES[@]}"; do
    echo "Running $file..."
    psql -U "$DB_USER" -h "$DB_HOST" -p "$DB_PORT" -d "$DB_NAME" < "$file"
done

