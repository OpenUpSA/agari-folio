#!/usr/bin/env python3
import os
import sys
import psycopg2
from pathlib import Path


def get_db_config():
    """Get database configuration from environment variables."""
    return {
        "user": os.getenv("DB_USER", "admin"),
        "host": os.getenv("DB_HOST", "localhost"),
        "port": os.getenv("DB_PORT", "5434"),
        "database": os.getenv("DB_NAME", "folio"),
        "password": os.getenv("DB_PASSWORD", "folio-db-pass-123"),
    }


def run_migration(conn, file_path):
    """Run a single migration file."""
    print(f"Running {file_path}...")

    try:
        with open(file_path, "r") as f:
            sql = f.read()

        with conn.cursor() as cursor:
            cursor.execute(sql)

        conn.commit()
        print(f"✓ Successfully executed {file_path}")
        return True

    except FileNotFoundError:
        print(f"✗ Error: File not found: {file_path}")
        return False
    except psycopg2.Error as e:
        print(f"✗ Database error in {file_path}: {e}")
        conn.rollback()
        return False
    except Exception as e:
        print(f"✗ Unexpected error in {file_path}: {e}")
        conn.rollback()
        return False


def main():
    """Run all migrations."""
    files = [
        "migrations/06-11-25-add-schema-and-version-to-pathogens.sql",
        "migrations/13-11-2025-submission-workflow-updates.sql",
        "migrations/14-11-2025-isolates-table.sql",
    ]

    db_config = get_db_config()

    try:
        # Connect to database
        print(
            f"Connecting to database {db_config['database']} at {db_config['host']}:{db_config['port']}..."
        )
        conn = psycopg2.connect(**db_config)
        print("✓ Connected successfully\n")

        # Run migrations
        success_count = 0
        for file_path in files:
            if run_migration(conn, file_path):
                success_count += 1
            print()  # Empty line between migrations

        # Summary
        total = len(files)
        print(f"\nMigration Summary: {success_count}/{total} successful")

        conn.close()

        # Exit with error code if any migration failed
        sys.exit(0 if success_count == total else 1)

    except psycopg2.OperationalError as e:
        print(f"✗ Failed to connect to database: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
