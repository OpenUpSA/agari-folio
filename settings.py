"""
Centralized configuration settings for the Folio application.
All environment variables should be read here and imported by other modules.
"""
import os

# Database Configuration
DB_HOST = os.getenv('DB_HOST', 'localhost')
DB_PORT = os.getenv('DB_PORT', '5434')
DB_NAME = os.getenv('DB_NAME', 'folio')
DB_USER = os.getenv('DB_USER', 'admin')
DB_PASSWORD = os.getenv('DB_PASSWORD', 'folio-db-pass-123')

# Keycloak Configuration
KEYCLOAK_URL = os.getenv('KEYCLOAK_URL', 'http://keycloak.local')
KEYCLOAK_REALM = os.getenv('KEYCLOAK_REALM', 'agari')
KEYCLOAK_CLIENT_ID = os.getenv('KEYCLOAK_CLIENT_ID', 'dms')
KEYCLOAK_CLIENT_SECRET = os.getenv('KEYCLOAK_CLIENT_SECRET', 'VDyLEjGR3xDQvoQlrHq5AB6OwbW0Refc')

# Overture (SONG and SCORE) Configuration
OVERTURE_SONG = os.getenv('OVERTURE_SONG', 'http://song.local')
OVERTURE_SCORE = os.getenv('OVERTURE_SCORE', 'http://score.local')

# MinIO Configuration
MINIO_ENDPOINT = os.getenv('MINIO_ENDPOINT', 'localhost:9000')
MINIO_ACCESS_KEY = os.getenv('MINIO_ACCESS_KEY', 'admin')
MINIO_SECRET_KEY = os.getenv('MINIO_SECRET_KEY', 'admin123')
MINIO_BUCKET = os.getenv('MINIO_BUCKET', 'agari-data')
MINIO_SECURE = os.getenv('MINIO_SECURE', 'false').lower() == 'true'
MINIO_INTERNAL_SECURE = os.getenv('MINIO_INTERNAL_SECURE', 'false').lower() == 'true'
MINIO_FRONTEND_ENDPOINT = os.getenv('MINIO_FRONTEND_ENDPOINT', 'localhost:9000')

# Elasticsearch Configuration
ELASTICSEARCH_URL = os.getenv('ELASTICSEARCH_URL', 'http://localhost:9200')
ELASTICSEARCH_INDEX = os.getenv('ELASTICSEARCH_INDEX', 'agari-samples')

# SendGrid Configuration
SENDGRID_API_KEY = os.getenv('SENDGRID_API_KEY', '')
SENDGRID_FROM_EMAIL = os.getenv('SENDGRID_FROM_EMAIL', 'webapps+agaridev@openup.org.za')
SENDGRID_FROM_NAME = os.getenv('SENDGRID_FROM_NAME', 'AGARI')

# VALIDATION
ALLOW_DUPLICATE_ISOLATE_IDS = os.getenv('ALLOW_DUPLICATE_ISOLATE_IDS', 'true').lower() == 'true'
REQUIRE_FASTA_FILE = os.getenv('REQUIRE_FASTA_FILE', 'false').lower() == 'true'

# Application Configuration
PORT = int(os.getenv('PORT', 8000))
