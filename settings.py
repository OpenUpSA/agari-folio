"""
Application settings and configuration.
All environment variables are centralized here.
"""

import os
from dotenv import load_dotenv

# Load environment variables from .env file if it exists
load_dotenv()

# Server configuration
PORT = int(os.getenv('PORT', '8000'))

# Database configuration
DB_HOST = os.getenv('FOLIO_DB_HOST', os.getenv('DB_HOST', 'localhost'))
DB_PORT = os.getenv('FOLIO_DB_PORT', os.getenv('DB_PORT', '5434'))
DB_NAME = os.getenv('FOLIO_DB_NAME', os.getenv('DB_NAME', 'folio'))
DB_USER = os.getenv('FOLIO_DB_USER', os.getenv('DB_USER', 'admin'))
DB_PASSWORD = os.getenv('FOLIO_DB_PASSWORD', os.getenv('DB_PASSWORD', 'folio-db-pass-123'))

# Keycloak authentication configuration
KEYCLOAK_URL = os.getenv('KEYCLOAK_URL', 'http://keycloak.local')
KEYCLOAK_HOST = os.getenv('KEYCLOAK_HOST', KEYCLOAK_URL)  # Alias for backwards compatibility
KEYCLOAK_REALM = os.getenv('KEYCLOAK_REALM', 'agari')
KEYCLOAK_CLIENT_ID = os.getenv('KEYCLOAK_CLIENT_ID', 'dms')
KEYCLOAK_CLIENT_SECRET = os.getenv('KEYCLOAK_CLIENT_SECRET', 'VDyLEjGR3xDQvoQlrHq5AB6OwbW0Refc')
KEYCLOAK_ISSUER = os.getenv('KEYCLOAK_ISSUER', f'{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}')

# Overture stack services configuration
OVERTURE_SONG_URL = os.getenv('OVERTURE_SONG', 'http://song.local')
OVERTURE_SCORE_URL = os.getenv('OVERTURE_SCORE', 'http://score.local')

# MinIO configuration
MINIO_ENDPOINT = os.getenv('MINIO_ENDPOINT', 'http://minio:9000')
MINIO_ACCESS_KEY = os.getenv('MINIO_ACCESS_KEY', 'admin')
MINIO_SECRET_KEY = os.getenv('MINIO_SECRET_KEY', 'admin123')
MINIO_SECURED = os.getenv('MINIO_SECURED', 'false').lower() == 'true'
MINIO_BUCKET = os.getenv('MINIO_BUCKET', 'folio')

# Helper to get clean MinIO endpoint (without http:// or https://)
MINIO_ENDPOINT_CLEAN = MINIO_ENDPOINT.replace('http://', '').replace('https://', '')
