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

# Elasticsearch Configuration
ELASTICSEARCH_URL = os.getenv('ELASTICSEARCH_URL', 'http://localhost:9200')

# SendGrid Configuration
SENDGRID_API_KEY = os.getenv('SENDGRID_API_KEY', '')
SENDGRID_FROM_EMAIL = os.getenv('SENDGRID_FROM_EMAIL', 'webapps+agaridev@openup.org.za')
SENDGRID_FROM_NAME = os.getenv('SENDGRID_FROM_NAME', 'AGARI')

# Application Configuration
PORT = int(os.getenv('PORT', 8000))
