import pytest
import settings

settings.DB_NAME = 'folio_test'
settings.DB_PORT = '5435'
settings.DB_HOST = 'localhost'
settings.DB_USER = 'admin'
settings.DB_PASSWORD = 'folio-db-pass-123'

# Import app after overriding settings
from app import app


@pytest.fixture
def client():
    """Create a test client for the Flask app"""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client
