"""
Pytest configuration and shared fixtures for tests.

Fixture functions are named after the resource they provide.
"""
import pytest
import json
import requests
import requests_mock as rm
from auth import KeycloakAuth
import settings
import os

# Default to what we have in docker-compose.dev.yml but allow overriding using TEST_ env vars.
settings.KEYCLOAK_URL = os.getenv("TEST_KEYCLOAK_URL", "http://localhost:8080")
settings.DB_HOST = os.getenv("TEST_DB_HOST", "localhost")
settings.DB_PORT = os.getenv("TEST_DB_PORT", 5434)
# Import only after overriding service urls
from app import app


@pytest.fixture
def requests_mock():
    """
    Custom requests_mock fixture configured to allow real HTTP for unmocked URLs.

    This allows Keycloak authentication requests to work with the real test service
    while mocking SONG API calls. Only explicitly registered URLs will be mocked;
    all other HTTP requests will pass through normally.
    """
    with rm.Mocker(real_http=True) as m:
        yield m


@pytest.fixture
def client():
    """Create a test client for the Flask app"""
    app.config['TESTING'] = True
    with app.test_client() as client:
        yield client


@pytest.fixture(scope="session", autouse=True)
def keycloak_auth():
    return KeycloakAuth(
        keycloak_url=settings.KEYCLOAK_URL,
        realm=settings.KEYCLOAK_REALM,
        client_id=settings.KEYCLOAK_CLIENT_ID,
        client_secret=settings.KEYCLOAK_CLIENT_SECRET,
    )


@pytest.fixture
def system_admin_token():
    """Get access token for system admin user"""
    return keycloak_password_auth('system.admin@agari.tech', 'pass123')


@pytest.fixture
def org1_admin_token():
    """Get access token for org admin user (org1)"""
    return keycloak_password_auth('org-admin@org1.ac.za', 'pass123')


def keycloak_password_auth(username, password):
    token_url = f"{settings.KEYCLOAK_URL}/realms/{settings.KEYCLOAK_REALM}/protocol/openid-connect/token"
    data = {
        'username': username,
        'password': password,
        'grant_type': 'password',
        'client_id': settings.KEYCLOAK_CLIENT_ID,
        'client_secret': settings.KEYCLOAK_CLIENT_SECRET
    }
    response = requests.post(token_url, data=data)
    assert response.status_code == 200, f"Failed to get user token: {response.text}"
    return response.json()['access_token']


@pytest.fixture
def pathogen(client, system_admin_token):
    """Create a test pathogen and clean it up after the test"""
    pathogen_data = {
        'name': 'Test Pathogen',
        'description': 'Test pathogen for testing',
        'scientific_name': 'Testus pathogenus'
    }
    response = client.post(
        '/pathogens/',
        data=json.dumps(pathogen_data),
        headers={
            'Authorization': f'Bearer {system_admin_token}',
            'Content-Type': 'application/json'
        }
    )
    assert response.status_code == 201, f"Failed to create pathogen: {response.get_json()}"
    pathogen = response.get_json()["pathogen"]
    pathogen_id = pathogen['id']

    yield pathogen

    # Cleanup: Delete the pathogen
    client.delete(
        f'/pathogens/{pathogen_id}?hard=true',
        headers={'Authorization': f'Bearer {system_admin_token}'}
    )


@pytest.fixture
def public_project1(client, org1_admin_token, pathogen):
    project = make_project(client, org1_admin_token, pathogen, name="Test Project 1")
    yield project

    # Cleanup: Delete the project
    client.delete(
        f'/projects/{project["id"]}?hard=true',
        headers={'Authorization': f'Bearer {org1_admin_token}'}
    )

@pytest.fixture
def public_project2(client, org1_admin_token, pathogen):
    project = make_project(client, org1_admin_token, pathogen, name="Test Project 2")
    yield project

    client.delete(
        f'/projects/{project["id"]}?hard=true',
        headers={'Authorization': f'Bearer {org1_admin_token}'}
    )
    # Cleanup: Delete the project


# TODO: Move this to a data layer
def make_project(client, org1_admin_token, pathogen, name):
    """Create a test project with public privacy and clean it up after the test"""
    project_data = {
        'name': name,
        'description': 'Test project for testing',
        'pathogen_id': pathogen['id'],
        'privacy': 'public'
    }
    response = client.post(
        '/projects/',
        data=json.dumps(project_data),
        headers={
            'Authorization': f'Bearer {org1_admin_token}',
            'Content-Type': 'application/json'
        }
    )
    assert response.status_code == 201, f"Failed to create project: {response.get_json()}"
    return response.get_json()["project"] 
