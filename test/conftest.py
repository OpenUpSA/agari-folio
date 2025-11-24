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

def keycloak_set_user_password(user_id, new_password, keycloak_auth):
    reset_url = f"{settings.KEYCLOAK_URL}/admin/realms/{settings.KEYCLOAK_REALM}/users/{user_id}/reset-password"
    payload = {
        "type": "password",
        "value": new_password,
        "temporary": False
    }
    response = requests.put(
        reset_url,
        data=json.dumps(payload),
        headers={
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {keycloak_auth.get_admin_token()}'
        }
    )
    assert response.status_code == 204, f"Failed to reset user password: {response.text}"
    


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
def system_admin_token():
    """Get access token for system admin user"""
    return keycloak_password_auth('system.admin@agari.tech', 'pass123')

@pytest.fixture
def org1(client, system_admin_token):
    """Create a test organisation (org1) and clean it up after the test"""
    org_data = {
        'name': 'Test Organisation 1',
        'description': 'Test organisation for testing'
    }
    
    organization = get_org_by_name(client, system_admin_token, org_data['name'])
    
    if not organization:
        response = client.post(
            '/organisations/',
            data=json.dumps(org_data),
            headers={
                'Authorization': f'Bearer {system_admin_token}',
                'Content-Type': 'application/json'
            }
        )
        assert response.status_code == 201, f"Failed to create organization: {response.get_json()}"
        organization = response.get_json()["organisation"]

    organization_id = organization['id']
    yield organization

    # Cleanup: Delete the organization
    client.delete(
        f'/organisations/{organization_id}?hard=true',
        headers={'Authorization': f'Bearer {system_admin_token}'}
    )

@pytest.fixture
def org2(client, system_admin_token):
    """Create a test organisation (org2) and clean it up after the test"""
    org_data = {
        'name': 'Test Organisation 2',
        'description': 'Test organisation for testing'
    }
    
    organization = get_org_by_name(client, system_admin_token, org_data['name'])
    
    if not organization:
        response = client.post(
            '/organisations/',
            data=json.dumps(org_data),
            headers={
                'Authorization': f'Bearer {system_admin_token}',
                'Content-Type': 'application/json'
            }
        )
        assert response.status_code == 201, f"Failed to create organization: {response.get_json()}"
        organization = response.get_json()["organisation"]

    organization_id = organization['id']
    yield organization

    # Cleanup: Delete the organization
    client.delete(
        f'/organisations/{organization_id}?hard=true',
        headers={'Authorization': f'Bearer {system_admin_token}'}
    )
    
@pytest.fixture
def org1_admin(client, org1, system_admin_token, keycloak_auth):
    """Create an org1 admin user and clean up after the test"""
    user_data = {
        'username': 'org-admin@org1.ac.za',
        'password': 'pass123',
        'first_name': 'Org',
        'last_name': 'Admin',
        'email': 'org-admin@org1.ac.za'
    }
    user = create_user_if_not_exists(client, system_admin_token, keycloak_auth, **user_data)

    # Add user to org1 with admin role using force_role
    response = client.post(
        f'/organisations/{org1["id"]}/members',
        data=json.dumps({'user_id': user['user_id'], 'role': 'org-admin', 'force_role': True}),
        headers={
            'Authorization': f'Bearer {system_admin_token}',
            'Content-Type': 'application/json'
        }
    )
    print("TESTME: ", response.get_json())
    assert response.status_code == 200, f"Failed to add org1 admin user: {response.get_json()}"

    yield user

    # Cleanup: Delete the user
    client.delete(
        f'/users/{user["user_id"]}?hard=true',
        headers={'Authorization': f'Bearer {system_admin_token}'}
    )

@pytest.fixture 
def org1_admin_token(org1_admin):
    """Get an auth token for the org1 admin user"""
    return keycloak_password_auth(org1_admin["email"], 'pass123')

@pytest.fixture
def org2_admin(client, org2, system_admin_token, keycloak_auth):
    """Create an org2 admin user and clean up after the test"""
    user_data = {
        'username': 'org-admin@org2.ac.za',
        'password': 'pass123',
        'first_name': 'Org',
        'last_name': 'Admin',
        'email': 'org-admin@org2.ac.za'
    }
    user = create_user_if_not_exists(client, system_admin_token, keycloak_auth, **user_data)

    # Add user to org2 with admin role using force_role
    response = client.post(
        f'/organisations/{org2["id"]}/members',
        data=json.dumps({'user_id': user['user_id'], 'role': 'org-admin', 'force_role': True}),
        headers={
            'Authorization': f'Bearer {system_admin_token}',
            'Content-Type': 'application/json'
        }
    )
    assert response.status_code == 200, f"Failed to add org2 admin user: {response.get_json()}"

    yield user

    # Cleanup: Delete the user
    client.delete(
        f'/users/{user["user_id"]}?hard=true',
        headers={'Authorization': f'Bearer {system_admin_token}'}
    )

@pytest.fixture
def org2_admin_token(org2_admin):
    """Get an auth token for the org2 admin user"""
    return keycloak_password_auth(org2_admin["email"], 'pass123')

@pytest.fixture
def org1_owner(client, org1, system_admin_token, keycloak_auth):
    """Create an org1 owner user and clean up after the test"""
    user_data = {
        'username': 'org-owner@org1.ac.za',
        'password': 'pass123',
        'first_name': 'Org',
        'last_name': 'Owner',
        'email': 'org-owner@org1.ac.za'
    }
    user = create_user_if_not_exists(client, system_admin_token, keycloak_auth, **user_data)

    # Add user to org1 with owner role using force_role
    response = client.post(
        f'/organisations/{org1["id"]}/members',
        data=json.dumps({'user_id': user['user_id'], 'role': 'org-owner', 'force_role': True}),
        headers={
            'Authorization': f'Bearer {system_admin_token}',
            'Content-Type': 'application/json'
        }
    )
    assert response.status_code == 200, f"Failed to add org1 owner user: {response.get_json()}"

    yield user

    # Cleanup: Delete the user
    client.delete(
        f'/users/{user["user_id"]}?hard=true',
        headers={'Authorization': f'Bearer {system_admin_token}'}
    )

@pytest.fixture
def org1_owner_token(org1_owner):
    """Get an auth token for the org1 owner user"""
    return keycloak_password_auth(org1_owner["email"], 'pass123')

@pytest.fixture
def org2_owner(client, org2, system_admin_token, keycloak_auth):
    """Create an org2 owner user and clean up after the test"""
    user_data = {
        'username': 'org-owner@org2.ac.za',
        'password': 'pass123',
        'first_name': 'Org',
        'last_name': 'Owner',
        'email': 'org-owner@org2.ac.za'
    }
    user = create_user_if_not_exists(client, system_admin_token, keycloak_auth, **user_data)

    # Add user to org2 with owner role using force_role
    response = client.post(
        f'/organisations/{org2["id"]}/members',
        data=json.dumps({'user_id': user['user_id'], 'role': 'org-owner', 'force_role': True}),
        headers={
            'Authorization': f'Bearer {system_admin_token}',
            'Content-Type': 'application/json'
        }
    )
    assert response.status_code == 200, f"Failed to add org2 owner user: {response.get_json()}"

    yield user

    # Cleanup: Delete the user
    client.delete(
        f'/users/{user["user_id"]}?hard=true',
        headers={'Authorization': f'Bearer {system_admin_token}'}
    )

@pytest.fixture
def org2_owner_token(org2_owner):
    """Get an auth token for the org2 owner user"""
    return keycloak_password_auth(org2_owner["email"], 'pass123')
    
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


def get_org_by_name(client, system_admin_token, org_name):
    """Get organisation details by name"""
    response = client.get(
        '/organisations/',
        headers={
            'Authorization': f'Bearer {system_admin_token}',
            'Content-Type': 'application/json'
        }
    )
    assert response.status_code == 200, f"Failed to get organisations: {response.get_json()}"
    orgs = response.get_json()
    for org in orgs:
        if org['name'] == org_name:
            return org
    return None

def create_user_if_not_exists(client, system_admin_token, keycloak_auth, **kwargs):
    """Create a user if they do not already exist"""
    users = keycloak_auth.get_users_by_attribute('email', kwargs.get('email'), exact_match=True)
    if users:
        return {'user_id': users[0]['id'], **kwargs}
    response = client.post(
        '/users/',
        data=json.dumps({'redirect_uri': 'http://example.com', **kwargs}),
        headers={
            'Authorization': f'Bearer {system_admin_token}',
            'Content-Type': 'application/json'
        }
    )
    user_id = response.get_json()["user_id"]
        
    keycloak_set_user_password(user_id, 'pass123', keycloak_auth)
    keycloak_auth.toggle_user_enabled(user_id, True)

    assert response.status_code == 200, f"Failed to create user: {response.get_json()}"
    return {'user_id': user_id, **kwargs}