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

# Fix Flask-RESTX JSON encoder configuration for testing
# The 'cls' parameter is not valid in newer Flask versions, use 'default' instead
if 'RESTX_JSON' in app.config and 'cls' in app.config['RESTX_JSON']:
    encoder_cls = app.config['RESTX_JSON']['cls']
    app.config['RESTX_JSON'] = {'default': encoder_cls().default}


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
        "name": "Test Pathogen",
        "description": "Test pathogen for testing",
        "scientific_name": "Testus pathogenus",
    }

    # Check if pathogen already exists
    existing_pathogen = get_pathogen_by_name(
        client, system_admin_token, pathogen_data["name"]
    )

    if existing_pathogen:
        pathogen = existing_pathogen
    else:
        response = client.post(
            "/pathogens/",
            data=json.dumps(pathogen_data),
            headers={
                "Authorization": f"Bearer {system_admin_token}",
                "Content-Type": "application/json",
            },
        )
        assert response.status_code == 201, (
            f"Failed to create pathogen: {response.get_json()}"
        )
        pathogen = response.get_json()["pathogen"]

    pathogen_id = pathogen["id"]

    yield pathogen

    # Cleanup: Delete the pathogen and schemas attached to it
    try:
        client.delete(
            f"/pathogens/{pathogen_id}?hard=true",
            headers={"Authorization": f"Bearer {system_admin_token}"},
        )
    except Exception as e:
        print(f"Error cleaning up pathogen {pathogen_id}: {e}")

@pytest.fixture
def pathogen_with_schema(client, system_admin_token, pathogen):
    """Create a test pathogen with schema assigned for e2e testing"""
    from io import BytesIO

    # First, create a minimal schema
    schema_data = {
        "name": "e2e_test_schema",
        "pathogen_id": pathogen["id"],
        "description": "E2E test schema",
        "version": 1,
        "schema": {
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object",
            "properties": {
                "isolate_id": {
                    "type": "string",
                    "description": "Unique isolate identifier",
                },
                "n50": {"type": ["string", "number"], "description": "N50 value"},
                "serogroup": {
                    "type": "string",
                    "description": "Serogroup classification",
                },
            },
            "required": ["isolate_id"],
        },
    }

    # Create a dummy JSON file for the schema
    schema_file = BytesIO(json.dumps(schema_data["schema"]).encode("utf-8"))

    # Create schema via API
    schema_response = client.post(
        "/schemas/",
        data={
            "metadata": json.dumps(schema_data),
            "file": (schema_file, "e2e_test_schema.json"),
        },
        headers={"Authorization": f"Bearer {system_admin_token}"},
        content_type="multipart/form-data",
    )
    assert schema_response.status_code == 201, (
        f"Failed to create schema: {schema_response.get_json() if schema_response.status_code != 308 else 'Got redirect (308)'}"
    )
    schema_id = schema_response.get_json()["schema"]["id"]

    # Update pathogen with schema_id
    pathogen_data = {
        "name": pathogen["name"],
        "description": pathogen["description"],
        "scientific_name": pathogen["scientific_name"],
        "schema_id": schema_id,
    }
    response = client.put(
        f"/pathogens/{pathogen['id']}",
        data=json.dumps(pathogen_data),
        headers={
            "Authorization": f"Bearer {system_admin_token}",
            "Content-Type": "application/json",
        },
    )
    assert response.status_code == 200, (
        f"Failed to update pathogen: {response.get_json()}"
    )
    updated_pathogen = response.get_json()["pathogen"]

    yield updated_pathogen

    # Cleanup: Delete the schema only (pathogen is cleaned up by the pathogen fixture)
    client.delete(
        f"/schemas/{schema_id}?hard=true",
        headers={"Authorization": f"Bearer {system_admin_token}"},
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


@pytest.fixture
def e2e_project(client, org1_admin_token, pathogen_with_schema):
    """Create a test project with schema-enabled pathogen for e2e testing"""
    project = make_project(
        client, org1_admin_token, pathogen_with_schema, name="E2E Test Project"
    )
    yield project

    # Cleanup: Delete the project
    client.delete(
        f"/projects/{project['id']}?hard=true",
        headers={"Authorization": f"Bearer {org1_admin_token}"},
    )


@pytest.fixture
def private_project(client, org1_admin_token, pathogen):
    """Create a private project"""
    project_data = {
        'name': 'Private Test Project',
        'description': 'Test private project',
        'pathogen_id': pathogen['id'],
        'privacy': 'private'
    }
    response = client.post(
        '/projects/',
        data=json.dumps(project_data),
        headers={
            'Authorization': f'Bearer {org1_admin_token}',
            'Content-Type': 'application/json'
        }
    )
    assert response.status_code == 201
    project = response.get_json()["project"]
    yield project

    client.delete(
        f'/projects/{project["id"]}?hard=true',
        headers={'Authorization': f'Bearer {org1_admin_token}'}
    )


@pytest.fixture
def semi_private_project(client, org1_admin_token, pathogen):
    """Create a semi-private project"""
    project_data = {
        'name': 'Semi-Private Test Project',
        'description': 'Test semi-private project',
        'pathogen_id': pathogen['id'],
        'privacy': 'semi-private'
    }
    response = client.post(
        '/projects/',
        data=json.dumps(project_data),
        headers={
            'Authorization': f'Bearer {org1_admin_token}',
            'Content-Type': 'application/json'
        }
    )
    assert response.status_code == 201
    project = response.get_json()["project"]
    yield project

    client.delete(
        f'/projects/{project["id"]}?hard=true',
        headers={'Authorization': f'Bearer {org1_admin_token}'}
    )


@pytest.fixture
def project_admin(client, system_admin_token, keycloak_auth):
    """Create a project admin user from org1"""
    user_data = {
        'username': 'project-admin@org1.ac.za',
        'password': 'pass123',
        'first_name': 'Project',
        'last_name': 'Admin',
        'email': 'project-admin@org1.ac.za'
    }
    user = create_user_if_not_exists(client, system_admin_token, keycloak_auth, **user_data)
    yield user

    client.delete(
        f'/users/{user["user_id"]}?hard=true',
        headers={'Authorization': f'Bearer {system_admin_token}'}
    )


@pytest.fixture
def project_admin_token(project_admin):
    """Get token for project admin"""
    return keycloak_password_auth(project_admin["email"], 'pass123')


@pytest.fixture
def project_contributor(client, system_admin_token, keycloak_auth):
    """Create a project contributor user from org1"""
    user_data = {
        'username': 'project-contributor@org1.ac.za',
        'password': 'pass123',
        'first_name': 'Project',
        'last_name': 'Contributor',
        'email': 'project-contributor@org1.ac.za'
    }
    user = create_user_if_not_exists(client, system_admin_token, keycloak_auth, **user_data)
    yield user

    client.delete(
        f'/users/{user["user_id"]}?hard=true',
        headers={'Authorization': f'Bearer {system_admin_token}'}
    )


@pytest.fixture
def project_contributor_token(project_contributor):
    """Get token for project contributor"""
    return keycloak_password_auth(project_contributor["email"], 'pass123')


@pytest.fixture
def project_viewer(client, system_admin_token, keycloak_auth):
    """Create a project viewer user from org1"""
    user_data = {
        'username': 'project-viewer@org1.ac.za',
        'password': 'pass123',
        'first_name': 'Project',
        'last_name': 'Viewer',
        'email': 'project-viewer@org1.ac.za'
    }
    user = create_user_if_not_exists(client, system_admin_token, keycloak_auth, **user_data)
    yield user

    client.delete(
        f'/users/{user["user_id"]}?hard=true',
        headers={'Authorization': f'Bearer {system_admin_token}'}
    )


@pytest.fixture
def project_viewer_token(project_viewer):
    """Get token for project viewer"""
    return keycloak_password_auth(project_viewer["email"], 'pass123')


@pytest.fixture
def external_user(client, system_admin_token, keycloak_auth):
    """Create an external user from org2 (not a project member)"""
    user_data = {
        'username': 'external-user@org2.ac.za',
        'password': 'pass123',
        'first_name': 'External',
        'last_name': 'User',
        'email': 'external-user@org2.ac.za'
    }
    user = create_user_if_not_exists(client, system_admin_token, keycloak_auth, **user_data)
    yield user

    client.delete(
        f'/users/{user["user_id"]}?hard=true',
        headers={'Authorization': f'Bearer {system_admin_token}'}
    )


@pytest.fixture
def external_user_token(external_user):
    """Get token for external user"""
    return keycloak_password_auth(external_user["email"], 'pass123')


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
    from database import get_db_cursor

    with get_db_cursor() as cursor:
        cursor.execute(
            """
            SELECT * FROM organisations WHERE name = %s AND deleted_at IS NULL
        """,
            (org_name,),
        )
        org = cursor.fetchone()
        return dict(org) if org else None


def get_pathogen_by_name(client, system_admin_token, pathogen_name):
    """Get pathogen details by name"""
    from database import get_db_cursor

    with get_db_cursor() as cursor:
        cursor.execute(
            """
            SELECT * FROM pathogens WHERE name = %s AND deleted_at IS NULL
        """,
            (pathogen_name,),
        )
        pathogen = cursor.fetchone()
        return dict(pathogen) if pathogen else None


def create_user_if_not_exists(client, system_admin_token, keycloak_auth, **kwargs):
    """Create a user if they do not already exist"""
    users = keycloak_auth.get_users_by_attribute('email', kwargs.get('email'), exact_match=True)
    if users:
        user_id = users[0]["id"]
        # Ensure password and enabled state for existing users too
        keycloak_set_user_password(user_id, "pass123", keycloak_auth)
        keycloak_auth.toggle_user_enabled(user_id, True)
        return {"user_id": user_id, **kwargs}

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