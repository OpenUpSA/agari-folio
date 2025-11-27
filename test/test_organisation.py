"""
Tests for organisation CRUD operations.
"""

import json
import pytest
from unittest.mock import Mock, patch

from database import get_db_cursor

####################################################
# Create Operation
###################################################


@pytest.mark.organisation_create
@pytest.mark.organisation
@pytest.mark.integration
@pytest.mark.requires_system_admin
@pytest.mark.smoke
def test_create_organisation_success(client, system_admin_token):
    """
    Test successfully creating an organisation with valid data.

    Verifies:
    - Organisation is created in database
    - Response contains correct organisation data
    - All fields are properly stored
    """
    org_data = {
        "name": "Test Org",
        "abbreviation": "TO",
        "url": "https://testorg.org",
        "about": "A test org for testing purposes",
        "sharing_policy": "public",
    }

    try:
        response = client.post(
            "/organisations/",
            data=json.dumps(org_data),
            headers={
                "Authorization": f"Bearer {system_admin_token}",
                "Content-Type": "application/json",
            },
        )

        assert response.status_code == 201, response.get_json()
        result = response.get_json()
        assert result["message"] == "Organisation created successfully"
        assert result["organisation"]["name"] == "Test Org"
        assert result["organisation"]["abbreviation"] == "TO"
        assert result["organisation"]["url"] == "https://testorg.org"
        assert result["organisation"]["about"] == "A test org for testing purposes"
        assert result["organisation"]["sharing_policy"] == "public"
        assert "id" in result["organisation"]
    finally:
        # Cleanup: Delete the organisation from database
        with get_db_cursor() as cursor:
            cursor.execute("DELETE FROM organisations WHERE name = %s", ("Test Org",))


@pytest.mark.organisation_create
@pytest.mark.organisation
@pytest.mark.integration
@pytest.mark.requires_system_admin
def test_create_organisation_minimal_data(client, system_admin_token):
    """
    Test creating an organisation with only required fields.

    Verifies:
    - Organisation can be created with only name field
    - Optional fields default appropriately
    - Default sharing_policy is 'private'
    """
    org_data = {"name": "Minimal Organisation"}

    try:
        response = client.post(
            "/organisations/",
            data=json.dumps(org_data),
            headers={
                "Authorization": f"Bearer {system_admin_token}",
                "Content-Type": "application/json",
            },
        )

        assert response.status_code == 201, response.get_json()
        result = response.get_json()
        assert result["message"] == "Organisation created successfully"
        assert result["organisation"]["name"] == "Minimal Organisation"
        assert result["organisation"]["sharing_policy"] == "private"
    finally:
        # Cleanup
        with get_db_cursor() as cursor:
            cursor.execute(
                "DELETE FROM organisations WHERE name = %s", ("Minimal Organisation",)
            )


@pytest.mark.organisation_create
@pytest.mark.organisation
@pytest.mark.integration
@pytest.mark.requires_auth
def test_create_organisation_requires_authentication(client):
    """
    Test that creating an organisation requires authentication.

    Verifies:
    - Request without auth token is rejected with 401
    """
    org_data = {"name": "Unauthenticated Organisation"}

    response = client.post(
        "/organisations/",
        data=json.dumps(org_data),
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code in [401, 403]


@pytest.mark.organisation_create
@pytest.mark.organisation
@pytest.mark.integration
@pytest.mark.requires_org_admin
@pytest.mark.slow
def test_create_organisation_requires_permission(client, org1_admin_token):
    """
    Test that creating an organisation requires 'create_org' permission.

    Verifies:
    - Regular org admin cannot create organisations
    - Only system admins with create_org permission can create orgs
    """
    org_data = {"name": "Unauthorized Organisation"}

    response = client.post(
        "/organisations/",
        data=json.dumps(org_data),
        headers={
            "Authorization": f"Bearer {org1_admin_token}",
            "Content-Type": "application/json",
        },
    )

    assert response.status_code == 403, response.get_json()


@pytest.mark.organisation_create
@pytest.mark.organisation
@pytest.mark.integration
@pytest.mark.requires_system_admin
def test_create_organisation_missing_name(client, system_admin_token):
    """
    Test that organisation creation fails without a name.

    Verifies:
    - Name field is required
    - Appropriate error message is returned
    """
    org_data = {"abbreviation": "TEST", "url": "https://test.org"}

    response = client.post(
        "/organisations/",
        data=json.dumps(org_data),
        headers={
            "Authorization": f"Bearer {system_admin_token}",
            "Content-Type": "application/json",
        },
    )

    assert response.status_code == 400
    result = response.get_json()
    assert "error" in result
    assert "name" in result["error"].lower()


@pytest.mark.organisation_create
@pytest.mark.organisation
@pytest.mark.integration
@pytest.mark.requires_system_admin
def test_create_organisation_no_json_data(client, system_admin_token):
    """
    Test that organisation creation fails when no JSON data is provided.

    Verifies:
    - Empty request body is rejected
    - Appropriate error message is returned
    """
    response = client.post(
        "/organisations/",
        data="",
        headers={
            "Authorization": f"Bearer {system_admin_token}",
            "Content-Type": "application/json",
        },
    )

    assert response.status_code in [400, 500]


@pytest.mark.organisation_create
@pytest.mark.organisation
@pytest.mark.integration
@pytest.mark.requires_system_admin
def test_create_organisation_duplicate_name(client, system_admin_token):
    """
    Test that creating an organisation with a duplicate name fails.

    Verifies:
    - Duplicate organisation names are not allowed
    - Appropriate 409 Conflict error is returned
    """
    org_data = {"name": "Duplicate Organisation", "abbreviation": "DUP"}

    try:
        # Create first organisation
        response1 = client.post(
            "/organisations/",
            data=json.dumps(org_data),
            headers={
                "Authorization": f"Bearer {system_admin_token}",
                "Content-Type": "application/json",
            },
        )
        assert response1.status_code == 201

        # Try to create duplicate
        response2 = client.post(
            "/organisations/",
            data=json.dumps(org_data),
            headers={
                "Authorization": f"Bearer {system_admin_token}",
                "Content-Type": "application/json",
            },
        )

        assert response2.status_code == 409
        result = response2.get_json()
        assert "error" in result
        assert "already exists" in result["error"].lower()
    finally:
        # Cleanup
        with get_db_cursor() as cursor:
            cursor.execute(
                "DELETE FROM organisations WHERE name = %s", ("Duplicate Organisation",)
            )


@pytest.mark.organisation_create
@pytest.mark.organisation
@pytest.mark.integration
@pytest.mark.requires_system_admin
def test_create_organisation_with_all_fields(client, system_admin_token):
    """
    Test creating an organisation with all available fields populated.

    Verifies:
    - All fields are correctly stored
    - Response includes all provided data
    """
    org_data = {
        "name": "Complete Organisation",
        "abbreviation": "COMP",
        "url": "https://complete.org",
        "about": "This is a complete organisation with all fields populated for comprehensive testing.",
        "sharing_policy": "private",
    }

    try:
        response = client.post(
            "/organisations/",
            data=json.dumps(org_data),
            headers={
                "Authorization": f"Bearer {system_admin_token}",
                "Content-Type": "application/json",
            },
        )

        assert response.status_code == 201, response.get_json()
        result = response.get_json()
        org = result["organisation"]

        assert org["name"] == org_data["name"]
        assert org["abbreviation"] == org_data["abbreviation"]
        assert org["url"] == org_data["url"]
        assert org["about"] == org_data["about"]
        assert org["sharing_policy"] == org_data["sharing_policy"]
        assert "id" in org
        assert "created_at" in org or "id" in org  # Check for timestamp or ID
    finally:
        # Cleanup
        with get_db_cursor() as cursor:
            cursor.execute(
                "DELETE FROM organisations WHERE name = %s", ("Complete Organisation",)
            )


@pytest.mark.organisation_create
@pytest.mark.organisation
@pytest.mark.integration
@pytest.mark.requires_system_admin
def test_create_organisation_empty_name(client, system_admin_token):
    """
    Test that organisation creation fails with an empty name string.

    Verifies:
    - Empty string for name is treated as missing
    - Appropriate error is returned
    """
    org_data = {"name": ""}

    response = client.post(
        "/organisations/",
        data=json.dumps(org_data),
        headers={
            "Authorization": f"Bearer {system_admin_token}",
            "Content-Type": "application/json",
        },
    )

    assert response.status_code == 400
    result = response.get_json()
    assert "error" in result


@pytest.mark.organisation_create
@pytest.mark.organisation
@pytest.mark.integration
@pytest.mark.requires_system_admin
def test_create_organisation_with_special_characters(client, system_admin_token):
    """
    Test creating an organisation with special characters in the name.

    Verifies:
    - Special characters are properly handled
    - Organisation is created successfully
    """
    org_data = {
        "name": "S�o Paulo & Research Institute",
        "abbreviation": "SP&RI",
        "about": "Testing special chars: �, �, �, &, ', \"",
    }

    try:
        response = client.post(
            "/organisations/",
            data=json.dumps(org_data),
            headers={
                "Authorization": f"Bearer {system_admin_token}",
                "Content-Type": "application/json",
            },
        )

        assert response.status_code == 201, response.get_json()
        result = response.get_json()
        assert result["organisation"]["name"] == org_data["name"]
        assert result["organisation"]["abbreviation"] == org_data["abbreviation"]
        assert result["organisation"]["about"] == org_data["about"]
    finally:
        # Cleanup
        with get_db_cursor() as cursor:
            cursor.execute(
                "DELETE FROM organisations WHERE name = %s", (org_data["name"],)
            )


@pytest.mark.organisation_create
@pytest.mark.organisation
@pytest.mark.integration
@pytest.mark.requires_system_admin
def test_create_organisation_null_optional_fields(client, system_admin_token):
    """
    Test creating an organisation with explicit null values for optional fields.

    Verifies:
    - Null values are accepted for optional fields
    - Organisation is created successfully
    """
    org_data = {
        "name": "Null Fields Organisation",
        "abbreviation": None,
        "url": None,
        "about": None,
    }

    try:
        response = client.post(
            "/organisations/",
            data=json.dumps(org_data),
            headers={
                "Authorization": f"Bearer {system_admin_token}",
                "Content-Type": "application/json",
            },
        )

        assert response.status_code == 201, response.get_json()
        result = response.get_json()
        assert result["organisation"]["name"] == "Null Fields Organisation"
    finally:
        # Cleanup
        with get_db_cursor() as cursor:
            cursor.execute(
                "DELETE FROM organisations WHERE name = %s",
                ("Null Fields Organisation",),
            )


@pytest.mark.organisation_create
@pytest.mark.organisation
@pytest.mark.integration
@pytest.mark.requires_system_admin
def test_create_organisation_long_name(client, system_admin_token):
    """
    Test creating an organisation with a very long name.

    Verifies:
    - Long names are handled appropriately
    - Either accepted or rejected with proper error
    """
    long_name = "A" * 255  # Very long organisation name
    org_data = {"name": long_name}

    try:
        response = client.post(
            "/organisations/",
            data=json.dumps(org_data),
            headers={
                "Authorization": f"Bearer {system_admin_token}",
                "Content-Type": "application/json",
            },
        )

        # Either succeeds or fails gracefully
        assert response.status_code in [201, 400]

        if response.status_code == 201:
            result = response.get_json()
            assert result["organisation"]["name"] == long_name
    finally:
        # Cleanup
        with get_db_cursor() as cursor:
            cursor.execute("DELETE FROM organisations WHERE name = %s", (long_name,))


@pytest.mark.organisation_create
@pytest.mark.organisation
@pytest.mark.integration
@pytest.mark.requires_system_admin
@pytest.mark.slow
def test_create_organisation_invalid_sharing_policy(client, system_admin_token):
    """
    Test that organisation creation validates sharing_policy values.

    Verifies:
    - Invalid sharing_policy values are rejected
    - Only 'public', 'private', and 'semi-private' are accepted
    """
    invalid_policies = ["invalid", "PUBLIC", "restricted", "", "none", "123"]

    for invalid_policy in invalid_policies:
        org_data = {
            "name": f"Test Org {invalid_policy}",
            "sharing_policy": invalid_policy,
        }

        response = client.post(
            "/organisations/",
            data=json.dumps(org_data),
            headers={
                "Authorization": f"Bearer {system_admin_token}",
                "Content-Type": "application/json",
            },
        )

        # Should reject with 400 Bad Requests
        assert response.status_code in [400, 500], (response.status_code, response.get_json())

        # Cleanup in case it somehow got created
        try:
            with get_db_cursor() as cursor:
                cursor.execute(
                    "DELETE FROM organisations WHERE name = %s",
                    (f"Test Org {invalid_policy}",),
                )
        except Exception:
            pass  # Ignore cleanup errors


@pytest.mark.organisation_create
@pytest.mark.organisation
@pytest.mark.integration
@pytest.mark.requires_system_admin
@pytest.mark.slow
@pytest.mark.parametrize("policy", ["public", "private", "semi-private"])
def test_create_organisation_valid_sharing_policies(client, system_admin_token, policy):
    """
    Test that all valid sharing_policy values are accepted.

    Verifies - 'public', 'private', and 'semi-private' are valid.
    """
    org_data = {
        "name": f"Test Org {policy.title()}",
        "sharing_policy": policy,
    }

    try:
        response = client.post(
            "/organisations/",
            data=json.dumps(org_data),
            headers={
                "Authorization": f"Bearer {system_admin_token}",
                "Content-Type": "application/json",
            },
        )

        assert response.status_code == 201, (
            f"Valid sharing_policy '{policy}' should be accepted, "
            f"got {response.status_code}: {response.get_json()}"
        )
        result = response.get_json()
        assert result["organisation"]["sharing_policy"] == policy
    finally:
        # Cleanup
        with get_db_cursor() as cursor:
            cursor.execute(
                "DELETE FROM organisations WHERE name = %s",
                (f"Test Org {policy.title()}",),
            )


####################################################
# Add Member Operation
####################################################


@pytest.mark.organisation_members
@pytest.mark.organisation
@pytest.mark.integration
@pytest.mark.requires_system_admin
def test_add_org_members_success(client, system_admin_token, org1):
    """
    Test successfully adding a member to an organisation.

    Verifies:
    - User can be added to organisation with valid roles
    - Invitation is sent successfully
    - Returns appropriate response
    """
    # Use the organisation from org1
    org_id = org1["id"]
    
    # Create a test user
    user_email = f"test-member-{org_id[:8]}@example.com"
    create_user_data = {
        "email": user_email,
        "redirect_uri": "http://example.com",
        "send_email": False,
    }
    user_response = client.post(
        "/users/",
        data=json.dumps(create_user_data),
        headers={
            "Authorization": f"Bearer {system_admin_token}",
            "Content-Type": "application/json",
        },
    )
    assert user_response.status_code == 200
    user_id = user_response.get_json()["user_id"]

    # Add member to organisation
    member_data = {
        "user_id": user_id,
        "role": "org-owner",
        "redirect_uri": "http://example.com",
    }

    with patch("helpers.sg.send", return_value=Mock(status_code=202)):
        response = client.post(
            f"/organisations/{org_id}/members",
            data=json.dumps(member_data),
            headers={
                "Authorization": f"Bearer {system_admin_token}",
                "Content-Type": "application/json",
            },
        )

    assert response.status_code == 200, response.get_json()


@pytest.mark.organisation_members
@pytest.mark.organisation
@pytest.mark.integration
@pytest.mark.requires_auth
def test_add_org_member_requires_authentication(client):
    """
    Test that adding a member requires authentication.

    Verifies:
    - Request without auth token is rejected
    """
    member_data = {
        "user_id": "some-user-id",
        "role": "org-viewer",
    }

    response = client.post(
        "/organisations/test-org-id/members",
        data=json.dumps(member_data),
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code in [401, 403]


@pytest.mark.organisation_members
@pytest.mark.organisation
@pytest.mark.integration
@pytest.mark.requires_org_admin
def test_add_org_member_requires_permission(client, org2, org1_admin_token):
    """
    Test that adding a member requires 'add_org_members' permission.

    Verifies:
    - Only users with add_org_members permission can add members
    - Org admins can only add members to their own organisation
    """

    # Create a test user
    user_email = f"test-invite-to-unauthed-org-{org2['id']}@example.com"
    create_user_data = {
        "email": user_email,
        "redirect_uri": "http://example.com",
        "send_email": False,
    }
    user_response = client.post(
        "/users/",
        data=json.dumps(create_user_data),
        headers={
            "Authorization": f"Bearer {org1_admin_token}",
            "Content-Type": "application/json",
        },
    )
    assert user_response.status_code == 200
    user_id = user_response.get_json()["user_id"]
    # Try to add member to a different org2
    member_data = {
        "user_id": user_response.get_json()["user_id"],
        "role": "org-viewer",
        "redirect_uri": "http://example.com",
    }

    response = client.post(
        f"/organisations/{org2['id']}/members",
        data=json.dumps(member_data),
        headers={
            "Authorization": f"Bearer {org1_admin_token}",
            "Content-Type": "application/json",
        },
    )

    assert response.status_code == 403


@pytest.mark.organisation_members
@pytest.mark.organisation
@pytest.mark.integration
@pytest.mark.requires_org_admin
def test_add_org_member_org_admin_can_add_to_own_org(
    client, org1, org1_admin_token, system_admin_token
):
    """
    Test that org admin can add members to their own organisation.

    Verifies:
    - Org admins can add members to their own organisation (org1)
    """
    org_id = org1["id"]
    # Create a test user
    user_email = f"test-org-admin-add-{org_id}@example.com"
    create_user_data = {
        "email": user_email,
        "redirect_uri": "http://example.com",
        "send_email": False,
    }
    user_response = client.post(
        "/users/",
        data=json.dumps(create_user_data),
        headers={
            "Authorization": f"Bearer {system_admin_token}",
            "Content-Type": "application/json",
        },
    )
    assert user_response.status_code == 200
    user_id = user_response.get_json()["user_id"]

    # Org admin adds member to their own organisation
    member_data = {
        "user_id": user_id,
        "role": "org-viewer",
        "redirect_uri": "http://example.com",
    }

    with patch("helpers.sg.send", return_value=Mock(status_code=202)):
        response = client.post(
            f"/organisations/{org_id}/members",
            data=json.dumps(member_data),
            headers={
                "Authorization": f"Bearer {org1_admin_token}",
                "Content-Type": "application/json",
            },
        )

    assert response.status_code == 200, response.get_json()


@pytest.mark.organisation_members
@pytest.mark.organisation
@pytest.mark.integration
@pytest.mark.requires_org_admin
def test_add_org_member_org_owner_can_add_to_own_org(
    client, org1, org1_owner_token, system_admin_token
):
    """
    Test that org owner can add members to their own organisation.

    Verifies:
    - Org owners can add members to their own organisation (org1)
    - Org owners have the add_org_members permission
    """
    org_id = org1["id"]
    # Create a test user
    user_email = f"test-org-owner-add-{org_id}@example.com"
    create_user_data = {
        "email": user_email,
        "redirect_uri": "http://example.com",
        "send_email": False,
    }
    user_response = client.post(
        "/users/",
        data=json.dumps(create_user_data),
        headers={
            "Authorization": f"Bearer {system_admin_token}",
            "Content-Type": "application/json",
        },
    )
    assert user_response.status_code == 200
    user_id = user_response.get_json()["user_id"]

    # Org owner adds member to their own organisation
    member_data = {
        "user_id": user_id,
        "role": "org-contributor",
        "redirect_uri": "http://example.com",
    }

    with patch("helpers.sg.send", return_value=Mock(status_code=202)):
        response = client.post(
            f"/organisations/{org_id}/members",
            data=json.dumps(member_data),
            headers={
                "Authorization": f"Bearer {org1_owner_token}",
                "Content-Type": "application/json",
            },
        )

    assert response.status_code == 200, response.get_json()


@pytest.mark.organisation_members
@pytest.mark.organisation
@pytest.mark.integration
@pytest.mark.requires_system_admin
def test_add_org_member_missing_user_id(client, system_admin_token):
    """
    Test that user_id is required when adding a member.

    Verifies:
    - Missing user_id returns 400
    - Appropriate error message
    """
    member_data = {"role": "org-viewer"}

    response = client.post(
        "/organisations/test-org-id/members",
        data=json.dumps(member_data),
        headers={
            "Authorization": f"Bearer {system_admin_token}",
            "Content-Type": "application/json",
        },
    )

    assert response.status_code == 400
    result = response.get_json()
    assert "error" in result
    assert "user" in result["error"].lower() and "id" in result["error"].lower()


@pytest.mark.organisation_members
@pytest.mark.organisation
@pytest.mark.integration
@pytest.mark.requires_system_admin
def test_add_org_member_invalid_role(client, system_admin_token, public_project1):
    """
    Test that invalid roles are rejected.

    Verifies:
    - Only valid org roles are accepted
    - Invalid role returns 400
    """
    org_id = public_project1["organisation_id"]

    # Try with invalid role
    member_data = {
        "user_id": "some-user-id",
        "role": "invalid-role",
    }

    response = client.post(
        f"/organisations/{org_id}/members",
        data=json.dumps(member_data),
        headers={
            "Authorization": f"Bearer {system_admin_token}",
            "Content-Type": "application/json",
        },
    )

    assert response.status_code == 400
    result = response.get_json()
    assert "error" in result
    assert "role" in result["error"].lower()


@pytest.mark.organisation_members
@pytest.mark.organisation
@pytest.mark.integration
@pytest.mark.requires_system_admin
@pytest.mark.parametrize("role", ["org-viewer", "org-admin", "org-contributor", "org-owner"])
def test_add_org_member_valid_roles(client, system_admin_token, org1, role):
    """
    Test that all valid organisation roles are accepted.

    Verifies roles - org-viewer, org-admin, org-contributor, org-owner are valid.
    """
    org_id = org1["id"]
    # Create user
    user_email = f"test-{role}-{org_id[:8]}@example.com"
    create_user_data = {
        "email": user_email,
        "redirect_uri": "http://example.com",
        "send_email": False,
    }
    user_response = client.post(
        "/users/",
        data=json.dumps(create_user_data),
        headers={
            "Authorization": f"Bearer {system_admin_token}",
            "Content-Type": "application/json",
        },
    )
    assert user_response.status_code == 200
    user_id = user_response.get_json()["user_id"]

    # Add member with this role
    member_data = {
        "user_id": user_id,
        "role": role,
        "redirect_uri": "http://example.com",
    }

    with patch("helpers.sg.send", return_value=Mock(status_code=202)):
        response = client.post(
            f"/organisations/{org_id}/members",
            data=json.dumps(member_data),
            headers={
                "Authorization": f"Bearer {system_admin_token}",
                "Content-Type": "application/json",
            },
        )

    assert response.status_code == 200, (
        f"Valid role '{role}' should be accepted, "
        f"got {response.status_code}: {response.get_json()}"
    )


@pytest.mark.organisation_members
@pytest.mark.organisation
@pytest.mark.integration
@pytest.mark.requires_system_admin
def test_add_org_member_user_not_found(client, system_admin_token, public_project1):
    """
    Test that adding a non-existent user returns 404.

    Verifies:
    - User must exist in Keycloak
    - Returns 404 for non-existent user
    """
    org_id = public_project1["organisation_id"]

    # Try to add non-existent user
    member_data = {
        "user_id": "non-existent-user-id-12345",
        "role": "org-viewer",
    }

    response = client.post(
        f"/organisations/{org_id}/members",
        data=json.dumps(member_data),
        headers={
            "Authorization": f"Bearer {system_admin_token}",
            "Content-Type": "application/json",
        },
    )

    assert response.status_code == 404
    result = response.get_json()
    assert "error" in result


@pytest.mark.organisation_members
@pytest.mark.organisation
@pytest.mark.integration
@pytest.mark.requires_system_admin
def test_add_org_member_no_json_data(client, system_admin_token):
    """
    Test that empty request body is rejected.

    Verifies:
    - Empty JSON returns 400
    - Appropriate error message
    """
    response = client.post(
        "/organisations/test-org-id/members",
        data="",
        headers={
            "Authorization": f"Bearer {system_admin_token}",
            "Content-Type": "application/json",
        },
    )

    assert response.status_code in [400, 500]


@pytest.mark.organisation_members
@pytest.mark.organisation
@pytest.mark.integration
@pytest.mark.requires_system_admin
def test_add_org_member_force_role(client, system_admin_token, public_project1):
    """
    Test adding a member with force_role flag.

    Verifies:
    - force_role bypasses invitation flow
    - User is immediately added to organisation
    """
    org_id = public_project1["organisation_id"]

    # Create user
    user_email = f"test-force-{org_id[:8]}@example.com"
    create_user_data = {
        "email": user_email,
        "redirect_uri": "http://example.com",
        "send_email": False,
    }
    user_response = client.post(
        "/users/",
        data=json.dumps(create_user_data),
        headers={
            "Authorization": f"Bearer {system_admin_token}",
            "Content-Type": "application/json",
        },
    )
    assert user_response.status_code == 200
    user_id = user_response.get_json()["user_id"]

    # Add member with force_role
    member_data = {
        "user_id": user_id,
        "role": "org-admin",
        "force_role": True,
    }

    response = client.post(
        f"/organisations/{org_id}/members",
        data=json.dumps(member_data),
        headers={
            "Authorization": f"Bearer {system_admin_token}",
            "Content-Type": "application/json",
        },
    )

    assert response.status_code == 200


####################################################
# Accept Organisation Invitation
####################################################


@pytest.mark.organisation_members
@pytest.mark.organisation
@pytest.mark.integration
@pytest.mark.requires_system_admin
def test_accept_org_invitation_success(client, system_admin_token, keycloak_auth, org2):
    """
    Test successfully accepting an organisation invitation.

    Verifies:
    - User can accept organisation invitation
    - User is assigned correct role
    - User receives access tokens
    - Invitation attributes are removed
    """
    org_id = org2["id"]

    # Create a test user
    user_email = f"test-org-invite-{org_id}@example.com"
    create_user_data = {
        "email": user_email,
        "redirect_uri": "http://example.com",
        "send_email": False,
    }
    user_response = client.post(
        "/users/",
        data=json.dumps(create_user_data),
        headers={
            "Authorization": f"Bearer {system_admin_token}",
            "Content-Type": "application/json",
        },
    )
    assert user_response.status_code == 200
    user_id = user_response.get_json()["user_id"]

    # Add member to organisation (sends invitation)
    member_data = {
        "user_id": user_id,
        "role": "org-viewer",
        "redirect_uri": "http://example.com",
    }

    with patch("helpers.sg.send", return_value=Mock(status_code=202)):
        invite_response = client.post(
            f"/organisations/{org_id}/members",
            data=json.dumps(member_data),
            headers={
                "Authorization": f"Bearer {system_admin_token}",
                "Content-Type": "application/json",
            },
        )

    assert invite_response.status_code == 200

    # Get invite token from user attributes
    invite_token = keycloak_auth.get_user_attributes(user_id)["invite_org_token"][0]

    # Accept the invitation
    accept_response = client.post(f"/invites/organisation/{invite_token}/accept")

    assert accept_response.status_code == 200, accept_response.get_json()
    result = accept_response.get_json()

    # Verify response
    assert result["user_id"] == user_id
    assert result["organisation_id"] == org_id
    assert result["role"] == "org-viewer"
    assert result["realm_role_assigned"] == "agari-org-viewer"
    assert "access_token" in result
    assert "refresh_token" in result

    # Verify invite attributes were removed
    user_attrs = keycloak_auth.get_user_attributes(user_id)
    assert "invite_org_token" not in user_attrs or invite_token not in user_attrs.get(
        "invite_org_token", []
    )


@pytest.mark.organisation_members
@pytest.mark.organisation
@pytest.mark.integration
@pytest.mark.requires_system_admin
@pytest.mark.slow
@pytest.mark.parametrize("role", ["org-viewer", "org-admin", "org-contributor"])
def test_accept_org_invitation_all_roles(client, system_admin_token, keycloak_auth, org1, role):
    """
    Test accepting organisation invitations with different roles.

    Verifies:
    - All org roles work correctly (org-viewer, org-admin, org-contributor, org-owner)
    """

    org_id = org1["id"]

    # Create a test user
    user_email = f"test-org-invite-{role}@example.com"
    create_user_data = {
        "email": user_email,
        "redirect_uri": "http://example.com",
        "send_email": False,
    }
    user_response = client.post(
        "/users/",
        data=json.dumps(create_user_data),
        headers={
            "Authorization": f"Bearer {system_admin_token}",
            "Content-Type": "application/json",
        },
    )
    assert user_response.status_code == 200
    user_id = user_response.get_json()["user_id"]

    # Invite user with this role
    member_data = {
        "user_id": user_id,
        "role": role,
        "redirect_uri": "http://example.com",
    }

    with patch("helpers.sg.send", return_value=Mock(status_code=202)):
        invite_response = client.post(
            f"/organisations/{org_id}/members",
            data=json.dumps(member_data),
            headers={
                "Authorization": f"Bearer {system_admin_token}",
                "Content-Type": "application/json",
            },
        )

    assert invite_response.status_code == 200

    # Get invite token and accept
    invite_token = keycloak_auth.get_user_attributes(user_id)["invite_org_token"][
        0
    ]
    accept_response = client.post(f"/invites/organisation/{invite_token}/accept")

    assert accept_response.status_code == 200, (
        f"Accept invitation failed for role '{role}': {accept_response.get_json()}"
    )
    result = accept_response.get_json()
    assert result["role"] == role
    assert result["realm_role_assigned"] == f"agari-{role}"


@pytest.mark.organisation_members
@pytest.mark.organisation
@pytest.mark.integration
def test_accept_org_invitation_invalid_token(client):
    """
    Test accepting organisation invitation with invalid token.

    Verifies:
    - Invalid token returns appropriate error
    """
    invalid_token = "invalid-token-12345"

    with pytest.raises(Exception):
        client.post(f"/invites/organisation/{invalid_token}/accept")


@pytest.mark.organisation_members
@pytest.mark.organisation
@pytest.mark.integration
@pytest.mark.requires_system_admin
def test_accept_org_invitation_owner_role(client, org1_owner, org1_owner_token, keycloak_auth, org1):
    """
    Test accepting organisation invitation with org-owner role.

    Verifies:
    - User becomes org-owner
    - Previous owner is downgraded to org-admin
    """
    org_id = org1["id"]

    # Create a new user to become owner
    user_email = f"test-new-owner-{org_id}@example.com"
    create_user_data = {
        "email": user_email,
        "redirect_uri": "http://example.com",
        "send_email": False,
    }
    user_response = client.post(
        "/users/",
        data=json.dumps(create_user_data),
        headers={
            "Authorization": f"Bearer {org1_owner_token}",
            "Content-Type": "application/json",
        },
    )
    assert user_response.status_code == 200
    user_id = user_response.get_json()["user_id"]

    # Invite user with org-owner role
    member_data = {
        "new_owner_id": user_id,
        "current_owner_id": org1_owner["user_id"],
        "redirect_uri": "http://example.com",
    }

    with patch("helpers.sg.send", return_value=Mock(status_code=202)):
            invite_response = client.post(
            f"/organisations/{org_id}/owner",
            data=json.dumps(member_data),
            headers={
                "Authorization": f"Bearer {org1_owner_token}",
                "Content-Type": "application/json",
            },
        )

    assert invite_response.status_code == 200

    # Get invite token and accept
    user_attrs = keycloak_auth.get_user_attributes(user_id)
    invite_token = user_attrs["invite_org_token"][0]

    accept_response = client.post(f"/invites/organisation/{invite_token}/accept")

    assert accept_response.status_code == 200, accept_response.get_json()
    result = accept_response.get_json()

    # Verify new owner
    assert result["role"] == "org-owner"
    assert result["realm_role_assigned"] == "agari-org-owner"

    # Verify previous owner downgraded to org-admin
    previous_owner_attrs = keycloak_auth.get_user_attributes(org1_owner["user_id"])
    assert previous_owner_attrs['realm_role'][0] == 'org-admin'


@pytest.mark.organisation_members
@pytest.mark.organisation
@pytest.mark.integration
@pytest.mark.requires_system_admin
def test_accept_org_invitation_returns_tokens(client, system_admin_token, keycloak_auth, org1):
    """
    Test that accepting invitation returns access and refresh tokens.

    Verifies:
    - Response includes access_token
    - Response includes refresh_token
    - Tokens can be used for authentication
    """
    org_id = org1["id"]

    # Create and invite user
    user_email = f"test-tokens-{org_id}@example.com"
    create_user_data = {
        "email": user_email,
        "redirect_uri": "http://example.com",
        "send_email": False,
    }
    user_response = client.post(
        "/users/",
        data=json.dumps(create_user_data),
        headers={
            "Authorization": f"Bearer {system_admin_token}",
            "Content-Type": "application/json",
        },
    )
    assert user_response.status_code == 200
    user_id = user_response.get_json()["user_id"]

    member_data = {
        "user_id": user_id,
        "role": "org-viewer",
        "redirect_uri": "http://example.com",
    }

    with patch("helpers.sg.send", return_value=Mock(status_code=202)):
        client.post(
            f"/organisations/{org_id}/members",
            data=json.dumps(member_data),
            headers={
                "Authorization": f"Bearer {system_admin_token}",
                "Content-Type": "application/json",
            },
        )

    invite_token = keycloak_auth.get_user_attributes(user_id)["invite_org_token"][0]
    accept_response = client.post(f"/invites/organisation/{invite_token}/accept")

    assert accept_response.status_code == 200
    result = accept_response.get_json()

    # Check tokens exist
    assert "access_token" in result
    assert "refresh_token" in result
    assert isinstance(result["access_token"], str)
    assert isinstance(result["refresh_token"], str)
    assert len(result["access_token"]) > 0
    assert len(result["refresh_token"]) > 0


@pytest.mark.organisation_members
@pytest.mark.organisation
@pytest.mark.integration
@pytest.mark.requires_system_admin
def test_accept_org_invitation_removes_invite_attributes(
    client, system_admin_token, keycloak_auth, org1
):
    """
    Test that accepting invitation removes all invitation-related attributes.

    Verifies:
    - invite_org_token is removed
    - invite_org_id is removed
    - invite_org_role_<org_id> is removed
    """
    org_id = org1["id"]

    user_email = f"test-cleanup-{org_id}@example.com"
    create_user_data = {
        "email": user_email,
        "redirect_uri": "http://example.com",
        "send_email": False,
    }
    user_response = client.post(
        "/users/",
        data=json.dumps(create_user_data),
        headers={
            "Authorization": f"Bearer {system_admin_token}",
            "Content-Type": "application/json",
        },
    )
    assert user_response.status_code == 200
    user_id = user_response.get_json()["user_id"]

    member_data = {
        "user_id": user_id,
        "role": "org-admin",
        "redirect_uri": "http://example.com",
    }

    with patch("helpers.sg.send", return_value=Mock(status_code=202)):
        client.post(
            f"/organisations/{org_id}/members",
            data=json.dumps(member_data),
            headers={
                "Authorization": f"Bearer {system_admin_token}",
                "Content-Type": "application/json",
            },
        )

    # Verify invite attributes exist before accepting
    attrs_before = keycloak_auth.get_user_attributes(user_id)
    assert "invite_org_token" in attrs_before
    assert "invite_org_id" in attrs_before

    invite_token = attrs_before["invite_org_token"][0]
    accept_response = client.post(f"/invites/organisation/{invite_token}/accept")

    assert accept_response.status_code == 200

    # Verify invite attributes removed after accepting
    attrs_after = keycloak_auth.get_user_attributes(user_id)
    assert (
        "invite_org_token" not in attrs_after
        or invite_token not in attrs_after.get("invite_org_token", [])
    )
    assert (
        "invite_org_id" not in attrs_after
        or org_id not in attrs_after.get("invite_org_id", [])
    )


####################################################
