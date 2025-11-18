"""
Tests for organisation CRUD operations.
"""

import json

from database import get_db_cursor

####################################################
# Create Opertation
###################################################


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

    assert response.status_code == 400
    result = response.get_json()
    assert "error" in result
    assert "No JSON data provided" in result["error"]


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


####################################################
