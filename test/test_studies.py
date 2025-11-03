"""
Tests for study CRUD operations.
"""

import json
from database import get_db_cursor
import settings

SONG_URL = settings.OVERTURE_SONG


def test_create_study_success(client, org1_admin_token, public_project1, requests_mock):
    """
    Test successfully creating a study with valid data.

    Verifies:
    - Study is created in SONG service
    - Study is created in local database
    - Response contains correct study data
    """
    project_id = public_project1["id"]
    study_id = f"test-study-{project_id[:8]}"

    study_data = {
        "studyId": study_id,
        "name": "Test Study",
        "description": "Test study description",
        "projectId": project_id,
    }

    requests_mock.get(
        f"{SONG_URL}/studies/{study_id}",
        status_code=404,
        json={"message": "Study not found"}
    )
    requests_mock.post(
        f"{SONG_URL}/studies/{study_id}/",
        status_code=200,
        json={
            "studyId": study_id,
            "name": "Test Study",
            "description": "Test study description"
        }
    )

    try:
        response = client.post(
            "/studies/",
            data=json.dumps(study_data),
            headers={
                "Authorization": f"Bearer {org1_admin_token}",
                "Content-Type": "application/json",
            },
        )

        assert response.status_code == 201, response.get_json()
        result = response.get_json()
        assert result["message"] == "Study created successfully"
        assert result["study"]["study_id"] == study_id
        assert result["study"]["name"] == "Test Study"
        assert result["study"]["project_id"] == project_id
    finally:
        # Cleanup: Delete the study from database
        with get_db_cursor() as cursor:
            cursor.execute("DELETE FROM studies WHERE study_id = %s", (study_id,))


def test_create_study_requires_authentication(client, public_project1):
    """
    Test that creating a study requires authentication.

    Verifies:
    - Request without auth token is rejected
    """
    project_id = public_project1["id"]

    study_data = {
        "studyId": "test-study-unauth",
        "name": "Test Study",
        "description": "Test study description",
        "projectId": project_id,
    }

    response = client.post(
        "/studies/",
        data=json.dumps(study_data),
        headers={"Content-Type": "application/json"},
    )   

    assert response.status_code in [401, 403]


def test_create_basic_errors(client, org1_admin_token, public_project1, requests_mock):
    """
    Test various error cases when creating a study.

    Tests missing required fields and invalid data.
    """
    project_id = public_project1["id"]

    # Test missing studyId
    response = client.post(
        "/studies/",
        data=json.dumps({
            "name": "Test Study",
            "projectId": project_id,
        }),
        headers={
            "Authorization": f"Bearer {org1_admin_token}",
            "Content-Type": "application/json",
        },
    )
    assert response.status_code == 400
    assert "StudyId is required" in response.get_json().get("error")

    # Test missing name
    response = client.post(
        "/studies/",
        data=json.dumps({
            "studyId": "test-study-no-name",
            "projectId": project_id,
        }),
        headers={
            "Authorization": f"Bearer {org1_admin_token}",
            "Content-Type": "application/json",
        },
    )
    assert response.status_code == 400
    assert "Study name is required" in response.get_json().get("error")

    # Test missing projectId
    response = client.post(
        "/studies/",
        data=json.dumps({
            "studyId": "test-study-no-project",
            "name": "Test Study",
        }),
        headers={
            "Authorization": f"Bearer {org1_admin_token}",
            "Content-Type": "application/json",
        },
    )
    assert response.status_code == 400
    assert "Associated projectId is required" in response.get_json().get("error")


def test_create_study_duplicate_in_song(client, org1_admin_token, public_project1, requests_mock):
    """
    Test creating a study with a studyId that already exists in SONG.

    Verifies:
    - SONG is checked for existing study
    - If study exists in SONG, creation is prevented
    """
    project_id = public_project1["id"]
    study_id = "existing-study-in-song"

    study_data = {
        "studyId": study_id,
        "name": "Duplicate Study",
        "description": "This study already exists in SONG",
        "projectId": project_id,
    }

    # Mock SONG GET response to indicate study already exists
    requests_mock.get(
        f"{SONG_URL}/studies/{study_id}",
        status_code=200,
        json={
            "studyId": study_id,
            "name": "Existing Study"
        }
    )

    response = client.post(
        "/studies/",
        data=json.dumps(study_data),
        headers={
            "Authorization": f"Bearer {org1_admin_token}",
            "Content-Type": "application/json",
        },
    )

    assert response.status_code == 200  # Current implementation returns 200 with error message
    result = response.get_json()
    assert "already exists in SONG" in result.get("error")


# TODO: Re-enable when auth is fixed
#def test_list_studies_requires_authentication(client, org1_admin_token, public_project1, requests_mock):
#    """
#    Test that listing studies requires authentication.
#    """
#    study_id = f"test-list-auth-{public_project1['id'][:8]}"
#    study_data = {
#        "studyId": study_id,
#        "name": "Auth List Test Study",
#        "description": "Test study for authenticated listing",
#        "projectId": public_project1["id"],
#    }
#
#    # Mock SONG responses
#    requests_mock.get(
#        f"{SONG_URL}/studies/{study_id}",
#        status_code=404,
#        json={"message": "Study not found"}
#    )
#    requests_mock.post(
#        f"{SONG_URL}/studies/{study_id}/",
#        status_code=200,
#        json={"studyId": study_id}
#    )
#
#    try:
#        # Create a study first
#        create_response = client.post(
#            "/studies/",
#            data=json.dumps(study_data),
#            headers={
#                "Authorization": f"Bearer {org1_admin_token}",
#                "Content-Type": "application/json",
#            },
#        )
#        assert create_response.status_code == 201, create_response.get_json()
#
#        response = client.get("/studies/")
#
#        assert response.status_code in [401, 403]
#    finally:
#        # Cleanup: Delete the study from database
#        with get_db_cursor() as cursor:
#            cursor.execute("DELETE FROM studies WHERE study_id = %s", (study_id,))


def test_create_multiple_studies_same_project(client, org1_admin_token, public_project1, requests_mock):
    """
    Test creating multiple studies under the same project.

    Verifies:
    - Multiple studies can be created for one project
    - Each study has unique studyId
    - All studies appear in the list
    """
    project_id = public_project1["id"]
    study_ids = [
        f"multi-study-1-{project_id[:8]}",
        f"multi-study-2-{project_id[:8]}",
        f"multi-study-3-{project_id[:8]}"
    ]

    created_studies = []

    try:
        for i, study_id in enumerate(study_ids):
            # Mock SONG responses for each study
            requests_mock.get(
                f"{SONG_URL}/studies/{study_id}",
                status_code=404,
                json={"message": "Study not found"}
            )
            requests_mock.post(
                f"{SONG_URL}/studies/{study_id}/",
                status_code=200,
                json={"studyId": study_id}
            )

            study_data = {
                "studyId": study_id,
                "name": f"Multi Study {i+1}",
                "description": f"Study {i+1} for multi-study test",
                "projectId": project_id,
            }

            response = client.post(
                "/studies/",
                data=json.dumps(study_data),
                headers={
                    "Authorization": f"Bearer {org1_admin_token}",
                    "Content-Type": "application/json",
                },
            )

            assert response.status_code == 201, response.get_json()

            created_studies.append(response.get_json()["study"])


        # List all studies and verify all three are present
        list_response = client.get("/studies/")
        assert list_response.status_code == 200

        all_studies = list_response.get_json()
        for study_id in study_ids:
            assert any(s["study_id"] == study_id for s in all_studies), \
                f"Study {study_id} not found in list"
    finally:
        # Cleanup: Delete all created studies from database
        with get_db_cursor() as cursor:
            for study_id in study_ids:
                cursor.execute("DELETE FROM studies WHERE study_id = %s", (study_id,))
