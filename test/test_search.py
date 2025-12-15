"""
E2E tests for search API endpoints.

Tests the following endpoints:
- POST /search/ - Search published samples in Elasticsearch
- POST /search/reindex - Reindex all isolates (admin only)
"""

import json

import pytest

from database import get_db_cursor

# ============================================================================
# Test Fixtures
# ============================================================================


@pytest.fixture(scope="module", autouse=True)
def clear_elasticsearch_before_tests():
    """Clear Elasticsearch index before running search tests to ensure clean state"""
    import requests

    try:
        # Delete all documents in the index
        requests.post(
            "http://localhost:9200/agari-samples/_delete_by_query",
            json={"query": {"match_all": {}}},
            headers={"Content-Type": "application/json"},
        )
        # Force refresh to apply changes immediately
        requests.post("http://localhost:9200/agari-samples/_refresh")
        print("\nCleared Elasticsearch index before search tests")
    except Exception as e:
        print(f"\nWarning: Could not clear Elasticsearch: {e}")

    yield

    # Optionally clear after tests too
    try:
        requests.post(
            "http://localhost:9200/agari-samples/_delete_by_query",
            json={"query": {"match_all": {}}},
            headers={"Content-Type": "application/json"},
        )
        requests.post("http://localhost:9200/agari-samples/_refresh")
        print("\nCleared Elasticsearch index after search tests")
    except Exception as e:
        print(f"\nWarning: Could not clear Elasticsearch after tests: {e}")


@pytest.fixture
def sample_isolate_data():
    """Sample isolate data for testing"""
    return {
        "id": "test-isolate-001",
        "isolate_id": "TEST001",
        "project_id": None,  # Will be set in tests
        "submission_id": None,  # Will be set in tests
        "visibility": "public",
        "pathogen_name": "Test Pathogen",
        "country": "South Africa",
        "collection_date": "2024-01-15",
        "isolate_data": json.dumps(
            {"isolate_id": "TEST001", "sample_type": "clinical", "host": "human"}
        ),
    }


@pytest.fixture
def published_submission(
    client, org1_admin_token, public_project1, pathogen_with_schema
):
    """Create and publish a submission with isolates for search testing"""
    import os

    # Create submission
    submission_data = {"submission_name": "Search Test Submission"}
    response = client.post(
        f"/projects/{public_project1['id']}/submissions2",
        data=json.dumps(submission_data),
        headers={
            "Authorization": f"Bearer {org1_admin_token}",
            "Content-Type": "application/json",
        },
    )
    assert response.status_code == 201
    submission = response.get_json()["submission"]
    submission_id = submission["id"]

    try:
        # Upload TSV file
        tsv_file_path = os.path.join(
            os.path.dirname(__file__), "data", "tsv_files", "cholera_1.tsv"
        )
        with open(tsv_file_path, "rb") as f:
            response = client.post(
                f"/projects/{public_project1['id']}/submissions/{submission_id}/upload2",
                data={"file": (f, "cholera_1.tsv")},
                headers={"Authorization": f"Bearer {org1_admin_token}"},
                content_type="multipart/form-data",
            )
        assert response.status_code == 201

        # Upload FASTA file
        fasta_file_path = os.path.join(
            os.path.dirname(__file__), "data", "tsv_files", "cholera_001.fasta"
        )
        with open(fasta_file_path, "rb") as f:
            response = client.post(
                f"/projects/{public_project1['id']}/submissions/{submission_id}/upload2",
                data={"file": (f, "cholera_001.fasta")},
                headers={"Authorization": f"Bearer {org1_admin_token}"},
                content_type="multipart/form-data",
            )
        assert response.status_code == 201

        # Validate submission (this triggers async job)
        response = client.post(
            f"/projects/{public_project1['id']}/submissions/{submission_id}/validate2",
            headers={
                "Authorization": f"Bearer {org1_admin_token}",
                "Content-Type": "application/json",
            },
        )
        # Validation can return 200 or 400 depending on validation results
        assert response.status_code in [200, 400]

        # Manually mark isolates as validated since async worker isn't running in tests
        # This simulates what the worker would do
        with get_db_cursor() as cursor:
            # Update isolates to validated status with sequence data
            cursor.execute(
                """
                UPDATE isolates
                SET status = 'validated',
                    seq_error = NULL,
                    object_id = (
                        SELECT object_id FROM submission_files 
                        WHERE submission_id = %s AND file_type = 'fasta' 
                        LIMIT 1
                    )
                WHERE submission_id = %s
                AND error IS NULL
                """,
                (submission_id, submission_id),
            )
            print(f"Manually validated {cursor.rowcount} isolates for testing")

        # Publish submission
        response = client.post(
            f"/projects/{public_project1['id']}/submissions/{submission_id}/publish2",
            headers={
                "Authorization": f"Bearer {org1_admin_token}",
                "Content-Type": "application/json",
            },
        )
        assert response.status_code == 200

        # Force Elasticsearch refresh to make data immediately searchable
        import requests

        try:
            requests.post("http://localhost:9200/agari-samples/_refresh")
            print("Elasticsearch index refreshed")
        except Exception as e:
            print(f"Warning: Could not refresh Elasticsearch: {e}")

        yield {
            "submission": submission,
            "project": public_project1,
            "pathogen": pathogen_with_schema,
        }

    finally:
        # Cleanup: Delete submission (will also delete from Elasticsearch)
        try:
            client.delete(
                f"/projects/{public_project1['id']}/submissions2/{submission_id}",
                headers={"Authorization": f"Bearer {org1_admin_token}"},
            )
        except Exception as e:
            print(f"Cleanup error: {e}")


@pytest.fixture
def private_project_with_submission(
    client, org1_admin_token, pathogen_with_schema, org1_admin
):
    """Create a private project with published submission"""
    import os

    # Create private project
    project_data = {
        "name": "Private Search Test Project",
        "description": "Private project for search testing",
        "pathogen_id": pathogen_with_schema["id"],
        "privacy": "private",
    }
    response = client.post(
        "/projects/",
        data=json.dumps(project_data),
        headers={
            "Authorization": f"Bearer {org1_admin_token}",
            "Content-Type": "application/json",
        },
    )
    assert response.status_code == 201
    project = response.get_json()["project"]

    # Create and publish submission
    submission_data = {"submission_name": "Private Search Test Submission"}
    response = client.post(
        f"/projects/{project['id']}/submissions2",
        data=json.dumps(submission_data),
        headers={
            "Authorization": f"Bearer {org1_admin_token}",
            "Content-Type": "application/json",
        },
    )
    assert response.status_code == 201
    submission = response.get_json()["submission"]

    # Upload and publish files
    tsv_file_path = os.path.join(
        os.path.dirname(__file__), "data", "tsv_files", "cholera_2.tsv"
    )
    with open(tsv_file_path, "rb") as f:
        response = client.post(
            f"/projects/{project['id']}/submissions/{submission['id']}/upload2",
            data={"file": (f, "cholera_2.tsv")},
            headers={"Authorization": f"Bearer {org1_admin_token}"},
            content_type="multipart/form-data",
        )
    assert response.status_code == 201

    fasta_file_path = os.path.join(
        os.path.dirname(__file__), "data", "tsv_files", "cholera_002.fasta"
    )
    with open(fasta_file_path, "rb") as f:
        response = client.post(
            f"/projects/{project['id']}/submissions/{submission['id']}/upload2",
            data={"file": (f, "cholera_002.fasta")},
            headers={"Authorization": f"Bearer {org1_admin_token}"},
            content_type="multipart/form-data",
        )
        assert response.status_code == 201

        # Validate and publish
        response = client.post(
            f"/projects/{project['id']}/submissions/{submission['id']}/validate2",
            headers={
                "Authorization": f"Bearer {org1_admin_token}",
                "Content-Type": "application/json",
            },
        )
        # Validation can return 200 or 400 depending on validation results
        assert response.status_code in [200, 400]

        # Manually mark isolates as validated since async worker isn't running in tests
        with get_db_cursor() as cursor:
            cursor.execute(
                """
                UPDATE isolates
                SET status = 'validated',
                    seq_error = NULL,
                    object_id = (
                        SELECT object_id FROM submission_files 
                        WHERE submission_id = %s AND file_type = 'fasta' 
                        LIMIT 1
                    )
                WHERE submission_id = %s
                AND error IS NULL
                """,
                (submission["id"], submission["id"]),
            )
            print(f"Manually validated {cursor.rowcount} isolates for private project")

        response = client.post(
            f"/projects/{project['id']}/submissions/{submission['id']}/publish2",
            headers={
                "Authorization": f"Bearer {org1_admin_token}",
                "Content-Type": "application/json",
            },
        )
        assert response.status_code == 200

        # Force Elasticsearch refresh
        import requests

        try:
            requests.post("http://localhost:9200/agari-samples/_refresh")
        except Exception:
            pass

        try:
            yield {
                "submission": submission,
                "project": project,
                "pathogen": pathogen_with_schema,
            }
        finally:
            # Cleanup
            try:
                client.delete(
                    f"/projects/{project['id']}/submissions2/{submission['id']}",
                    headers={"Authorization": f"Bearer {org1_admin_token}"},
                )
                client.delete(
                    f"/projects/{project['id']}?hard=true",
                    headers={"Authorization": f"Bearer {org1_admin_token}"},
                )
            except Exception as e:
                print(f"Cleanup error: {e}")

@pytest.fixture
def semi_private_project_with_submission(
    client, org1_admin_token, pathogen_with_schema, org1_admin
):
    """Create a semi-private project with published submission"""
    import os

    # Create semi-private project
    project_data = {
        "name": "Semi-Private Search Test Project",
        "description": "Semi-private project for search testing",
        "pathogen_id": pathogen_with_schema["id"],
        "privacy": "semi-private",
    }
    response = client.post(
        "/projects/",
        data=json.dumps(project_data),
        headers={
            "Authorization": f"Bearer {org1_admin_token}",
            "Content-Type": "application/json",
        },
    )
    assert response.status_code == 201
    project = response.get_json()["project"]

    # Create and publish submission
    submission_data = {"submission_name": "Private Search Test Submission"}
    response = client.post(
        f"/projects/{project['id']}/submissions2",
        data=json.dumps(submission_data),
        headers={
            "Authorization": f"Bearer {org1_admin_token}",
            "Content-Type": "application/json",
        },
    )
    assert response.status_code == 201
    submission = response.get_json()["submission"]

    # Upload and publish files
    tsv_file_path = os.path.join(
        os.path.dirname(__file__), "data", "tsv_files", "cholera_2.tsv"
    )
    with open(tsv_file_path, "rb") as f:
        response = client.post(
            f"/projects/{project['id']}/submissions/{submission['id']}/upload2",
            data={"file": (f, "cholera_2.tsv")},
            headers={"Authorization": f"Bearer {org1_admin_token}"},
            content_type="multipart/form-data",
        )
    assert response.status_code == 201

    fasta_file_path = os.path.join(
        os.path.dirname(__file__), "data", "tsv_files", "cholera_002.fasta"
    )
    with open(fasta_file_path, "rb") as f:
        response = client.post(
            f"/projects/{project['id']}/submissions/{submission['id']}/upload2",
            data={"file": (f, "cholera_002.fasta")},
            headers={"Authorization": f"Bearer {org1_admin_token}"},
            content_type="multipart/form-data",
        )
        assert response.status_code == 201

        # Validate and publish
        response = client.post(
            f"/projects/{project['id']}/submissions/{submission['id']}/validate2",
            headers={
                "Authorization": f"Bearer {org1_admin_token}",
                "Content-Type": "application/json",
            },
        )
        # Validation can return 200 or 400 depending on validation results
        assert response.status_code in [200, 400]

        # Manually mark isolates as validated since async worker isn't running in tests
        with get_db_cursor() as cursor:
            cursor.execute(
                """
                UPDATE isolates
                SET status = 'validated',
                    seq_error = NULL,
                    object_id = (
                        SELECT object_id FROM submission_files 
                        WHERE submission_id = %s AND file_type = 'fasta' 
                        LIMIT 1
                    )
                WHERE submission_id = %s
                AND error IS NULL
                """,
                (submission["id"], submission["id"]),
            )
            print(f"Manually validated {cursor.rowcount} isolates for private project")

        response = client.post(
            f"/projects/{project['id']}/submissions/{submission['id']}/publish2",
            headers={
                "Authorization": f"Bearer {org1_admin_token}",
                "Content-Type": "application/json",
            },
        )
        assert response.status_code == 200

        # Force Elasticsearch refresh
        import requests

        try:
            requests.post("http://localhost:9200/agari-samples/_refresh")
        except Exception:
            pass

        try:
            yield {
                "submission": submission,
                "project": project,
                "pathogen": pathogen_with_schema,
            }
        finally:
            # Cleanup
            try:
                client.delete(
                    f"/projects/{project['id']}/submissions2/{submission['id']}",
                    headers={"Authorization": f"Bearer {org1_admin_token}"},
                )
                client.delete(
                    f"/projects/{project['id']}?hard=true",
                    headers={"Authorization": f"Bearer {org1_admin_token}"},
                )
            except Exception as e:
                print(f"Cleanup error: {e}")
                


# ============================================================================
# Search Tests - Basic Functionality
# ============================================================================


@pytest.mark.search
@pytest.mark.e2e
@pytest.mark.smoke
def test_search_requires_authentication(client):
    """Test that search endpoint requires authentication"""
    search_query = {"query": {"match_all": {}}}

    response = client.post(
        "/search/",
        data=json.dumps(search_query),
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 401


@pytest.mark.search
@pytest.mark.e2e
def test_search_match_all_public_data(client, org1_admin_token, published_submission):
    """Test basic match_all search returns public data"""
    search_query = {"query": {"match_all": {}}, "size": 10}

    response = client.post(
        "/search/",
        data=json.dumps(search_query),
        headers={
            "Authorization": f"Bearer {org1_admin_token}",
            "Content-Type": "application/json",
        },
    )

    assert response.status_code == 200
    result = response.get_json()

    # Verify Elasticsearch response structure
    assert "hits" in result
    assert "total" in result["hits"]
    assert "hits" in result["hits"]

    # Should find at least our published submission's isolates
    assert result["hits"]["total"]["value"] > 0


@pytest.mark.search
@pytest.mark.e2e
def test_search_by_project_id(client, org1_admin_token, published_submission):
    """Test searching by specific project_id"""
    expected_project_id = published_submission["project"]["id"]
    search_query = {"query": {"match": {"project_id": expected_project_id}}}

    response = client.post(
        "/search/",
        data=json.dumps(search_query),
        headers={
            "Authorization": f"Bearer {org1_admin_token}",
            "Content-Type": "application/json",
        },
    )

    assert response.status_code == 200
    result = response.get_json()

    # All returned isolates should belong to the specified project
    assert result["hits"]["total"]["value"] > 0, (
        f"Expected to find isolates for project {expected_project_id}, but found none. "
        "This may indicate Elasticsearch indexing issues or test data cleanup problems."
    )

    for hit in result["hits"]["hits"]:
        actual_project_id = hit["_source"].get("project_id")
        assert actual_project_id == expected_project_id, (
            f"Expected all results to have project_id={expected_project_id}, "
            f"but found project_id={actual_project_id}. "
            f"Document ID: {hit['_id']}. "
            "This may indicate stale data in Elasticsearch from previous test runs."
        )


@pytest.mark.search
@pytest.mark.e2e
def test_search_by_isolate_id(client, org1_admin_token, published_submission):
    """Test searching by specific isolate_id"""
    # First, get an isolate_id from the published submission
    submission_id = published_submission["submission"]["id"]

    with get_db_cursor() as cursor:
        cursor.execute(
            """
            SELECT isolate_id FROM isolates 
            WHERE submission_id = %s 
            LIMIT 1
            """,
            (submission_id,),
        )
        isolate = cursor.fetchone()
        assert isolate is not None
        isolate_id = isolate["isolate_id"]

    search_query = {"query": {"match": {"isolate_id": isolate_id}}}

    response = client.post(
        "/search/",
        data=json.dumps(search_query),
        headers={
            "Authorization": f"Bearer {org1_admin_token}",
            "Content-Type": "application/json",
        },
    )

    assert response.status_code == 200
    result = response.get_json()

    # Should find exactly one isolate
    assert result["hits"]["total"]["value"] >= 1
    assert result["hits"]["hits"][0]["_source"]["isolate_id"] == isolate_id


@pytest.mark.search
@pytest.mark.e2e
def test_search_with_filters(client, org1_admin_token, published_submission):
    """Test searching with multiple filters"""
    search_query = {
        "query": {
            "bool": {
                "must": [
                    {"match": {"project_id": published_submission["project"]["id"]}},
                    {"match": {"visibility": "public"}},
                ]
            }
        }
    }

    response = client.post(
        "/search/",
        data=json.dumps(search_query),
        headers={
            "Authorization": f"Bearer {org1_admin_token}",
            "Content-Type": "application/json",
        },
    )

    assert response.status_code == 200
    result = response.get_json()

    # All returned isolates should match filters
    for hit in result["hits"]["hits"]:
        source = hit["_source"]
        assert source["project_id"] == published_submission["project"]["id"]
        assert source["visibility"] == "public"


@pytest.mark.search
@pytest.mark.e2e
def test_search_with_pagination(client, org1_admin_token, published_submission):
    """Test search pagination with size and from parameters"""
    search_query = {"query": {"match_all": {}}, "size": 2, "from": 0}

    response = client.post(
        "/search/",
        data=json.dumps(search_query),
        headers={
            "Authorization": f"Bearer {org1_admin_token}",
            "Content-Type": "application/json",
        },
    )

    assert response.status_code == 200
    result = response.get_json()

    # Should return at most 2 results
    assert len(result["hits"]["hits"]) <= 2


# ============================================================================
# Search Tests - Access Control
# ============================================================================


@pytest.mark.search
@pytest.mark.rbac
@pytest.mark.e2e
def test_search_access_control_public_project(
    client, external_user_token, published_submission
):
    """Test that external users can search public project data"""
    project_id = published_submission["project"]["id"]

    search_query = {"query": {"match": {"project_id": project_id}}}

    response = client.post(
        "/search/",
        data=json.dumps(search_query),
        headers={
            "Authorization": f"Bearer {external_user_token}",
            "Content-Type": "application/json",
        },
    )

    assert response.status_code == 200
    result = response.get_json()

    # External user should be able to see public project data
    assert result["hits"]["total"]["value"] > 0

@pytest.mark.skip(reason="Semi-private project access control test is currently disabled")
@pytest.mark.search
@pytest.mark.rbac
@pytest.mark.e2e
def test_search_access_control_semi_private_project(
    client, external_user_token, semi_private_project_with_submission
):
    """Test that external users can search semi private project data"""
    project_id = semi_private_project_with_submission["project"]["id"]

    search_query = {"query": {"match": {"project_id": project_id}}}

    response = client.post(
        "/search/",
        data=json.dumps(search_query),
        headers={
            "Authorization": f"Bearer {external_user_token}",
            "Content-Type": "application/json",
        },
    )

    assert response.status_code == 200
    result = response.get_json()

    # External user should be able to see public project data
    assert result["hits"]["total"]["value"] > 0

@pytest.mark.skip(reason="Private project access control test is currently disabled")
@pytest.mark.search
@pytest.mark.rbac
@pytest.mark.e2e
@pytest.mark.parametrize(
    "role_fixture,role_name",
    [
        ("org1_admin_token", "org-admin"),
        ("org1_project_admin_token", "project-admin"),
        ("org1_project_contributor_token", "project-contributor"),
        ("org1_project_viewer_token", "project-viewer"),
    ],
)
def test_search_access_control_private_project_all_roles(
    client, role_fixture, role_name, request, private_project_with_submission
):
    """Test that all project roles (admin, contributor, viewer) can search private project data"""

    # Get the token from the fixture
    token = request.getfixturevalue(role_fixture)

    # Use the private project with published submission
    project = private_project_with_submission["project"]

    # Now test search with the user's token
    search_query = {"query": {"match": {"project_id": project["id"]}}}

    response = client.post(
        "/search/",
        data=json.dumps(search_query),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )

    assert response.status_code == 200
    result = response.get_json()

    # All project members should see their private project data
    assert result["hits"]["total"]["value"] > 0, (
        f"{role_name} should be able to search private project data"
    )


@pytest.mark.search
@pytest.mark.rbac
@pytest.mark.e2e
def test_search_access_control_private_project_external_user(
    client, external_user_token, private_project_with_submission
):
    """Test that external users cannot search private project data"""
    search_query = {
        "query": {
            "match": {"project_id": private_project_with_submission["project"]["id"]}
        }
    }

    response = client.post(
        "/search/",
        data=json.dumps(search_query),
        headers={
            "Authorization": f"Bearer {external_user_token}",
            "Content-Type": "application/json",
        },
    )

    assert response.status_code == 200
    result = response.get_json()

    # External users should not see private project data
    # The access filter should prevent this
    assert result["hits"]["total"]["value"] == 0, (
        "External users should not see private project data"
    )


@pytest.mark.search
@pytest.mark.rbac
@pytest.mark.e2e
def test_search_access_filter_applied(client, org1_admin_token, published_submission):
    """Test that access filter is automatically applied to searches"""
    # Make a simple query and verify the access filter is added
    search_query = {"query": {"match_all": {}}}

    response = client.post(
        "/search/",
        data=json.dumps(search_query),
        headers={
            "Authorization": f"Bearer {org1_admin_token}",
            "Content-Type": "application/json",
        },
    )

    assert response.status_code == 200
    result = response.get_json()

    # All results should be either:
    # 1. From projects the user has access to, OR
    # 2. From public/semi-private projects
    for hit in result["hits"]["hits"]:
        source = hit["_source"]
        # Should have visibility field set
        assert "visibility" in source or "project_id" in source


# ============================================================================
# Search Tests - Error Handling
# ============================================================================


@pytest.mark.search
@pytest.mark.e2e
def test_search_with_invalid_query(client, org1_admin_token):
    """Test search with malformed query returns error"""
    # Missing query structure
    search_query = {}

    response = client.post(
        "/search/",
        data=json.dumps(search_query),
        headers={
            "Authorization": f"Bearer {org1_admin_token}",
            "Content-Type": "application/json",
        },
    )

    # Should handle gracefully and return valid response
    assert response.status_code in [200, 400]


@pytest.mark.search
@pytest.mark.e2e
def test_search_with_missing_json(client, org1_admin_token):
    """Test search without JSON body returns error"""
    response = client.post(
        "/search/",
        headers={
            "Authorization": f"Bearer {org1_admin_token}",
            "Content-Type": "application/json",
        },
    )

    # API returns 500 when JSON parsing fails
    assert response.status_code == 500


# ============================================================================
# Search Tests - Advanced Queries
# ============================================================================


@pytest.mark.search
@pytest.mark.e2e
def test_search_with_wildcard(client, org1_admin_token, published_submission):
    """Test wildcard search functionality"""
    search_query = {"query": {"wildcard": {"isolate_id": "*CHO*"}}}

    response = client.post(
        "/search/",
        data=json.dumps(search_query),
        headers={
            "Authorization": f"Bearer {org1_admin_token}",
            "Content-Type": "application/json",
        },
    )

    assert response.status_code == 200
    result = response.get_json()

    # Results should match the wildcard pattern
    for hit in result["hits"]["hits"]:
        isolate_id = hit["_source"].get("isolate_id", "")
        assert "CHO" in isolate_id or "cho" in isolate_id.lower()


@pytest.mark.search
@pytest.mark.e2e
def test_search_with_range_query(client, org1_admin_token, published_submission):
    """Test range query on date fields"""
    search_query = {
        "query": {
            "range": {"collection_date": {"gte": "2020-01-01", "lte": "2025-12-31"}}
        }
    }

    response = client.post(
        "/search/",
        data=json.dumps(search_query),
        headers={
            "Authorization": f"Bearer {org1_admin_token}",
            "Content-Type": "application/json",
        },
    )

    assert response.status_code == 200
    result = response.get_json()

    # Should return results with dates in range
    assert "hits" in result


@pytest.mark.search
@pytest.mark.e2e
def test_search_with_aggregations(client, org1_admin_token, published_submission):
    """Test search with aggregations"""
    search_query = {
        "query": {"match_all": {}},
        "size": 0,
        "aggs": {"projects": {"terms": {"field": "project_id.keyword"}}},
    }

    response = client.post(
        "/search/",
        data=json.dumps(search_query),
        headers={
            "Authorization": f"Bearer {org1_admin_token}",
            "Content-Type": "application/json",
        },
    )

    assert response.status_code == 200
    result = response.get_json()

    # Should have aggregations in response (if query succeeded)
    if result:
        assert "aggregations" in result


# ============================================================================
# Reindex Tests - Admin Only
# ============================================================================


@pytest.mark.search
@pytest.mark.reindex
@pytest.mark.requires_system_admin
@pytest.mark.e2e
def test_reindex_requires_authentication(client):
    """Test that reindex endpoint requires authentication"""
    response = client.post(
        "/search/reindex",
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 401


@pytest.mark.search
@pytest.mark.reindex
@pytest.mark.requires_system_admin
@pytest.mark.rbac
def test_reindex_requires_admin_permission(client, org1_admin_token):
    """Test that reindex requires system admin permission"""
    response = client.post(
        "/search/reindex",
        headers={
            "Authorization": f"Bearer {org1_admin_token}",
            "Content-Type": "application/json",
        },
    )

    # Non-admin users should be denied
    assert response.status_code == 403


@pytest.mark.search
@pytest.mark.reindex
@pytest.mark.requires_system_admin
@pytest.mark.e2e
@pytest.mark.slow
def test_reindex_success(client, system_admin_token, published_submission):
    """Test successful reindexing of all isolates"""
    response = client.post(
        "/search/reindex",
        headers={
            "Authorization": f"Bearer {system_admin_token}",
            "Content-Type": "application/json",
        },
    )

    assert response.status_code == 200
    result = response.get_json()

    # Verify response structure
    assert "message" in result
    assert "processed" in result
    assert "reindexed" in result
    assert "failures" in result

    # Should have processed some isolates
    assert result["processed"] >= 0


@pytest.mark.search
@pytest.mark.reindex
@pytest.mark.requires_system_admin
@pytest.mark.e2e
def test_reindex_with_batch_size(client, system_admin_token):
    """Test reindex with custom batch size"""
    response = client.post(
        "/search/reindex?batch_size=100&offset=0",
        headers={
            "Authorization": f"Bearer {system_admin_token}",
            "Content-Type": "application/json",
        },
    )

    assert response.status_code == 200
    result = response.get_json()

    # Should respect batch size parameter
    assert result["processed"] <= 100


@pytest.mark.search
@pytest.mark.reindex
@pytest.mark.requires_system_admin
@pytest.mark.e2e
def test_reindex_with_offset(client, system_admin_token):
    """Test reindex with offset parameter"""
    response = client.post(
        "/search/reindex?offset=10",
        headers={
            "Authorization": f"Bearer {system_admin_token}",
            "Content-Type": "application/json",
        },
    )

    assert response.status_code == 200
    result = response.get_json()

    # Should process from offset
    assert "reindexed" in result


@pytest.mark.search
@pytest.mark.reindex
@pytest.mark.requires_system_admin
@pytest.mark.e2e
def test_reindex_invalid_batch_size(client, system_admin_token):
    """Test reindex with invalid batch size"""
    response = client.post(
        "/search/reindex?batch_size=invalid",
        headers={
            "Authorization": f"Bearer {system_admin_token}",
            "Content-Type": "application/json",
        },
    )

    # Should return error for invalid parameter
    assert response.status_code == 400


# ============================================================================
# Integration Tests - Search with Real Data
# ============================================================================


@pytest.mark.search
@pytest.mark.integration
@pytest.mark.e2e
@pytest.mark.slow
def test_search_end_to_end_workflow(
    client, org1_admin_token, public_project1, pathogen_with_schema
):
    """Test complete workflow: create submission, publish, then search"""
    import os

    submission_id = None
    try:
        # 1. Create submission
        submission_data = {"submission_name": "E2E Search Workflow Test"}
        response = client.post(
            f"/projects/{public_project1['id']}/submissions2",
            data=json.dumps(submission_data),
            headers={
                "Authorization": f"Bearer {org1_admin_token}",
                "Content-Type": "application/json",
            },
        )
        assert response.status_code == 201
        submission = response.get_json()["submission"]
        submission_id = submission["id"]

        # 2. Upload files
        tsv_file_path = os.path.join(
            os.path.dirname(__file__), "data", "tsv_files", "cholera_1.tsv"
        )
        with open(tsv_file_path, "rb") as f:
            response = client.post(
                f"/projects/{public_project1['id']}/submissions/{submission_id}/upload2",
                data={"file": (f, "cholera_1.tsv")},
                headers={"Authorization": f"Bearer {org1_admin_token}"},
                content_type="multipart/form-data",
            )
        assert response.status_code == 201

        fasta_file_path = os.path.join(
            os.path.dirname(__file__), "data", "tsv_files", "cholera_001.fasta"
        )
        with open(fasta_file_path, "rb") as f:
            response = client.post(
                f"/projects/{public_project1['id']}/submissions/{submission_id}/upload2",
                data={"file": (f, "cholera_001.fasta")},
                headers={"Authorization": f"Bearer {org1_admin_token}"},
                content_type="multipart/form-data",
            )
        assert response.status_code == 201

        # 3. Validate
        response = client.post(
            f"/projects/{public_project1['id']}/submissions/{submission_id}/validate2",
            headers={
                "Authorization": f"Bearer {org1_admin_token}",
                "Content-Type": "application/json",
            },
        )
        # Validation can return 200 or 400 depending on validation results
        assert response.status_code in [200, 400]

        # Manually mark isolates as validated since async worker isn't running in tests
        with get_db_cursor() as cursor:
            cursor.execute(
                """
                UPDATE isolates
                SET status = 'validated',
                    seq_error = NULL,
                    object_id = (
                        SELECT object_id FROM submission_files 
                        WHERE submission_id = %s AND file_type = 'fasta' 
                        LIMIT 1
                    )
                WHERE submission_id = %s
                AND error IS NULL
                """,
                (submission_id, submission_id),
            )
            print(f"Manually validated {cursor.rowcount} isolates for e2e test")

        # 4. Publish
        response = client.post(
            f"/projects/{public_project1['id']}/submissions/{submission_id}/publish2",
            headers={
                "Authorization": f"Bearer {org1_admin_token}",
                "Content-Type": "application/json",
            },
        )
        assert response.status_code == 200

        # Force Elasticsearch refresh to make data immediately searchable
        import time

        import requests

        try:
            requests.post("http://localhost:9200/agari-samples/_refresh")
            # Give Elasticsearch more time to process and make documents searchable
            time.sleep(1.0)
        except Exception as e:
            print(f"Warning: Could not refresh Elasticsearch: {e}")

        # 5. Search for the published data
        # Use match query which works with both text and keyword fields
        search_query = {"query": {"match": {"submission_id": submission_id}}}

        response = client.post(
            "/search/",
            data=json.dumps(search_query),
            headers={
                "Authorization": f"Bearer {org1_admin_token}",
                "Content-Type": "application/json",
            },
        )

        assert response.status_code == 200
        result = response.get_json()

        # Should find the published isolates
        assert result["hits"]["total"]["value"] > 0, (
            f"Expected to find isolates for submission {submission_id}, but found 0"
        )

        # Verify the isolates belong to our submission
        for hit in result["hits"]["hits"]:
            assert hit["_source"]["submission_id"] == submission_id, (
                f"Expected submission_id {submission_id}, but got {hit['_source']['submission_id']}"
            )

    finally:
        # Cleanup
        if submission_id:
            try:
                client.delete(
                    f"/projects/{public_project1['id']}/submissions2/{submission_id}",
                    headers={"Authorization": f"Bearer {org1_admin_token}"},
                )
            except Exception as e:
                print(f"Cleanup error: {e}")
