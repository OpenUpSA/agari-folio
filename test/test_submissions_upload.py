"""
E2E tests for submission creation and file upload endpoints.

Tests the following endpoints:
- POST /projects/<project_id>/submissions2 - Create a new submission
- POST /projects/<project_id>/submissions/<submission_id>/upload2 - Upload files to a submission
"""

import json
import os
import pytest
from database import get_db_cursor
from helpers import get_minio_client


# ============================================================================
# Test Fixtures
# ============================================================================


@pytest.fixture
def submission_data():
    """Basic submission data for testing"""
    return {"submission_name": "Test Submission E2E"}


@pytest.fixture
def tsv_file_path():
    """Path to test TSV file"""
    return os.path.join(os.path.dirname(__file__), "data", "tsv_files", "cholera_1.tsv")


@pytest.fixture
def fasta_file_path():
    """Path to test FASTA file"""
    return os.path.join(os.path.dirname(__file__), "data", "tsv_files", "cholera_001.fasta")


# ============================================================================
# Submission Creation Tests
# ============================================================================


@pytest.mark.submission
@pytest.mark.submission_create
@pytest.mark.e2e
@pytest.mark.smoke
def test_create_submission_success(client, org1_admin_token, public_project1):
    """Test successful submission creation with valid data"""
    submission_data = {"submission_name": "E2E Test Submission"}

    submission_id = None
    try:
        response = client.post(
            f"/projects/{public_project1['id']}/submissions2",
            data=json.dumps(submission_data),
            headers={
                "Authorization": f"Bearer {org1_admin_token}",
                "Content-Type": "application/json",
            },
        )

        assert response.status_code == 201
        result = response.get_json()

        # Verify response structure
        assert result["message"] == "Submission created successfully"
        assert "submission" in result
        assert result["submission"]["submission_name"] == "E2E Test Submission"
        assert result["submission"]["project_id"] == public_project1["id"]
        assert result["submission"]["status"] == "draft"
        assert "id" in result["submission"]
        assert "created_at" in result["submission"]
        assert "updated_at" in result["submission"]

        submission_id = result["submission"]["id"]

        # Verify database record
        with get_db_cursor() as cursor:
            cursor.execute(
                "SELECT id, submission_name, status, project_id FROM submissions WHERE id = %s",
                (submission_id,),
            )
            db_record = cursor.fetchone()
            assert db_record is not None
            assert db_record["submission_name"] == "E2E Test Submission"
            assert db_record["status"] == "draft"
            assert db_record["project_id"] == public_project1["id"]

    finally:
        # Cleanup
        if submission_id:
            with get_db_cursor() as cursor:
                cursor.execute("DELETE FROM submissions WHERE id = %s", (submission_id,))


@pytest.mark.submission
@pytest.mark.submission_create
@pytest.mark.requires_auth
@pytest.mark.integration
def test_create_submission_requires_authentication(client, public_project1):
    """Test that submission creation requires authentication"""
    submission_data = {"submission_name": "Unauthenticated Submission"}

    response = client.post(
        f"/projects/{public_project1['id']}/submissions2",
        data=json.dumps(submission_data),
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code in [401, 403]


@pytest.mark.submission
@pytest.mark.submission_create
@pytest.mark.requires_permission
@pytest.mark.integration
def test_create_submission_missing_name(client, org1_admin_token, public_project1):
    """Test that submission creation fails without submission_name"""
    submission_data = {"invalid_field": "No Name"}

    response = client.post(
        f"/projects/{public_project1['id']}/submissions2",
        data=json.dumps(submission_data),
        headers={
            "Authorization": f"Bearer {org1_admin_token}",
            "Content-Type": "application/json",
        },
    )

    assert response.status_code == 400
    result = response.get_json()
    assert "error" in result
    assert "submission_name" in result["error"].lower()


@pytest.mark.submission
@pytest.mark.submission_create
@pytest.mark.integration
def test_create_submission_invalid_project(client, org1_admin_token):
    """Test that submission creation fails with invalid project_id"""
    submission_data = {"submission_name": "Test Submission"}
    invalid_project_id = "00000000-0000-0000-0000-000000000000"

    response = client.post(
        f"/projects/{invalid_project_id}/submissions2",
        data=json.dumps(submission_data),
        headers={
            "Authorization": f"Bearer {org1_admin_token}",
            "Content-Type": "application/json",
        },
    )

    assert response.status_code in [403, 404]


# ============================================================================
# File Upload Tests - TSV Files
# ============================================================================


@pytest.mark.submission
@pytest.mark.submission_upload
@pytest.mark.e2e
@pytest.mark.smoke
def test_upload_tsv_file_success(client, org1_admin_token, public_project1, tsv_file_path):
    """Test successful TSV file upload to a submission"""
    # Step 1: Create submission
    submission_data = {"submission_name": "TSV Upload Test"}

    response = client.post(
        f"/projects/{public_project1['id']}/submissions2",
        data=json.dumps(submission_data),
        headers={
            "Authorization": f"Bearer {org1_admin_token}",
            "Content-Type": "application/json",
        },
    )
    assert response.status_code == 201
    submission_id = response.get_json()["submission"]["id"]

    try:
        # Step 2: Upload TSV file
        with open(tsv_file_path, "rb") as f:
            file_data = {
                "file": (f, "cholera_1.tsv"),
            }

            response = client.post(
                f"/projects/{public_project1['id']}/submissions/{submission_id}/upload2",
                data=file_data,
                headers={
                    "Authorization": f"Bearer {org1_admin_token}",
                },
                content_type="multipart/form-data",
            )

        assert response.status_code == 201
        result = response.get_json()

        # Verify response structure
        assert result["message"] == "File uploaded successfully"
        assert result["submission_id"] == submission_id
        assert "file" in result
        assert result["file"]["filename"] == "cholera_1.tsv"
        assert result["file"]["file_type"] == "tsv"
        assert result["file"]["file_size"] > 0
        assert "id" in result["file"]
        assert "object_id" in result["file"]

        file_id = result["file"]["id"]
        object_id = result["file"]["object_id"]

        # Verify database record
        with get_db_cursor() as cursor:
            cursor.execute(
                """
                SELECT filename, file_type, file_size, object_id, md5_hash
                FROM submission_files WHERE id = %s
                """,
                (file_id,),
            )
            db_record = cursor.fetchone()
            assert db_record is not None
            assert db_record["filename"] == "cholera_1.tsv"
            assert db_record["file_type"] == "tsv"
            assert db_record["file_size"] > 0
            assert db_record["object_id"] == object_id
            assert db_record["md5_hash"] is not None  # MD5 hash should be calculated

        # Verify file in MinIO
        minio_client = get_minio_client(client)
        from settings import MINIO_BUCKET

        try:
            stat = minio_client.stat_object(MINIO_BUCKET, str(object_id))
            assert stat.size > 0
        except Exception as e:
            pytest.fail(f"File not found in MinIO: {e}")

        # Cleanup MinIO
        try:
            minio_client.remove_object(MINIO_BUCKET, str(object_id))
        except Exception:
            pass

    finally:
        # Cleanup database
        with get_db_cursor() as cursor:
            cursor.execute("DELETE FROM submissions WHERE id = %s", (submission_id,))


@pytest.mark.submission
@pytest.mark.submission_upload
@pytest.mark.e2e
def test_upload_multiple_tsv_files(client, org1_admin_token, public_project1, tsv_file_path):
    """Test uploading multiple TSV files to the same submission"""
    # Create submission
    submission_data = {"submission_name": "Multiple TSV Upload Test"}

    response = client.post(
        f"/projects/{public_project1['id']}/submissions2",
        data=json.dumps(submission_data),
        headers={
            "Authorization": f"Bearer {org1_admin_token}",
            "Content-Type": "application/json",
        },
    )
    assert response.status_code == 201
    submission_id = response.get_json()["submission"]["id"]

    object_ids = []
    try:
        # Upload first TSV file
        with open(tsv_file_path, "rb") as f:
            file_data = {"file": (f, "cholera_1.tsv")}
            response = client.post(
                f"/projects/{public_project1['id']}/submissions/{submission_id}/upload2",
                data=file_data,
                headers={"Authorization": f"Bearer {org1_admin_token}"},
                content_type="multipart/form-data",
            )

        assert response.status_code == 201
        object_ids.append(response.get_json()["file"]["object_id"])

        # Upload second TSV file (using same file with different name)
        with open(tsv_file_path, "rb") as f:
            file_data = {"file": (f, "cholera_2.tsv")}
            response = client.post(
                f"/projects/{public_project1['id']}/submissions/{submission_id}/upload2",
                data=file_data,
                headers={"Authorization": f"Bearer {org1_admin_token}"},
                content_type="multipart/form-data",
            )

        assert response.status_code == 201
        object_ids.append(response.get_json()["file"]["object_id"])

        # Verify both files are in database
        with get_db_cursor() as cursor:
            cursor.execute(
                "SELECT COUNT(*) as count FROM submission_files WHERE submission_id = %s",
                (submission_id,),
            )
            result = cursor.fetchone()
            assert result["count"] == 2

        # Cleanup MinIO
        minio_client = get_minio_client(client)
        from settings import MINIO_BUCKET
        for object_id in object_ids:
            try:
                minio_client.remove_object(MINIO_BUCKET, str(object_id))
            except Exception:
                pass

    finally:
        # Cleanup database
        with get_db_cursor() as cursor:
            cursor.execute("DELETE FROM submissions WHERE id = %s", (submission_id,))


# ============================================================================
# File Upload Tests - FASTA Files
# ============================================================================


@pytest.mark.submission
@pytest.mark.submission_upload
@pytest.mark.e2e
@pytest.mark.smoke
def test_upload_fasta_file_success(client, org1_admin_token, public_project1, fasta_file_path):
    """Test successful FASTA file upload to a submission"""
    # Create submission
    submission_data = {"submission_name": "FASTA Upload Test"}

    response = client.post(
        f"/projects/{public_project1['id']}/submissions2",
        data=json.dumps(submission_data),
        headers={
            "Authorization": f"Bearer {org1_admin_token}",
            "Content-Type": "application/json",
        },
    )
    assert response.status_code == 201
    submission_id = response.get_json()["submission"]["id"]

    try:
        # Upload FASTA file
        with open(fasta_file_path, "rb") as f:
            file_data = {"file": (f, "cholera_001.fasta")}

            response = client.post(
                f"/projects/{public_project1['id']}/submissions/{submission_id}/upload2",
                data=file_data,
                headers={"Authorization": f"Bearer {org1_admin_token}"},
                content_type="multipart/form-data",
            )

        assert response.status_code == 201
        result = response.get_json()

        # Verify response structure
        assert result["message"] == "File uploaded successfully"
        assert result["file"]["filename"] == "cholera_001.fasta"
        assert result["file"]["file_type"] == "fasta"
        assert result["file"]["file_size"] > 0

        object_id = result["file"]["object_id"]

        # Verify database record
        with get_db_cursor() as cursor:
            cursor.execute(
                "SELECT file_type, md5_hash FROM submission_files WHERE object_id = %s",
                (object_id,),
            )
            db_record = cursor.fetchone()
            assert db_record is not None
            assert db_record["file_type"] == "fasta"
            assert db_record["md5_hash"] is not None

        # Cleanup MinIO
        minio_client = get_minio_client(client)
        from settings import MINIO_BUCKET
        try:
            minio_client.remove_object(MINIO_BUCKET, str(object_id))
        except Exception:
            pass

    finally:
        # Cleanup database
        with get_db_cursor() as cursor:
            cursor.execute("DELETE FROM submissions WHERE id = %s", (submission_id,))


# ============================================================================
# File Upload Tests - Error Cases
# ============================================================================


@pytest.mark.submission
@pytest.mark.submission_upload
@pytest.mark.integration
def test_upload_requires_existing_submission(client, org1_admin_token, public_project1, tsv_file_path):
    """Test that file upload fails with invalid submission_id"""
    invalid_submission_id = "00000000-0000-0000-0000-000000000000"

    with open(tsv_file_path, "rb") as f:
        file_data = {"file": (f, "cholera_1.tsv")}

        response = client.post(
            f"/projects/{public_project1['id']}/submissions/{invalid_submission_id}/upload2",
            data=file_data,
            headers={"Authorization": f"Bearer {org1_admin_token}"},
            content_type="multipart/form-data",
        )

    assert response.status_code == 404
    result = response.get_json()
    assert "error" in result
    assert "not found" in result["error"].lower()


@pytest.mark.submission
@pytest.mark.submission_upload
@pytest.mark.integration
def test_upload_missing_file(client, org1_admin_token, public_project1):
    """Test that file upload fails without a file"""
    # Create submission
    submission_data = {"submission_name": "Missing File Test"}

    response = client.post(
        f"/projects/{public_project1['id']}/submissions2",
        data=json.dumps(submission_data),
        headers={
            "Authorization": f"Bearer {org1_admin_token}",
            "Content-Type": "application/json",
        },
    )
    assert response.status_code == 201
    submission_id = response.get_json()["submission"]["id"]

    try:
        # Try to upload without a file
        response = client.post(
            f"/projects/{public_project1['id']}/submissions/{submission_id}/upload2",
            data={},
            headers={"Authorization": f"Bearer {org1_admin_token}"},
        )

        assert response.status_code == 400
        result = response.get_json()
        assert "error" in result
        assert "file" in result["error"].lower()

    finally:
        # Cleanup
        with get_db_cursor() as cursor:
            cursor.execute("DELETE FROM submissions WHERE id = %s", (submission_id,))


@pytest.mark.submission
@pytest.mark.submission_upload
@pytest.mark.integration
def test_upload_invalid_file_type(client, org1_admin_token, public_project1):
    """Test that file upload fails with invalid file type (not TSV or FASTA)"""
    # Create submission
    submission_data = {"submission_name": "Invalid File Type Test"}

    response = client.post(
        f"/projects/{public_project1['id']}/submissions2",
        data=json.dumps(submission_data),
        headers={
            "Authorization": f"Bearer {org1_admin_token}",
            "Content-Type": "application/json",
        },
    )
    assert response.status_code == 201
    submission_id = response.get_json()["submission"]["id"]

    try:
        # Try to upload a PDF file (invalid type)
        import io
        fake_pdf = io.BytesIO(b"%PDF-1.4 fake content")
        fake_pdf.name = "test.pdf"

        file_data = {"file": (fake_pdf, "test.pdf")}

        response = client.post(
            f"/projects/{public_project1['id']}/submissions/{submission_id}/upload2",
            data=file_data,
            headers={"Authorization": f"Bearer {org1_admin_token}"},
            content_type="multipart/form-data",
        )

        assert response.status_code == 400
        result = response.get_json()
        assert "error" in result
        assert ("format" in result["error"].lower())

    finally:
        # Cleanup
        with get_db_cursor() as cursor:
            cursor.execute("DELETE FROM submissions WHERE id = %s", (submission_id,))


@pytest.mark.submission
@pytest.mark.submission_upload
@pytest.mark.integration
def test_upload_to_published_submission_fails(client, org1_admin_token, public_project1, tsv_file_path):
    """Test that file upload fails when submission status is 'published'"""
    # Create submission
    submission_data = {"submission_name": "Published Submission Test"}

    response = client.post(
        f"/projects/{public_project1['id']}/submissions2",
        data=json.dumps(submission_data),
        headers={
            "Authorization": f"Bearer {org1_admin_token}",
            "Content-Type": "application/json",
        },
    )
    assert response.status_code == 201
    submission_id = response.get_json()["submission"]["id"]

    try:
        # Manually set submission status to 'published'
        with get_db_cursor() as cursor:
            cursor.execute(
                "UPDATE submissions SET status = %s WHERE id = %s",
                ("published", submission_id),
            )

        # Try to upload a file
        with open(tsv_file_path, "rb") as f:
            file_data = {"file": (f, "cholera_1.tsv")}

            response = client.post(
                f"/projects/{public_project1['id']}/submissions/{submission_id}/upload2",
                data=file_data,
                headers={"Authorization": f"Bearer {org1_admin_token}"},
                content_type="multipart/form-data",
            )

        assert response.status_code == 400
        result = response.get_json()
        assert "error" in result
        assert "status" in result["error"].lower()

    finally:
        # Cleanup
        with get_db_cursor() as cursor:
            cursor.execute("DELETE FROM submissions WHERE id = %s", (submission_id,))


@pytest.mark.submission
@pytest.mark.submission_upload
@pytest.mark.requires_auth
@pytest.mark.integration
def test_upload_requires_authentication(client, org1_admin_token, public_project1, tsv_file_path):
    """Test that file upload requires authentication"""
    # Create submission first (with authentication)
    submission_data = {"submission_name": "Auth Test"}
    response = client.post(
        f"/projects/{public_project1['id']}/submissions2",
        data=json.dumps(submission_data),
        headers={
            "Authorization": f"Bearer {org1_admin_token}",
            "Content-Type": "application/json",
        },
    )
    assert response.status_code == 201
    submission_id = response.get_json()["submission"]["id"]

    try:
        # Try to upload without authentication
        with open(tsv_file_path, "rb") as f:
            file_data = {"file": (f, "cholera_1.tsv")}

            response = client.post(
                f"/projects/{public_project1['id']}/submissions/{submission_id}/upload2",
                data=file_data,
                content_type="multipart/form-data",
            )

        assert response.status_code in [401, 403]

    finally:
        # Cleanup
        with get_db_cursor() as cursor:
            cursor.execute("DELETE FROM submissions WHERE id = %s", (submission_id,))


# ============================================================================
# Integration Tests - Complete Workflow
# ============================================================================


@pytest.mark.submission
@pytest.mark.e2e
@pytest.mark.integration
@pytest.mark.slow
def test_complete_submission_workflow(client, org1_admin_token, public_project1, tsv_file_path, fasta_file_path):
    """Test complete submission workflow: create → upload TSV → upload FASTA"""
    object_ids = []
    
    print(public_project1)

    # Step 1: Create submission
    submission_data = {"submission_name": "Complete Workflow Test"}

    response = client.post(
        f"/projects/{public_project1['id']}/submissions2",
        data=json.dumps(submission_data),
        headers={
            "Authorization": f"Bearer {org1_admin_token}",
            "Content-Type": "application/json",
        },
    )

    assert response.status_code == 201
    submission_id = response.get_json()["submission"]["id"]
    assert response.get_json()["submission"]["status"] == "draft"

    try:
        # Step 2: Upload TSV file
        with open(tsv_file_path, "rb") as f:
            file_data = {"file": (f, "cholera_1.tsv")}

            response = client.post(
                f"/projects/{public_project1['id']}/submissions/{submission_id}/upload2",
                data=file_data,
                headers={"Authorization": f"Bearer {org1_admin_token}"},
                content_type="multipart/form-data",
            )

        assert response.status_code == 201
        assert response.get_json()["file"]["file_type"] == "tsv"
        object_ids.append(response.get_json()["file"]["object_id"])

        # Step 3: Upload FASTA file
        with open(fasta_file_path, "rb") as f:
            file_data = {"file": (f, "cholera_001.fasta")}

            response = client.post(
                f"/projects/{public_project1['id']}/submissions/{submission_id}/upload2",
                data=file_data,
                headers={"Authorization": f"Bearer {org1_admin_token}"},
                content_type="multipart/form-data",
            )

        assert response.status_code == 201
        assert response.get_json()["file"]["file_type"] == "fasta"
        object_ids.append(response.get_json()["file"]["object_id"])

        # Step 4: Verify both files are associated with submission
        with get_db_cursor() as cursor:
            cursor.execute(
                """
                SELECT filename, file_type
                FROM submission_files
                WHERE submission_id = %s
                ORDER BY created_at
                """,
                (submission_id,),
            )
            files = cursor.fetchall()
            assert len(files) == 2
            assert files[0]["file_type"] == "tsv"
            assert files[1]["file_type"] == "fasta"

        # Step 5: Verify all files exist in MinIO
        minio_client = get_minio_client(client)
        from settings import MINIO_BUCKET

        for object_id in object_ids:
            try:
                stat = minio_client.stat_object(MINIO_BUCKET, str(object_id))
                assert stat.size > 0
            except Exception as e:
                pytest.fail(f"File {object_id} not found in MinIO: {e}")

        # Cleanup MinIO
        for object_id in object_ids:
            try:
                minio_client.remove_object(MINIO_BUCKET, str(object_id))
            except Exception:
                pass

    finally:
        # Cleanup database
        with get_db_cursor() as cursor:
            cursor.execute("DELETE FROM submissions WHERE id = %s", (submission_id,))


@pytest.mark.submission
@pytest.mark.e2e
@pytest.mark.integration
def test_submission_md5_hash_calculation(client, org1_admin_token, public_project1, tsv_file_path):
    """Test that MD5 hash is correctly calculated for uploaded files"""
    import hashlib

    # Calculate expected MD5 hash
    with open(tsv_file_path, "rb") as f:
        file_content = f.read()
        expected_md5 = hashlib.md5(file_content).hexdigest()

    # Create submission
    submission_data = {"submission_name": "MD5 Hash Test"}

    response = client.post(
        f"/projects/{public_project1['id']}/submissions2",
        data=json.dumps(submission_data),
        headers={
            "Authorization": f"Bearer {org1_admin_token}",
            "Content-Type": "application/json",
        },
    )
    assert response.status_code == 201
    submission_id = response.get_json()["submission"]["id"]

    try:
        # Upload file
        with open(tsv_file_path, "rb") as f:
            file_data = {"file": (f, "cholera_1.tsv")}

            response = client.post(
                f"/projects/{public_project1['id']}/submissions/{submission_id}/upload2",
                data=file_data,
                headers={"Authorization": f"Bearer {org1_admin_token}"},
                content_type="multipart/form-data",
            )

        assert response.status_code == 201
        file_id = response.get_json()["file"]["id"]
        object_id = response.get_json()["file"]["object_id"]

        # Verify MD5 hash in database
        with get_db_cursor() as cursor:
            cursor.execute(
                "SELECT md5_hash FROM submission_files WHERE id = %s",
                (file_id,),
            )
            result = cursor.fetchone()
            assert result["md5_hash"] == expected_md5

        # Cleanup MinIO
        minio_client = get_minio_client(client)
        from settings import MINIO_BUCKET
        try:
            minio_client.remove_object(MINIO_BUCKET, str(object_id))
        except Exception:
            pass

    finally:
        # Cleanup database
        with get_db_cursor() as cursor:
            cursor.execute("DELETE FROM submissions WHERE id = %s", (submission_id,))
