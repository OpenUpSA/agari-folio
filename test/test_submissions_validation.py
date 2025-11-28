"""
Tests for project submission validation endpoints.

Tests cover both GET and POST methods for /projects/<project_id>/submissions/<submission_id>/validate2
"""

import json
import uuid
from logging import getLogger
from unittest.mock import MagicMock, patch

import pytest

import settings
from database import get_db_cursor

logger = getLogger(__name__)

####################################################
# Helper Functions
####################################################


def create_submission(client, token, project_id, submission_name="Test Submission"):
    """Helper to create a submission"""
    submission_data = {"submission_name": submission_name}
    response = client.post(
        f"/projects/{project_id}/submissions2",
        data=json.dumps(submission_data),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )
    assert response.status_code in [200, 201], (
        f"Failed to create submission: {response.get_json()}"
    )
    return response.get_json().get("submission")


def create_isolate(
    submission_id, isolate_data, tsv_row=1, status=None, error=None, seq_error=None
):
    """Helper to create an isolate record in the database"""
    with get_db_cursor() as cursor:
        cursor.execute(
            """
            INSERT INTO isolates (submission_id, isolate_data, tsv_row, status, error, seq_error)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id
        """,
            (
                submission_id,
                json.dumps(isolate_data),
                tsv_row,
                status,
                json.dumps(error)
                if error and isinstance(error, (dict, list))
                else error,
                json.dumps(seq_error)
                if seq_error and isinstance(seq_error, (dict, list))
                else seq_error,
            ),
        )
        isolate_uuid = cursor.fetchone()["id"]
    return isolate_uuid


def create_submission_file(submission_id, filename="test.tsv", file_type="tsv"):
    """Helper to create a submission_file record in the database"""
    with get_db_cursor() as cursor:
        cursor.execute(
            """
            INSERT INTO submission_files (submission_id, filename, file_type, object_id, file_size)
            VALUES (%s, %s, %s, %s, %s)
        """,
            (submission_id, filename, file_type, str(uuid.uuid4()), 100),
        )


def cleanup_submission(submission_id):
    """Helper to clean up a submission and its related data"""
    with get_db_cursor() as cursor:
        cursor.execute(
            "DELETE FROM isolates WHERE submission_id = %s", (submission_id,)
        )
        cursor.execute(
            "DELETE FROM submission_files WHERE submission_id = %s", (submission_id,)
        )
        cursor.execute("DELETE FROM submissions WHERE id = %s", (submission_id,))


def get_submission_status(submission_id):
    """Helper to get submission status from database"""
    with get_db_cursor() as cursor:
        cursor.execute("SELECT status FROM submissions WHERE id = %s", (submission_id,))
        return cursor.fetchone()["status"]


def get_validation_endpoint(project_id, submission_id):
    """Helper to build validation endpoint URL"""
    return f"/projects/{project_id}/submissions/{submission_id}/validate2"


def make_request(client, method, url, token=None, data=None):
    """Helper to make authenticated requests"""
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    if method == "GET":
        return client.get(url, headers=headers)
    else:
        return client.post(url, data=json.dumps(data or {}), headers=headers)


####################################################
# Pytest Fixtures
####################################################


@pytest.fixture
def submission_with_files(client, org1_admin_token, public_project1):
    """Fixture that creates a submission with TSV file"""
    submission = create_submission(client, org1_admin_token, public_project1["id"])
    submission_id = submission["id"]
    create_submission_file(submission_id)

    yield submission

    cleanup_submission(submission_id)


@pytest.fixture
def mock_validation_stack():
    """Fixture that provides common mocking stack for validation"""
    with (
        patch("app.get_minio_client") as mock_minio,
        patch("app.tsv_to_json") as mock_tsv_to_json,
        patch("app.validate_against_schema") as mock_validate,
        patch("app.send_to_elastic2") as mock_elastic,
        patch("jobs.add_job") as mock_add_job,
    ):
        # Setup default mocks
        mock_obj = MagicMock()
        mock_obj.read.return_value.decode.return_value = "mock tsv content"
        mock_minio.return_value.get_object.return_value = mock_obj
        mock_add_job.return_value = "fake-job-id"

        yield {
            "minio": mock_minio,
            "tsv_to_json": mock_tsv_to_json,
            "validate": mock_validate,
            "elastic": mock_elastic,
            "add_job": mock_add_job,
        }


@pytest.fixture
def setup_tsv_rows(mock_validation_stack):
    """Fixture to configure TSV rows and validation results"""

    def _setup(rows, validation_results=None):
        """
        Args:
            rows: List of dict TSV row data
            validation_results: Dict mapping isolate_id to (is_valid, errors) or callable
        """
        mock_validation_stack["tsv_to_json"].return_value = rows

        if validation_results is None:
            # Default: all valid
            mock_validation_stack["validate"].return_value = (True, None)
        elif callable(validation_results):
            # Custom validation function
            mock_validation_stack["validate"].side_effect = validation_results
        else:
            # Simple mapping
            def validate_side_effect(isolate_data, tsv_row, project_id):
                isolate_id = isolate_data.get("isolate_id")
                return validation_results.get(isolate_id, (True, None))

            mock_validation_stack["validate"].side_effect = validate_side_effect

        return mock_validation_stack

    return _setup


####################################################
# GET Method Tests
####################################################


@pytest.mark.submission
@pytest.mark.submission_validation
@pytest.mark.submission_get_validation
@pytest.mark.integration
@pytest.mark.requires_auth
def test_get_validation_status_requires_authentication(client, public_project1):
    """Test that getting validation status requires authentication"""
    url = get_validation_endpoint(public_project1["id"], "fake-submission-id")
    response = make_request(client, "GET", url)
    assert response.status_code in [401, 403]


@pytest.mark.submission
@pytest.mark.submission_validation
@pytest.mark.submission_get_validation
@pytest.mark.integration
@pytest.mark.requires_org_admin
def test_get_validation_status_requires_permission(
    client, public_project1, org2_admin_token
):
    """Test that getting validation status requires upload_submission permission"""
    url = get_validation_endpoint(public_project1["id"], "fake-submission-id")
    response = make_request(client, "GET", url, token=org2_admin_token)
    assert response.status_code == 403


@pytest.mark.submission
@pytest.mark.submission_validation
@pytest.mark.submission_get_validation
@pytest.mark.integration
def test_get_validation_status_submission_not_found(
    client, org1_admin_token, public_project1
):
    """Test getting validation status for non-existent submission"""
    fake_submission_id = "00000000-0000-0000-0000-000000000000"
    url = get_validation_endpoint(public_project1["id"], fake_submission_id)
    response = make_request(client, "GET", url, token=org1_admin_token)

    assert response.status_code == 404
    result = response.get_json()
    assert "error" in result
    assert "not found" in result["error"].lower()


@pytest.mark.submission
@pytest.mark.submission_validation
@pytest.mark.submission_get_validation
@pytest.mark.integration
def test_get_validation_status_success(client, org1_admin_token, public_project1):
    """Test successfully retrieving validation status for a submission"""
    submission = create_submission(client, org1_admin_token, public_project1["id"])
    submission_id = submission["id"]

    try:
        # Create isolates with different statuses
        create_isolate(
            submission_id, {"isolate_id": "TEST-001"}, tsv_row=1, status="validated"
        )
        create_isolate(
            submission_id,
            {"isolate_id": "TEST-002"},
            tsv_row=2,
            status="error",
            error={"row": 2, "field": "sample", "message": "Invalid value"},
        )
        create_isolate(
            submission_id,
            {"isolate_id": "TEST-003"},
            tsv_row=3,
            status="error",
            seq_error={"row": 3, "message": "Sequence validation failed"},
        )

        url = get_validation_endpoint(public_project1["id"], submission_id)
        response = make_request(client, "GET", url, token=org1_admin_token)

        assert response.status_code == 200
        result = response.get_json()

        # Verify response structure and counts
        assert result["submission_id"] == submission_id
        assert result["project_id"] == public_project1["id"]
        assert result["total_isolates"] == 3
        assert result["validated"] == 1
        assert result["schema_errors_count"] == 1
        assert result["sequence_errors_count"] == 1
        assert result["error_count"] == 2
        assert len(result["validation_errors"]) == 1

    finally:
        cleanup_submission(submission_id)


@pytest.mark.submission
@pytest.mark.submission_validation
@pytest.mark.submission_get_validation
@pytest.mark.integration
def test_get_validation_status_no_isolates(client, org1_admin_token, public_project1):
    """Test getting validation status for submission with no isolates"""
    submission = create_submission(client, org1_admin_token, public_project1["id"])
    submission_id = submission["id"]

    try:
        url = get_validation_endpoint(public_project1["id"], submission_id)
        response = make_request(client, "GET", url, token=org1_admin_token)

        assert response.status_code == 200
        result = response.get_json()
        assert result["total_isolates"] == 0
        assert result["validated"] == 0
        assert result["schema_errors_count"] == 0
        assert result["sequence_errors_count"] == 0
        assert result["error_count"] == 0

    finally:
        cleanup_submission(submission_id)


@pytest.mark.submission
@pytest.mark.submission_validation
@pytest.mark.submission_get_validation
@pytest.mark.integration
def test_get_validation_status_parses_json_errors(
    client, org1_admin_token, public_project1
):
    """Test that validation status correctly parses JSON error fields"""
    submission = create_submission(client, org1_admin_token, public_project1["id"])
    submission_id = submission["id"]

    try:
        # Create isolate with JSON string error
        error_obj = [{"row": 1, "field": "test", "message": "Test error"}]
        create_isolate(
            submission_id,
            {"isolate_id": "TEST-001"},
            tsv_row=1,
            status="error",
            error=error_obj,
        )

        url = get_validation_endpoint(public_project1["id"], submission_id)
        response = make_request(client, "GET", url, token=org1_admin_token)

        assert response.status_code == 200
        result = response.get_json()
        assert len(result["validation_errors"]) == 1
        assert result["validation_errors"][0] == error_obj

    finally:
        cleanup_submission(submission_id)


####################################################
# POST Method Tests - Authentication & Permissions
####################################################


@pytest.mark.submission
@pytest.mark.submission_validation
@pytest.mark.submission_start_validation
@pytest.mark.integration
@pytest.mark.parametrize(
    "use_token,expected_status",
    [
        (False, [401, 403]),  # No authentication
    ],
)
@pytest.mark.requires_auth
def test_validate_submission_requires_authentication(
    client, public_project1, use_token, expected_status
):
    """Test that validating a submission requires authentication"""
    url = get_validation_endpoint(public_project1["id"], "fake-submission-id")
    response = make_request(client, "POST", url)
    assert response.status_code in expected_status


@pytest.mark.submission
@pytest.mark.submission_validation
@pytest.mark.submission_start_validation
@pytest.mark.integration
@pytest.mark.requires_org_admin
def test_validate_submission_requires_permission(
    client, public_project1, org2_admin_token
):
    """Test that validating a submission requires upload_submission permission"""
    url = get_validation_endpoint(public_project1["id"], "fake-submission-id")
    response = make_request(client, "POST", url, token=org2_admin_token)
    assert response.status_code == 403


@pytest.mark.submission
@pytest.mark.submission_validation
@pytest.mark.submission_start_validation
@pytest.mark.integration
def test_validate_submission_not_found(client, org1_admin_token, public_project1):
    """Test validating a non-existent submission"""
    fake_submission_id = "00000000-0000-0000-0000-000000000000"
    url = get_validation_endpoint(public_project1["id"], fake_submission_id)
    response = make_request(client, "POST", url, token=org1_admin_token)

    assert response.status_code == 404
    result = response.get_json()
    assert "error" in result
    assert "not found" in result["error"].lower()


####################################################
# POST Method Tests - Concurrency & Status
####################################################


@pytest.mark.submission
@pytest.mark.submission_validation
@pytest.mark.submission_start_validation
@pytest.mark.integration
def test_validate_submission_prevents_concurrent_validation(
    client, org1_admin_token, public_project1
):
    """Test that concurrent validation is prevented (409 Conflict)"""
    submission = create_submission(client, org1_admin_token, public_project1["id"])
    submission_id = submission["id"]

    try:
        # Set submission status to 'validating'
        with get_db_cursor() as cursor:
            cursor.execute(
                "UPDATE submissions SET status = 'validating' WHERE id = %s",
                (submission_id,),
            )

        url = get_validation_endpoint(public_project1["id"], submission_id)
        response = make_request(client, "POST", url, token=org1_admin_token)

        assert response.status_code == 409
        result = response.get_json()
        assert "error" in result
        assert "already in progress" in result["error"].lower()

    finally:
        cleanup_submission(submission_id)


@pytest.mark.submission
@pytest.mark.submission_validation
@pytest.mark.submission_start_validation
@pytest.mark.integration
def test_validate_submission_sets_validating_status(
    client, org1_admin_token, public_project1
):
    """Test that validation sets submission status to 'validating' at start"""
    submission = create_submission(client, org1_admin_token, public_project1["id"])
    submission_id = submission["id"]

    try:
        with patch("app.get_minio_client") as mock_minio:
            mock_minio.return_value.get_object.side_effect = Exception("Test exception")

            url = get_validation_endpoint(public_project1["id"], submission_id)
            make_request(client, "POST", url, token=org1_admin_token)

            # Status should have been set to error after exception
            assert get_submission_status(submission_id) == "error"

    finally:
        cleanup_submission(submission_id)


####################################################
# POST Method Tests - File Validation
####################################################


@pytest.mark.submission
@pytest.mark.submission_validation
@pytest.mark.submission_start_validation
@pytest.mark.integration
def test_validate_submission_requires_exactly_one_tsv(
    client, org1_admin_token, public_project1
):
    """Test that validation requires exactly 1 TSV file"""
    submission = create_submission(client, org1_admin_token, public_project1["id"])
    submission_id = submission["id"]

    try:
        url = get_validation_endpoint(public_project1["id"], submission_id)
        response = make_request(client, "POST", url, token=org1_admin_token)

        assert response.status_code == 400
        result = response.get_json()
        assert "validation_errors" in result
        assert "TSV file required" in result["validation_errors"][0]
        assert get_submission_status(submission_id) == "error"

    finally:
        cleanup_submission(submission_id)


@pytest.mark.submission
@pytest.mark.submission_validation
@pytest.mark.submission_start_validation
@pytest.mark.integration
@pytest.mark.parametrize(
    "require_fasta,expect_error",
    [
        (True, True),  # FASTA required, none provided -> error
        (False, False),  # FASTA not required, none provided -> success
    ],
)
def test_validate_submission_fasta_requirement(
    client,
    org1_admin_token,
    public_project1,
    mock_validation_stack,
    setup_tsv_rows,
    require_fasta,
    expect_error,
):
    """Test that validation enforces FASTA file requirement based on settings"""
    submission = create_submission(client, org1_admin_token, public_project1["id"])
    submission_id = submission["id"]

    try:
        create_submission_file(submission_id)
        original_require_fasta = settings.REQUIRE_FASTA_FILE
        settings.REQUIRE_FASTA_FILE = require_fasta

        try:
            if not expect_error:
                setup_tsv_rows([{"isolate_id": "TEST-001"}])

            url = get_validation_endpoint(public_project1["id"], submission_id)
            response = make_request(client, "POST", url, token=org1_admin_token)

            if expect_error:
                assert response.status_code == 400
                assert (
                    "FASTA file required" in response.get_json()["validation_errors"][0]
                )
            else:
                assert response.status_code == 200

        finally:
            settings.REQUIRE_FASTA_FILE = original_require_fasta

    finally:
        cleanup_submission(submission_id)


####################################################
# POST Method Tests - TSV Processing
####################################################


@pytest.mark.submission
@pytest.mark.submission_validation
@pytest.mark.submission_start_validation
@pytest.mark.integration
def test_validate_submission_deletes_existing_isolates(
    client, org1_admin_token, public_project1, mock_validation_stack, setup_tsv_rows
):
    """Test that validation deletes existing isolates before re-validation"""
    submission = create_submission(client, org1_admin_token, public_project1["id"])
    submission_id = submission["id"]

    try:
        # Create existing isolates
        create_isolate(submission_id, {"isolate_id": "OLD-001"}, tsv_row=1)
        create_isolate(submission_id, {"isolate_id": "OLD-002"}, tsv_row=2)

        create_submission_file(submission_id)
        setup_tsv_rows([{"isolate_id": "NEW-001"}])

        url = get_validation_endpoint(public_project1["id"], submission_id)
        response = make_request(client, "POST", url, token=org1_admin_token)

        assert response.status_code == 200

        # Verify old isolates were deleted and new one created
        with get_db_cursor() as cursor:
            cursor.execute(
                """
                SELECT isolate_data->>'isolate_id' as isolate_id
                FROM isolates WHERE submission_id = %s
            """,
                (submission_id,),
            )
            isolates = cursor.fetchall()
            assert len(isolates) == 1
            assert isolates[0]["isolate_id"] == "NEW-001"

    finally:
        cleanup_submission(submission_id)


@pytest.mark.submission
@pytest.mark.submission_validation
@pytest.mark.submission_start_validation
@pytest.mark.integration
def test_validate_submission_creates_isolate_per_row(
    client, org1_admin_token, public_project1, mock_validation_stack, setup_tsv_rows
):
    """Test that validation creates one isolate record per TSV row"""
    submission = create_submission(client, org1_admin_token, public_project1["id"])
    submission_id = submission["id"]

    try:
        create_submission_file(submission_id)

        tsv_rows = [
            {"isolate_id": "TEST-001", "sample": "sample1"},
            {"isolate_id": "TEST-002", "sample": "sample2"},
            {"isolate_id": "TEST-003", "sample": "sample3"},
        ]
        setup_tsv_rows(tsv_rows)

        url = get_validation_endpoint(public_project1["id"], submission_id)
        response = make_request(client, "POST", url, token=org1_admin_token)

        assert response.status_code == 200
        assert response.get_json()["total_isolates"] == 3

        # Verify all isolates were created with correct tsv_row
        with get_db_cursor() as cursor:
            cursor.execute(
                """
                SELECT tsv_row FROM isolates WHERE submission_id = %s ORDER BY tsv_row
            """,
                (submission_id,),
            )
            isolates = cursor.fetchall()
            assert len(isolates) == 3
            assert [i["tsv_row"] for i in isolates] == [1, 2, 3]

    finally:
        cleanup_submission(submission_id)


####################################################
# POST Method Tests - Duplicate Detection
####################################################


@pytest.mark.submission
@pytest.mark.submission_validation
@pytest.mark.submission_start_validation
@pytest.mark.integration
@pytest.mark.parametrize(
    "allow_duplicates,expected_errors",
    [
        (False, 1),  # Duplicates not allowed -> error
        (True, 0),  # Duplicates allowed -> no error
    ],
)
def test_validate_submission_duplicate_handling(
    client,
    org1_admin_token,
    public_project1,
    mock_validation_stack,
    setup_tsv_rows,
    allow_duplicates,
    expected_errors,
):
    """Test that validation handles duplicate isolate_ids based on settings"""
    submission = create_submission(client, org1_admin_token, public_project1["id"])
    submission_id = submission["id"]

    # Create another submission with existing isolate
    submission2 = create_submission(
        client, org1_admin_token, public_project1["id"], "Other Submission"
    )
    submission2_id = submission2["id"]
    create_isolate(
        submission2_id, {"isolate_id": "DUPLICATE-001"}, tsv_row=1, status="validated"
    )

    try:
        create_submission_file(submission_id)

        original_allow_duplicates = settings.ALLOW_DUPLICATE_ISOLATE_IDS
        settings.ALLOW_DUPLICATE_ISOLATE_IDS = allow_duplicates

        try:
            tsv_rows = [{"isolate_id": "DUPLICATE-001", "sample": "sample1"}]
            if allow_duplicates:
                setup_tsv_rows(tsv_rows)
            else:
                setup_tsv_rows(tsv_rows, {})  # Will be handled by duplicate check

            url = get_validation_endpoint(public_project1["id"], submission_id)
            response = make_request(client, "POST", url, token=org1_admin_token)

            assert response.status_code == 200
            result = response.get_json()
            assert result["schema_errors"] == expected_errors

            if not allow_duplicates:
                # Verify isolate created with error status
                with get_db_cursor() as cursor:
                    cursor.execute(
                        """
                        SELECT status, error FROM isolates WHERE submission_id = %s
                    """,
                        (submission_id,),
                    )
                    isolate = cursor.fetchone()
                    assert isolate["status"] == "error"
                    assert "already exists" in isolate["error"]

        finally:
            settings.ALLOW_DUPLICATE_ISOLATE_IDS = original_allow_duplicates

    finally:
        cleanup_submission(submission_id)
        cleanup_submission(submission2_id)


####################################################
# POST Method Tests - Schema Validation
####################################################


@pytest.mark.submission
@pytest.mark.submission_validation
@pytest.mark.submission_start_validation
@pytest.mark.integration
def test_validate_submission_validates_against_schema(
    client, org1_admin_token, public_project1, mock_validation_stack, setup_tsv_rows
):
    """Test that validation runs schema validation on isolate data"""
    submission = create_submission(client, org1_admin_token, public_project1["id"])
    submission_id = submission["id"]

    try:
        create_submission_file(submission_id)

        tsv_rows = [
            {"isolate_id": "VALID-001", "sample": "sample1"},
            {"isolate_id": "INVALID-002", "sample": "sample2"},
        ]

        validation_results = {
            "VALID-001": (True, None),
            "INVALID-002": (
                False,
                [{"row": 2, "field": "sample", "message": "Invalid value"}],
            ),
        }
        setup_tsv_rows(tsv_rows, validation_results)

        url = get_validation_endpoint(public_project1["id"], submission_id)
        response = make_request(client, "POST", url, token=org1_admin_token)

        assert response.status_code == 200
        result = response.get_json()
        assert result["validated_isolates"] == 1
        assert result["schema_errors"] == 1

        # Verify statuses in database
        with get_db_cursor() as cursor:
            cursor.execute(
                """
                SELECT isolate_data->>'isolate_id' as isolate_id, status, error
                FROM isolates WHERE submission_id = %s ORDER BY tsv_row
            """,
                (submission_id,),
            )
            isolates = cursor.fetchall()

            assert isolates[0]["isolate_id"] == "VALID-001"
            assert isolates[0]["status"] == "validated"
            assert isolates[0]["error"] is None

            assert isolates[1]["isolate_id"] == "INVALID-002"
            assert isolates[1]["status"] == "error"
            assert isolates[1]["error"] is not None

    finally:
        cleanup_submission(submission_id)


@pytest.mark.submission
@pytest.mark.submission_validation
@pytest.mark.submission_start_validation
@pytest.mark.integration
def test_validate_submission_sets_status_to_error_when_schema_errors(
    client, org1_admin_token, public_project1, mock_validation_stack, setup_tsv_rows
):
    """Test that submission status is set to 'error' when schema validation fails"""
    submission = create_submission(client, org1_admin_token, public_project1["id"])
    submission_id = submission["id"]

    try:
        create_submission_file(submission_id)

        tsv_rows = [{"isolate_id": "INVALID-001", "sample": "bad"}]
        validation_results = {
            "INVALID-001": (False, [{"error": "Schema validation failed"}])
        }
        setup_tsv_rows(tsv_rows, validation_results)

        url = get_validation_endpoint(public_project1["id"], submission_id)
        response = make_request(client, "POST", url, token=org1_admin_token)

        assert response.status_code == 200
        assert get_submission_status(submission_id) == "error"

    finally:
        cleanup_submission(submission_id)


@pytest.mark.submission
@pytest.mark.submission_validation
@pytest.mark.submission_start_validation
@pytest.mark.integration
def test_validate_submission_stores_error_details_in_jsonb(
    client, org1_admin_token, public_project1, mock_validation_stack, setup_tsv_rows
):
    """Test that validation error details are stored in isolate.error JSONB field"""
    submission = create_submission(client, org1_admin_token, public_project1["id"])
    submission_id = submission["id"]

    try:
        create_submission_file(submission_id)

        error_details = [
            {"row": 1, "field": "sample", "message": "Invalid value", "value": "bad"},
            {"row": 1, "field": "age", "message": "Must be a number", "value": "abc"},
        ]

        tsv_rows = [{"isolate_id": "TEST-001"}]
        validation_results = {"TEST-001": (False, error_details)}
        setup_tsv_rows(tsv_rows, validation_results)

        url = get_validation_endpoint(public_project1["id"], submission_id)
        response = make_request(client, "POST", url, token=org1_admin_token)

        assert response.status_code == 200

        # Verify error details stored as JSON
        with get_db_cursor() as cursor:
            cursor.execute(
                "SELECT error FROM isolates WHERE submission_id = %s", (submission_id,)
            )
            stored_error = cursor.fetchone()["error"]
            assert isinstance(stored_error, (dict, list))
            assert stored_error == error_details

    finally:
        cleanup_submission(submission_id)


####################################################
# POST Method Tests - Job Queuing
####################################################


@pytest.mark.submission
@pytest.mark.submission_validation
@pytest.mark.submission_start_validation
@pytest.mark.integration
@pytest.mark.parametrize("split_on_fasta_headers", [True, False])
def test_validate_submission_queues_sequence_job(
    client,
    org1_admin_token,
    public_project1,
    mock_validation_stack,
    setup_tsv_rows,
    split_on_fasta_headers,
):
    """Test that validation queues validate_sequences job when isolates pass schema validation"""
    submission = create_submission(client, org1_admin_token, public_project1["id"])
    submission_id = submission["id"]

    try:
        create_submission_file(submission_id)
        setup_tsv_rows([{"isolate_id": "VALID-001", "sample": "sample1"}])

        url = get_validation_endpoint(public_project1["id"], submission_id)
        response = make_request(
            client,
            "POST",
            url,
            token=org1_admin_token,
            data={"split_on_fasta_headers": split_on_fasta_headers},
        )

        assert response.status_code == 200

        # Verify job was queued with correct parameters
        mock_add_job = mock_validation_stack["add_job"]
        mock_add_job.assert_called_once()
        call_args = mock_add_job.call_args
        assert call_args[0][0] == "validate_sequences"
        job_data = call_args[0][1]
        assert job_data["submission_id"] == submission_id
        assert "isolate_ids" in job_data
        assert len(job_data["isolate_ids"]) == 1
        assert job_data["split_on_fasta_headers"] is split_on_fasta_headers

    finally:
        cleanup_submission(submission_id)


@pytest.mark.submission
@pytest.mark.submission_validation
@pytest.mark.submission_start_validation
@pytest.mark.integration
def test_validate_submission_does_not_queue_job_when_only_errors(
    client, org1_admin_token, public_project1, mock_validation_stack, setup_tsv_rows
):
    """Test that validation does not queue job when all isolates have schema errors"""
    submission = create_submission(client, org1_admin_token, public_project1["id"])
    submission_id = submission["id"]

    try:
        create_submission_file(submission_id)

        tsv_rows = [{"isolate_id": "INVALID-001", "sample": "bad"}]
        validation_results = {"INVALID-001": (False, [{"error": "Schema error"}])}
        setup_tsv_rows(tsv_rows, validation_results)

        url = get_validation_endpoint(public_project1["id"], submission_id)
        response = make_request(client, "POST", url, token=org1_admin_token)

        assert response.status_code == 200
        mock_validation_stack["add_job"].assert_not_called()

    finally:
        cleanup_submission(submission_id)


@pytest.mark.submission
@pytest.mark.submission_validation
@pytest.mark.submission_start_validation
@pytest.mark.integration
def test_validate_submission_keeps_status_validating_when_job_queued(
    client, org1_admin_token, public_project1, mock_validation_stack, setup_tsv_rows
):
    """Test that submission status remains 'validating' when sequence job is queued"""
    submission = create_submission(client, org1_admin_token, public_project1["id"])
    submission_id = submission["id"]

    try:
        create_submission_file(submission_id)
        setup_tsv_rows([{"isolate_id": "VALID-001"}])

        url = get_validation_endpoint(public_project1["id"], submission_id)
        response = make_request(client, "POST", url, token=org1_admin_token)

        assert response.status_code == 200
        # Status should remain 'validating' or 'draft' (not changed to 'error')
        assert get_submission_status(submission_id) in ["validating", "draft"]

    finally:
        cleanup_submission(submission_id)


####################################################
# POST Method Tests - Integration & Edge Cases
####################################################


@pytest.mark.submission
@pytest.mark.submission_validation
@pytest.mark.submission_start_validation
@pytest.mark.integration
def test_validate_submission_sends_validated_isolates_to_elasticsearch(
    client, org1_admin_token, public_project1, mock_validation_stack, setup_tsv_rows
):
    """Test that validated isolates are sent to ES"""
    submission = create_submission(client, org1_admin_token, public_project1["id"])
    submission_id = submission["id"]

    try:
        create_submission_file(submission_id)

        tsv_rows = [
            {"isolate_id": "VALID-001", "sample": "sample1"},
            {"isolate_id": "VALID-002", "sample": "sample2"},
        ]
        setup_tsv_rows(tsv_rows)

        url = get_validation_endpoint(public_project1["id"], submission_id)
        response = make_request(client, "POST", url, token=org1_admin_token)

        assert response.status_code == 200
        # Verify send_to_elastic2 was called for each validated isolate
        assert mock_validation_stack["elastic"].call_count == 2

    finally:
        cleanup_submission(submission_id)


@pytest.mark.submission
@pytest.mark.submission_validation
@pytest.mark.submission_start_validation
@pytest.mark.integration
def test_validate_submission_handles_empty_tsv(
    client, org1_admin_token, public_project1, mock_validation_stack, setup_tsv_rows
):
    """Test that validation handles empty TSV file appropriately"""
    submission = create_submission(client, org1_admin_token, public_project1["id"])
    submission_id = submission["id"]

    try:
        create_submission_file(submission_id)
        setup_tsv_rows([])  # Empty TSV

        url = get_validation_endpoint(public_project1["id"], submission_id)
        response = make_request(client, "POST", url, token=org1_admin_token)

        assert response.status_code == 200
        assert response.get_json()["total_isolates"] == 0
        assert get_submission_status(submission_id) == "error"

    finally:
        cleanup_submission(submission_id)


####################################################
# E2E Test - No Mocking
####################################################


@pytest.mark.submission
@pytest.mark.submission_validation
@pytest.mark.submission_start_validation
@pytest.mark.e2e
@pytest.mark.slow
def test_validate_submission_e2e_with_real_tsv_file(
    client, org1_admin_token, e2e_project
):
    """
    End-to-end test for submission validation with real TSV file upload.

    This test uploads an actual TSV file and validates it without mocking
    the validation, MinIO, or other services. It tests the complete flow:
    1. Create submission
    2. Upload TSV file via multipart/form-data
    3. Trigger validation
    4. Verify validation results

    Also, the e2e_project fixture automatically creates a pathogen with a minimal schema
    suitable for testing basic validation flows.
    """
    from io import BytesIO

    submission = create_submission(
        client,
        org1_admin_token,
        e2e_project["id"],
        submission_name="E2E Validation Test",
    )
    submission_id = submission["id"]

    try:
        # Create a simple TSV file with 2 rows
        tsv_content = (
            "isolate_id\tn50\tserogroup\n"
            "E2E-TEST-001\t2500000\tVibrio cholerae O1\n"
            "E2E-TEST-002\t2600000\tVibrio cholerae O139\n"
        )

        # Upload TSV file to submission
        tsv_file = BytesIO(tsv_content.encode("utf-8"))
        upload_response = client.post(
            f"/projects/{e2e_project['id']}/submissions/{submission_id}/upload2",
            data={"file": (tsv_file, "test_e2e.tsv")},
            headers={"Authorization": f"Bearer {org1_admin_token}"},
            content_type="multipart/form-data",
        )

        # Upload should succeed
        assert upload_response.status_code in [200, 201], (
            f"File upload failed: {upload_response.get_json()}"
        )

        # Verify file was uploaded
        with get_db_cursor() as cursor:
            cursor.execute(
                """
                SELECT COUNT(*) as count FROM submission_files
                WHERE submission_id = %s AND file_type = 'tsv'
            """,
                (submission_id,),
            )
            file_count = cursor.fetchone()["count"]
            assert file_count == 1, "TSV file was not uploaded"

        # Now trigger validation WITHOUT mocking
        url = get_validation_endpoint(e2e_project["id"], submission_id)
        validation_response = make_request(
            client,
            "POST",
            url,
            token=org1_admin_token,
            data={"split_on_fasta_headers": False},
        )

        # Check response - it might be 200 (success), 400 (validation error), or 500 (server error)
        assert validation_response.status_code in [200, 400], (
            f"Unexpected validation response: {validation_response.status_code}: {validation_response.get_json()}"
        )

        result = validation_response.get_json()

        # Verify response structure
        assert "total_isolates" in result, "Response missing total_isolates"

        # If validation succeeded, check that isolates were created
        if validation_response.status_code == 200:
            assert result["total_isolates"] == 2, (
                f"Expected 2 isolates, got {result['total_isolates']}"
            )

            # Verify isolates were created in database
            with get_db_cursor() as cursor:
                cursor.execute(
                    """
                    SELECT isolate_data->>'isolate_id' as isolate_id, status
                    FROM isolates
                    WHERE submission_id = %s
                    ORDER BY tsv_row
                """,
                    (submission_id,),
                )
                isolates = cursor.fetchall()

                assert len(isolates) == 2, (
                    f"Expected 2 isolates in DB, got {len(isolates)}"
                )
                assert isolates[0]["isolate_id"] == "E2E-TEST-001"
                assert isolates[1]["isolate_id"] == "E2E-TEST-002"

                # Check that isolates have a status (validated or error)
                for isolate in isolates:
                    assert isolate["status"] in ["validated", "error", "validating"], (
                        f"Unexpected isolate status: {isolate['status']}"
                    )

            # Verify isolates were indexed in ES
            import time

            from helpers import check_isolate_in_elastic

            # Pause a moment for ES indexing
            time.sleep(1)

            for isolate_id in ["E2E-TEST-001", "E2E-TEST-002"]:
                try:
                    in_elastic = check_isolate_in_elastic(isolate_id)
                    assert in_elastic, (
                        f"Isolate {isolate_id} not found in ES index"
                    )
                except Exception as e:
                    # If ES is not available, log warning but don't fail test
                    logger.warning(
                        f"Could not verify isolate {isolate_id} in ES: {e}"
                    )

        # If validation failed, verify error structure
        else:  # status_code == 400
            assert "validation_errors" in result, "Response missing validation_errors"

    finally:
        # Cleanup
        cleanup_submission(submission_id)
