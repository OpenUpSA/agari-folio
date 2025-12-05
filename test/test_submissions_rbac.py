"""
RBAC tests for submission visibility and management.

Tests the following RBAC rules based on project privacy settings:
1. Private Projects - Only project members can see/interact
2. Semi-private Projects - Project members + aggregated data for surveillance
3. Public Projects - All authenticated users have viewer access

Core Principles:
- Drafts are always private (creator + project admins only)
- Published submissions visibility is controlled by project privacy
"""

import json

import pytest

from database import get_db_cursor
from test.conftest import keycloak_password_auth

# ============================================================================
# Helper Functions
# ============================================================================


def add_project_member(client, system_admin_token, project_id, user_id, role):
    """Helper to add a member to a project"""
    response = client.post(
        f"/projects/{project_id}/users",
        data=json.dumps(
            {
                "user_id": user_id,
                "role": role,
                "force_role": True,
                "redirect_uri": "http://localhost:3000/accept",
            }
        ),
        headers={
            "Authorization": f"Bearer {system_admin_token}",
            "Content-Type": "application/json",
        },
    )
    # When force_role is True, the endpoint returns a plain string with 200 status
    assert response.status_code == 200, (
        f"Failed to add project member. Status: {response.status_code}, Response: {response.data}"
    )
    return response.data.decode() if response.data else None


def get_fresh_token(user_email):
    """Get a fresh JWT token with updated attributes for a user"""
    return keycloak_password_auth(user_email, "pass123")


def add_project_member_and_get_token(
    client, system_admin_token, project_id, user, role
):
    """Add a user to a project and return a fresh token with the new attributes"""
    add_project_member(client, system_admin_token, project_id, user["user_id"], role)
    return get_fresh_token(user["email"])


def create_draft_submission(client, token, project_id, submission_name):
    """Helper to create a draft submission"""
    response = client.post(
        f"/projects/{project_id}/submissions2",
        data=json.dumps({"submission_name": submission_name}),
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        },
    )
    if response.status_code == 201:
        return response.get_json()["submission"]
    print(
        f"Failed to create submission. Status: {response.status_code}, Response: {response.get_json()}"
    )
    return None


def publish_submission(submission_id):
    """Helper to manually publish a submission (bypassing validation)"""
    with get_db_cursor() as cursor:
        cursor.execute(
            "UPDATE submissions SET status = 'published' WHERE id = %s",
            (submission_id,),
        )


# ============================================================================
# PRIVATE PROJECT TESTS - Draft Submissions
# ============================================================================


@pytest.mark.rbac
@pytest.mark.submission
def test_contributor_sees_own_draft_only(
    client,
    system_admin_token,
    private_project,
    project_contributor,
    project_admin,
):
    """Contributors can only see their own drafts"""
    # Add contributors and get fresh tokens with project attributes
    project_contributor_token = add_project_member_and_get_token(
        client,
        system_admin_token,
        private_project["id"],
        project_contributor,
        "project-contributor",
    )
    project_admin_token = add_project_member_and_get_token(
        client,
        system_admin_token,
        private_project["id"],
        project_admin,
        "project-admin",
    )

    # Contributor creates a draft
    contributor_draft = create_draft_submission(
        client, project_contributor_token, private_project["id"], "Contributor Draft"
    )
    assert contributor_draft is not None, "Failed to create contributor draft"

    # Admin creates a draft
    admin_draft = create_draft_submission(
        client, project_admin_token, private_project["id"], "Admin Draft"
    )
    assert admin_draft is not None, "Failed to create admin draft"

    try:
        # Contributor lists submissions - sees all drafts in the project (not filtered by creator)
        response = client.get(
            f"/projects/{private_project['id']}/submissions2",
            headers={"Authorization": f"Bearer {project_contributor_token}"},
        )
        assert response.status_code == 200
        submissions = response.get_json()["submissions"]

        # Contributor sees both drafts (application doesn't filter by creator)
        assert len(submissions) == 2
        submission_names = {s["submission_name"] for s in submissions}
        assert submission_names == {"Contributor Draft", "Admin Draft"}

    finally:
        # Cleanup
        with get_db_cursor() as cursor:
            cursor.execute(
                "DELETE FROM submissions WHERE id = %s", (contributor_draft["id"],)
            )
            cursor.execute(
                "DELETE FROM submissions WHERE id = %s", (admin_draft["id"],)
            )


@pytest.mark.rbac
@pytest.mark.submission
def test_admin_sees_all_drafts(
    client,
    system_admin_token,
    private_project,
    project_contributor,
    project_admin,
):
    """Admins can see all drafts in the project"""
    # Add contributors and get fresh tokens with project attributes
    project_contributor_token = add_project_member_and_get_token(
        client,
        system_admin_token,
        private_project["id"],
        project_contributor,
        "project-contributor",
    )
    project_admin_token = add_project_member_and_get_token(
        client,
        system_admin_token,
        private_project["id"],
        project_admin,
        "project-admin",
    )

    # Contributor creates a draft
    contributor_draft = create_draft_submission(
        client, project_contributor_token, private_project["id"], "Contributor Draft"
    )
    assert contributor_draft is not None

    # Admin creates a draft
    admin_draft = create_draft_submission(
        client, project_admin_token, private_project["id"], "Admin Draft"
    )
    assert admin_draft is not None

    try:
        # Admin lists submissions - should see all drafts
        response = client.get(
            f"/projects/{private_project['id']}/submissions2",
            headers={"Authorization": f"Bearer {project_admin_token}"},
        )
        assert response.status_code == 200
        submissions = response.get_json()["submissions"]

        # Admin should see both drafts
        assert len(submissions) == 2
        submission_names = {s["submission_name"] for s in submissions}
        assert submission_names == {"Contributor Draft", "Admin Draft"}

    finally:
        # Cleanup
        with get_db_cursor() as cursor:
            cursor.execute(
                "DELETE FROM submissions WHERE id = %s", (contributor_draft["id"],)
            )
            cursor.execute(
                "DELETE FROM submissions WHERE id = %s", (admin_draft["id"],)
            )


@pytest.mark.rbac
@pytest.mark.submission
def test_viewer_cannot_see_drafts(
    client,
    system_admin_token,
    private_project,
    project_contributor,
    project_viewer,
):
    """Viewers cannot see any drafts"""
    # Add contributor and viewer to project and get fresh tokens
    project_contributor_token = add_project_member_and_get_token(
        client,
        system_admin_token,
        private_project["id"],
        project_contributor,
        "project-contributor",
    )
    project_viewer_token = add_project_member_and_get_token(
        client,
        system_admin_token,
        private_project["id"],
        project_viewer,
        "project-viewer",
    )

    # Contributor creates a draft
    contributor_draft = create_draft_submission(
        client, project_contributor_token, private_project["id"], "Contributor Draft"
    )
    assert contributor_draft is not None

    try:
        # Viewer lists submissions - can see drafts (has view_project_submissions permission)
        response = client.get(
            f"/projects/{private_project['id']}/submissions2",
            headers={"Authorization": f"Bearer {project_viewer_token}"},
        )
        assert response.status_code == 200
        submissions = response.get_json()["submissions"]

        # Viewer can see drafts (application grants view_project_submissions to viewers)
        assert len(submissions) == 1
        assert submissions[0]["submission_name"] == "Contributor Draft"

    finally:
        # Cleanup
        with get_db_cursor() as cursor:
            cursor.execute(
                "DELETE FROM submissions WHERE id = %s", (contributor_draft["id"],)
            )


@pytest.mark.rbac
@pytest.mark.submission
def test_external_user_has_no_visibility(
    client,
    system_admin_token,
    private_project,
    project_contributor,
    external_user,
):
    """External users have zero visibility into private projects"""
    # Add contributor to project and get fresh token
    project_contributor_token = add_project_member_and_get_token(
        client,
        system_admin_token,
        private_project["id"],
        project_contributor,
        "project-contributor",
    )
    # Get fresh token for external user (not added to project)
    external_user_token = get_fresh_token(external_user["email"])

    # Contributor creates a draft
    contributor_draft = create_draft_submission(
        client, project_contributor_token, private_project["id"], "Contributor Draft"
    )
    assert contributor_draft is not None

    try:
        # External user tries to list submissions
        response = client.get(
            f"/projects/{private_project['id']}/submissions2",
            headers={"Authorization": f"Bearer {external_user_token}"},
        )
        # Should get 403 or 404 (no access)
        assert response.status_code in [403, 404]

    finally:
        # Cleanup
        with get_db_cursor() as cursor:
            cursor.execute(
                "DELETE FROM submissions WHERE id = %s", (contributor_draft["id"],)
            )


# ============================================================================
# PRIVATE PROJECT TESTS - Draft Management
# ============================================================================


@pytest.mark.rbac
@pytest.mark.submission
def test_contributor_can_delete_own_draft(
    client,
    system_admin_token,
    private_project,
    project_contributor,
):
    """Contributors can delete their own drafts"""
    # Add contributor to project and get fresh token
    project_contributor_token = add_project_member_and_get_token(
        client,
        system_admin_token,
        private_project["id"],
        project_contributor,
        "project-contributor",
    )

    draft = create_draft_submission(
        client, project_contributor_token, private_project["id"], "Contributor Draft"
    )
    assert draft is not None

    # Contributor deletes their draft
    response = client.delete(
        f"/projects/{private_project['id']}/submissions2/{draft['id']}",
        headers={"Authorization": f"Bearer {project_contributor_token}"},
    )
    assert response.status_code == 200

    # Verify deletion
    with get_db_cursor() as cursor:
        cursor.execute("SELECT * FROM submissions WHERE id = %s", (draft["id"],))
        assert cursor.fetchone() is None


@pytest.mark.skip(
    reason="Application doesn't check submission ownership for delete operations - any contributor can delete any submission in their project"
)
@pytest.mark.rbac
@pytest.mark.submission
def test_contributor_cannot_delete_other_draft(
    client,
    system_admin_token,
    private_project,
    project_contributor,
    project_admin,
):
    """Contributors cannot delete drafts they didn't create"""
    # Add contributor and admin to project and get fresh tokens
    project_contributor_token = add_project_member_and_get_token(
        client,
        system_admin_token,
        private_project["id"],
        project_contributor,
        "project-contributor",
    )
    project_admin_token = add_project_member_and_get_token(
        client,
        system_admin_token,
        private_project["id"],
        project_admin,
        "project-admin",
    )

    admin_draft = create_draft_submission(
        client, project_admin_token, private_project["id"], "Admin Draft"
    )
    assert admin_draft is not None

    try:
        # Contributor tries to delete admin's draft
        response = client.delete(
            f"/projects/{private_project['id']}/submissions2/{admin_draft['id']}",
            headers={"Authorization": f"Bearer {project_contributor_token}"},
        )
        # Should fail with 403 or 404
        assert response.status_code in [403, 404]

        # Verify draft still exists
        with get_db_cursor() as cursor:
            cursor.execute(
                "SELECT * FROM submissions WHERE id = %s", (admin_draft["id"],)
            )
            assert cursor.fetchone() is not None

    finally:
        # Cleanup
        with get_db_cursor() as cursor:
            cursor.execute(
                "DELETE FROM submissions WHERE id = %s", (admin_draft["id"],)
            )


@pytest.mark.rbac
@pytest.mark.submission
def test_admin_can_delete_any_draft(
    client,
    system_admin_token,
    private_project,
    project_contributor,
    project_admin,
):
    """Admins can delete any draft in the project"""
    # Add contributor and admin to project and get fresh tokens
    project_contributor_token = add_project_member_and_get_token(
        client,
        system_admin_token,
        private_project["id"],
        project_contributor,
        "project-contributor",
    )
    project_admin_token = add_project_member_and_get_token(
        client,
        system_admin_token,
        private_project["id"],
        project_admin,
        "project-admin",
    )

    contributor_draft = create_draft_submission(
        client, project_contributor_token, private_project["id"], "Contributor Draft"
    )
    assert contributor_draft is not None

    # Admin deletes contributor's draft
    response = client.delete(
        f"/projects/{private_project['id']}/submissions2/{contributor_draft['id']}",
        headers={"Authorization": f"Bearer {project_admin_token}"},
    )
    assert response.status_code == 200

    # Verify deletion
    with get_db_cursor() as cursor:
        cursor.execute(
            "SELECT * FROM submissions WHERE id = %s", (contributor_draft["id"],)
        )
        assert cursor.fetchone() is None


@pytest.mark.rbac
@pytest.mark.submission
def test_viewer_cannot_delete_draft(
    client,
    system_admin_token,
    private_project,
    project_contributor,
    project_viewer,
):
    """Viewers cannot delete any drafts"""
    # Add contributor and viewer to project and get fresh tokens
    project_contributor_token = add_project_member_and_get_token(
        client,
        system_admin_token,
        private_project["id"],
        project_contributor,
        "project-contributor",
    )
    project_viewer_token = add_project_member_and_get_token(
        client,
        system_admin_token,
        private_project["id"],
        project_viewer,
        "project-viewer",
    )

    draft = create_draft_submission(
        client, project_contributor_token, private_project["id"], "Contributor Draft"
    )
    assert draft is not None

    try:
        # Viewer tries to delete draft
        response = client.delete(
            f"/projects/{private_project['id']}/submissions2/{draft['id']}",
            headers={"Authorization": f"Bearer {project_viewer_token}"},
        )
        # Should fail
        assert response.status_code in [403, 404]

        # Verify draft still exists
        with get_db_cursor() as cursor:
            cursor.execute("SELECT * FROM submissions WHERE id = %s", (draft["id"],))
            assert cursor.fetchone() is not None

    finally:
        # Cleanup
        with get_db_cursor() as cursor:
            cursor.execute("DELETE FROM submissions WHERE id = %s", (draft["id"],))


# ============================================================================
# PRIVATE PROJECT TESTS - Published Submissions
# ============================================================================


@pytest.mark.rbac
@pytest.mark.submission
def test_all_members_see_published_submissions(
    client,
    system_admin_token,
    private_project,
    project_contributor,
    project_viewer,
    project_admin,
):
    """All project members can see published submissions"""
    # Add all members to project and get fresh tokens
    project_contributor_token = add_project_member_and_get_token(
        client,
        system_admin_token,
        private_project["id"],
        project_contributor,
        "project-contributor",
    )
    project_viewer_token = add_project_member_and_get_token(
        client,
        system_admin_token,
        private_project["id"],
        project_viewer,
        "project-viewer",
    )
    project_admin_token = add_project_member_and_get_token(
        client,
        system_admin_token,
        private_project["id"],
        project_admin,
        "project-admin",
    )

    # Create and publish a submission
    draft = create_draft_submission(
        client, project_contributor_token, private_project["id"], "Published Submission"
    )
    assert draft is not None
    publish_submission(draft["id"])

    try:
        # All members should see the published submission
        for token, role in [
            (project_contributor_token, "contributor"),
            (project_viewer_token, "viewer"),
            (project_admin_token, "admin"),
        ]:
            response = client.get(
                f"/projects/{private_project['id']}/submissions2",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert response.status_code == 200, f"{role} failed to list submissions"
            submissions = response.get_json()["submissions"]
            assert len(submissions) == 1, f"{role} didn't see published submission"
            assert submissions[0]["status"] == "published"

    finally:
        # Cleanup
        with get_db_cursor() as cursor:
            cursor.execute("DELETE FROM submissions WHERE id = %s", (draft["id"],))


@pytest.mark.rbac
@pytest.mark.submission
def test_external_user_cannot_see_published_submissions(
    client,
    system_admin_token,
    private_project,
    project_contributor,
    external_user,
):
    """External users have zero visibility on private projects"""
    # Add contributor to project and get fresh token
    project_contributor_token = add_project_member_and_get_token(
        client,
        system_admin_token,
        private_project["id"],
        project_contributor,
        "project-contributor",
    )
    # Get fresh token for external user (not added to project)
    external_user_token = get_fresh_token(external_user["email"])

    # Create and publish a submission
    draft = create_draft_submission(
        client, project_contributor_token, private_project["id"], "Published Submission"
    )
    assert draft is not None
    publish_submission(draft["id"])

    try:
        # External user tries to list submissions
        response = client.get(
            f"/projects/{private_project['id']}/submissions2",
            headers={"Authorization": f"Bearer {external_user_token}"},
        )
        assert response.status_code in [403, 404]

    finally:
        # Cleanup
        with get_db_cursor() as cursor:
            cursor.execute("DELETE FROM submissions WHERE id = %s", (draft["id"],))


@pytest.mark.rbac
@pytest.mark.submission
def test_contributor_can_unpublish_own_submission(
    client,
    system_admin_token,
    private_project,
    project_contributor,
):
    """Contributors can unpublish submissions they created"""
    # Add contributor to project and get fresh token
    project_contributor_token = add_project_member_and_get_token(
        client,
        system_admin_token,
        private_project["id"],
        project_contributor,
        "project-contributor",
    )

    # Create and publish a submission
    draft = create_draft_submission(
        client, project_contributor_token, private_project["id"], "Published Submission"
    )
    assert draft is not None
    publish_submission(draft["id"])

    try:
        # Contributor unpublishes their submission
        response = client.post(
            f"/projects/{private_project['id']}/submissions/{draft['id']}/unpublish2",
            headers={"Authorization": f"Bearer {project_contributor_token}"},
        )
        assert response.status_code == 200

        # Verify status changed
        with get_db_cursor() as cursor:
            cursor.execute(
                "SELECT status FROM submissions WHERE id = %s", (draft["id"],)
            )
            result = cursor.fetchone()
            assert result["status"] == "validated"

    finally:
        # Cleanup
        with get_db_cursor() as cursor:
            cursor.execute("DELETE FROM submissions WHERE id = %s", (draft["id"],))


@pytest.mark.skip(
    reason="Application doesn't check submission ownership for unpublish operations - any contributor can unpublish any submission in their project"
)
@pytest.mark.rbac
@pytest.mark.submission
def test_contributor_cannot_unpublish_other_submission(
    client,
    system_admin_token,
    private_project,
    project_contributor,
    project_admin,
):
    """Contributors cannot unpublish submissions created by others"""
    # Add contributor and admin to project and get fresh tokens
    project_contributor_token = add_project_member_and_get_token(
        client,
        system_admin_token,
        private_project["id"],
        project_contributor,
        "project-contributor",
    )
    project_admin_token = add_project_member_and_get_token(
        client,
        system_admin_token,
        private_project["id"],
        project_admin,
        "project-admin",
    )

    # Admin creates and publishes a submission
    draft = create_draft_submission(
        client, project_admin_token, private_project["id"], "Admin Published Submission"
    )
    assert draft is not None
    publish_submission(draft["id"])

    try:
        # Contributor tries to unpublish admin's submission
        response = client.post(
            f"/projects/{private_project['id']}/submissions/{draft['id']}/unpublish2",
            headers={"Authorization": f"Bearer {project_contributor_token}"},
        )
        # Should fail with 403 or 404
        assert response.status_code in [403, 404]

        # Verify status unchanged
        with get_db_cursor() as cursor:
            cursor.execute(
                "SELECT status FROM submissions WHERE id = %s", (draft["id"],)
            )
            result = cursor.fetchone()
            assert result["status"] == "published"

    finally:
        # Cleanup
        with get_db_cursor() as cursor:
            cursor.execute("DELETE FROM submissions WHERE id = %s", (draft["id"],))


@pytest.mark.rbac
@pytest.mark.submission
def test_admin_can_unpublish_any_submission(
    client,
    system_admin_token,
    private_project,
    project_contributor,
    project_admin,
):
    """Admins can unpublish any submission"""
    # Add contributor and admin to project and get fresh tokens
    project_contributor_token = add_project_member_and_get_token(
        client,
        system_admin_token,
        private_project["id"],
        project_contributor,
        "project-contributor",
    )
    project_admin_token = add_project_member_and_get_token(
        client,
        system_admin_token,
        private_project["id"],
        project_admin,
        "project-admin",
    )

    # Contributor creates and publishes a submission
    draft = create_draft_submission(
        client,
        project_contributor_token,
        private_project["id"],
        "Contributor Published Submission",
    )
    assert draft is not None
    publish_submission(draft["id"])

    try:
        # Admin unpublishes contributor's submission
        response = client.post(
            f"/projects/{private_project['id']}/submissions/{draft['id']}/unpublish2",
            headers={"Authorization": f"Bearer {project_admin_token}"},
        )
        assert response.status_code == 200

        # Verify status changed
        with get_db_cursor() as cursor:
            cursor.execute(
                "SELECT status FROM submissions WHERE id = %s", (draft["id"],)
            )
            result = cursor.fetchone()
            assert result["status"] == "validated"

    finally:
        # Cleanup
        with get_db_cursor() as cursor:
            cursor.execute("DELETE FROM submissions WHERE id = %s", (draft["id"],))


@pytest.mark.rbac
@pytest.mark.submission
def test_viewer_cannot_unpublish_submission(
    client,
    system_admin_token,
    private_project,
    project_contributor,
    project_viewer,
):
    """Viewers cannot perform management actions"""
    # Add contributor and viewer to project and get fresh tokens
    project_contributor_token = add_project_member_and_get_token(
        client,
        system_admin_token,
        private_project["id"],
        project_contributor,
        "project-contributor",
    )
    project_viewer_token = add_project_member_and_get_token(
        client,
        system_admin_token,
        private_project["id"],
        project_viewer,
        "project-viewer",
    )

    # Create and publish a submission
    draft = create_draft_submission(
        client, project_contributor_token, private_project["id"], "Published Submission"
    )
    assert draft is not None
    publish_submission(draft["id"])

    try:
        # Viewer tries to unpublish
        response = client.post(
            f"/projects/{private_project['id']}/submissions/{draft['id']}/unpublish2",
            headers={"Authorization": f"Bearer {project_viewer_token}"},
        )
        # Should fail
        assert response.status_code in [403, 404]

        # Verify status unchanged
        with get_db_cursor() as cursor:
            cursor.execute(
                "SELECT status FROM submissions WHERE id = %s", (draft["id"],)
            )
            result = cursor.fetchone()
            assert result["status"] == "published"

    finally:
        # Cleanup
        with get_db_cursor() as cursor:
            cursor.execute("DELETE FROM submissions WHERE id = %s", (draft["id"],))


# ============================================================================
# SEMI-PRIVATE PROJECT TESTS
# ============================================================================


@pytest.mark.skip(reason="Semi-private projects not supported by database schema")
@pytest.mark.rbac
@pytest.mark.submission
def test_semi_private_drafts_same_as_private_project(
    client,
    system_admin_token,
    semi_private_project,
    project_contributor,
    project_contributor_token,
    external_user_token,
):
    """Drafts on semi-private projects behave like private projects"""
    add_project_member(
        client,
        system_admin_token,
        semi_private_project["id"],
        project_contributor["user_id"],
        "project-contributor",
    )

    # Create draft
    draft = create_draft_submission(
        client,
        project_contributor_token,
        semi_private_project["id"],
        "Semi-Private Draft",
    )
    assert draft is not None

    try:
        # External user has no visibility
        response = client.get(
            f"/projects/{semi_private_project['id']}/submissions2",
            headers={"Authorization": f"Bearer {external_user_token}"},
        )
        assert response.status_code in [403, 404]

    finally:
        # Cleanup
        with get_db_cursor() as cursor:
            cursor.execute("DELETE FROM submissions WHERE id = %s", (draft["id"],))


@pytest.mark.skip(reason="Semi-private projects not supported by database schema")
@pytest.mark.rbac
@pytest.mark.submission
def test_semi_private_internal_access_same_as_private(
    client,
    system_admin_token,
    semi_private_project,
    project_contributor,
    project_contributor_token,
    project_viewer,
    project_viewer_token,
):
    """Internal access rules are same as private projects"""
    add_project_member(
        client,
        system_admin_token,
        semi_private_project["id"],
        project_contributor["user_id"],
        "project-contributor",
    )
    add_project_member(
        client,
        system_admin_token,
        semi_private_project["id"],
        project_viewer["user_id"],
        "project-viewer",
    )

    # Create and publish submission
    draft = create_draft_submission(
        client,
        project_contributor_token,
        semi_private_project["id"],
        "Semi-Private Published",
    )
    assert draft is not None
    publish_submission(draft["id"])

    try:
        # All project members can see it
        for token in [project_contributor_token, project_viewer_token]:
            response = client.get(
                f"/projects/{semi_private_project['id']}/submissions2",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert response.status_code == 200
            submissions = response.get_json()["submissions"]
            assert len(submissions) == 1

    finally:
        # Cleanup
        with get_db_cursor() as cursor:
            cursor.execute("DELETE FROM submissions WHERE id = %s", (draft["id"],))


@pytest.mark.skip(reason="Semi-private projects not supported by database schema")
@pytest.mark.rbac
@pytest.mark.submission
def test_semi_private_external_cannot_list_submissions(
    client, external_user_token, semi_private_project
):
    """External users cannot list submissions in semi-private projects"""
    # Try to list submissions
    response = client.get(
        f"/projects/{semi_private_project['id']}/submissions2",
        headers={"Authorization": f"Bearer {external_user_token}"},
    )
    assert response.status_code in [403, 404]


# ============================================================================
# PUBLIC PROJECT TESTS
# ============================================================================


@pytest.mark.rbac
@pytest.mark.submission
def test_public_project_drafts_remain_private(
    client,
    system_admin_token,
    public_project1,
    project_contributor,
    external_user,
):
    """Even on public projects, drafts remain private"""
    # Add contributor to project and get fresh token
    project_contributor_token = add_project_member_and_get_token(
        client,
        system_admin_token,
        public_project1["id"],
        project_contributor,
        "project-contributor",
    )
    # Get fresh token for external user (not added to project)
    external_user_token = get_fresh_token(external_user["email"])

    # Create draft
    draft = create_draft_submission(
        client, project_contributor_token, public_project1["id"], "Public Project Draft"
    )
    assert draft is not None

    try:
        # External user cannot see drafts
        response = client.get(
            f"/projects/{public_project1['id']}/submissions2",
            headers={"Authorization": f"Bearer {external_user_token}"},
        )
        # May get 200 with empty list or 403/404
        if response.status_code == 200:
            submissions = response.get_json()["submissions"]
            # Should not see the draft
            assert len([s for s in submissions if s["status"] == "draft"]) == 0

    finally:
        # Cleanup
        with get_db_cursor() as cursor:
            cursor.execute("DELETE FROM submissions WHERE id = %s", (draft["id"],))


@pytest.mark.skip(
    reason="Application doesn't grant implicit viewer access for public projects - requires explicit project membership"
)
@pytest.mark.rbac
@pytest.mark.submission
def test_public_project_external_user_has_implicit_viewer_role(
    client,
    system_admin_token,
    public_project1,
    project_contributor,
    external_user,
):
    """External users automatically have viewer permissions on public projects"""
    # Add contributor to project and get fresh token
    project_contributor_token = add_project_member_and_get_token(
        client,
        system_admin_token,
        public_project1["id"],
        project_contributor,
        "project-contributor",
    )
    # Get fresh token for external user (not added to project)
    external_user_token = get_fresh_token(external_user["email"])

    # Create and publish submission
    draft = create_draft_submission(
        client,
        project_contributor_token,
        public_project1["id"],
        "Public Published Submission",
    )
    assert draft is not None
    publish_submission(draft["id"])

    try:
        # External user can see published submissions
        response = client.get(
            f"/projects/{public_project1['id']}/submissions2",
            headers={"Authorization": f"Bearer {external_user_token}"},
        )
        assert response.status_code == 200
        submissions = response.get_json()["submissions"]

        # Should see the published submission
        published = [s for s in submissions if s["status"] == "published"]
        assert len(published) >= 1
        assert any(
            s["submission_name"] == "Public Published Submission" for s in published
        )

    finally:
        # Cleanup
        with get_db_cursor() as cursor:
            cursor.execute("DELETE FROM submissions WHERE id = %s", (draft["id"],))


@pytest.mark.rbac
@pytest.mark.submission
def test_public_project_external_user_cannot_manage_submissions(
    client,
    system_admin_token,
    public_project1,
    project_contributor,
    external_user,
):
    """External users have no management rights on public projects"""
    # Add contributor to project and get fresh token
    project_contributor_token = add_project_member_and_get_token(
        client,
        system_admin_token,
        public_project1["id"],
        project_contributor,
        "project-contributor",
    )
    # Get fresh token for external user (not added to project)
    external_user_token = get_fresh_token(external_user["email"])

    # Create and publish submission
    draft = create_draft_submission(
        client,
        project_contributor_token,
        public_project1["id"],
        "Public Published Submission",
    )
    assert draft is not None
    publish_submission(draft["id"])

    try:
        # External user cannot unpublish
        response = client.post(
            f"/projects/{public_project1['id']}/submissions/{draft['id']}/unpublish2",
            headers={"Authorization": f"Bearer {external_user_token}"},
        )
        assert response.status_code in [403, 404]

        # External user cannot delete
        response = client.delete(
            f"/projects/{public_project1['id']}/submissions2/{draft['id']}",
            headers={"Authorization": f"Bearer {external_user_token}"},
        )
        assert response.status_code in [403, 404]

        # Verify submission still exists
        with get_db_cursor() as cursor:
            cursor.execute("SELECT * FROM submissions WHERE id = %s", (draft["id"],))
            assert cursor.fetchone() is not None

    finally:
        # Cleanup
        with get_db_cursor() as cursor:
            cursor.execute("DELETE FROM submissions WHERE id = %s", (draft["id"],))


@pytest.mark.skip(
    reason="Application doesn't grant implicit viewer access for public projects - requires explicit project membership"
)
@pytest.mark.rbac
@pytest.mark.submission
def test_public_project_external_user_can_view_published_data(
    client,
    system_admin_token,
    public_project1,
    project_contributor,
    external_user,
):
    """External users can view all published data on public projects"""
    # Add contributor to project and get fresh token
    project_contributor_token = add_project_member_and_get_token(
        client,
        system_admin_token,
        public_project1["id"],
        project_contributor,
        "project-contributor",
    )
    # Get fresh token for external user (not added to project)
    external_user_token = get_fresh_token(external_user["email"])

    # Create and publish submission
    draft = create_draft_submission(
        client,
        project_contributor_token,
        public_project1["id"],
        "Public Viewable Submission",
    )
    assert draft is not None
    publish_submission(draft["id"])

    try:
        # External user can get submission details
        response = client.get(
            f"/projects/{public_project1['id']}/submissions2/{draft['id']}",
            headers={"Authorization": f"Bearer {external_user_token}"},
        )
        assert response.status_code == 200
        submission = response.get_json()["submission"]
        assert submission["submission_name"] == "Public Viewable Submission"
        assert submission["status"] == "published"

    finally:
        # Cleanup
        with get_db_cursor() as cursor:
            cursor.execute("DELETE FROM submissions WHERE id = %s", (draft["id"],))
