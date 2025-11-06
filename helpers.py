from email import message
import subprocess
import json
import hashlib
import requests
import settings
from flask import render_template_string
from auth import KeycloakAuth
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import (
    Mail,
    From,
    To,
    Attachment,
    FileContent,
    FileName,
    FileType,
    Disposition,
    ContentId,
)
import base64

from database import get_db_cursor
from settings import (
    SENDGRID_API_KEY,
    SENDGRID_FROM_EMAIL,
    SENDGRID_FROM_NAME,
    KEYCLOAK_URL,
    KEYCLOAK_REALM,
    KEYCLOAK_CLIENT_ID,
    KEYCLOAK_CLIENT_SECRET,
)

sg_api_key = SENDGRID_API_KEY
sg_from_email = SENDGRID_FROM_EMAIL
sg_from_name = SENDGRID_FROM_NAME

sg = SendGridAPIClient(sg_api_key)

keycloak_auth = KeycloakAuth(
    keycloak_url=KEYCLOAK_URL,
    realm=KEYCLOAK_REALM,
    client_id=KEYCLOAK_CLIENT_ID,
    client_secret=KEYCLOAK_CLIENT_SECRET,
)


def sendgrid_email(to_email, to_name, subject, html_content):
    message = Mail(
        from_email=From(sg_from_email, sg_from_name),
        to_emails=To(to_email, to_name),
        subject=subject,
        html_content=html_content,
    )

    with open("email_templates/agari_logo.png", "rb") as f:
        data = f.read()
        encoded_file = base64.b64encode(data).decode()
    attachment = Attachment(
        FileContent(encoded_file),
        FileName("agari_logo.png"),
        FileType("image/png"),
        Disposition("inline"),
        ContentId("agari_logo"),
    )
    message.add_attachment(attachment)

    if sg_api_key != "":
        response = sg.send(message)
        return response, response.status_code
    else:
        return {"error": "Email not configured"}, 204


def mjml_to_html(template_name):
    result = subprocess.run(
        ["mjml", f"email_templates/{template_name}.mjml", "--stdout"],
        capture_output=True,
        text=True,
        check=True,
    )
    html_template = result.stdout
    return html_template


def magic_link(email, redirect_uri, expiration_seconds=600, send_email=True):
    admin_token = keycloak_auth.get_admin_token()
    if not admin_token:
        return {"error": "Failed to authenticate with Keycloak admin"}, 500
    headers = {
        "Authorization": f"Bearer {admin_token}",
        "Content-Type": "application/json",
    }
    payload = {
        "email": email,
        "client_id": keycloak_auth.client_id,
        "redirect_uri": redirect_uri,
        "expiration_seconds": expiration_seconds,
        "force_create": True,
        "reusable": False,
        "send_email": False,
    }
    magic_link_url = (
        f"{keycloak_auth.keycloak_url}/realms/{keycloak_auth.realm}/magic-link"
    )
    keycloak_response = requests.post(magic_link_url, headers=headers, json=payload)
    response_data = json.loads(keycloak_response.content.decode("utf-8"))

    if send_email:
        # Manually send magic link
        html_template = mjml_to_html("magic_link")
        html_content = render_template_string(
            html_template, magic_link=response_data["link"]
        )
        sendgrid_email(email, "", "Your AGARI sign-in link", html_content)
        message = "Magic link sent successfully"
    else:
        message = "Magic link created successfully (email not sent)"

    if keycloak_response.status_code == 200:
        response_data = keycloak_response.json()
        return {
            "message": message,
            "email": email,
            "user_id": response_data.get("user_id"),
        }, 200
    else:
        return {"error": f"Failed to create magic link."}, 500


def quiet_create_user(email, redirect_uri):
    keycloak_response = magic_link(email, redirect_uri, 0, False)

    return keycloak_response


def invite_user_to_project(user, redirect_uri, project_id, role):
    if user.get("attributes"):
        name = user["attributes"].get("name", [""])[0]
        surname = user["attributes"].get("surname", [""])[0]
        to_name = f"{name} {surname}".strip()
    else:
        to_name = ""
    to_email = user["email"]
    subject = "You've been invited to AGARI"

    # Get project name
    with get_db_cursor() as cursor:
        cursor.execute(
            """
            SELECT *
            FROM projects
            WHERE id = %s AND deleted_at IS NULL
        """,
            (project_id,),
        )
        project = cursor.fetchone()
        if not project:
            return {"error": "Project not found"}, 404

    hash_string = f"{user['id']}{project_id}"
    inv_token = hashlib.md5(hash_string.encode()).hexdigest()
    accept_link = (
        f"{redirect_uri}/accept-invite-project?userid={user['id']}&token={inv_token}"
    )

    html_template = mjml_to_html("project_invite")
    html_content = render_template_string(
        html_template, project_name=project["name"], accept_link=accept_link
    )

    result, status_code = sendgrid_email(to_email, to_name, subject, html_content)

    if status_code in [200, 201, 202, 204]:
        # assign temp invite attributes to user
        keycloak_auth.add_attribute_value(user["id"], "invite_token", inv_token)
        keycloak_auth.add_attribute_value(user["id"], "invite_project_id", project_id)
        keycloak_auth.add_attribute_value(user["id"], f"invite_role_{project_id}", role)
        if status_code == 204:
            return f"Invite created without sending email"
        else:
            return f"Invitation email sent successfully"
    else:
        return {"error": "Failed to send invitation email"}, 500


def invite_user_to_org(user, redirect_uri, org_id, role):
    if user.get("attributes"):
        name = user["attributes"].get("name", [""])[0]
        surname = user["attributes"].get("surname", [""])[0]
        to_name = f"{name} {surname}".strip()
    else:
        to_name = ""
    to_email = user["email"]

    with get_db_cursor() as cursor:
        cursor.execute(
            """
            SELECT *
            FROM organisations
            WHERE id = %s AND deleted_at IS NULL
        """,
            (org_id,),
        )
        org = cursor.fetchone()
        if not org:
            return {"error": "Organisation not found"}, 404

    hash_string = f"{user['id']}{org_id}"
    inv_token = hashlib.md5(hash_string.encode()).hexdigest()

    accept_link = f"{redirect_uri}/accept-invite-org?userid={user['id']}&token={inv_token}"  #

    if role == "org-owner":
        subject = f"Invitation: Become the Owner of {org["name"]}"
        html_template = mjml_to_html("org_ownership")
    else:
        subject = "You've been invited to AGARI"
        html_template = mjml_to_html("new_user")
    html_content = render_template_string(
        html_template, org_name=org["name"], accept_link=accept_link
    )
    result, status_code = sendgrid_email(to_email, to_name, subject, html_content)

    if status_code in [200, 201, 202, 204]:
        # assign temp invite attributes to user
        keycloak_auth.add_attribute_value(user["id"], "invite_org_token", inv_token)
        keycloak_auth.add_attribute_value(user["id"], "invite_org_id", org_id)
        keycloak_auth.add_attribute_value(user["id"], f"invite_org_role_{org_id}", role)
        if status_code == 204:
            return f"Email not sent"
        else:
            return f"Invitation email sent successfully"
    else:
        return {"error": "Failed to send invitation email"}, 500


def role_user(user_id, project_id, role):
    # Remove user from all existing project roles first (role hierarchy enforcement)
    removed_roles = []
    for existing_role in ["project-admin", "project-contributor", "project-viewer"]:
        if keycloak_auth.user_has_attribute(user_id, existing_role, project_id):
            success = keycloak_auth.remove_attribute_value(
                user_id, existing_role, project_id
            )
            if success:
                removed_roles.append(existing_role)
                print(
                    f"Removed project_id {project_id} from role {existing_role} for user {user_id}"
                )
            else:
                return {"error": f"Failed to remove existing role {existing_role}"}, 500

    # Add the user to the new role
    success = keycloak_auth.add_attribute_value(user_id, role, project_id)
    if not success:
        return {"error": f"Failed to add user to role {role}"}, 500
    return removed_roles


def access_revoked_notification(user_id):
    user = keycloak_auth.get_user(user_id)

    to_email = user["email"]
    to_name = ""
    subject = "Regarding your AGARI account"

    html_template = mjml_to_html("revoke_access")
    html_content = render_template_string(html_template)

    sendgrid_email(to_email, to_name, subject, html_content)


def log_event(log_type, resource_id, log_entry):
    try:
        with get_db_cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO logs (log_type, resource_id, log_entry)
                VALUES (%s, %s, %s)
                """,
                (log_type, resource_id, log_entry),
            )
            return True

    except Exception as e:
        print(f"Error saving submission log: {e}")
        return False


def log_submission(submission_id, user_id, status, message):
    try:
        with get_db_cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO submissions_log (submission_id, user_id, status, message)
                VALUES (%s, %s, %s, %s)
                """,
                (submission_id, user_id, status, json.dumps(message)),
            )
            return True

    except Exception as e:
        print(f"Error saving submission log: {e}")
        return False


def tsv_to_json(tsv_string):
    lines = tsv_string.strip().split("\n")
    headers = lines[0].split("\t")
    json_list = []

    for line in lines[1:]:
        values = line.split("\t")
        record = {headers[i]: values[i] for i in range(len(headers))}
        json_list.append(record)

    return json_list


def send_to_elastic(index, document):
    es_url = settings.ELASTICSEARCH_URL

    # Extract document ID if provided
    doc_id = document.pop("_id", None) if isinstance(document, dict) else None

    if doc_id:
        # Use PUT with specific document ID to avoid duplicates
        es_index_url = f"{es_url}/{index}/_doc/{doc_id}"
        method = requests.put
    else:
        # Use POST to auto-generate document ID
        es_index_url = f"{es_url}/{index}/_doc"
        method = requests.post

    try:
        response = method(es_index_url, json=document)
        if response.status_code in [200, 201]:
            print(f"Successfully indexed document to {index}")
            return True
        else:
            print(f"Failed to index document: {response.text}")
            return False
    except Exception as e:
        print(f"Error sending document to Elasticsearch: {e}")
        return False


def remove_from_elastic(index, doc_id):
    es_url = settings.ELASTICSEARCH_URL
    es_delete_url = f"{es_url}/{index}/_doc/{doc_id}"

    try:
        response = requests.delete(es_delete_url)
        if response.status_code in [
            200,
            404,
        ]:  # 404 means document doesn't exist, which is OK
            print(f"Successfully removed document {doc_id} from {index}")
            return True
        else:
            print(f"Failed to remove document: {response.text}")
            return False
    except Exception as e:
        print(f"Error removing document from Elasticsearch: {e}")
        return False


def remove_samples_from_elastic(analysis_id):
    """Remove all sample documents for a specific analysis from Elasticsearch"""
    es_url = settings.ELASTICSEARCH_URL

    # Use delete by query to remove all sample documents for this analysis
    delete_query = {"query": {"term": {"analysisId.keyword": analysis_id}}}

    es_delete_url = f"{es_url}/agari-samples/_delete_by_query"

    try:
        response = requests.post(
            es_delete_url,
            json=delete_query,
            headers={"Content-Type": "application/json"},
        )
        if response.status_code in [200, 409]:  # 409 can happen if no documents found
            result = response.json()
            deleted_count = result.get("deleted", 0)
            print(
                f"Successfully removed {deleted_count} sample documents for analysis {analysis_id}"
            )
            return True
        else:
            print(f"Failed to remove sample documents: {response.text}")
            return False
    except Exception as e:
        print(f"Error removing sample documents from Elasticsearch: {e}")
        return False


def check_user_id(data, param_id):
    user_id = data.get(param_id)

    if not user_id:
        return {"error": "User ID is required"}, 400

    # Check if user exists in Keycloak
    user = keycloak_auth.get_user(user_id)
    if not user:
        return {"error": f"User {user_id} not found in Keycloak"}, 404
    return user
