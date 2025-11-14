from email import message
import subprocess
import json
from datetime import datetime, date
import hashlib
import asyncio
import random
import uuid
import requests
import settings
from jsonschema import validate, ValidationError, Draft7Validator
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
from minio import Minio

from database import get_db_cursor
import os
from typing import Any, Dict

SCHEMAS_DIR = os.path.join(os.path.dirname(__file__), "test", "data")

def load_json_schema(filename: str) -> Dict[str, Any]:
    
    """
    Load a JSON Schema from the helpers/schemas directory (or absolute path).
    Usage: schema = load_json_schema("my_schema.json") or load_json_schema("my_schema")
    """

    # allow passing either "name.json" or "name"
    if not filename.endswith(".json"):
        filename = f"{filename}.json"

    path = filename if os.path.isabs(filename) else os.path.join(SCHEMAS_DIR, filename)

    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)




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

    accept_link = (
        f"{redirect_uri}/accept-invite-org?userid={user['id']}&token={inv_token}"
    )

    if role == "org-owner":
        subject = f"Invitation: Become the Owner of {org['name']}"
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


def invite_email_change(user, redirect_uri, new_email):
    if user.get("attributes"):
        name = user["attributes"].get("name", [""])[0]
        surname = user["attributes"].get("surname", [""])[0]
        to_name = f"{name} {surname}".strip()
    else:
        to_name = ""
    to_email = new_email
    subject = "Confirm your new email for AGARI"

    hash_string = f"{user['user_id']}"
    inv_token = hashlib.md5(hash_string.encode()).hexdigest()
    accept_link = (
        f"{redirect_uri}/confirm-email-change?userid={user['user_id']}&token={inv_token}"
    )

    html_template = mjml_to_html("change_email")
    html_content = render_template_string(
        html_template, accept_link=accept_link
    )

    result, status_code = sendgrid_email(to_email, to_name, subject, html_content)

    user_id = "af52b5d2-29bc-4b5d-ac65-2c1bc5583368" # user["user_id"]
    if status_code in [200, 201, 202, 204]:
        # assign temp invite attributes to user
        keycloak_auth.add_attribute_value(user_id, "invite_token", inv_token)
        keycloak_auth.add_attribute_value(user_id, "invite_new_email", new_email)
        if status_code == 204:
            return f"Email confirmation created without sending notification"
        else:
            return f"Confirmation email sent successfully"
    else:
        return {"error": "Failed to send confirmation email"}, 500


def role_project_member(user_id, project_id, role):
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


def role_org_member(user_id, org_id, role):
    # Prepare update data with proper structure
    update_data = {
        "attributes": {"organisation_id": [org_id]},
        "realm_roles": [f"agari-{role}"],
    }
    keycloak_auth.remove_realm_roles(user_id)
    result = keycloak_auth.update_user(user_id, update_data)
    return result


def access_revoked_notification(user_id):
    user = keycloak_auth.get_user(user_id)

    to_email = user["email"]
    to_name = ""
    subject = "Regarding your AGARI account"

    html_template = mjml_to_html("revoke_access")
    html_content = render_template_string(html_template)

    sendgrid_email(to_email, to_name, subject, html_content)


def extract_invite_roles(users_list, invite_type):
    result = []

    for user in users_list:
        user_id = user.get("user_id")
        attributes = user.get("attributes", {})

        role = None
        for key, value in attributes.items():
            if key.startswith(f"invite_{invite_type}role_"):
                role = value[0] if isinstance(value, list) and value else value

        if role:
            result.append({"user_id": user_id, "invite_role": role})

    return result


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


def check_user_id(data, param_id):
    user_id = data.get(param_id)

    if not user_id:
        return {"error": "User ID is required"}, 400

    # Check if user exists in Keycloak
    user = keycloak_auth.get_user(user_id)
    if not user:
        return {"error": f"User {user_id} not found in Keycloak"}, 404
    return user


#############################
### SUBMISSION HELPERS
#############################


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

def get_minio_client(self):
    """Get MinIO client instance"""
    try:
        from minio import Minio
        
        # Get MinIO settings
        minio_endpoint = settings.MINIO_ENDPOINT
        minio_access_key = settings.MINIO_ACCESS_KEY
        minio_secret_key = settings.MINIO_SECRET_KEY
        minio_secure = getattr(settings, 'MINIO_SECURE', False)
        
        client = Minio(
            endpoint=minio_endpoint,
            access_key=minio_access_key,
            secret_key=minio_secret_key,
            secure=minio_secure
        )
        
        # Ensure bucket exists
        bucket_name = settings.MINIO_BUCKET or 'agari-data'
        if not client.bucket_exists(bucket_name):
            client.make_bucket(bucket_name)
        
        return client
        
    except Exception as e:
        raise e

##############################
### VALIDATION HELPERS
##############################

def validate_against_schema(data, row, schema_info):
    schemas = load_json_schema("schemas-all.json")

    schema_name = schema_info.get("schema")
    schema_version = schema_info.get("version")


    resultset = schemas["schemas"]

    resultset_schema = [
        s for s in resultset 
        if s.get("name") == schema_name and s.get("version") == schema_version
    ]
    
    if not resultset_schema:
        return False, f"Schema '{schema_name}' version {schema_version} not found"
    
    schema_obj = resultset_schema[0]["schema"]

    all_errors = []
    
    validator = Draft7Validator(schema_obj)
    
    # Collect all validation errors for this specific row
    for error in validator.iter_errors(data):
        error_info = {
            "row": row,
            "field": ".".join(str(x) for x in error.path) if error.path else "root",
            "invalid_value": error.instance,
            "message": error.message,
            "description": error.schema.get("description", "")
        }
        all_errors.append(error_info)
 
    if all_errors:
        return False, all_errors
    return True, None

##############################
### SPLIT WORK
##############################



def get_isolate_fasta(id):
    with get_db_cursor() as cursor:
        cursor.execute(
            """
            SELECT isolate_data
            FROM isolates
            WHERE id = %s AND deleted_at IS NULL
        """,
            (id,),
        )
        isolate = cursor.fetchone()
        if not isolate:
            return None

    isolate_data = isolate["isolate_data"]
    if isinstance(isolate_data, str):
        isolate_data = json.loads(isolate_data)

    fasta_file = isolate_data.get("fasta_file_name", "")
    fasta_header = isolate_data.get("fasta_header_name", "")
    isolate_sample_id = isolate_data.get("isolate_id", "")
    isolate_sample_id = isolate_sample_id.replace("ISO_", "")

    print(f"FASTA File: {fasta_file}")
    print(f"FASTA Header: {fasta_header}")
    print(f"Isolate Sample ID: {isolate_sample_id}")

    with get_db_cursor() as cursor:
        cursor.execute(
            """
            SELECT object_id 
            FROM submission_files 
            WHERE filename = %s AND file_type = 'fasta'
            ORDER BY created_at DESC 
            LIMIT 1
            """,
            (fasta_file,),
        )
        file_record = cursor.fetchone()
        
        if not file_record:
            return None

    object_id = file_record["object_id"]

    # Load the FASTA file from MinIO
    minio_endpoint = settings.MINIO_ENDPOINT
    minio_access_key = settings.MINIO_ACCESS_KEY
    minio_secret_key = settings.MINIO_SECRET_KEY
    minio_secure = settings.MINIO_SECURE

    minio_client = Minio(
        endpoint=minio_endpoint,
        access_key=minio_access_key,
        secret_key=minio_secret_key,
        secure=minio_secure
    )

    bucket_name = settings.MINIO_BUCKET 

    try:
        response = minio_client.get_object(bucket_name, object_id)
        fasta_content = response.read().decode('utf-8')
        response.close()
        response.release_conn()

        # Extract the specific sequence by header
        fasta_lines = fasta_content.splitlines()
        sequence_lines = []
        recording = False

        for line in fasta_lines:
            if line.startswith('>'):
                if isolate_sample_id in line[1:].strip():
                    recording = True
                    sequence_lines.append(line)
                else:
                    if recording:
                        break  
            else:
                if recording:
                    sequence_lines.append(line)

        return '\n'.join(sequence_lines)


    except Exception as e:
        print(f"Error loading FASTA file from MinIO: {e}")
        return None



async def check_for_sequence_data(row, isolate):
    for i in range(1, 201):
        await asyncio.sleep(0.03)
        if i % 20 == 0:
            print(f"Counted to {i}")
    
    errors = [
        "No sequence data found",
        "Sequence data is corrupted",
        "FASTA header does not match isolate ID"
    ]

    if random.choice([True, False]):
        return random.choice(errors)


##############################
### ELASTICSEARCH HELPERS
##############################

def json_serial(obj):
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")

# NEW FUNCTION TO SEND TO FIXED INDEX
def send_to_elastic2(document):

    es_index_url = f"{settings.ELASTICSEARCH_URL}/{settings.ELASTICSEARCH_INDEX}/_doc"
    method = requests.post

    try:
        serialized_document = json.loads(json.dumps(document, default=json_serial))
    except Exception as e:
        print(f"Error serializing document: {e}")
        return False

    try:
        response = method(es_index_url, json=serialized_document)
        if response.status_code in [200, 201]:
            print(f"Successfully indexed document to {es_index_url}")
            return True
        else:
            print(f"Failed to index document: {response.text}")
            return False
    except Exception as e:
        print(f"Error sending document to Elasticsearch: {e}")
        return False


##############################
### DOWNLOAD
##############################























# OLD FUNCTION FOR LEGACY USE
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





def query_elastic(query_body):
    es_url = settings.ELASTICSEARCH_URL
    es_query_url = f"{es_url}/agari-samples/_search"

    try:
        response = requests.post(
            es_query_url, json=query_body, headers={"Content-Type": "application/json"}
        )
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Failed to query Elasticsearch: {response.text}")
            return None
    except Exception as e:
        print(f"Error querying Elasticsearch: {e}")
        return None
