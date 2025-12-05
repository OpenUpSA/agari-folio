from email import message
import subprocess
import json
from datetime import datetime, date
import hashlib
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
from logging import getLogger

logger = getLogger(__name__)

SCHEMAS_DIR = os.path.join(os.path.dirname(__file__), "test", "data")

PROJECT_ROLE_MAPPING = {
    "project-admin": "Admin",
    "project-contributor": "Contributor",
    "project-viewer": "Viewer",
}

ORG_ROLE_MAPPING = {
    "org-owner": "Owner",
    "org-admin": "Admin",
    "org-contributor": "Contributor",
    "org-viewer": "viewer",
    "org-partial": "Partial member",
}


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
        "expiration_seconds": 90000,
        "force_create": True,
        "reusable": True,
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
        logger.error(f"Magic link creation failed: {keycloak_response.text}")
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

    user_id = user["user_id"]
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


def role_org_member_attr(user_id, org_id, role):
    # Prepare update data with proper structure
    update_data = {
        "attributes": {"organisation_id": [org_id], "realm_role": [role]},
    }
    result = keycloak_auth.update_user(user_id, update_data)
    return result


def access_toggled_notification(user_id, enabled):
    user = keycloak_auth.get_user(user_id)

    to_email = user["email"]
    to_name = ""
    subject = "Regarding your AGARI account"

    if enabled:
        toggle_status = "enabled"
    else:
        toggle_status = "disabled"

    html_template = mjml_to_html("toggle_access")
    html_content = render_template_string(html_template, toggle_status=toggle_status)

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


def log_event(log_type, resource_id, log_entry, user_info=None):
    """
    Event types:
    - project_created, project_deleted, project_privacy
    - user_added, user_invited, user_accepted, project_user_deleted
    - org_user_added, org_user_invited, org_user_accepted
    - submission_created, file_uploaded, submission_validated, submission_published, submission_unpublished
    - data_download
    """
    try:
        if user_info:
            action_name = f"{user_info['name']} {user_info['surname']}" if user_info.get('name') and user_info.get('surname') else user_info['username']
            log_entry['action_email'] = user_info['username']
            log_entry['action_name'] = action_name

        with get_db_cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO logs (log_type, resource_id, log_entry)
                VALUES (%s, %s, %s)
                """,
                (log_type, resource_id, json.dumps(log_entry, default=json_serial) if log_entry else None))
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


def tsv_to_json(tsv_string, project_id):
    import re

    tsv_string = tsv_string.replace('\r\n', '\n').replace('\r', '\n')
    
    with get_db_cursor() as cursor:
        cursor.execute(
            """
            SELECT pathogen_id
            FROM projects
            WHERE id = %s AND deleted_at IS NULL
            """,
            (project_id,),
        )
        project_record = cursor.fetchone()
        if not project_record:
            raise ValueError(f"Project ID {project_id} not found")
        
        pathogen_id = project_record["pathogen_id"]
        
        cursor.execute(
            """
            SELECT schema_id
            FROM pathogens
            WHERE id = %s AND deleted_at IS NULL
            """,
            (pathogen_id,),
        )
        pathogen_record = cursor.fetchone()
        if not pathogen_record:
            raise ValueError(f"Pathogen ID {pathogen_id} not found")
        
        schema_id = pathogen_record["schema_id"]
        
        cursor.execute(
            """
            SELECT schema
            FROM schemas
            WHERE id = %s AND deleted_at IS NULL
            """,
            (schema_id,),
        )
        schema_record = cursor.fetchone()
        if not schema_record:
            raise ValueError(f"Schema ID {schema_id} not found")
        
        schema = schema_record["schema"]

        lines = tsv_string.strip().split("\n")
        headers = [h.strip().replace('\r', '') for h in lines[0].split("\t")]
        json_list = []

        for line in lines[1:]:
            values = line.split("\t")
            values = [v.strip().replace('\r', '') for v in values]
            
            # Process each value according to its schema definition
            for i in range(min(len(values), len(headers))):
                header = headers[i]
                value = values[i]

                # Get field schema definition
                field_schema = schema.get("properties", {}).get(header, {})
                field_type = field_schema.get("type")
                split_regex = field_schema.get("x-split-regex")
                
                if not value or value.strip() == "":
                    # For string fields, use empty string; for others use None
                    if field_type == "string":
                        values[i] = ""
                    else:
                        values[i] = None
                    continue
                
                # Handle array fields (with or without regex splitting)
                if field_type == "array" and value:
                    # Try regex splitting first if pattern exists
                    if split_regex:
                        try:
                            split_values = re.split(split_regex, value)
                            # Strip whitespace and filter out empty strings
                            split_values = [v.strip() for v in split_values if v.strip()]
                            if len(split_values) > 1:  # Only use regex result if it actually split
                                values[i] = split_values
                            else:
                                # Fallback to comma splitting
                                split_values = [v.strip() for v in value.split(",")]
                                values[i] = [v for v in split_values if v]
                        except re.error:
                            # If regex is invalid, fallback to comma splitting
                            split_values = [v.strip() for v in value.split(",")]
                            values[i] = [v for v in split_values if v]
                    else:
                        # No regex pattern, use comma splitting for arrays
                        split_values = [v.strip() for v in value.split(",")]
                        values[i] = [v for v in split_values if v]
                
                # Handle type conversion for non-array fields
                elif field_type == "number":
                    try:
                        # Try to convert to int first, then float
                        if '.' in value:
                            values[i] = float(value.strip())
                        else:
                            values[i] = int(value.strip())
                    except ValueError:
                        # If conversion fails, keep as string (validation will catch this later)
                        values[i] = value.strip()
                
                # Keep strings as strings, but strip whitespace
                else:
                    values[i] = value.strip()

            # Create record ensuring we handle cases where there are fewer values than headers
            record = {}
            for i in range(len(headers)):
                if i < len(values):
                    record[headers[i]] = values[i]
                else:
                    # For missing values, use empty string for string fields, None for others
                    field_schema = schema.get("properties", {}).get(headers[i], {})
                    field_type = field_schema.get("type")
                    record[headers[i]] = "" if field_type == "string" else None
            
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
        minio_secure = getattr(settings, 'MINIO_INTERNAL_SECURE', False)
        
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

def validate_against_schema(data, row, project_id):

    with get_db_cursor() as cursor:
        cursor.execute(
            """
            SELECT pathogen_id
            FROM projects
            WHERE id = %s AND deleted_at IS NULL
            """,
            (project_id,),
        )
        project_record = cursor.fetchone()
        if not project_record:
            return False, f"Project ID {project_id} not found"
        
        pathogen_id = project_record["pathogen_id"]
        
        cursor.execute(
            """
            SELECT schema_id
            FROM pathogens
            WHERE id = %s AND deleted_at IS NULL
            """,
            (pathogen_id,),
        )
        pathogen_record = cursor.fetchone()
        if not pathogen_record:
            return False, f"Pathogen ID {pathogen_id} not found"
        
        schema_id = pathogen_record["schema_id"]
        
        cursor.execute(
            """
            SELECT schema
            FROM schemas
            WHERE id = %s AND deleted_at IS NULL
            """,
            (schema_id,),
        )
        schema = cursor.fetchone()

    
    if not schema:
        return False, f"Schema ID {schema_id} not found"

    schema_obj = schema["schema"]

    all_errors = []
    
    validator = Draft7Validator(schema_obj)
    
    # Collect all validation errors for this specific row
    for error in validator.iter_errors(data):

        error_info = {
            "row": row,
            "field": ".".join(str(x) for x in error.path) if error.path else "root",
            "invalid_value": error.instance,
            "x-hint": error.schema.get("x-hint", ""),
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

async def check_for_sequence_data(isolate, split_on_fasta_headers=True):
    """
    Check if sequence data exists for an isolate and extract it.
    
    Args:
        isolate: Dictionary containing isolate data with fasta_file_name, fasta_header_name, isolate_id
        
    Returns:
        tuple: (success: bool, result: str) 
               - On success: (True, object_id)
               - On error: (False, error_message)
    """
    try:
        # 1. First, check if this isolate already has an object_id
        isolate_id = isolate.get('id')
        if isolate_id:
            with get_db_cursor() as cursor:
                cursor.execute(
                    "SELECT object_id FROM isolates WHERE id = %s AND object_id IS NOT NULL",
                    (isolate_id,),
                )
                existing_record = cursor.fetchone()
                
                if existing_record:
                    existing_object_id = existing_record["object_id"]
                    print(f"Isolate {isolate_id} already has object_id: {existing_object_id}")
                    return True, existing_object_id
        
        # 2. If no existing object_id, proceed with sequence extraction
        # Get the isolate data - it should be a dictionary already
        isolate_data = isolate.get('isolate_data', {})
        if isinstance(isolate_data, str):
            isolate_data = json.loads(isolate_data)
        
        fasta_file = isolate_data.get("fasta_file_name", "")
        fasta_header = isolate_data.get("fasta_header_name", "")
        isolate_sample_id = isolate_data.get("isolate_id", "")
        
        # Check if FASTA file is provided
        if not fasta_file:
            return False, "Missing FASTA file name in isolate data"
        
        # If no header specified, link to the complete original file instead of extracting
        if not split_on_fasta_headers:
            print(f"No header specified for isolate {isolate_sample_id} - linking to complete FASTA file")
            
            # Get the object_id from submission_files table where filename matches
            with get_db_cursor() as cursor:
                cursor.execute(
                    """
                    SELECT object_id 
                    FROM submission_files 
                    WHERE filename = %s AND file_type = 'fasta' AND submission_id = %s
                    ORDER BY created_at DESC 
                    LIMIT 1
                    """,
                    (fasta_file, isolate['submission_id']),
                )
                file_record = cursor.fetchone()
                
                if not file_record:
                    return False, f"FASTA file '{fasta_file}' not found in submission_files"
            
            # Return the original file's object_id (no extraction needed)
            print(f"Linked isolate {isolate_sample_id} to original file with object_id: {file_record['object_id']}")
            return True, file_record["object_id"]
        
        # EXISTING: Header specified - extract specific sequence
        print(f"Looking for FASTA File: {fasta_file}, Header: {fasta_header}")
        
        # 3. Get the object_id from submission_files table where filename matches
        with get_db_cursor() as cursor:
            cursor.execute(
                """
                SELECT object_id 
                FROM submission_files 
                WHERE filename = %s AND file_type = 'fasta' AND submission_id = %s
                ORDER BY created_at DESC 
                LIMIT 1
                """,
                (fasta_file, isolate['submission_id']),
            )
            file_record = cursor.fetchone()
            
            if not file_record:
                return False, f"FASTA file '{fasta_file}' not found in submission_files"
        
        object_id = file_record["object_id"]
        
        # 3. Load the FASTA file from MinIO
        minio_client = Minio(
            endpoint=settings.MINIO_ENDPOINT,
            access_key=settings.MINIO_ACCESS_KEY,
            secret_key=settings.MINIO_SECRET_KEY,
            secure=settings.MINIO_INTERNAL_SECURE
        )
        
        bucket_name = settings.MINIO_BUCKET
        
        try:
            # Add timeout to MinIO operations
            import socket
            original_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(30) 
            
            response = minio_client.get_object(bucket_name, object_id)
            fasta_content = response.read().decode('utf-8')
            print("====================")
            print(fasta_content)
            print("====================")
            response.close()
            response.release_conn()
            
            # Restore original timeout
            socket.setdefaulttimeout(original_timeout)
        except Exception as e:
            socket.setdefaulttimeout(original_timeout)  # Restore timeout even on error
            return False, f"Error loading FASTA file from MinIO: {str(e)}"
        
        # 5. Parse the FASTA file to check if header is in the file
        fasta_lines = fasta_content.splitlines()
        sequence_lines = []
        recording = False
        header_found = False
        
        for line in fasta_lines:
            if line.startswith('>'):
                # Check if this header matches what we're looking for
                if line.startswith(f'>{fasta_header} ') or line == f'>{fasta_header}' or line.startswith(f'>{fasta_header}\t'):
                    recording = True
                    header_found = True
                    sequence_lines.append(line)
                else:
                    # If we were recording and hit a different header, stop
                    if recording:
                        break
            else:
                if recording:
                    sequence_lines.append(line)

        print(sequence_lines)
        
        # 6. Return error if header not found
        if not header_found:
            return False, f"Header '{fasta_header}' not found in {fasta_file} for isolate '{isolate_sample_id}'"
        
        sequence_data = '\n'.join(sequence_lines)
        
        if not sequence_data.strip():
            return False, f"No sequence data found for isolate '{isolate_sample_id}'"
        
        # 7. If file and header found, pass to save_sequence_data for processing
        new_object_id = await save_sequence_data(sequence_data, isolate['submission_id'], isolate['id'])
        
        # 8. Return the object_id of new FASTA file or error
        if new_object_id:
            return True, new_object_id
        else:
            return False, "Failed to save sequence data"
            
    except Exception as e:
        return False, f"Error processing sequence data: {str(e)}"


async def save_sequence_data(sequence, submission_id=None, isolate_id=None):
    """
    Save sequence data to a FASTA file and upload it to MinIO.
    
    Args:
        sequence: String containing FASTA header and sequence data
        submission_id: ID of the submission this sequence belongs to
        isolate_id: ID of the isolate this sequence belongs to
        
    Returns:
        str: Object ID of the uploaded file, or None on error
    """
    try:
        if not sequence or not sequence.strip():
            print("Error: No sequence data provided")
            return None
        
        # 1. Generate a unique filename for the FASTA file
        unique_id = str(uuid.uuid4())
        filename = f"isolate_sequence_{unique_id}.fasta"
        
        # 2. Create FASTA file content (sequence should already be in FASTA format)
        fasta_content = sequence.strip()
        
        # Ensure it's valid FASTA format (starts with >)
        if not fasta_content.startswith('>'):
            print("Error: Sequence data is not in valid FASTA format")
            return None
        
        print(f"Saving sequence data to file: {filename}")
        print(f"Submission ID: {submission_id}, Isolate ID: {isolate_id}")
        
        # 3. Upload the FASTA file to MinIO
        minio_client = Minio(
            endpoint=settings.MINIO_ENDPOINT,
            access_key=settings.MINIO_ACCESS_KEY,
            secret_key=settings.MINIO_SECRET_KEY,
            secure=settings.MINIO_INTERNAL_SECURE
        )
        
        bucket_name = settings.MINIO_BUCKET
        
        # Ensure bucket exists
        if not minio_client.bucket_exists(bucket_name):
            minio_client.make_bucket(bucket_name)
        
        # Convert string to bytes for upload
        fasta_bytes = fasta_content.encode('utf-8')
        
        # Generate object_id for MinIO storage
        object_id = unique_id
        
        # Upload to MinIO with timeout
        from io import BytesIO
        data = BytesIO(fasta_bytes)
        
        # Add timeout for MinIO operations
        import socket
        original_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(30) 
        
        try:
            minio_client.put_object(
                bucket_name=bucket_name,
                object_name=object_id,
                data=data,
                length=len(fasta_bytes),
                content_type='text/plain'
            )
            socket.setdefaulttimeout(original_timeout)  # Restore timeout
        except Exception as e:
            socket.setdefaulttimeout(original_timeout)  # Restore timeout even on error
            print(f"Failed to upload to MinIO: {str(e)}")
            return None
        
        print(f"Successfully uploaded sequence data to MinIO with object_id: {object_id}")
        
        # Optionally, save file metadata to database (submission_files table)
        try:
            with get_db_cursor() as cursor:
                cursor.execute(
                    """
                    INSERT INTO submission_files (submission_id, isolate_id, filename, object_id, file_type, file_size, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, NOW())
                    """,
                    (submission_id, isolate_id, filename, object_id, 'fasta', len(fasta_bytes)),
                )
                print(f"File metadata saved to database: {filename}")
                
                # Also update the isolates table with the object_id
                if isolate_id:
                    cursor.execute(
                        """
                        UPDATE isolates 
                        SET object_id = %s, updated_at = NOW() 
                        WHERE id = %s
                        """,
                        (object_id, isolate_id),
                    )
                    print(f"Updated isolate {isolate_id} with object_id: {object_id}")
                    
        except Exception as db_error:
            print(f"Warning: Could not save file metadata to database: {db_error}")
            # Continue anyway, as the file was uploaded successfully
        
        # 3. Return the object_id of the uploaded file
        return object_id
        
    except Exception as e:
        print(f"Error saving sequence data: {str(e)}")
        return None


def get_object_id_url(object_id, expires_in_hours=24):
    """Generate a presigned MinIO URL for the given object ID."""
    try:
        
        # Get MinIO client
        minio_client = Minio(
            endpoint=settings.MINIO_FRONTEND_ENDPOINT,
            access_key=settings.MINIO_ACCESS_KEY,
            secret_key=settings.MINIO_SECRET_KEY,
            secure=settings.MINIO_SECURE
        )
        
        bucket_name = settings.MINIO_BUCKET
        
        # Test if object exists
        try:
            minio_client.stat_object(bucket_name, object_id)
            print(f"Object '{object_id}' exists in bucket")
        except Exception as stat_error:
            print(f"Object stat error: {stat_error}")
        
        # Generate presigned URL with expiration
        from datetime import timedelta
        expires = timedelta(hours=expires_in_hours)
        
        print("Generating presigned URL...")
        presigned_url = minio_client.presigned_get_object(
            bucket_name=bucket_name,
            object_name=object_id,
            expires=expires
        )
        
        print(f"Generated URL: {presigned_url}")
        return presigned_url
        
    except Exception as e:
        print(f"Error generating presigned URL for object {object_id}: {e}")
        import traceback
        traceback.print_exc()  # This will show the full error
        return None
    
def delete_minio_object(object_id):
    """Delete an object from MinIO by its object ID."""
    try:
        # Get MinIO client
        minio_client = Minio(
            endpoint=settings.MINIO_ENDPOINT,
            access_key=settings.MINIO_ACCESS_KEY,
            secret_key=settings.MINIO_SECRET_KEY,
            secure=settings.MINIO_INTERNAL_SECURE
        )
        
        bucket_name = settings.MINIO_BUCKET
        
        minio_client.remove_object(bucket_name, object_id)
        print(f"Successfully deleted object '{object_id}' from bucket '{bucket_name}'")
        return True
        
    except Exception as e:
        print(f"Error deleting object {object_id} from MinIO: {e}")
        return False


##############################
### ELASTICSEARCH HELPERS
##############################

def json_serial(obj):
    if isinstance(obj, (datetime, date)):
        return obj.isoformat()
    if isinstance(obj, set):
        return list(obj)
    raise TypeError(f"Type {type(obj)} not serializable")


# NEW FUNCTION TO SEND TO FIXED INDEX
def send_to_elastic2(document):
    try:
        serialized_document = json.loads(json.dumps(document, default=json_serial))
    except Exception as e:
        print(f"Error serializing document: {e}")
        return False
    
    # NEW ES INDEX AND FRONTEND WORKAROUND
    # This will flatten the isolate_data field into top-level fields which is compatible with new ES mapping and existing frontend code

    # Flatten isolate_data if it exists
    if 'isolate_data' in serialized_document and serialized_document['isolate_data']:
        isolate_data = serialized_document['isolate_data']
        if isinstance(isolate_data, str):
            try:
                isolate_data = json.loads(isolate_data)
            except json.JSONDecodeError:
                print(f"Warning: Could not parse isolate_data as JSON: {isolate_data}")
                isolate_data = {}
        
        if isinstance(isolate_data, dict):
            # Add all fields from isolate_data to top level
            for key, value in isolate_data.items():
                if key not in serialized_document:  # Don't overwrite existing fields
                    serialized_document[key] = value
        
        # Remove the original isolate_data field
        del serialized_document['isolate_data']

    # End workaround

    # Check if document has an id field 
    document_id = serialized_document.get('id')
    if not document_id:
        print("Warning: Document has no 'id' field, creating new document")
        es_index_url = f"{settings.ELASTICSEARCH_URL}/{settings.ELASTICSEARCH_INDEX}/_doc"
        method = requests.post
    else:
        # Use the document's UUID as the Elasticsearch document ID
        # This ensures we always update the same document
        es_index_url = f"{settings.ELASTICSEARCH_URL}/{settings.ELASTICSEARCH_INDEX}/_doc/{document_id}"
        method = requests.put
        print(f"Using document ID {document_id} as Elasticsearch document ID for upsert")

    try:
        # Add timeout to HTTP requests to prevent hanging
        response = method(es_index_url, json=serialized_document, timeout=30)
        if response.status_code in [200, 201]:
            action = "updated/created" if method == requests.put else "indexed"
            print(f"Successfully {action} document to {es_index_url}")
            print(f"DEBUG: Document {document_id} with data: object_id={serialized_document.get('object_id')}, seq_error={serialized_document.get('seq_error')}")
            return True
        else:
            print(f"Failed to index document: {response.text}")
            return False, response.text
    except Exception as e:
        print(f"Error sending document to Elasticsearch: {e}")
        return False, str(e)


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


def check_isolate_in_elastic(isolate_id):
    es_url = settings.ELASTICSEARCH_URL
    es_query_url = f"{es_url}/agari-samples/_search"

    query_body = {
        "query": {
            "term": {
                "isolate_id": isolate_id
            }
        }
    }

    try:
        response = requests.post(
            es_query_url, json=query_body, headers={"Content-Type": "application/json"}
        )
        if response.status_code == 200:
            result = response.json()
            hits = result.get("hits", {}).get("total", {}).get("value", 0)
            return hits > 0
        else:
            print(f"Failed to query Elasticsearch: {response.text}")
            return False
    except Exception as e:
        print(f"Error querying Elasticsearch: {e}")
        return False

def delete_from_elastic(submission_id):

    es_url = settings.ELASTICSEARCH_URL
    es_delete_url = f"{es_url}/agari-samples/_delete_by_query"
    query_body = {
        "query": {
            "term": {
                "submission_id": submission_id
            }
        }
    }

    try:
        response = requests.post(es_delete_url, json=query_body)
        if response.status_code == 200:
            print(f"Successfully deleted documents with submission_id {submission_id} from Elasticsearch")
            return True
        else:
            print(f"Failed to delete documents from Elasticsearch: {response.text}")
            return False
    except Exception as e:
        print(f"Error deleting documents from Elasticsearch: {e}")
        return False