from email import message
import subprocess
import json
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

def validate_sample_file_correspondence(submission_id, samples):
    """
    Validate that every sample has a corresponding FASTA sequence.
    Returns (success: bool, errors: list)
    """
    try:
        # Get FASTA files for this submission
        with get_db_cursor() as cursor:
            cursor.execute("""
                SELECT * FROM submission_files 
                WHERE submission_id = %s AND file_type = 'fasta'
            """, (submission_id,))
            fasta_files = cursor.fetchall()
        
        if not fasta_files:
            return False, ["No FASTA files found for validation"]
        
        # Build a map of available sequences by streaming each FASTA file
        available_sequences = set()
        
        # Get MinIO client and settings
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
        
        minio_bucket = settings.MINIO_BUCKET
        
        for fasta_file in fasta_files:
            try:
                print(f"Processing FASTA file: {fasta_file['filename']}")
                
                # Stream read the FASTA file to extract headers
                fasta_object = minio_client.get_object(
                    bucket_name=minio_bucket,
                    object_name=fasta_file['object_id']
                )
                
                # Stream process the FASTA file line by line
                remaining_data = b""
                for chunk in fasta_object.stream(1024 * 1024):  # 1MB chunks
                    # Combine with any remaining data from previous chunk
                    data_chunk = remaining_data + chunk
                    
                    # Split into lines, keeping incomplete last line for next iteration
                    lines = data_chunk.split(b'\n')
                    remaining_data = lines[-1]  # This might be incomplete
                    
                    # Process complete lines
                    for line_bytes in lines[:-1]:
                        try:
                            line = line_bytes.decode('utf-8').strip()
                            if line.startswith('>'):
                                # Extract sequence identifier from header
                                header = line[1:].strip()
                                available_sequences.add(header)
                                print(f"Found FASTA header: {header}")
                        except UnicodeDecodeError:
                            # Skip lines that can't be decoded
                            continue
                
                # Process any remaining data
                if remaining_data:
                    try:
                        line = remaining_data.decode('utf-8').strip()
                        if line.startswith('>'):
                            header = line[1:].strip()
                            available_sequences.add(header)
                            print(f"Found FASTA header: {header}")
                    except UnicodeDecodeError:
                        pass
                
                fasta_object.close()
                fasta_object.release_conn()
                
            except Exception as e:
                return False, [f"Error reading FASTA file {fasta_file['filename']}: {str(e)}"]
        
        print(f"Total FASTA headers found: {len(available_sequences)}")
        
        # Validate each sample against available sequences
        missing_sequences = []
        for i, sample in enumerate(samples):
            isolate_id = sample.get('isolate_id', '')
            fasta_header_name = sample.get('fasta_header_name', '')
            
            # Try to find this sample in available sequences
            # Check for exact matches or partial matches
            sample_found = False
            
            # First try exact match with fasta_header_name
            if fasta_header_name in available_sequences:
                sample_found = True
            else:
                # Try partial matches - look for isolate_id or fasta_header_name in sequence headers
                for seq_header in available_sequences:
                    if (isolate_id and isolate_id in seq_header) or \
                       (fasta_header_name and fasta_header_name in seq_header):
                        sample_found = True
                        break
            
            if not sample_found:
                missing_sequences.append({
                    "row": i + 1,  # 1-based row numbering for user clarity
                    "isolate_id": isolate_id,
                    "fasta_header_name": fasta_header_name,
                    "error": f"No corresponding FASTA sequence found for isolate_id: '{isolate_id}' or fasta_header_name: '{fasta_header_name}'"
                })
        
        if missing_sequences:
            print(f"Found {len(missing_sequences)} samples without corresponding FASTA sequences")
            return False, missing_sequences
        
        print("All samples have corresponding FASTA sequences")
        return True, []
        
    except Exception as e:
        print(f"File correspondence validation error: {str(e)}")
        return False, [f"File correspondence validation failed: {str(e)}"]


def validate_against_schema(data, schema, submission_id=None):
    # load json schema file
    schemas = load_json_schema("schemas-all.json")

    resultset_schema = [
        s for s in schemas["resultSet"] if s["name"] == schema["schema"] and s["version"] == schema["version"]
    ]
    
    if not resultset_schema:
        return False, f"Schema '{schema['schema']}' version {schema['version']} not found"
    
    schema_obj = resultset_schema[0]["schema"]
    
    
    # Ensure data is always a list (TSV rows)
    if not isinstance(data["samples"], list):
        return False, "Data must be an array of TSV rows"

    all_errors = []
    
    # Validate each row in the TSV
    for row_index, row_data in enumerate(data["samples"]):
        
        # Create validator for this row
        validator = Draft7Validator(schema_obj)
        
        # Collect all validation errors for this specific row
        for error in validator.iter_errors(row_data):
            # Extract field name from the validation path
            field_path = list(error.absolute_path)
            field_name = field_path[-1] if field_path else "unknown"
            
            print(f"  Error in row {row_index}, field '{field_name}': {error.message}")
            
            # Get field description from schema if available
            field_description = ""
            try:
                field_schema = schema_obj
                for path_part in field_path:
                    if isinstance(path_part, str) and 'properties' in field_schema:
                        field_schema = field_schema['properties'].get(path_part, {})
                    elif isinstance(path_part, int) and 'items' in field_schema:
                        field_schema = field_schema['items']
                field_description = field_schema.get('description', '')
            except:
                pass
            
            error_obj = {
                "row": row_index,
                "field": field_name,
                "value": error.instance,
                "error": error.message,
                "description": field_description
            }
            all_errors.append(error_obj)
    
    print(f"Total schema errors found: {len(all_errors)}")
    
    # If schema validation passed and we have a submission_id, validate file correspondence
    if not all_errors and submission_id:
        print("Schema validation passed, checking file correspondence...")
        file_validation_result = validate_sample_file_correspondence(submission_id, data["samples"])
        
        if not file_validation_result[0]:
            # File correspondence validation failed
            # Convert file validation errors to same format as schema errors
            for file_error in file_validation_result[1]:
                if isinstance(file_error, dict):
                    all_errors.append(file_error)
                else:
                    # Handle string errors
                    all_errors.append({
                        "row": "N/A",
                        "field": "file_correspondence",
                        "value": "",
                        "error": str(file_error),
                        "description": "File correspondence validation"
                    })
    
    print(f"Total validation errors found: {len(all_errors)}")
    
    if all_errors:
        return False, all_errors
    return True, None

##############################
### ASYNC VALIDATION HELPERS
##############################

def perform_validation(submission_id, tsv_json, async_mode=False):
    """Actual validation logic"""
    try:
        data = {"samples": tsv_json}
        validation = validate_against_schema(data, {"schema": 'cholera_schema', "version": 1}, submission_id)
        
        if validation[0] == False:
            return {
                'status': 'error',
                'validation_errors': validation[1]
            }
        else:
            return {
                'status': 'validated',
                'validation_warnings': validation[1] if validation[1] else []
            }
    except Exception as e:
        print(f"Validation error: {str(e)}")
        return {
            'status': 'error',
            'validation_errors': [f'Validation failed: {str(e)}']
        }


def perform_async_validation(submission_id, tsv_json):
    """Background validation function"""
    import logging
    logger = logging.getLogger(__name__)
    
    try:
        print(f"Starting async validation for submission {submission_id}")
        result = perform_validation(submission_id, tsv_json, async_mode=True)
        
        # Update database with final result
        with get_db_cursor() as cursor:
            if result['status'] == 'validated':
                cursor.execute("""
                    UPDATE submissions 
                    SET status = 'validated', updated_at = NOW()
                    WHERE id = %s
                """, (submission_id,))
                print(f"Async validation completed successfully for submission {submission_id}")
            else:
                cursor.execute("""
                    UPDATE submissions 
                    SET status = 'error', updated_at = NOW()
                    WHERE id = %s
                """, (submission_id,))
                print(f"Async validation failed for submission {submission_id}: {result.get('validation_errors', [])}")
                
        # Log the validation completion
        log_submission(
            submission_id, 
            None,  # user_id not available in async context
            result['status'], 
            f"Async validation completed: {result['status']}"
        )
                
    except Exception as e:
        logger.exception(f"Background validation failed for submission {submission_id}: {str(e)}")
        try:
            with get_db_cursor() as cursor:
                cursor.execute("""
                    UPDATE submissions 
                    SET status = 'error', updated_at = NOW()
                    WHERE id = %s
                """, (submission_id,))
            
            log_submission(
                submission_id, 
                None, 
                'error', 
                f"Async validation exception: {str(e)}"
            )
        except Exception as db_error:
            logger.exception(f"Failed to update submission status after validation error: {str(db_error)}")

##############################
### SPLIT WORK
##############################

def split_submission(submission_id):
    """
    Split a validated submission by reading TSV from MinIO and inserting samples into isolates table.
    Only processes submissions with status = 'ready'.
    """
    try:
        with get_db_cursor() as cursor:
            # Get the submission details and verify status
            cursor.execute("""
                SELECT s.*, p.id as project_id, p.name as project_name
                FROM submissions s
                LEFT JOIN projects p ON s.project_id = p.id
                WHERE s.id = %s AND s.status = 'validated'
            """, (submission_id,))
            
            submission = cursor.fetchone()
            if not submission:
                return False, "Submission not found or not validated"
            
            # Get TSV files for this submission
            cursor.execute("""
                SELECT * FROM submission_files
                WHERE submission_id = %s AND file_type = 'tsv'
            """, (submission_id,))
            
            tsv_files = cursor.fetchall()
            if not tsv_files:
                return False, "No TSV files found for submission"
        
        
        
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
        
        bucket_name = settings.MINIO_BUCKET or 'agari-data'
        total_samples_processed = 0
        
        # Process each TSV file
        for tsv_file in tsv_files:
            try:
                # Get file from MinIO using object_id
                response = minio_client.get_object(bucket_name, tsv_file['object_id'])
                tsv_content = response.read().decode('utf-8')
                response.close()
                response.release_conn()
                
                # Convert TSV to JSON array
                samples_data = tsv_to_json(tsv_content)
                
                # Insert each sample as an isolate
                with get_db_cursor() as cursor:
                    for sample in samples_data:
                        cursor.execute("""
                            INSERT INTO isolates (
                                submission_id, isolate_id, object_id, isolate_data, created_at
                            ) VALUES (%s, %s, %s, %s, NOW())
                        """, (
                            submission_id,
                            sample.get('isolate_id'),
                            None,
                            json.dumps(sample),
                        ))
                        total_samples_processed += 1
                
            except Exception as file_error:
                return False, f"Failed to process TSV file: {tsv_file['filename']} - {str(file_error)}"
        
      
        
        return True, f"Successfully processed {total_samples_processed} samples"
        
    except Exception as e:
        print(f"Error splitting submission {submission_id}: {str(e)}")
        
      
            
        return False, f"Failed to split submission: {str(e)}"


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




##############################
### ELASTICSEARCH HELPERS
##############################


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

def get_isolate_from_elastic(isolate_id):

    es_url = settings.ELASTICSEARCH_URL
    es_query_url = f"{es_url}/agari-samples/_search"

    query_body = {
        "query": {
            "term": {
                "id.keyword": isolate_id
            }
        }
    }

    print(query_body)

    try:
        response = requests.post(
            es_query_url, json=query_body, headers={"Content-Type": "application/json"}
        )
        if response.status_code == 200:
            result = response.json()
            hits = result.get("hits", {}).get("hits", [])
            if hits:
                return hits[0]
            else:
                return None
        else:
            print(f"Failed to query Elasticsearch: {response.text}")
            return None
    except Exception as e:
        print(f"Error querying Elasticsearch: {e}")
        return None
    

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
