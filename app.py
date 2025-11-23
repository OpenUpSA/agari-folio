from os import truncate
from flask import Flask, request
from flask_restx import Api, Resource
from auth import (
    KeycloakAuth,
    require_auth,
    extract_user_info,
    require_permission,
    user_has_permission,
)
import asyncio
from permissions import PERMISSIONS
from database import get_db_cursor, test_connection
import json
from datetime import datetime, date
from decimal import Decimal
import requests
from helpers import (
    magic_link,
    invite_user_to_project,
    invite_user_to_org,
    invite_email_change,
    extract_invite_roles,
    role_project_member,
    role_org_member,
    check_user_id,
    access_toggled_notification,
    log_event,
    get_minio_client,
    tsv_to_json,
    validate_against_schema,
    check_for_sequence_data,
    send_to_elastic,
    send_to_elastic2,
    check_isolate_in_elastic,
    check_user_id,
    query_elastic,
    get_object_id_url,
    PROJECT_ROLE_MAPPING,
    ORG_ROLE_MAPPING
)
import uuid
import hashlib
import settings  # module import allows override via conftest.py
from logging import getLogger

logger = getLogger(__name__)



# Custom JSON encoder to handle datetime and other types
class CustomJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.strftime("%Y-%m-%d %H:%M:%S")
        elif isinstance(obj, date):
            return obj.strftime("%Y-%m-%d")
        elif isinstance(obj, Decimal):
            return float(obj)
        return super().default(obj)

app = Flask(__name__)
app.json_encoder = CustomJSONEncoder

print("app", settings.KEYCLOAK_URL)
keycloak_auth = KeycloakAuth(
    keycloak_url=settings.KEYCLOAK_URL,
    realm=settings.KEYCLOAK_REALM,
    client_id=settings.KEYCLOAK_CLIENT_ID,
    client_secret=settings.KEYCLOAK_CLIENT_SECRET,
)

app.keycloak_auth = keycloak_auth

api = Api(app, 
    version="1.0",
    title="Folio API",
    description="API documentation for the Folio application",
    doc="/docs/"
)

# Configure Flask-RESTX to use our custom JSON encoder
app.config['RESTX_JSON'] = {'cls': CustomJSONEncoder}

##########################
### INFO
##########################

default_ns = api.namespace('info', description='Utility endpoints')

@default_ns.route('/health')
class Health(Resource):

    ### GET /info/health ###

    @api.doc('get_health')
    def get(self):
        """Check application health status"""
        return {'status': 'healthy'}

@default_ns.route('/health/db')
class DatabaseHealth(Resource):

    ### GET /info/health/db ###

    @api.doc('get_db_health')
    def get(self):
        """Check database connectivity and schema"""
        db_test = test_connection()
        if db_test:
            return {
                'status': 'healthy',
            }
        else:
            return {'status': 'unhealthy', 'error': 'Database connection failed'}, 503

@default_ns.route('/whoami')
class WhoAmI(Resource):

    ### GET /info/whoami ###

    @api.doc('get_whoami')
    @require_auth(keycloak_auth)
    def get(self):

        """Get current user information from JWT token"""
        
        return extract_user_info(request.user)

@default_ns.route('/permissions')
class Permissions(Resource):

    ### GET /info/permissions ###

    @api.doc('get_permissions')
    @require_auth(keycloak_auth)
    def get(self):

        """Get all defined permissions"""
        
        return PERMISSIONS
    
@default_ns.route('/permissions/check/<permission_name>')
class PermissionsCheck(Resource):

    ### GET /info/permissions/check/<permission_name> ###

    @api.doc('check_permission')
    @require_auth(keycloak_auth)
    def get(self, permission_name):

        return

@default_ns.route('/permissions/check')
class PermissionsCheckResource(Resource):

    ### POST /info/permissions/check ###

    @api.doc('check_permission_for_resource')
    @require_auth(keycloak_auth)
    def post(self):
        """
        Check if the current user has a specific permission for a resource

        Request Body:
        {
            "resource_type": "project|study",
            "resource_id": "<uuid>",
            "permission": "edit_project|delete_project|etc",
            "parent_project_id": "<uuid>"  # Optional, for study checks
        }

        Returns detailed permission check information for debugging
        """
        try:
            data = request.get_json()
            if not data:
                return {'error': 'No JSON data provided'}, 400

            resource_type = data.get('resource_type')
            resource_id = data.get('resource_id')
            permission = data.get('permission')
            parent_project_id = data.get('parent_project_id')

            user_info = extract_user_info(request.user)
            has_perm, details = user_has_permission(
                user_info,
                permission,
                resource_type=resource_type,
                resource_id=resource_id,
                parent_project_id=parent_project_id
            )
            return {
                'has_permission': has_perm,
                'details': details
            }
        except Exception as e:
            logger.exception(f"Error checking permission: {str(e)}")
            return {'error': f'Failed to check permission: {str(e)}'}, 500


##########################
### PATHOGENS
##########################

pathogen_ns = api.namespace('pathogens', description='Pathogen management endpoints')

@pathogen_ns.route('/')
class PathogenList(Resource):

    ### GET /pathogens ###

    @pathogen_ns.doc('list_pathogens')
    def get(self):

        """List all pathogens (public access)
        
        Query Parameters:
        - deleted: true/false (default: false) - If true, include soft-deleted pathogens
        """
        
        try:
            # Check if deleted pathogens should be included
            include_deleted = request.args.get('deleted', 'false').lower() == 'true'
            
            with get_db_cursor() as cursor:
                if include_deleted:
                    # Include all pathogens (both active and deleted)
                    cursor.execute("""
                        SELECT *
                        FROM pathogens 
                        ORDER BY deleted_at IS NULL DESC, name
                    """)
                else:
                    # Only active pathogens (default behavior)
                    cursor.execute("""
                        SELECT *
                        FROM pathogens 
                        WHERE deleted_at IS NULL 
                        ORDER BY name
                    """)
                
                pathogens = cursor.fetchall()

                return pathogens

        except Exception as e:
            logger.exception(f"Error retrieving pathogens: {str(e)}")
            return {'error': f'Database error: {str(e)}'}, 500


    ### POST /pathogens ###

    @pathogen_ns.doc('create_pathogen')
    @require_auth(keycloak_auth)
    @require_permission('create_pathogen')
    def post(self):

        """Create a new pathogen (system-admin only)"""
        
        try:
            data = request.get_json()
            if not data:
                return {'error': 'No JSON data provided'}, 400
            
            name = data.get('name')
            scientific_name = data.get('scientific_name')
            description = data.get('description')
            schema_id = data.get('schema_id') or None
            
            if not name:
                return {'error': 'Pathogen name is required'}, 400
            if not scientific_name:
                return {'error': 'Scientific name is required'}, 400

            with get_db_cursor() as cursor:
                cursor.execute("""
                    INSERT INTO pathogens (name, scientific_name, description, schema_id)
                    VALUES (%s, %s, %s, %s)
                    RETURNING id, name, scientific_name, description, created_at
                """, (name, scientific_name, description, schema_id))

                new_pathogen = cursor.fetchone()
                
                return {
                    'message': 'Pathogen created successfully',
                    'pathogen': new_pathogen
                }, 201
                
        except Exception as e:
            if 'duplicate key value violates unique constraint' in str(e):
                return {'error': f'Pathogen with name "{name}" already exists'}, 409
            logger.exception(f"Error creating pathogen: {str(e)}")
            return {'error': f'Database error: {str(e)}'}, 500

@pathogen_ns.route('/<string:pathogen_id>')
class Pathogen(Resource):

    ### GET /pathogens/<pathogen_id> ###

    @pathogen_ns.doc('get_pathogen')
    def get(self, pathogen_id):

        """Get details of a specific pathogen by ID (public access)"""
        
        try:
            with get_db_cursor() as cursor:
                cursor.execute("""
                    SELECT id, name, scientific_name, description, schema_id, created_at, updated_at
                    FROM pathogens 
                    WHERE id = %s AND deleted_at IS NULL
                """, (pathogen_id,))
                
                pathogen = cursor.fetchone()
                
                if not pathogen:
                    return {'error': 'Pathogen not found'}, 404
                
                return pathogen
                
        except Exception as e:
            logger.exception(f"Error retrieving pathogen {pathogen_id}: {str(e)}")
            return {'error': f'Database error: {str(e)}'}, 500
        
    ### DELETE /pathogens/<pathogen_id> ###

    @pathogen_ns.doc('delete_pathogen')
    @require_auth(keycloak_auth)
    @require_permission('create_pathogen')
    def delete(self, pathogen_id):
        """Delete a pathogen by ID (system-admin only)
        
        Query Parameters: 
        - hard: true/false (default: false) - If true, permanently delete from database
        """
        
        try:
            # Check if hard delete is requested
            hard_delete = request.args.get('hard', 'false').lower() == 'true'
            
            with get_db_cursor() as cursor:
                if hard_delete:
                    # Hard delete - permanently remove from database
                    cursor.execute("""
                        DELETE FROM pathogens 
                        WHERE id = %s
                        RETURNING id, name
                    """, (pathogen_id,))
                    
                    deleted_pathogen = cursor.fetchone()
                    
                    if not deleted_pathogen:
                        return {'error': 'Pathogen not found'}, 404
                    
                    return {
                        'message': f'Pathogen "{deleted_pathogen["name"]}" permanently deleted',
                        'delete_type': 'hard'
                    }
                else:
                    # Soft delete - set deleted_at timestamp
                    cursor.execute("""
                        UPDATE pathogens 
                        SET deleted_at = NOW(), updated_at = NOW()
                        WHERE id = %s AND deleted_at IS NULL
                        RETURNING id, name
                    """, (pathogen_id,))
                    
                    deleted_pathogen = cursor.fetchone()
                    
                    if not deleted_pathogen:
                        return {'error': 'Pathogen not found or already deleted'}, 404
                    
                    return {
                        'message': f'Pathogen "{deleted_pathogen["name"]}" deleted (can be restored)',
                        'delete_type': 'soft'
                    }
                
        except Exception as e:
            logger.exception(f"Error deleting pathogen {pathogen_id}: {str(e)}")
            return {'error': f'Database error: {str(e)}'}, 500
        
    ### PUT /pathogens/<pathogen_id> ###

    @pathogen_ns.doc('update_pathogen')
    @require_auth(keycloak_auth)
    @require_permission('create_pathogen')
    def put(self, pathogen_id):

        """Update a pathogen by ID (system-admin only)"""
        
        try:
            data = request.get_json()
            if not data:
                return {'error': 'No JSON data provided'}, 400
            
            # Build dynamic update query based on provided fields
            update_fields = []
            update_values = []
            
            if 'name' in data:
                update_fields.append('name = %s')
                update_values.append(data['name'])
                
            if 'scientific_name' in data:
                update_fields.append('scientific_name = %s')
                update_values.append(data['scientific_name'])
                
            if 'description' in data:
                update_fields.append('description = %s')
                update_values.append(data['description'])
                
            if 'schema_id' in data:
                update_fields.append('schema_id = %s')
                update_values.append(data['schema_id'])
            
            if not update_fields:
                return {'error': 'No valid fields provided for update'}, 400
            
            # Always update the updated_at timestamp
            update_fields.append('updated_at = NOW()')
            update_values.append(pathogen_id)

            with get_db_cursor() as cursor:
                query = f"""
                    UPDATE pathogens 
                    SET {', '.join(update_fields)}
                    WHERE id = %s AND deleted_at IS NULL
                    RETURNING id, name, scientific_name, description, schema_id, created_at, updated_at
                """
                
                cursor.execute(query, update_values)

                updated_pathogen = cursor.fetchone()
                
                if not updated_pathogen:
                    return {'error': 'Pathogen not found or already deleted'}, 404
                
                return {
                    'message': 'Pathogen updated successfully',
                    'pathogen': updated_pathogen
                }
                
        except Exception as e:
            if 'duplicate key value violates unique constraint' in str(e):
                # Extract the field name from the error for better error message
                field_name = data.get('name', 'unknown')
                return {'error': f'Pathogen with name "{field_name}" already exists'}, 409
            logger.exception(f"Error updating pathogen {pathogen_id}: {str(e)}")
            return {'error': f'Database error: {str(e)}'}, 500


@pathogen_ns.route('/<string:pathogen_id>/restore')
class PathogenRestore(Resource):

    ### POST /pathogens/<pathogen_id>/restore ###

    @pathogen_ns.doc('restore_pathogen')
    @require_auth(keycloak_auth)
    @require_permission('create_pathogen')
    def post(self, pathogen_id):

        """Restore a soft-deleted pathogen (system-admin only)"""
        
        try:
            with get_db_cursor() as cursor:
                cursor.execute("""
                    UPDATE pathogens 
                    SET deleted_at = NULL, updated_at = NOW()
                    WHERE id = %s AND deleted_at IS NOT NULL
                    RETURNING id, name, scientific_name, description, schema_id, created_at, updated_at
                """, (pathogen_id,))
                
                restored_pathogen = cursor.fetchone()
                
                if not restored_pathogen:
                    return {'error': 'Pathogen not found or not deleted'}, 404
                
                return {
                    'message': f'Pathogen "{restored_pathogen["name"]}" restored successfully',
                    'pathogen': restored_pathogen
                }
                
        except Exception as e:
            if 'duplicate key value violates unique constraint' in str(e):
                return {'error': 'Cannot restore: A pathogen with this name already exists'}, 409
            logger.exception(f"Error restoring pathogen {pathogen_id}: {str(e)}")
            return {'error': f'Database error: {str(e)}'}, 500
        
##########################
### SCHEMAS
##########################

schema_ns = api.namespace('schemas', description='Schema management endpoints')

@schema_ns.route('/')
class SchemaList(Resource):

    ### GET /schemas ###

    @schema_ns.doc('list_schemas')
    def get(self):

        """List all available schemas (public access)"""
        
        try:
            with get_db_cursor() as cursor:
                cursor.execute("""
                    SELECT s.id, s.name, s.description, s.version, p.name AS pathogen_name
                    FROM schemas s
                    JOIN pathogens p ON s.pathogen_id = p.id
                """)
                schemas = cursor.fetchall()
                return schemas

        except Exception as e:
            logger.exception(f"Error retrieving schemas: {str(e)}")
            return {'error': f'Database error: {str(e)}'}, 500
        

    ### POST /schemas ###
    @schema_ns.doc('register_schema')
    @require_auth(keycloak_auth)
    @require_permission('create_pathogen')
    def post(self):

        """Register a new schema (system-admin only)"""

        # Check if we have multipart form data
        if 'metadata' not in request.form or 'file' not in request.files:
            return {'error': 'Missing metadata or file in multipart form data'}, 400

        # Parse metadata from form data
        try:
            metadata = json.loads(request.form['metadata'])
        except json.JSONDecodeError as e:
            return {'error': f'Invalid JSON in metadata: {str(e)}'}, 400

        # Validate and extract schema details from metadata
        schema_name = metadata.get('name')
        pathogen_id = metadata.get('pathogen_id')
        description = metadata.get('description')

        if not schema_name:
            return {'error': 'Schema name is required'}, 400
        
        if not pathogen_id:
            return {'error': 'Pathogen ID is required'}, 400

        # Get the uploaded file
        uploaded_file = request.files['file']
        if uploaded_file.filename == '':
            return {'error': 'No file selected'}, 400

        # Read and validate schema JSON from the uploaded file
        try:
            file_content = uploaded_file.read()
            schema = json.loads(file_content.decode('utf-8'))
        except json.JSONDecodeError as e:
            return {'error': f'Invalid JSON in uploaded file: {str(e)}'}, 400
        except UnicodeDecodeError as e:
            return {'error': f'Invalid file encoding: {str(e)}'}, 400

        try:
            with get_db_cursor() as cursor:
                cursor.execute("""
                    INSERT INTO schemas (name, schema, pathogen_id, description)
                    VALUES (%s, %s, %s, %s)
                    RETURNING id, name, schema, description, pathogen_id, created_at, updated_at
                """, (schema_name, json.dumps(schema), pathogen_id, description))
                new_schema = cursor.fetchone()
                
                # Convert the schema back to dict for response if it's a string
                response_schema = dict(new_schema)
                if isinstance(response_schema.get('schema'), str):
                    try:
                        response_schema['schema'] = json.loads(response_schema['schema'])
                    except json.JSONDecodeError:
                        pass  # Keep as string if can't parse
                
                return {
                    'message': 'Schema created successfully',
                    'schema': response_schema
                }, 201

        except Exception as e:
            logger.exception(f"Error creating schema: {str(e)}")
            return {'error': f'Database error: {str(e)}'}, 500
        
    
@schema_ns.route('/<string:schema_id>')
class Schema(Resource):
    ### GET /schemas/<schema_id> ###

    @schema_ns.doc('get_schema')
    def get(self, schema_id):

        """Get schema details by ID (public access)"""
        
        try:
            with get_db_cursor() as cursor:
                cursor.execute("""
                    SELECT s.id, s.name, s.description, s.version, p.name AS pathogen_name, s.created_at, s.schema
                    FROM schemas s
                    JOIN pathogens p ON s.pathogen_id = p.id
                    WHERE s.id = %s
                """, (schema_id,))
                
                schema = cursor.fetchone()
                
                if not schema:
                    return {'error': 'Schema not found'}, 404
                
                return schema
                
        except Exception as e:
            logger.exception(f"Error retrieving schema {schema_id}: {str(e)}")
            return {'error': f'Database error: {str(e)}'}, 500







##########################
### USERS
##########################

user_ns = api.namespace('users', description='User management endpoints')
@user_ns.route('/')
class UserList(Resource):
    ### GET /users ###

    @user_ns.doc('list_users')
    @require_auth(keycloak_auth)
    @require_permission('system_admin_access')
    def get(self):

        """List all users (system-admin only)"""
        
        try:
            users = keycloak_auth.get_all_users()
            return users
        except Exception as e:
            logger.exception(f"Error retrieving users: {str(e)}")
            return {'error': f'Failed to retrieve users: {str(e)}'}, 500

    ### POST /users ###
    @user_ns.doc('create_user')
    @require_auth(keycloak_auth)
    @require_permission('create_user')
    def post(self):
        data = request.get_json()
        if not data:
            return {'error': 'No JSON data provided'}, 400

        email = data.get('email')
        redirect_uri = data.get('redirect_uri')
        expiration_seconds = data.get('expiration_seconds', 600)
        send_email = data.get('send_email', True)

        if not email:
            return {'error': 'Email is required'}, 400
        if not redirect_uri:
            return {'error': 'Redirect is required'}, 400

        keycloak_response = magic_link(email, redirect_uri, expiration_seconds, send_email)
        return keycloak_response


@user_ns.route('/<string:user_id>')        
class User(Resource):

    ### GET /users/<user_id> ###

    @user_ns.doc('get_user')
    @require_auth(keycloak_auth)
    def get(self, user_id):
        """Get user details by ID
        
        Users can view their own profile.
        Admins can view any user's profile.
        """

        try:
            # Get current user info
            user_info = extract_user_info(request.user)
            current_user_id = user_info.get('user_id')
            
            # Check if user is trying to view their own profile
            is_self_view = current_user_id == user_id
            
            # Check permissions - allow self-view or admin access
            if not is_self_view:
                has_perm, details = user_has_permission(user_info, 'manage_users')
                if not has_perm:
                    return {'error': 'Permission denied. You can only view your own profile or need admin permissions.', 'details': details}, 403
            
            return user_info
            
        except Exception as e:
            logger.exception(f"Error retrieving user {user_id}: {str(e)}")
            return {'error': f'Failed to retrieve user: {str(e)}'}, 500

    ### DELETE /users/<user_id> ###

    @user_ns.doc('delete_user')
    @require_auth(keycloak_auth)
    @require_permission('manage_users')
    def delete(self, user_id):
        """Delete a user by ID (system-admin only)"""
        try:
            keycloak_auth.toggle_user_enabled(user_id, enabled=False)
            access_toggled_notification(user_id, enabled=False)
            return {'message': 'User disabled successfully'}
        except Exception as e:
            logger.exception(f"Error deleting user {user_id}: {str(e)}")
            return {'error': f'Failed to delete user: {str(e)}'}, 500


    ### POST /users/<user_id> ###

    @user_ns.doc('enable_user')
    @require_auth(keycloak_auth)
    @require_permission('manage_users')
    def post(self, user_id):
        """Enable a disabled user by ID (system-admin only)"""
        try:
            keycloak_auth.toggle_user_enabled(user_id, enabled=True)
            access_toggled_notification(user_id, enabled=True)
            return {'message': 'User enabled successfully'}
        except Exception as e:
            logger.exception(f"Error enabling user {user_id}: {str(e)}")
            return {'error': f'Failed to enable user: {str(e)}'}, 500


    ### PUT /users/<user_id> ###

    @user_ns.doc('update_user')
    @require_auth(keycloak_auth)
    def put(self, user_id):
        """Update user details by ID
        
        Admins can update any user's details.
        Users can only update their own basic profile fields: name, surame, email, title, bio
        """
        
        try:
            data = request.get_json()
            if not data:
                return {'error': 'No JSON data provided'}, 400
            
            # Get current user info
            user_info = extract_user_info(request.user)
            current_user_id = user_info.get('user_id')
            
            # Check if user is trying to edit their own profile
            is_self_edit = current_user_id == user_id
            
            # Check permissions
            if not is_self_edit:
                # Not editing own profile - need admin permissions
                has_perm, details = user_has_permission(user_info, 'manage_users')

                organisation_id = user_info.get('organisation_id')[0]

                requested_user_info = keycloak_auth.get_user_info_by_id(user_id)
                request_user_organisation_id = requested_user_info.get('organisation_id')[0]

                has_org_perm = organisation_id == request_user_organisation_id

                if not has_perm and not has_org_perm:
                    return {'error': 'Permission denied. You can only edit your own profile or need admin permissions.', 'details': details}, 403
            
            # Define allowed fields for self-editing
            self_edit_allowed_fields = {'name', 'surname', 'email', 'title', 'bio', 'preferences', 'accepted_terms', 'accepted_governance'}
            
            # Filter update data based on permissions
            if is_self_edit:
                # User editing their own profile - filter to allowed fields only
                filtered_data = {}
                for key, value in data.items():
                    if key in self_edit_allowed_fields:
                        filtered_data[key] = value
                    else:
                        return {'error': f'Field "{key}" not allowed for self-editing. Allowed fields: {", ".join(self_edit_allowed_fields)}'}, 400
                
                if not filtered_data:
                    return {'error': f'No valid fields provided. Allowed fields for self-editing: {", ".join(self_edit_allowed_fields)}'}, 400
                    
                update_data = filtered_data
            else:
                # Admin editing user - allow all fields
                update_data = data
            
            # Call the auth update_user method
            result = keycloak_auth.update_user(user_id, update_data)
            
            if result.get('success'):
                return {
                    'message': 'User updated successfully',
                    'user_id': user_id,
                    'updates': result.get('updates', {}),
                    'is_self_edit': is_self_edit
                }
            else:
                return {
                    'error': 'Failed to update user',
                    'details': result.get('error'),
                    'errors': result.get('errors', {})
                }, 500
                
        except Exception as e:
            logger.exception(f"Error updating user {user_id}: {str(e)}")
            return {'error': f'Failed to update user: {str(e)}'}, 500


@user_ns.route('/email')
class UserEmail(Resource):
    ### PUT /users/<user_id> ###
    @user_ns.doc('changer_user_email')
    @require_auth(keycloak_auth)
    def put(self):
        try:
            data = request.get_json()
            if not data:
                return {"error": "No JSON data provided"}, 400

            user_info = extract_user_info(request.user)
            current_user_id = user_info.get("user_id")
            redirect_uri = data.get("redirect_uri")
            new_email = data.get("new_email")

            if not redirect_uri:
                return {"error": "redirect_uri is required for confirmation link"}, 400
            if not new_email:
                return {"error": "new_email is required for confirmation link"}, 400

            # Check if user is trying to edit their own profile
            print(user_info)
            return invite_email_change(user_info, redirect_uri, new_email)
        except Exception as e:
            logger.exception(f"Changing user email failed: {str(e)}")
            return {"error": f"Changing user email failed: {str(e)}"}, 500


##########################
### ORGANISATIONS
##########################

organisation_ns = api.namespace('organisations', description='Organisation management endpoints')
@organisation_ns.route('/')
class OrganisationList(Resource):
    
    ### GET /organisations ###

    @organisation_ns.doc('list_organisations')
    @require_auth(keycloak_auth)
    def get(self):

        """List all organisations"""
        
        try:
            with get_db_cursor() as cursor:
                cursor.execute("""
                    SELECT *
                    FROM organisations
                    ORDER BY name
                """)
                
                organisations = cursor.fetchall()
                return organisations

        except Exception as e:
            logger.exception(f"Error retrieving organisations: {str(e)}")
            return {'error': f'Database error: {str(e)}'}, 500
        

    ### POST /organisations ###

    @organisation_ns.doc('create_organisation')
    @require_auth(keycloak_auth)
    @require_permission('create_org')
    def post(self):
        
        """Create a new organisation"""
        
        try:
            data = request.get_json()
            if not data:
                return {'error': 'No JSON data provided'}, 400
            
            name = data.get('name')
            abbreviation = data.get('abbreviation')
            url = data.get('url')
            about = data.get('about')
            sharing_policy = data.get('sharing_policy', 'private')
            
            if not name:
                return {'error': 'Organisation name is required'}, 400
            
            with get_db_cursor() as cursor:
                cursor.execute("""
                    INSERT INTO organisations (name, abbreviation, url, about, sharing_policy)
                    VALUES (%s, %s, %s, %s, %s)
                    RETURNING *
                """, (name, abbreviation, url, about, sharing_policy))
                
                new_org = cursor.fetchone()
                
                return {
                    'message': 'Organisation created successfully',
                    'organisation': new_org
                }, 201
            
        except Exception as e:
            if 'duplicate key value violates unique constraint' in str(e):
                return {'error': f'Organisation with name "{name}" already exists'}, 409
            logger.exception(f"Error creating organisation: {str(e)}")
            return {'error': f'Database error: {str(e)}'}, 500


@organisation_ns.route('/<string:org_id>')
class Organisation(Resource):

    ### GET /organisations/<id> ###
    
    @organisation_ns.doc('get_organisation')
    def get(self, org_id):

        """Get organisation details by ID"""
        
        try:
            with get_db_cursor() as cursor:
                cursor.execute("""
                    SELECT *
                    FROM organisations
                    WHERE id = %s
                """, (org_id,))
                
                organisation = cursor.fetchone()
                
                if not organisation:
                    return {'error': 'Organisation not found'}, 404
                
                return organisation
                
        except Exception as e:
            logger.exception(f"Error retrieving organisation {org_id}: {str(e)}")
            return {'error': f'Database error: {str(e)}'}, 500
        
    ### PUT /organisations/<id> ###
    @organisation_ns.doc('update_organisation')
    @require_auth(keycloak_auth)
    @require_permission('manage_org_settings')
    def put(self, org_id):

        """Update organisation details by ID"""

        # Extract user info to get the organisation_id
        user_info = extract_user_info(request.user)
        user_org_id = user_info.get('organisation_id')[0]

        # system-admin
        if user_info.get('roles') and 'system-admin' in user_info.get('roles'):
            pass
        # org-admin or org-owner
        elif user_org_id == org_id:
            pass
        else:
            return {'error': 'Permission denied. You can only update your own organisation or need system-admin permissions.'}, 403

        
        try:
            data = request.get_json()
            if not data:
                return {'error': 'No JSON data provided'}, 400
            
            # Build dynamic update query based on provided fields
            update_fields = []
            update_values = []
            
            if 'name' in data:
                update_fields.append('name = %s')
                update_values.append(data['name'])
                
            if 'abbreviation' in data:
                update_fields.append('abbreviation = %s')
                update_values.append(data['abbreviation'])
                
            if 'url' in data:
                update_fields.append('url = %s')
                update_values.append(data['url'])
                
            if 'about' in data:
                update_fields.append('about = %s')
                update_values.append(data['about'])
            
            if not update_fields:
                return {'error': 'No valid fields provided for update'}, 400
            
            # Always update the updated_at timestamp
            update_fields.append('updated_at = NOW()')
            update_values.append(org_id)

            with get_db_cursor() as cursor:
                query = f"""
                    UPDATE organisations
                    SET {', '.join(update_fields)}
                    WHERE id = %s
                    RETURNING *
                """
                
                cursor.execute(query, update_values)
                
                updated_org = cursor.fetchone()
                
                if not updated_org:
                    return {'error': 'Organisation not found'}, 404
                
                return {
                    'message': 'Organisation updated successfully',
                    'organisation': updated_org
                }
                
        except Exception as e:
            if 'duplicate key value violates unique constraint' in str(e):
                return {'error': f'Organisation name already exists'}, 409
            logger.exception(f"Error updating organisation {org_id}: {str(e)}")
            return {'error': f'Database error: {str(e)}'}, 500
        
    ### DELETE /organisations/<id> ###
    @organisation_ns.doc('delete_organisation')
    @require_auth(keycloak_auth)
    @require_permission('delete_org')
    def delete(self, org_id):

        """Delete an organisation by ID"""

        try:
            with get_db_cursor() as cursor:
                cursor.execute("""
                    DELETE FROM organisations
                    WHERE id = %s
                    RETURNING id, name
                """, (org_id,))
                
                deleted_org = cursor.fetchone()
                
                if not deleted_org:
                    return {'error': 'Organisation not found'}, 404
                
                return {
                    'message': f'Organisation "{deleted_org["name"]}" deleted successfully'
                }, 204
                
        except Exception as e:
            logger.exception(f"Error deleting organisation {org_id}: {str(e)}")
            return {'error': f'Database error: {str(e)}'}, 500


@organisation_ns.route('/<string:org_id>/members')
class OrganisationUsers(Resource):

    ### GET /organisations/<org_id>/members ###

    @organisation_ns.doc('list_organisation_members')
    @require_auth(keycloak_auth)
    @require_permission('view_org_members')
    def get(self, org_id):

        """List all users in an organisation"""
        
        try:
            users = keycloak_auth.get_users_by_attribute('organisation_id', org_id)
            return users
        except Exception as e:
            logger.exception(f"Error retrieving organisation members for {org_id}: {str(e)}")
            return {'error': f'Failed to retrieve users: {str(e)}'}, 500
        
    
    ### POST /organisations/<org_id>/members ###
    
    @organisation_ns.doc('add_organisation_member')
    @require_auth(keycloak_auth)
    @require_permission('add_org_members')
    def post(self, org_id):
        """Add a user to an organisation with role"""

        try:
            # Extract current user info to check organization access
            user_info = extract_user_info(request.user)
            user_org_id = user_info.get('organisation_id')

            # Check if user is system-admin (can add to any org)
            if 'system-admin' not in user_info.get('roles', []):
                # For non-system-admin users, check organization match
                if not user_org_id:
                    return {'error': 'Permission denied. User not assigned to any organisation.'}, 403

                # Handle case where user_org_id might be a list or string
                user_orgs = user_org_id if isinstance(user_org_id, list) else [user_org_id]

                if org_id not in user_orgs:
                    return {'error': 'Permission denied. You can only add members to your own organisation.'}, 403

            data = request.get_json()
            if not data:
                return {'error': 'No JSON data provided'}, 400

            user_id = data.get('user_id')
            role = data.get('role')
            redirect_uri = data.get('redirect_uri')

            if not user_id:
                return {'error': 'User ID is required'}, 400
            if role not in {'org-viewer', 'org-admin', 'org-contributor', 'org-owner'}:
                return {'error': 'Invalid role specified'}, 400

            # Check if user exists in Keycloak
            user = keycloak_auth.get_user(user_id)
            if not user:
                return {'error': 'User not found in Keycloak'}, 404

            # Update user's organisation_id and org_role attributes in Keycloak
            if 'force_role' in data:
                role_org_member(user["id"], org_id, role)
                log_event("org_user_added", org_id, {"email": user["username"], "role": ORG_ROLE_MAPPING[role]}, user_info)
                return f"User role updated for organisation {org_id}"
            else:
                response = invite_user_to_org(user, redirect_uri, org_id, role)
                log_event("org_user_invited", org_id, {"email": user["username"], "role": ORG_ROLE_MAPPING[role]}, user_info)
            return response

        except Exception as e:
            logger.exception(f"Error adding user to organisation {org_id}: {str(e)}")
            return {'error': f'Failed to add user to organisation: {str(e)}'}, 500


@organisation_ns.route('/members')
class OrganisationRoles(Resource):
    ### DELETE /organisations/members ###

    @organisation_ns.doc('remove_organisation_member')
    @require_auth(keycloak_auth)
    @require_permission('remove_org_members')
    def delete(self):
        """Remove a user from an organisation"""
        try:
            data = request.get_json()
            if not data:
                return {'error': 'No JSON data provided'}, 400

            user_id = data.get('user_id')
            if not user_id:
                return {'error': 'User ID is required'}, 400

            # Check if user exists in Keycloak
            user = keycloak_auth.get_user(user_id)
            if not user:
                return {'error': 'User not found in Keycloak'}, 404

            removed_role = keycloak_auth.remove_realm_roles(user["id"])
            keycloak_auth.remove_org_attribute(user_id)
            if removed_role:
                return f"Removed role {removed_role}"
            else:
                return f"User has no role"
        except Exception as e:
            logger.exception(f"Error removing user from organisation role: {str(e)}")
            return {'error': f"Failed to remove user from organisation role: {str(e)}"}, 500


@organisation_ns.route('/<string:org_id>/owner')
class OrganisationOwner(Resource):
    ### POST /organisations/owner ###

    @organisation_ns.doc('change_organisation_owner')
    @require_auth(keycloak_auth)
    @require_permission('change_org_owner')
    def post(self, org_id):
        """Change an organisation's owner"""
        try:
            data = request.get_json()
            if not data:
                return {"error": "No JSON data provided"}, 400

            current_owner = check_user_id(data, "current_owner_id")
            new_owner = check_user_id(data, "new_owner_id")
            redirect_uri = data.get("redirect_uri")

            if isinstance(current_owner, tuple):
                return current_owner
            if isinstance(new_owner, tuple):
                return new_owner

            # Invite new owner and save old owner id
            response = invite_user_to_org(new_owner, redirect_uri, org_id, "org-owner")
            keycloak_auth.add_attribute_value(new_owner["id"], "invite_org_old_owner", current_owner["id"])
            return response

        except Exception as e:
            logger.exception(f"Error changing organisation owner: {str(e)}")
            return {'error': f"Error changing organisation owner: {str(e)}"}, 500


##########################
### PROJECTS
##########################

project_ns = api.namespace('projects', description='Project management endpoints')

@project_ns.route('/')
class ProjectList(Resource):

    ### GET /projects ###

    @api.doc('list_projects')
    def get(self):
        
        """List projects based on user permissions with filtering and pagination
        
        Query Parameters:
        - organisation_id: Filter by organisation ID
        - pathogen_id: Filter by pathogen ID
        - page: Page number (default: 1)
        - limit: Items per page (default: 20, max: 100)
        - search: Search in project name and description
        """

        organisation_id = keycloak_auth.get_user_org()

        # Get query parameters
        filter_org_id = request.args.get('organisation_id')
        filter_pathogen_id = request.args.get('pathogen_id')
        search_term = request.args.get('search')
        
        # Pagination parameters
        try:
            page = int(request.args.get('page', 1))
            limit = min(int(request.args.get('limit', 20)), 100)  
            offset = (page - 1) * limit
        except ValueError:
            return {'error': 'Invalid page or limit parameter'}, 400

        if page < 1 or limit < 1:
            return {'error': 'Page and limit must be positive integers'}, 400

        try:
            with get_db_cursor() as cursor:
                base_conditions = ["p.deleted_at IS NULL"]
                params = []
                
                if organisation_id is not None:
                    base_conditions.append("(p.privacy = 'public' OR p.privacy = 'semi-private' OR p.organisation_id = %s)")
                    params.append(organisation_id)
                else:
                    base_conditions.append("(p.privacy = 'public' OR p.privacy = 'semi-private')")
                
                # Add additional filters
                if filter_org_id:
                    base_conditions.append("p.organisation_id = %s")
                    params.append(filter_org_id)
                
                if filter_pathogen_id:
                    # Validate UUID format before using in query
                    try:
                        import uuid
                        uuid.UUID(filter_pathogen_id)  # This will raise ValueError if invalid UUID
                        base_conditions.append("p.pathogen_id = %s")
                        params.append(filter_pathogen_id)
                    except ValueError:
                        return {'error': f'Invalid pathogen_id format: {filter_pathogen_id}. Must be a valid UUID.'}, 400

                if search_term:
                    base_conditions.append("(p.name ILIKE %s OR p.description ILIKE %s)")
                    search_pattern = f"%{search_term}%"
                    params.extend([search_pattern, search_pattern])
                
                where_clause = " AND ".join(base_conditions)
                
                # Get total count for pagination metadata
                count_query = f"""
                    SELECT COUNT(*) as total
                    FROM projects p
                    WHERE {where_clause}
                """
                cursor.execute(count_query, params)
                total_count = cursor.fetchone()['total']
                
                # Get paginated results with joins for additional info
                main_query = f"""
                    SELECT 
                        p.*,
                        pat.name as pathogen_name,
                        pat.scientific_name as pathogen_scientific_name,
                        org.name as organisation_name,
                        org.abbreviation as organisation_abbreviation
                    FROM projects p
                    LEFT JOIN pathogens pat ON p.pathogen_id::uuid = pat.id::uuid
                    LEFT JOIN organisations org ON p.organisation_id::text = org.id::text
                    WHERE {where_clause}
                    ORDER BY p.name
                    LIMIT %s OFFSET %s
                """
                
                cursor.execute(main_query, params + [limit, offset])
                projects = cursor.fetchall()
                
                # Calculate pagination metadata
                total_pages = (total_count + limit - 1) // limit  # Ceiling division
                has_next = page < total_pages
                has_prev = page > 1
                
                print(f"Found {len(projects)} projects (page {page}/{total_pages}, total: {total_count})")
                for p in projects:
                    print(f"Project '{p['name']}' - org: '{p['organisation_id']}', pathogen: '{p['pathogen_name']}', privacy: '{p['privacy']}'")
                
                return {
                    'projects': projects,
                    'pagination': {
                        'page': page,
                        'limit': limit,
                        'total_count': total_count,
                        'total_pages': total_pages,
                        'has_next': has_next,
                        'has_prev': has_prev
                    },
                    'filters': {
                        'organisation_id': filter_org_id,
                        'pathogen_id': filter_pathogen_id,
                        'search': search_term
                    }
                }

        except Exception as e:
            logger.exception(f"Error retrieving projects: {str(e)}")
            return {'error': f'Database error: {str(e)}'}, 500
        
    ### POST /projects ###

    @api.doc('create_project')
    @require_auth(keycloak_auth)
    @require_permission('create_project')
    def post(self):
        """Create a new project

        Request Body:
        {
            "name": "Project Name",
            "description": "Optional description",
            "pathogen_id": "<associated_pathogen_id>",
            "privacy": "public|private|semi-private" 
        }
        """

        # Extract user info to get the user_id and organisation_id
        user_info = extract_user_info(request.user)
        user_id = user_info.get('user_id')
        organisation_id = user_info.get('organisation_id')[0]

        if not organisation_id:
            return {'error': 'User does not belong to any organization'}, 400

        try:
            data = request.get_json()
            if not data:
                return {'error': 'No JSON data provided'}, 400

            name = data.get('name')
            description = data.get('description')
            pathogen_id = data.get('pathogen_id')
            privacy = data.get('privacy', 'public')

            if not name:
                return {'error': 'Project name is required'}, 400
            if not pathogen_id:
                return {'error': 'Associated pathogen_id is required'}, 400

            with get_db_cursor() as cursor:
                cursor.execute("""
                    INSERT INTO projects (name, description, pathogen_id, user_id, organisation_id, privacy)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    RETURNING *
                """, (name, description, pathogen_id, user_id, organisation_id, privacy))

                new_project = cursor.fetchone()
                role_project_member(user_id, new_project["id"], "project-admin")

                log_event("project_created", organisation_id, {"project_name": name}, user_info)
                return {
                    'message': 'Project created successfully',
                    'project': new_project
                }, 201

        except Exception as e:
            if 'duplicate key value violates unique constraint' in str(e):
                return {'error': f'Project with name "{name}" already exists'}, 409
            logger.exception(f"Error creating project: {str(e)}")
            return {'error': f'Database error: {str(e)}'}, 500


@project_ns.route('/<string:project_id>')
class Project(Resource):

    ### GET /projects/<project_id> ###

    @api.doc('get_project')
    def get(self, project_id):

        """Get single project details based on user permissions"""

        organisation_id = keycloak_auth.get_user_org()

        try:
                
            with get_db_cursor() as cursor:
                if organisation_id is not None:
                    cursor.execute("""
                        SELECT *
                        FROM projects
                        WHERE id = %s AND deleted_at IS NULL
                        AND (privacy = 'public' OR organisation_id = %s)
                        ORDER BY name
                    """, (project_id, organisation_id))
                else:
                    user_projects = keycloak_auth.get_user_projects()
                    cursor.execute("""
                        SELECT *
                        FROM projects
                        WHERE id = %s AND deleted_at IS NULL
                        AND (privacy = 'public' OR privacy = 'semi-private' OR id = ANY(%s::uuid[]))
                        ORDER BY name
                    """, (project_id, user_projects))

                project = cursor.fetchone()
                if not project:
                    return {'error': 'Project not found or access denied'}, 404
                else:
                    return project

        except Exception as e:
            logger.exception(f"Error retrieving project {project_id}: {str(e)}")
            return {'error': f'Database error: {str(e)}'}, 500
        
    ### PUT /projects/<project_id> ###    
        
    @api.doc('update_project')
    @require_auth(keycloak_auth)
    @require_permission('edit_projects')
    def put(self, project_id):

        """Update a project by ID user permissions and organisation scope

        Request Body (any of the fields can be updated):
        {
            "name": "New Project Name",
            "description": "Updated description",
            "pathogen_id": "<new_pathogen_id>",
            "privacy": "public|private|semi-private"
        }
        """

        try:
            data = request.get_json()
            if not data:
                return {'error': 'No JSON data provided'}, 400
            
            update_fields = []
            update_values = []
            
            if 'name' in data:
                update_fields.append('name = %s')
                update_values.append(data['name'])
                
            if 'description' in data:
                update_fields.append('description = %s')
                update_values.append(data['description'])
                
            if 'pathogen_id' in data:
                update_fields.append('pathogen_id = %s')
                update_values.append(data['pathogen_id'])

            if 'privacy' in data:
                update_fields.append('privacy = %s')
                update_values.append(data['privacy'])

            if not update_fields:
                return {'error': 'No valid fields provided for update'}, 400
            
            # Always update the updated_at timestamp
            update_fields.append('updated_at = NOW()')
            update_values.append(project_id)

            with get_db_cursor() as cursor:
                query = f"""
                    UPDATE projects 
                    SET {', '.join(update_fields)}
                    WHERE id = %s AND deleted_at IS NULL
                    RETURNING *
                """
                
                cursor.execute(query, update_values)
                
                updated_project = cursor.fetchone()
                
                if not updated_project:
                    return {'error': 'Project not found or already deleted'}, 404
                
                return {
                    'message': 'Project updated successfully',
                    'project': updated_project
                }
                
        except Exception as e:
            if 'duplicate key value violates unique constraint' in str(e):
                return {'error': f'Project name already exists'}, 409
            logger.exception(f"Error updating project {project_id}: {str(e)}")
            return {'error': f'Database error: {str(e)}'}, 500
        

    ### DELETE /projects/<project_id> ###

    @api.doc('delete_project')
    @require_auth(keycloak_auth)
    @require_permission('delete_projects')
    def delete(self, project_id):

        """Delete a project by ID user permissions and organisation scope

        Query Parameters: 
        - hard: true/false (default: false) - If true, permanently delete from database
        """

        try:
            user_info = extract_user_info(request.user)
            # Check if hard delete is requested
            hard_delete = request.args.get('hard', 'false').lower() == 'true'
            
            with get_db_cursor() as cursor:
                if hard_delete:
                    # Hard delete - permanently remove from database
                    cursor.execute("""
                        DELETE FROM projects 
                        WHERE id = %s
                        RETURNING id, name
                    """, (project_id,))
                    
                    deleted_project = cursor.fetchone()
                    
                    if not deleted_project:
                        return {'error': 'Project not found'}, 404
                    
                    return {
                        'message': f'Project "{deleted_project["name"]}" permanently deleted',
                        'delete_type': 'hard'
                    }
                else:
                    # Soft delete - set deleted_at timestamp
                    cursor.execute("""
                        UPDATE projects 
                        SET deleted_at = NOW(), updated_at = NOW()
                        WHERE id = %s AND deleted_at IS NULL
                        RETURNING id, name
                    """, (project_id,))

                    deleted_project = cursor.fetchone()

                    if not deleted_project:
                        return {'error': 'Project not found or already deleted'}, 404

                    log_event("project_deleted", deleted_project["organisation_id"], {"project_name": deleted_project["name"]}, user_info)
                    return {
                        'message': f'Project "{deleted_project["name"]}" deleted (can be restored)',
                        'delete_type': 'soft'
                    }
                
        except Exception as e:
            logger.exception(f"Error deleting project {project_id}: {str(e)}")
            return {'error': f'Database error: {str(e)}'}, 500

@project_ns.route('/<string:project_id>/restore')
class ProjectRestore(Resource):
    
    ### POST /projects/<project_id>/restore ###
    
    @api.doc('restore_project')
    @require_auth(keycloak_auth)
    @require_permission('create_projects')
    def post(self, project_id):

        """Restore a soft-deleted project (system-admin only)"""

        try:
            with get_db_cursor() as cursor:
                cursor.execute("""
                    UPDATE projects 
                    SET deleted_at = NULL, updated_at = NOW()
                    WHERE id = %s AND deleted_at IS NOT NULL
                    RETURNING *
                """, (project_id,))
                
                restored_project = cursor.fetchone()
                
                if not restored_project:
                    return {'error': 'Project not found or not deleted'}, 404
                
                return {
                    'message': f'Project "{restored_project["name"]}" restored successfully',
                    'project': restored_project
                }
        except Exception as e:
            if 'duplicate key value violates unique constraint' in str(e):
                return {'error': 'Cannot restore: A project with this name already exists'}, 409
            logger.exception(f"Error restoring project {project_id}: {str(e)}")
            return {'error': f'Database error: {str(e)}'}, 500


@project_ns.route('/<string:project_id>/users')
class ProjectUsers(Resource):
    
    ### GET /projects/<project_id>/users ###
    
    @api.doc('list_project_users')
    @require_auth(keycloak_auth)
    @require_permission('view_project_users', resource_type='project', resource_id_arg='project_id')
    def get(self, project_id):

        """List users associated with a project"""

        try:
            # Get all users with any project role
            all_project_admins = keycloak_auth.get_users_by_attribute('project-admin', project_id)
            all_project_contributors = keycloak_auth.get_users_by_attribute('project-contributor', project_id)
            all_project_viewers = keycloak_auth.get_users_by_attribute('project-viewer', project_id)

            # Create sets of user IDs for each role
            admin_user_ids = {user['user_id'] for user in all_project_admins}
            contributor_user_ids = {user['user_id'] for user in all_project_contributors}
            viewer_user_ids = {user['user_id'] for user in all_project_viewers}

            # Apply role hierarchy: admin > contributor > viewer
            # Remove lower privilege roles if user has higher privilege
            
            # If user is admin, remove them from contributor and viewer lists
            contributor_user_ids = contributor_user_ids - admin_user_ids
            viewer_user_ids = viewer_user_ids - admin_user_ids
            
            # If user is contributor (but not admin), remove them from viewer list
            viewer_user_ids = viewer_user_ids - contributor_user_ids

            # Filter the user lists based on the cleaned user ID sets
            project_admins = [user for user in all_project_admins if user['user_id'] in admin_user_ids]
            project_contributors = [user for user in all_project_contributors if user['user_id'] in contributor_user_ids]
            project_viewers = [user for user in all_project_viewers if user['user_id'] in viewer_user_ids]

            return {
                'project_id': project_id,
                'project_admins': project_admins,
                'project_contributors': project_contributors,
                'project_viewers': project_viewers,
                'total_users': len(project_admins) + len(project_contributors) + len(project_viewers)
            }
        except Exception as e:
            logger.exception(f"Error retrieving users for project {project_id}: {str(e)}")
            return {'error': f'Failed to retrieve project users: {str(e)}'}, 500
    
    ### POST /projects/<project_id>/users ###
    ### Body: { "user_id": "<keycloak_user_id>", "role": "project-admin|project-contributor|project-viewer", "redirect_uri": "<redirect_uri>" } ###
    
    @api.doc('add_project_user')
    @require_auth(keycloak_auth)
    @require_permission('manage_project_users', resource_type='project', resource_id_arg='project_id')
    def post(self, project_id):
        """Add a user to a project with a specific role"""

        try:
            user_info = extract_user_info(request.user)
            data = request.get_json()
            if not data:
                return {'error': 'No JSON data provided'}, 400

            user_id = data.get('user_id')
            role = data.get('role')
            redirect_uri = data.get('redirect_uri')

            if not user_id or role not in ['project-admin', 'project-contributor', 'project-viewer']:
                return {'error': 'user_id and valid role (project-admin, project-contributor, project-viewer) are required'}, 400

            if not redirect_uri:
                return {'error': 'redirect_uri is required for acceptance link'}, 400

            # Check if user exists in Keycloak
            user = keycloak_auth.get_user(user_id)
            if not user:
                return {'error': 'User not found in Keycloak'}, 404

            if 'force_role' in data:
                role_project_member(user["id"], project_id, role)
                log_event("user_added", project_id, {"email": user["username"], "role": PROJECT_ROLE_MAPPING[role]}, user_info)
                return f"User role updated for project {project_id}"
            else:
                response = invite_user_to_project(user, redirect_uri, project_id, role)
                log_event("user_invited", project_id, {"email": user["username"], "role": PROJECT_ROLE_MAPPING[role]}, user_info)
            return response
        except Exception as e:
            logger.exception(f"Error adding user to project: {str(e)}")
            return {'error': f'Failed to add user to project: {str(e)}'}, 500


@project_ns.route('/<string:project_id>/users/<string:user_id>')
class DeleteProjectUsers(Resource):

    ### DELETE /projects/<project_id>/users ###

    @api.doc('remove_project_user')
    @require_auth(keycloak_auth)
    @require_permission('manage_project_users', resource_type='project', resource_id_arg='project_id')
    def delete(self, project_id, user_id):

        """Remove a user from a project"""

        try:
            user_info = extract_user_info(request.user)
            # Check if user exists in Keycloak
            user = keycloak_auth.get_user(user_id)
            if not user:
                return {'error': 'User not found in Keycloak'}, 404

            # Remove user from all project roles
            removed_roles = []
            for role in ['project-admin', 'project-contributor', 'project-viewer']:
                if keycloak_auth.user_has_attribute(user_id, role, project_id):
                    success = keycloak_auth.remove_attribute_value(user_id, role, project_id)
                    if success:
                        removed_roles.append(role)
                        print(f"Removed project_id {project_id} from role {role} for user {user_id}")
                    else:
                        return {'error': f'Failed to remove role {role}'}, 500

            if not removed_roles:
                return {'message': 'User was not associated with the project'}, 200

            users_name = f"{user['attributes']['name']} {user['attributes']['surname']}"
            log_event("project_user_deleted", project_id, {"email": user["username"], "name": users_name}, user_info)
            return {
                'message': 'User removed from project successfully',
                'user_id': user_id,
                'project_id': project_id,
                'removed_roles': removed_roles
            }, 200

        except Exception as e:
            logger.exception(f"Error removing user from project: {str(e)}")
            return {'error': f'Failed to remove user from project: {str(e)}'}, 500


##########################
### SUBMISSIONS 
##########################

@project_ns.route('/<string:project_id>/submissions2')
class ProjectSubmissions2(Resource):

    ### GET /projects/<project_id>/submissions2

    @api.doc('list_submissions_v2')
    @require_auth(keycloak_auth) 
    @require_permission('view_project_submissions', resource_type='project', resource_id_arg='project_id')
    def get(self, project_id):

        """List all submissions including drafts"""

        try:
            with get_db_cursor() as cursor:
                cursor.execute("""
                    SELECT s.*, 
                           COUNT(sf.id) as file_count,
                           ARRAY_AGG(sf.filename) FILTER (WHERE sf.id IS NOT NULL) as filenames
                    FROM submissions s
                    LEFT JOIN submission_files sf ON s.id = sf.submission_id
                    WHERE s.project_id = %s
                    GROUP BY s.id
                    ORDER BY s.created_at DESC
                """, (project_id,))
                
                submissions = cursor.fetchall()
                
                return {
                    'project_id': project_id,
                    'submissions': submissions,
                    'total': len(submissions)
                }
                
        except Exception as e:
            logger.exception(f"Error listing submissions: {str(e)}")
            return {'error': f'Failed to list submissions: {str(e)}'}, 500
        
    ### POST /projects/<project_id>/submissions2

    @api.doc('create_submission_v2')
    @require_auth(keycloak_auth)
    @require_permission('upload_submission', resource_type='project', resource_id_arg='project_id')
    def post(self, project_id):

        """Create a new submission"""
        
        try:
            data = request.get_json()
            if not data:
                return {'error': 'No JSON data provided'}, 400

            submission_name = data.get('submission_name')

            user_info = extract_user_info(request.user)
            current_user_id = user_info.get('user_id')
            
            if not submission_name:
                return {'error': 'submission_name is required'}, 400

            if not current_user_id:
                return {'error': 'user_id is required'}, 400

            with get_db_cursor() as cursor:
                cursor.execute("""
                    INSERT INTO submissions (project_id, submission_name, status, user_id)
                    VALUES (%s, %s, 'draft', %s)
                    RETURNING *
                """, (project_id, submission_name, current_user_id))
                
                new_submission = cursor.fetchone()

                log_event("submission_created", new_submission['id'], {"sumbission": new_submission}, user_info)
                return {
                    'message': 'Submission created successfully',
                    'submission': new_submission
                }, 201

        except Exception as e:
            logger.exception(f"Error creating submission for project {project_id}: {str(e)}")
            return {'error': f'Failed to create submission: {str(e)}'}, 500


@project_ns.route('/<string:project_id>/submissions2/<string:submission_id>')
class ProjectSubmission2(Resource):

    ### GET /projects/<project_id>/submissions2/<submission_id>

    @api.doc('get_submission_v2')
    @require_auth(keycloak_auth)
    @require_permission('view_project_submissions', resource_type='project', resource_id_arg='project_id')
    def get(self, project_id, submission_id):

        """Get submission details including associated files"""

        try:
            with get_db_cursor() as cursor:
                # Get submission details only
                cursor.execute("""
                    SELECT s.*, p.name as project_name, pat.id as pathogend_id, pat.name as pathogen_name, COUNT(sf.id) as file_count
                    FROM submissions s
                    LEFT JOIN submission_files sf ON s.id = sf.submission_id
                    LEFT JOIN projects p ON s.project_id = p.id
                    LEFT JOIN pathogens pat ON p.pathogen_id::uuid = pat.id::uuid
                    WHERE s.id = %s AND s.project_id = %s
                    GROUP BY s.id, p.id, pat.id
                """, (submission_id, project_id))
                
                submission = cursor.fetchone()
                
                if not submission:
                    return {'error': 'Submission not found'}, 404
                

                cursor.execute("""
                    SELECT * FROM submission_files
                    WHERE submission_id = %s
                """, (submission_id,))
                
                files = cursor.fetchall()
                
                return {
                    'submission': submission,
                    'files': files
                }
        except Exception as e:
            logger.exception(f"Error retrieving submission {submission_id}: {str(e)}")
            return {'error': f'Failed to retrieve submission: {str(e)}'}, 500
        
    ### DELETE /projects/<project_id>/submissions2/<submission_id>

    @api.doc('delete_submission_v2')
    @require_auth(keycloak_auth)
    @require_permission('upload_submission', resource_type='project', resource_id_arg='project_id')
    def delete(self, project_id, submission_id):

        """Delete a submission"""

        try:
            with get_db_cursor() as cursor:
                
                # check if submission exists
                cursor.execute("""
                    SELECT * FROM submissions 
                    WHERE id = %s AND project_id = %s
                """, (submission_id, project_id))
                submission = cursor.fetchone()
                if not submission:
                    return {'error': 'Submission not found'}, 404
                
                # Delete associated files first
                cursor.execute("""
                    DELETE FROM submission_files
                    WHERE submission_id = %s
                """, (submission_id,))

                # delete the isolates from isolates table
                cursor.execute("""
                    DELETE FROM isolates
                    WHERE submission_id = %s
                """, (submission_id,))

                ### DELETE MINIO OBJECTS HERE

                # Delete the submission
                cursor.execute("""
                    DELETE FROM submissions 
                    WHERE id = %s AND project_id = %s
                """, (submission_id, project_id)) 

                return {
                    'message': f'Submission {submission_id} deleted successfully'
                }, 200
                

        except Exception as e:
            logger.exception(f"Error deleting submission {submission_id}: {str(e)}")
            return {'error': f'Failed to delete submission: {str(e)}'}, 500
        
    ### PUT /projects/<project_id>/submissions2/<submission_id>

    @api.doc('update_submission_v2')
    @require_auth(keycloak_auth)
    @require_permission('upload_submission', resource_type='project', resource_id_arg='project_id')
    def put(self, project_id, submission_id):
        
        """Update submission details (e.g., submission_name)"""

        try:
            data = request.get_json()

            submission_name = data.get('submission_name')

            if not submission_name:
                return {'error': 'submission_name is required'}, 400

            with get_db_cursor() as cursor:
                cursor.execute("""
                    UPDATE submissions 
                    SET submission_name = %s, updated_at = NOW()
                    WHERE id = %s AND project_id = %s
                    RETURNING *
                """, (submission_name, submission_id, project_id))
                
                updated_submission = cursor.fetchone()
                
                if not updated_submission:
                    return {'error': 'Submission not found'}, 404
                
                return {
                    'message': 'Submission updated successfully',
                    'submission': updated_submission
                }
                
        except Exception as e:
            logger.exception(f"Error updating submission {submission_id}: {str(e)}")
            return {'error': f'Database error: {str(e)}'}, 500


@project_ns.route('/<string:project_id>/submissions/<string:submission_id>/upload2')
class ProjectSubmissionFiles2(Resource):

    ### POST /projects/<project_id>/submissions2/<submission_id>/upload2

    @api.doc('upload_file_v2')
    @require_auth(keycloak_auth)
    @require_permission('upload_submission', resource_type='project', resource_id_arg='project_id')
    def post(self, project_id, submission_id):

        """Upload a file to submission with streaming to MinIO"""

        try:
            user_info = extract_user_info(request.user)
            with get_db_cursor() as cursor:
                cursor.execute("""
                    SELECT * FROM submissions 
                    WHERE id = %s AND project_id = %s
                """, (submission_id, project_id))
                
                submission = cursor.fetchone()
                if not submission:
                    return {'error': 'Submission not found'}, 404

                if submission['status'] not in ['draft', 'error', 'validating', 'validated']:
                    return {'error': f'Cannot upload files to submission in status: {submission["status"]}.'}, 400

            # Check file upload
            if 'file' not in request.files:
                return {'error': 'No file provided'}, 400
            
            file = request.files['file']
            if not file or not file.filename:
                return {'error': 'Invalid file'}, 400

            # Determine file type
            filename = file.filename.lower()
            if filename.endswith('.tsv') or filename.endswith('.txt'):
                file_type = 'tsv'
            elif filename.endswith(('.fasta', '.fa', '.fas')):
                file_type = 'fasta'
            else:
                return {'error': 'File must be TSV or FASTA format'}, 400

            # Stream process file and calculate metadata
            file_data = []
            file_size = 0
            md5_hash = hashlib.md5()
            
            # Read file in chunks for streaming
            while True:
                chunk = file.stream.read(8192)  
                if not chunk:
                    break
                file_data.append(chunk)
                file_size += len(chunk)
                md5_hash.update(chunk)
            
            file_md5 = md5_hash.hexdigest()
            
            # Generate object_id for MinIO
            object_id = str(uuid.uuid4())
            
            # Upload directly to MinIO
            file_content = b''.join(file_data)
            
            try:
                # Get MinIO credentials and upload
                minio_bucket = settings.MINIO_BUCKET 
                minio_client = get_minio_client(self)
                
                # Upload to MinIO with object_id as the key
                from io import BytesIO
                file_stream = BytesIO(file_content)
                
                result = minio_client.put_object(
                    bucket_name=minio_bucket,
                    object_name=object_id,
                    data=file_stream,
                    length=file_size,
                    content_type='application/octet-stream'
                )
                
                logger.info(f"Uploaded {file.filename} ({file_size} bytes) to MinIO bucket '{minio_bucket}' with object_id {object_id}")
                
            except Exception as upload_error:
                logger.exception(f"Failed to upload file to MinIO: {str(upload_error)}")
                return {'error': f'MinIO upload failed: {str(upload_error)}'}, 500
            
            # Store file record in database
            with get_db_cursor() as cursor:
                cursor.execute("""
                    INSERT INTO submission_files 
                    (submission_id, filename, file_type, object_id, file_size, md5_hash)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    RETURNING *
                """, (submission_id, file.filename, file_type, object_id, file_size, file_md5))
                
                file_record = cursor.fetchone()

            log_event("file_uploaded", project_id, {"submission_id": {submission_id}, "files": file_record}, user_info)
            return {
                'message': 'File uploaded successfully',
                'submission_id': file_record['submission_id'],
                'file': {
                    'id': file_record['id'],
                    'filename': file_record['filename'],
                    'file_type': file_record['file_type'],
                    'file_size': file_record['file_size'],
                    'object_id': file_record['object_id']
                }
            }, 201
            
        except Exception as e:
            logger.exception(f"Error uploading file to submission {submission_id}")
            return {'error': f'Upload failed: {str(e)}'}, 500
    

@project_ns.route('/<string:project_id>/submissions/<string:submission_id>/files2/<string:file_id>')
class ReplaceProjectSubmissionFile2(Resource):

    ### PUT /projects/<project_id>/submissions2/<submission_id>/files2/<file_id>

    @api.doc('replace_file_v2')
    @require_auth(keycloak_auth)
    @require_permission('upload_submission', resource_type='project', resource_id_arg='project_id')
    def put(self, project_id, submission_id, file_id):
        """Replace an existing submission file with a new upload (streaming to MinIO)"""
        # Similar to upload but replaces existing file record
        pass  # Implementation would be similar to the upload_file_v2 method

    
    ### DELETE /projects/<project_id>/submissions2/<submission_id>/files2/<file_id>
    
    @api.doc('delete_file_v2')
    @require_auth(keycloak_auth)
    @require_permission('upload_submission', resource_type='project', resource_id_arg='project_id')
    def delete(self, project_id, submission_id, file_id):

        """Delete a submission file both from MinIO and database"""
        
        try:
            # Verify submission exists and is in 'uploading' status
            with get_db_cursor() as cursor:
                cursor.execute("""
                    SELECT * FROM submissions 
                    WHERE id = %s AND project_id = %s
                """, (submission_id, project_id))
                
                submission = cursor.fetchone()
                if not submission:
                    return {'error': 'Submission not found'}, 404

                if submission['status'] not in ['draft', 'error', 'validating', 'validated']:
                    return {'error': f'Cannot delete files from submission in status: {submission["status"]}.'}, 400

                # Verify file exists in this submission
                cursor.execute("""
                    SELECT * FROM submission_files 
                    WHERE id = %s AND submission_id = %s
                """, (file_id, submission_id))
                
                file_record = cursor.fetchone()
                if not file_record:
                    return {'error': 'File not found'}, 404

            # Delete from MinIO
            try:
                minio_bucket = settings.MINIO_BUCKET
                minio_client = get_minio_client(self)
                
                minio_client.remove_object(
                    bucket_name=minio_bucket,
                    object_name=file_record['object_id']
                )
                
                logger.info(f"Deleted file {file_record['filename']} from MinIO bucket '{minio_bucket}'")
                
            except Exception as delete_error:
                logger.exception(f"Failed to delete file from MinIO: {str(delete_error)}")
                return {'error': f'MinIO deletion failed: {str(delete_error)}'}, 500

            # Delete from database
            with get_db_cursor() as cursor:
                cursor.execute("""
                    DELETE FROM submission_files 
                    WHERE id = %s
                """, (file_id,))

            
            
            return {
                'message': 'File deleted successfully',
                'file_id': file_id
            }, 200
            
        except Exception as e:
            logger.exception(f"Error deleting file {file_id} from submission {submission_id}: {str(e)}")
            return {'error': f'Deletion failed: {str(e)}'}, 500


@project_ns.route('/<string:project_id>/submissions/<string:submission_id>/validate2')
class ProjectSubmissionValidate2(Resource):

    ### GET /projects/<project_id>/submissions2/<submission_id>/validate2

    @api.doc('get_validation_status_v2')
    @require_auth(keycloak_auth)
    @require_permission('upload_submission', resource_type='project', resource_id_arg='project_id')
    def get(self, project_id, submission_id):

        """Get validation status and errors for a submission"""
        
        try:
          
            with get_db_cursor() as cursor:
                cursor.execute("""
                    SELECT s.*, p.name as project_name, p.privacy 
                    FROM submissions s
                    JOIN projects p ON s.project_id = p.id
                    WHERE s.id = %s AND s.project_id = %s
                """, (submission_id, project_id))
                
                submission = cursor.fetchone()
                if not submission:
                    return {'error': 'Submission not found'}, 404


            with get_db_cursor() as cursor:
                cursor.execute("""
                    SELECT * FROM isolates 
                    WHERE submission_id = %s
                """, (submission_id,))
                
                isolates = cursor.fetchall()
                
                # Separate different types of errors and parse JSON fields
                validation_errors = []
                sequence_errors = []
                
                for iso in isolates:
                    if iso['status'] == 'error' and iso['error']:
                        try:
                            parsed_error = json.loads(iso['error']) if isinstance(iso['error'], str) else iso['error']
                            validation_errors.append(parsed_error)
                        except (json.JSONDecodeError, TypeError):
                            validation_errors.append(iso['error'])
                    
                    if iso['status'] == 'sequence_error' and iso['seq_error']:
                        try:
                            parsed_seq_error = json.loads(iso['seq_error']) if isinstance(iso['seq_error'], str) else iso['seq_error']
                            sequence_errors.append(parsed_seq_error)
                        except (json.JSONDecodeError, TypeError):
                            sequence_errors.append(iso['seq_error'])

                return {
                    'submission_id': submission_id,
                    'submission_name': submission['submission_name'],
                    'project_id': project_id,
                    'project_name': submission['project_name'],
                    'visibility': submission['privacy'],
                    'status': submission['status'],
                    'total_isolates': len(isolates),
                    'validated': len([iso for iso in isolates if iso['status'] == 'validated']),
                    'schema_errors': len([iso for iso in isolates if iso['status'] == 'error']),
                    'sequence_errors': len([iso for iso in isolates if iso['status'] == 'sequence_error']),
                    'validation_errors': validation_errors,
                    'sequence_errors_details': sequence_errors,
                    'error_count': len([iso for iso in isolates if iso['status'] in ['error', 'sequence_error']])
                }
          
        except Exception as e:
            logger.exception(f"Error retrieving validation status for submission {submission_id}: {str(e)}")
            return {'error': f'Failed to retrieve validation status: {str(e)}'}, 500

    ### POST /projects/<project_id>/submissions2/<submission_id>/validate2

    @api.doc('validate_submission_v2')
    @require_auth(keycloak_auth)
    @require_permission('upload_submission', resource_type='project', resource_id_arg='project_id')
    def post(self, project_id, submission_id):

        """Validate submission files"""
        
        try:
            user_info = extract_user_info(request.user)
            # Check if validation is already running and prevent concurrent validation
            with get_db_cursor() as cursor:
                cursor.execute("""
                    SELECT status FROM submissions 
                    WHERE id = %s
                """, (submission_id,))
                
                submission = cursor.fetchone()
                if not submission:
                    return {'error': 'Submission not found'}, 404
                
                if submission['status'] == 'validating':
                    return {'error': 'Validation already in progress for this submission'}, 409
                
                # Set status to validating to prevent concurrent validation
                cursor.execute("""
                    UPDATE submissions 
                    SET status = 'validating', updated_at = NOW()
                    WHERE id = %s AND status != 'validating'
                """, (submission_id,))
                
                if cursor.rowcount == 0:
                    return {'error': 'Validation already in progress for this submission'}, 409

            # Get uploaded files for basic validation
            with get_db_cursor() as cursor:
                cursor.execute("""
                    SELECT * FROM submission_files 
                    WHERE submission_id = %s
                """, (submission_id,))
                files = cursor.fetchall()

            tsv_files = [f for f in files if f['file_type'] == 'tsv']
            fasta_files = [f for f in files if f['file_type'] == 'fasta']

            # Basic validation: check file counts
            if len(tsv_files) != 1:
                with get_db_cursor() as cursor:
                    cursor.execute("""
                        UPDATE submissions 
                        SET status = 'error'
                        WHERE id = %s
                    """, (submission_id,))
                
                return {
                    'status': 'error',
                    'validation_errors': [f'Exactly 1 TSV file required, found {len(tsv_files)}']
                }, 400
            
            if len(fasta_files) < 1:
                with get_db_cursor() as cursor:
                    cursor.execute("""
                        UPDATE submissions 
                        SET status = 'error'
                        WHERE id = %s
                    """, (submission_id,))
                
                return {
                    'status': 'error',
                    'validation_errors': [f'At least 1 FASTA file required, found {len(fasta_files)}']
                }, 400
            
            tsv_file_record = tsv_files[0]
            
            minio_bucket = settings.MINIO_BUCKET
            minio_client = get_minio_client(self)

            try:
                tsv_object = minio_client.get_object(
                    bucket_name=minio_bucket,
                    object_name=tsv_file_record['object_id']
                )
                tsv_content = tsv_object.read().decode('utf-8')

                tsv_json = tsv_to_json(tsv_content, project_id)

                # Delete all existing isolates for this submission first (clean slate)
                with get_db_cursor() as cursor:
                    cursor.execute("""
                        DELETE FROM isolates 
                        WHERE submission_id = %s
                    """, (submission_id,))
                    
                    deleted_count = cursor.rowcount
                    if deleted_count > 0:
                        print(f"Deleted {deleted_count} existing isolates for submission {submission_id}")

                # Insert all rows fresh from the TSV
                for row_index, row in enumerate(tsv_json):
                    with get_db_cursor() as cursor:
                        cursor.execute("""
                            INSERT INTO isolates (submission_id, isolate_data, tsv_row)
                            VALUES (%s, %s, %s)
                        """, (submission_id, json.dumps(row), row_index + 1))
                
                with get_db_cursor() as cursor:
                    cursor.execute("""
                        SELECT * FROM isolates 
                        WHERE submission_id = %s 
                        AND (status IS NULL OR status = '' OR status = 'error')
                    """, (submission_id,))
                    
                    existing_isolates = cursor.fetchall()
                    
                    for isolate in existing_isolates:
                        isolate_data = isolate.get('isolate_data', {})
                        
                        # Run validation against schema
                        is_valid, errors = validate_against_schema(isolate_data, isolate['tsv_row'], project_id)

                        if not is_valid:
                            cursor.execute("""
                                UPDATE isolates
                                SET error = %s, status = 'error', updated_at = NOW()
                                WHERE id = %s
                            """, (json.dumps(errors), isolate['id']))
                        else:
                            cursor.execute("""
                                UPDATE isolates 
                                SET status = 'validated', updated_at = NOW()
                                WHERE id = %s
                            """, (isolate['id'],))

                            # only index if validated
                            cursor.execute("""
                                SELECT i.*, s.project_id, p.pathogen_id, p.privacy as visibility, p.name as project_name, pat.name as pathogen_name
                                FROM isolates i
                                LEFT JOIN submissions s ON i.submission_id = s.id
                                LEFT JOIN projects p ON s.project_id = p.id
                                LEFT JOIN pathogens pat ON p.pathogen_id = pat.id
                                WHERE i.id = %s
                            """, (isolate['id'],))

                            isolate_data = cursor.fetchone()

                            if isolate_data:
                                send_to_elastic2(isolate_data)

                # After validating all isolates, check if any have errors
                with get_db_cursor() as cursor:
                    cursor.execute("""
                        SELECT * FROM isolates 
                        WHERE submission_id = %s
                    """, (submission_id,))

                    all_isolates = cursor.fetchall()

                    isolates_with_errors = [iso["error"] for iso in all_isolates if iso['status'] == 'error']


                    # Only start job for sequence checking if there are validated isolates
                    validated_isolates = [iso for iso in all_isolates if iso['status'] == 'validated']
                    schema_errors = [iso for iso in all_isolates if iso['status'] == 'error']
                    
                    # Set submission status based on immediate results (schema validation)
                    if schema_errors:
                        # If there are schema errors, set submission status to 'error' immediately
                        cursor.execute("""
                            UPDATE submissions 
                            SET status = 'error', updated_at = NOW()
                            WHERE id = %s
                        """, (submission_id,))
                        print(f"Schema validation found {len(schema_errors)} errors - setting submission status to 'error'")
                    elif validated_isolates:
                        # If no schema errors but have validated isolates, keep as 'validating' until job completes
                        print(f"Schema validation passed for {len(validated_isolates)} isolates - keeping submission status as 'validating' until sequence checking completes")
                        
                        # Queue sequence validation job
                        from jobs import add_job
                        job_data = {
                            'submission_id': submission_id,
                            'isolate_ids': [iso['id'] for iso in validated_isolates]
                        }
                        job_id = add_job('validate_sequences', job_data)
                        print(f"Queued sequence validation job {job_id} for {len(validated_isolates)} validated isolates")
                    else:
                        # Edge case: no isolates at all
                        cursor.execute("""
                            UPDATE submissions 
                            SET status = 'error', updated_at = NOW()
                            WHERE id = %s
                        """, (submission_id,))
                        print("No isolates found - setting submission status to 'error'")

                    log_event("submission_validated", submission_id, {
                       "total_isolates": len(all_isolates),
                       "schema_errors": len(schema_errors),
                       "validated_isolates": len(all_isolates) - len(isolates_with_errors)}, user_info)

                    return {
                        "total_isolates": len(all_isolates),
                        "schema_errors": len(schema_errors), 
                        "validated_isolates": len(validated_isolates),
                        "validation_errors": [iso['error'] if iso['error'] else None for iso in schema_errors]
                    }, 200


            except Exception as e:
                logger.exception(f"Error validating submission {submission_id}: {str(e)}")
                # Reset submission status from 'validating' to allow retry
                with get_db_cursor() as cursor:
                    cursor.execute("""
                        UPDATE submissions 
                        SET status = 'error', updated_at = NOW()
                        WHERE id = %s
                    """, (submission_id,))
                return {'error': f'Validation failed: {str(e)}'}, 500

        except Exception as e:
            logger.exception(f"Error during validation of submission {submission_id}: {str(e)}")
            # Reset submission status from 'validating' to allow retry
            with get_db_cursor() as cursor:
                cursor.execute("""
                    UPDATE submissions 
                    SET status = 'error', updated_at = NOW()
                    WHERE id = %s
                """, (submission_id,))
            return {'error': f'Validation failed: {str(e)}'}, 500


@project_ns.route('/<string:project_id>/submissions/<string:submission_id>/publish2')
class ProjectSubmissionPublish2(Resource):

    ### POST /projects/<project_id>/submissions2/<submission_id>/publish2 ###

    @api.doc('publish_submission_v2')
    @require_auth(keycloak_auth)
    @require_permission('publish_submission', resource_type='project', resource_id_arg='project_id')
    def post(self, project_id, submission_id):

        """Publish a submission - makes isolates searchable"""
        user_info = extract_user_info(request.user)
        with get_db_cursor() as cursor:
            # First check if ALL isolates in the submission are validated
            cursor.execute("""
                SELECT COUNT(*) as total,
                    COUNT(*) FILTER (WHERE status = 'validated' AND error IS NULL AND seq_error IS NULL AND object_id IS NOT NULL) as ready_for_publish
                FROM isolates 
                WHERE submission_id = %s
            """, (submission_id,))
            
            counts = cursor.fetchone()
            
            # All-or-nothing approach: only publish if ALL isolates are ready
            if counts['ready_for_publish'] != counts['total'] or counts['total'] == 0:
                return {
                    'error': f'Cannot publish: {counts["ready_for_publish"]} of {counts["total"]} isolates are ready. All isolates must be validated with no errors to publish.'
                }, 400
            
            # All isolates are ready, proceed with publishing
            cursor.execute("""
                UPDATE isolates
                SET status = 'published'
                WHERE submission_id = %s
                AND status = 'validated'
                AND seq_error IS NULL
                AND error IS NULL
                AND object_id IS NOT NULL
            """, (submission_id,))

            # Update submission status to published
            cursor.execute("""
                UPDATE submissions
                SET status = 'published', updated_at = NOW()
                WHERE id = %s
            """, (submission_id,))

            # Get published isolates to re-index in Elasticsearch
            cursor.execute("""
                SELECT i.*, s.project_id, p.pathogen_id FROM isolates i
                LEFT JOIN submissions s ON i.submission_id = s.id
                LEFT JOIN projects p ON s.project_id = p.id
                WHERE i.submission_id = %s
                AND i.status = 'published'
            """, (submission_id,))
            published_isolates = cursor.fetchall()

            for isolate in published_isolates:
                send_to_elastic2(isolate)

        log_event("submission_published", submission_id, {"published_isolates": len(published_isolates)}, user_info)
        return {'message': f'Submission published successfully with {len(published_isolates)} isolates'}, 200

@project_ns.route('/<string:project_id>/submissions/<string:submission_id>/unpublish2')
class ProjectSubmissionUnpublish2(Resource):

    ### POST /projects/<project_id>/submissions2/<submission_id>/unpublish2 ###

    @api.doc('unpublish_submission_v2')
    @require_auth(keycloak_auth)
    @require_permission('publish_submission', resource_type='project', resource_id_arg='project_id')
    def post(self, project_id, submission_id):

        """Unpublish a submission - makes isolates non-searchable"""
        user_info = extract_user_info(request.user)
        with get_db_cursor() as cursor:
            # Revert isolates from published back to validated
            cursor.execute("""
                UPDATE isolates
                SET status = 'validated'
                WHERE submission_id = %s
                AND status = 'published'
            """, (submission_id,))

            # Update submission status back to validated
            cursor.execute("""
                UPDATE submissions
                SET status = 'validated', updated_at = NOW()
                WHERE id = %s
            """, (submission_id,))

            # Get unpublished isolates to re-index in Elasticsearch with updated status
            cursor.execute("""
                SELECT i.*, s.project_id, p.pathogen_id FROM isolates i
                LEFT JOIN submissions s ON i.submission_id = s.id
                LEFT JOIN projects p ON s.project_id = p.id
                WHERE i.submission_id = %s
                AND i.status = 'validated'
            """, (submission_id,))
            unpublished_isolates = cursor.fetchall()

            for isolate in unpublished_isolates:
                send_to_elastic2(isolate)

        log_event("submission_unpublished", submission_id, {"unpublished_isolates": len(unpublished_isolates)}, user_info)
        return {'message': f'Submission unpublished successfully. {len(unpublished_isolates)} isolates reverted to validated status'}, 200



###########################
### SEARCH
###########################

search_ns = api.namespace('search', description='Search endpoints')
@search_ns.route('/')

class Search(Resource):
    
    ### POST /search ###

    @api.doc('search_samples')
    @require_auth(keycloak_auth)
    def post(self):

        print("Search samples called")

        """Search published samples in Elasticsearch"""

        try:
            data = request.get_json()

            print('========================================')
            print("Incoming search query:")
            print(data)
            print('========================================')

            # convert json data to string and replace all .keyword with ''
            data_str = json.dumps(data).replace('.keyword', '')
            data = json.loads(data_str)

            user_project_ids = keycloak_auth.get_user_projects()
            organisation_project_ids = keycloak_auth.get_user_organisation_projects()

            user_project_ids.extend(organisation_project_ids)

            access_filter = {
                "bool": {
                    "should": [
                        {
                            "terms": {
                                "project_id": user_project_ids
                            }
                        },
                        {
                            "terms": {
                                "visibility": ["public", "semi-private"]
                            }
                        }
                    ],
                    "minimum_should_match": 1
                }
            }

            print(f"Access filter: {access_filter}")

            # Add access filter to the query
            if 'query' in data and 'bool' in data['query']:
                if 'must' not in data['query']['bool']:
                    data['query']['bool']['must'] = []
                elif not isinstance(data['query']['bool']['must'], list):
                    data['query']['bool']['must'] = [data['query']['bool']['must']]
                
                data['query']['bool']['must'].append(access_filter)
            elif 'query' in data:
                existing_query = data['query']

                data['query'] = {
                    "bool": {
                        "must": [
                            existing_query
                        ]
                    }
                }

            else:
                data['query'] = access_filter

            if not data:
                return {'error': 'No JSON data provided'}, 400

            print("Final Query ========================")
            print(data['query'])
            print("===================================")

            results = query_elastic(data)

            print(results)

            return results, 200

        except Exception as e:
            logger.exception(f"Error searching samples: {str(e)}")
            return {'error': f'Search error: {str(e)}'}, 500


@search_ns.route('/reindex')
class Reindex(Resource):

    ### POST /search/reindex ###

    @api.doc('reindex_samples')
    @require_auth(keycloak_auth)
    @require_permission('system_admin_access')
    def post(self):
        """Reindex all isolates in Elasticsearch with batch processing
        
        Query Parameters:
        - batch_size: Number of isolates to process per request (default: 500, max: 2000)
        - offset: Starting position (default: 0)
        """
        try:
            batch_size = min(int(request.args.get('batch_size', 500)), 2000)
            offset = int(request.args.get('offset', 0))

            failures = []
            
            
            with get_db_cursor() as cursor:
                # Get total count
                cursor.execute("""
                    SELECT COUNT(*) as total
                    FROM isolates i
                    JOIN submissions s ON i.submission_id = s.id
                    JOIN projects p ON s.project_id = p.id
                """)
                total_count = cursor.fetchone()['total']
                
                # Get batch
                cursor.execute("""
                    SELECT i.*, s.project_id as project_id, p.privacy as visibility, p.pathogen_id as pathogen_id
                    FROM isolates i
                    JOIN submissions s ON i.submission_id = s.id
                    JOIN projects p ON s.project_id = p.id
                    ORDER BY i.id
                    LIMIT %s OFFSET %s
                """, (batch_size, offset))
                
                isolates_batch = cursor.fetchall()
                reindexed_count = 0

                for isolate in isolates_batch:
                    es_exists = check_isolate_in_elastic(isolate['id'])
                    if not es_exists:
                        elastic_operation = send_to_elastic2(isolate)
                        
                        if elastic_operation:
                            reindexed_count += 1
                        else:
                            failures.append({
                                'isolate_id': isolate['id'],
                                'error': 'Failed to index isolate in Elasticsearch'
                            })
                            


            next_offset = offset + batch_size
            has_more = next_offset < total_count
            
            return {
                'message': f'Batch completed. {reindexed_count} isolates reindexed.',
                'processed': len(isolates_batch),
                'reindexed': reindexed_count,
                'progress': {
                    'current_offset': offset,
                    'next_offset': next_offset if has_more else None,
                    'total': total_count,
                    'completed': min(next_offset, total_count),
                    'percent': round((min(next_offset, total_count) / total_count) * 100, 2)
                },
                'has_more': has_more,
                'failures': failures
            }, 200
        
        except ValueError:
            return {'error': 'Invalid batch_size or offset parameter'}, 400
        except Exception as e:
            logger.exception(f"Error during reindexing: {str(e)}")
            return {'error': f'Reindexing error: {str(e)}'}, 500



##########################
### DOWNLOAD
##########################

download_ns = api.namespace('download', description='Download endpoints')

@download_ns.route('/isolates')
class DownloadSamples(Resource):

    ### POST /download/isolates ###

    @api.doc('download_isolates')
    @require_auth(keycloak_auth)
    def post(self):

        try:
            user_info = extract_user_info(request.user)
            data = request.get_json()
            isolate_ids = data.get('isolates', [])

            if not isolate_ids:
                return {'error': 'isolates list is required'}, 400
            
            # Get isolate data and validate permissions
            with get_db_cursor() as cursor:
                placeholders = ','.join(['%s'] * len(isolate_ids))
                cursor.execute(f"""
                    SELECT i.id, i.isolate_id, i.object_id, i.isolate_data, 
                           s.project_id, p.name as project_name
                    FROM isolates i
                    JOIN submissions s ON i.submission_id = s.id
                    JOIN projects p ON s.project_id = p.id
                    WHERE i.id IN ({placeholders})
                    AND i.status = 'published'
                    AND i.object_id IS NOT NULL
                    AND i.isolate_data IS NOT NULL
                """, isolate_ids)
                
                isolates = cursor.fetchall()

            if not isolates:
                return {'error': 'No valid isolates found'}, 404

            # Compile isolate data into TSV format
            tsv_content = ""
            tsv_lines = []
            header_written = False
            for isolate in isolates:
                isolate_data = isolate['isolate_data']
                if not header_written:
                    headers = isolate_data.keys()
                    tsv_lines.append('\t'.join(headers))
                    header_written = True
                values = [str(isolate_data.get(h, '')) for h in headers]
                tsv_lines.append('\t'.join(values))
                tsv_content = '\n'.join(tsv_lines)

            # get every object_id and generate download URLs with get_object_id_url(object_id)
            download_links = []
            for isolate in isolates:
                object_id = isolate['object_id']
                download_url = get_object_id_url(object_id)
                download_links.append({
                    'isolate_id': isolate['isolate_id'],
                    'project_id': isolate['project_id'],
                    'project_name': isolate['project_name'],
                    'download_url': download_url
                })

            log_event("data_download", isolates[0]['project_id'], {"sample_count": len(isolates)}, user_info)
            return {
                'tsv_data': tsv_content,
                'download_links': download_links
            }, 200
        except Exception as e:
            logger.exception(f"Error downloading isolates: {str(e)}")
            return {'error': f'Download error: {str(e)}'}, 500
            
@download_ns.route('/query')
class DownloadSamplesByQuery(Resource):

    ### POST /download/query ###

    @api.doc('download_isolates_by_query')
    @require_auth(keycloak_auth)
    def post(self):
        try:
            data = request.get_json()

            if not data:
                return {'error': 'No JSON data provided'}, 400

            results = query_elastic(data)

            hits = results.get('hits', {}).get('hits', [])
            if not hits:
                return {'error': 'No matching isolates found'}, 404

            # Compile isolate data into TSV format
            tsv_content = ""
            tsv_lines = []
            header_written = False
            for hit in hits:
                source = hit.get('_source', {})
                sample_data = source.get('sample_data', {})  
                if not header_written:
                    headers = sample_data.keys()  
                    tsv_lines.append('\t'.join(headers))
                    header_written = True
                values = [str(sample_data.get(h, '')) for h in headers]  
                tsv_lines.append('\t'.join(values))
            tsv_content = '\n'.join(tsv_lines)

            return {
                'tsv_data': tsv_content
            }, 200

        except Exception as e:
            logger.exception(f"Error downloading isolates by query: {str(e)}")
            return {'error': f'Download error: {str(e)}'}, 500

##########################
### INVITES
##########################

invite_ns = api.namespace('invites', description='Invite management endpoints')


@invite_ns.route('/project/<string:project_id>')
class ProjectInviteStatus(Resource):
    ### GET /invites/project/<project_id> ###

    @api.doc('get_project_invites')
    def get(self, project_id):
        users = keycloak_auth.get_users_by_attribute('invite_project_id', project_id)
        user_invites = extract_invite_roles(users, "")
        print(user_invites)
        return user_invites, 200


@invite_ns.route('/organisation/<string:org_id>')
class OrgInviteStatus(Resource):
    ### GET /invites/organisation/<org_id> ###

    @api.doc('get_project_invites')
    def get(self, org_id):
        users = keycloak_auth.get_users_by_attribute('invite_org_id', org_id)
        user_invites = extract_invite_roles(users, "org_")
        print(user_invites)
        return user_invites, 200


@invite_ns.route('/project/<string:token>/accept')
class ProjectInviteConfirm(Resource):
    ### POST /invites/project/<token>/accept ###

    @api.doc('accept_project_invite')
    def post(self, token):
        user = keycloak_auth.get_users_by_attribute('invite_token', token)[0]
        user_id = user["user_id"]

        invite_project_id = user["attributes"].get("invite_project_id", [""])[0]
        invite_role = user["attributes"].get(f"invite_role_{invite_project_id}", [""])[0]

        removed_roles = role_project_member(user_id, invite_project_id, invite_role)
        print(f"Added project_id {invite_project_id} to role {invite_role} for user {user_id}")
        # If not in an organisation, assign the org-partial role
        org = keycloak_auth.get_user_org()
        if not org:
            project_org_id = keycloak_auth.get_project_parent_org(invite_project_id)
            role_org_member(user_id, project_org_id, "org-partial")

        # Remove temp attributes
        keycloak_auth.remove_attribute_value(user_id, 'invite_token', token)
        keycloak_auth.remove_attribute_value(user_id, 'invite_project_id', invite_project_id)
        keycloak_auth.remove_attribute_value(user_id, f'invite_role_{invite_project_id}', invite_role)

        # Get access token for the user
        auth_tokens = keycloak_auth.get_user_auth_tokens(user_id)
        if not auth_tokens:
            return {'error': f'"Failed to obtain auth tokens for user {user_id}'}, 500

        log_event("user_accepted", invite_project_id, {"email": user["username"], "role": PROJECT_ROLE_MAPPING[invite_role]})
        return {
            'message': 'User added to project successfully',
            'user_id': user_id,
            'project_id': invite_project_id,
            'new_role': invite_role,
            'removed_roles': removed_roles,
            'access_token': auth_tokens["access_token"],
            'refresh_token': auth_tokens["refresh_token"]
        }, 200


@invite_ns.route('/organisation/<string:token>/accept')
class OrganisationInviteConfirm(Resource):
    ### POST /invites/organisation/<token>/accept ###

    @api.doc('accept_organisation_invite')
    def post(self, token):
        user = keycloak_auth.get_users_by_attribute('invite_org_token', token)[0]
        user_id = user["user_id"]

        invite_org_id = user["attributes"].get("invite_org_id", [""])[0]
        invite_org_role = user["attributes"].get(f"invite_org_role_{invite_org_id}", [""])[0]

        result = role_org_member(user_id, invite_org_id, invite_org_role)

        # Remove temp attributes
        keycloak_auth.remove_attribute_value(user_id, 'invite_org_token', token)
        keycloak_auth.remove_attribute_value(user_id, 'invite_org_id', invite_org_id)
        keycloak_auth.remove_attribute_value(user_id, f'invite_org_role_{invite_org_id}', invite_org_role)

        if invite_org_role == 'org-owner':
            user_attr = keycloak_auth.get_user_attributes(user_id)
            # Downgrade previous owner to org-admin
            role_org_member(user_attr["invite_org_old_owner"][0], invite_org_id, "org-admin")
            keycloak_auth.remove_attribute_value(user_id, "invite_org_old_owner", user_attr["invite_org_old_owner"][0])

        # Get access token for the user
        auth_tokens = keycloak_auth.get_user_auth_tokens(user_id)
        if not auth_tokens:
            return {'error': f'"Failed to obtain access token for user {user_id}'}, 500

        if result.get('success'):
            log_event("org_user_accepted", invite_org_id, {"email": user["username"], "role": ORG_ROLE_MAPPING[invite_org_role]})
            return {
                'message': f'User added to organisation with role "{invite_org_role}"',
                'user_id': user_id,
                'organisation_id': invite_org_id,
                'role': invite_org_role,
                'realm_role_assigned': f'agari-{invite_org_role}',
                'update_details': result.get('updates', {}),
                'access_token': auth_tokens["access_token"],
                'refresh_token': auth_tokens["refresh_token"]
            }
        else:
            return {
                'error': 'Failed to add user to organisation',
                'details': result.get('error'),
                'errors': result.get('errors', {})
            }, 500

@invite_ns.route('/email/<string:token>/confirm')
class EmailChangeConfirm(Resource):
    ### POST /invites/email/<token>/confirm ###

    @api.doc('accept_project_invite')
    def post(self, token):
        user = keycloak_auth.get_users_by_attribute('invite_token', token)[0]
        user_id = user["user_id"]

        invite_email = user["attributes"].get("invite_new_email", [""])[0]

        success = keycloak_auth.change_username(user_id, invite_email)
        if not success:
            return success

        # Remove temp attributes
        keycloak_auth.remove_attribute_value(user_id, 'invite_token', token)
        keycloak_auth.remove_attribute_value(user_id, 'invite_new_email', invite_email)

        # Get access token for the user
        auth_tokens = keycloak_auth.get_user_auth_tokens(user_id)
        if not auth_tokens:
            return {'error': f'"Failed to obtain auth tokens for user {user_id}'}, 500

        return {
            'message': 'User changed email successfully',
            'user_id': user_id,
            'new_email': invite_email,
            'previous_email': user["username"],
            'access_token': auth_tokens["access_token"],
            'refresh_token': auth_tokens["refresh_token"]
        }, 200


##########################
### ACTIVITY LOG
##########################


study_ns = api.namespace('activity-log', description='Activity logs')

@study_ns.route('/<string:resource_id>')
class ActivityLogs(Resource):
    ### GET /activity-log/<resource_id> ###

    @study_ns.doc('list_logs')
    #@require_auth(keycloak_auth)
    #@require_permission('manage_project_users')
    def get(self, resource_id):
        try:
            #data = request.get_json()
            #page = int(data.get('page', 1))
            #limit = int(data.get('limit', 10))
            #offset = (page - 1) * limit

            with get_db_cursor() as cursor:
                main_query = """
                    SELECT *
                    FROM logs
                    WHERE resource_id = %s
                    ORDER BY created_at DESC
                    LIMIT %s OFFSET %s
                """
                #cursor.execute(main_query, (resource_id, limit, offset))
                cursor.execute("""
                    SELECT *
                    FROM logs
                    WHERE resource_id = %s
                    ORDER BY created_at DESC
                """, (resource_id,))
                logs = cursor.fetchall()
                #total_count = len(logs)

                # Pagination metadata
                #total_pages = (total_count + limit - 1) // limit
                #has_next = page < total_pages
                #has_prev = page > 1

                return logs
                return {
                    'logs': logs,
                    'pagination': {
                        'page': page,
                        'limit': limit,
                        'total_count': total_count,
                        'total_pages': total_pages,
                        'has_next': has_next,
                        'has_prev': has_prev
                    }
                }
        except Exception as e:
            logger.exception("Error retrieving activity logs")
            return {'error': f'Database error: {str(e)}'}, 500


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=settings.PORT)
