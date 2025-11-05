from flask import Flask, request
from flask_restx import Api, Resource
from auth import (
    KeycloakAuth,
    require_auth,
    extract_user_info,
    require_permission,
    user_has_permission,
)
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
    access_revoked_notification,
    log_event,
    log_submission,
    tsv_to_json,
    role_user,
)
import uuid
import settings  # module import allows override via conftest.py
from logging import getLogger

SONG_URL = settings.OVERTURE_SONG
SCORE_URL = settings.OVERTURE_SCORE

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
            
            if not name:
                return {'error': 'Pathogen name is required'}, 400
            if not scientific_name:
                return {'error': 'Scientific name is required'}, 400

            with get_db_cursor() as cursor:
                cursor.execute("""
                    INSERT INTO pathogens (name, scientific_name, description)
                    VALUES (%s, %s, %s)
                    RETURNING id, name, scientific_name, description, created_at
                """, (name, scientific_name, description))
                
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
                    SELECT id, name, scientific_name, description, created_at, updated_at
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
            
            name = data.get('name')
            scientific_name = data.get('scientific_name')
            description = data.get('description')
            
            if not name:
                return {'error': 'Pathogen name is required'}, 400
            if not scientific_name:
                return {'error': 'Scientific name is required'}, 400

            with get_db_cursor() as cursor:
                cursor.execute("""
                    UPDATE pathogens 
                    SET name = %s, scientific_name = %s, description = %s, updated_at = NOW()
                    WHERE id = %s AND deleted_at IS NULL
                    RETURNING id, name, scientific_name, description, updated_at
                """, (name, scientific_name, description, pathogen_id))
                
                updated_pathogen = cursor.fetchone()
                
                if not updated_pathogen:
                    return {'error': 'Pathogen not found or already deleted'}, 404
                
                return {
                    'message': 'Pathogen updated successfully',
                    'pathogen': updated_pathogen
                }
                
        except Exception as e:
            if 'duplicate key value violates unique constraint' in str(e):
                return {'error': f'Pathogen with name "{name}" already exists'}, 409
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
                    RETURNING id, name, scientific_name, description, updated_at
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
            keycloak_auth.delete_user(user_id)
            access_revoked_notification(user_id)
            return {'message': 'User deleted successfully'}, 204
        except Exception as e:
            logger.exception(f"Error deleting user {user_id}: {str(e)}")
            return {'error': f'Failed to delete user: {str(e)}'}, 500
        
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
            if role not in {'org-viewer', 'org-admin', 'org-owner'}:
                return {'error': 'Invalid role specified'}, 400

            # Check if user exists in Keycloak
            user = keycloak_auth.get_user(user_id)
            if not user:
                return {'error': 'User not found in Keycloak'}, 404

            # Update user's organisation_id and org_role attributes in Keycloak
            response = invite_user_to_org(user, redirect_uri, org_id, role)
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
            if removed_role:
                return f"Removed role {removed_role}"
            else:
                return f"User has no role"

        except Exception as e:
            logger.exception(f"Error removing user from organisation role: {str(e)}")
            return {'error': f"Failed to remove user from organisation role: {str(e)}"}, 500


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
                role_user(user_id, new_project["id"], "project-admin")

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
                role_user(user["id"], project_id, role)
                return f"User role updated for project {project_id}"
            else:
                response = invite_user_to_project(user, redirect_uri, project_id, role)
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

            return {
                'message': 'User removed from project successfully',
                'user_id': user_id,
                'project_id': project_id,
                'removed_roles': removed_roles
            }, 200

        except Exception as e:
            logger.exception(f"Error removing user from project: {str(e)}")
            return {'error': f'Failed to remove user from project: {str(e)}'}, 500


@project_ns.route('/<string:project_id>/submissions')
class ProjectSubmissions(Resource):

    ### GET /projects/<project_id>/submissions ###

    @api.doc('list_project_submissions')
    @require_auth(keycloak_auth)
    @require_permission('view_project_submissions', resource_type='project', resource_id_arg='project_id')
    def get(self, project_id):

        """List all submissions associated with a project"""

        try:
            with get_db_cursor() as cursor:
                cursor.execute("""
                    SELECT s.*
                    FROM submissions s
                    WHERE s.project_id = %s
                    ORDER BY s.created_at DESC
                """, (project_id,))
                
                submissions = cursor.fetchall()
                
                # Get logs for each submission
                for submission in submissions:
                    cursor.execute("""
                        SELECT *
                        FROM submissions_log
                        WHERE submission_id = %s
                        ORDER BY created_at DESC
                    """, (submission['id'],))
                    
                    submission['logs'] = cursor.fetchall()
                
                return {
                    'project_id': project_id,
                    'total_submissions': len(submissions),
                    'submissions': submissions
                }
        except Exception as e:
            logger.exception(f"Error retrieving submissions for project {project_id}: {str(e)}")
            return {'error': f'Database error: {str(e)}'}, 500
        
    

    ### POST /projects/<project_id>/submissions ###

    @api.doc('upload_submissions')
    @require_auth(keycloak_auth)
    @require_permission('upload_submission', resource_type='project', resource_id_arg='project_id')
    def post(self, project_id):

        """Submit an analysis (submission in Agari) to SONG (proxy endpoint)
        
        Accepts either:
        1. JSON data directly in request body
        2. TSV file upload with JSON metadata containing files array
        """

        try:
            data = None
            
            # Check if this is a file upload (multipart/form-data)
            if request.files and 'file' in request.files:
                file = request.files['file']
                
                if file.filename == '':
                    return {'error': 'No file selected'}, 400
                
                # Check if it's a TSV file
                if not file.filename.lower().endswith(('.tsv', '.txt')):
                    return {'error': 'File must be a TSV file (.tsv or .txt)'}, 400
                
                try:
                    # Read and convert TSV to JSON
                    file_content = file.read().decode('utf-8')
                    
                    samples_data = tsv_to_json(file_content)
                    
                    metadata_json = request.form.get('metadata')

                    if not metadata_json:
                        return {'error': 'Metadata with files array is required when uploading TSV'}, 400

                    try:
                        metadata = json.loads(metadata_json)

                        if 'studyId' not in metadata:
                            return {'error': 'studyId is required in metadata'}, 400
                        
                        if 'analysisType' not in metadata:
                            return {'error': 'analysisType is required in metadata'}, 400

                        if 'files' not in metadata:
                            return {'error': 'files array is required in metadata'}, 400

                        if 'submissionName' not in metadata:
                            return {'error': 'submissionName is required in metadata'}, 400

                    except json.JSONDecodeError as e:
                        return {'error': f'Invalid JSON in metadata field: {str(e)}'}, 400
                    
                    # Validate that files array exists in metadata
                    if 'files' not in metadata:
                        return {'error': 'files array required in metadata'}, 400
                    
                    # Build the complete payload
                    data = {
                        "studyId": metadata['studyId'],
                        "analysisType": metadata['analysisType'],
                        "files": metadata['files'],
                        "samples": samples_data
                    }
                    
                    print(f"Final payload structure: studyId={data['studyId']}, samples_count={len(data['samples'])}, files_count={len(data['files'])}")
                    
                except UnicodeDecodeError:
                    return {'error': 'File must be UTF-8 encoded'}, 400
                except Exception as e:
                    logger.exception(f"Error processing TSV: {str(e)}")
                    return {'error': f'Failed to process TSV file: {str(e)}'}, 500
            else:
                print("No file upload detected, checking for JSON body")
                # Get JSON data directly from request body
                data = request.get_json()
                
            if not data:
                return {'error': 'No data provided (either JSON or TSV file with metadata required)'}, 400

            # Get client token for SONG API
            song_token = keycloak_auth.get_client_token()
            if not song_token:
                return {'error': 'Failed to authenticate with SONG service'}, 500

            # Set up headers for SONG request
            song_headers = {
                'Authorization': f'Bearer {song_token}',
                'Content-Type': 'application/json'
            }
            
            # Forward the request to SONG
            song_submit_url = f"{SONG_URL}/submit/{metadata['studyId']}?allowDuplicates=true"
            song_response = requests.post(song_submit_url, headers=song_headers, json=data)

            print(f"SONG submit response status: {song_response.status_code}")
            
            # Forward SONG's response directly
            try:
                response_data = song_response.json()
            except:
                response_data = {'message': song_response.text}

            if song_response.status_code == 200:
                analysis_id = response_data.get('analysisId')
            else:
                analysis_id = None

            with get_db_cursor() as cursor:
                cursor.execute("""
                    INSERT INTO submissions (project_id, study_id, analysis_id, submission_name)
                    VALUES (%s, %s, %s, %s)
                    RETURNING id
                """, (project_id, metadata['studyId'], analysis_id, metadata.get('submissionName')))
                
                submission_id = cursor.fetchone()['id']

                log_submission(submission_id, request.user.get('user_id'), song_response.status_code, song_response.text)

                response_data['submission_id'] = submission_id

            return response_data, song_response.status_code

        except Exception as e:
            logger.exception(f"Error submitting analysis for project {project_id}: {str(e)}")
            return {'error': f'Failed to submit analysis: {str(e)}'}, 500
        

@project_ns.route('/<string:project_id>/submissions/<string:submission_id>')
class ProjectSubmission(Resource):
    
    ### GET /projects/<project_id>/submissions/<submission_id> ###

    @api.doc('get_project_submission')
    @require_auth(keycloak_auth)
    @require_permission('view_project_submissions', resource_type='project', resource_id_arg='project_id')
    def get(self, project_id, submission_id):

        """Get details of a specific submission associated with a project"""

        try:
            with get_db_cursor() as cursor:
                
                # Clean and validate project_id
                try:
                    clean_project_id = str(uuid.UUID(project_id.strip('"')))
                except ValueError:
                    return {'error': f'Invalid project_id format: {project_id}'}, 400
                
                # Clean and validate submission_id  
                try:
                    clean_submission_id = str(uuid.UUID(submission_id.strip('"')))
                except ValueError:
                    return {'error': f'Invalid submission_id format: {submission_id}'}, 400
                
                cursor.execute("""
                    SELECT s.*
                    FROM submissions s
                    WHERE s.project_id = %s AND s.id = %s
                """, (clean_project_id, clean_submission_id))
                
                submission = cursor.fetchone()
                
                if not submission:
                    return {'error': 'Submission not found for this project'}, 404
                
                # Get logs for this submission
                cursor.execute("""
                    SELECT *
                    FROM submissions_log
                    WHERE submission_id = %s
                    ORDER BY created_at DESC
                """, (clean_submission_id,))
                
                submission['logs'] = cursor.fetchall()
                
                # get analysis status from SONG
                analysis_id = submission.get('analysis_id')
                study_id = submission.get('study_id')

                if analysis_id and study_id:
                    # Get client token for SONG API
                    song_token = keycloak_auth.get_client_token()
                    if not song_token:
                        return {'error': 'Failed to authenticate with SONG service'}, 500

                    song_headers = {
                        'Authorization': f'Bearer {song_token}',
                        'Content-Type': 'application/json'
                    }

                    song_response = requests.get(f"{SONG_URL}/studies/{study_id}/analysis/{analysis_id}", headers=song_headers)

                    if song_response.status_code == 200:
                        song_data = song_response.json()
                        submission['analysis'] = song_data

                return submission
        except Exception as e:
            logger.exception(f"Error retrieving submission {submission_id} for project {project_id}: {str(e)}")
            return {'error': f'Database error: {str(e)}'}, 500


@project_ns.route('/<string:project_id>/submissions/<string:submission_id>/upload/init')
class ProjectSubmissionUploadInit(Resource):

    ### POST /projects/<project_id>/submissions/<submission_id>/upload/init ###

    @api.doc('init_submission_upload')
    @require_auth(keycloak_auth)
    @require_permission('upload_submission', resource_type='project', resource_id_arg='project_id')
    def post(self, project_id, submission_id):

        """Initialize upload with SCORE (Step 1 of upload process)"""

        try:

            data = request.get_json()

            object_id = data.get('object_id')
            file_size = data.get('fileSize')
            file_md5 = data.get('md5')
            overwrite = data.get('overwrite', True)

            if not object_id or not file_size or not file_md5:
                return {'error': 'object_id, fileSize, and md5 are required'}, 400

            # Get client token for SCORE API
            score_token = keycloak_auth.get_client_token()
            if not score_token:
                return {'error': 'Failed to authenticate with SCORE service'}, 500

            score_headers = {
                'Authorization': f'Bearer {score_token}',
                'Content-Type': 'application/x-www-form-urlencoded'
            }

            # Initialize upload with SCORE
            init_upload_url = f"{SCORE_URL}/upload/{object_id}/uploads"
            init_data = {
                'fileSize': file_size,
                'md5': file_md5,
                'overwrite': overwrite
            }

            init_response = requests.post(init_upload_url, headers=score_headers, data=init_data)
            
            if init_response.status_code != 200:
                log_submission(submission_id, request.user.get('user_id'), init_response.status_code, f'Failed to initialize upload: {init_response.status_code} - {init_response.text}')
                return {'error': f'Failed to initialize upload: {init_response.status_code} - {init_response.text}'}, init_response.status_code

            log_submission(submission_id, request.user.get('user_id'), init_response.status_code, 'Upload initialized successfully')
            return init_response.json(), 200

        except Exception as e:
            logger.exception(f"Error initializing upload for submission {submission_id}: {str(e)}")
            log_submission(submission_id, request.user.get('user_id'), 500, f'Failed to initialize upload: {str(e)}')
            return {'error': f'Failed to initialize upload: {str(e)}'}, 500


@project_ns.route('/<string:project_id>/submissions/<string:submission_id>/upload/finalise-part')
class ProjectSubmissionUploadFinalisePart(Resource):

    ### POST /projects/<project_id>/submissions/<submission_id>/upload/finalise-part ###

    @api.doc('finalise_part_upload')
    @require_auth(keycloak_auth)
    @require_permission('upload_submission', resource_type='project', resource_id_arg='project_id')
    def post(self, project_id, submission_id):

        """Finalize part upload with SCORE (Step 3 of upload process)"""

        try:
            data = request.get_json()
            if not data:
                return {'error': 'No JSON data provided'}, 400

            object_id = data.get('object_id')
            upload_id = data.get('upload_id')
            etag = data.get('etag')
            object_md5 = data.get('md5')
            part_number = data.get('part_number', 1)

            if not all([etag]):
                return {'error': 'object_id, upload_id, etag, and object_md5 are required'}, 400

            # Get client token for SCORE API
            score_token = keycloak_auth.get_client_token()
            if not score_token:
                return {'error': 'Failed to authenticate with SCORE service'}, 500

            score_json_headers = {
                'Authorization': f'Bearer {score_token}',
                'Content-Type': 'application/json'
            }

            # Finalise part upload
            finalise_part_url = f"{SCORE_URL}/upload/{object_id}/parts"
            finalise_part_params = {
                'partNumber': part_number,
                'etag': etag,
                'md5': object_md5,
                'uploadId': upload_id
            }
            
            finalise_part_response = requests.post(
                finalise_part_url, 
                headers=score_json_headers, 
                params=finalise_part_params
            )

            if finalise_part_response.status_code != 200:
                log_submission(submission_id, request.user.get('user_id'), finalise_part_response.status_code, finalise_part_response.text)
                return {'error': f'Failed to finalise part upload: {finalise_part_response.status_code} - {finalise_part_response.text}'}, finalise_part_response.status_code

            log_submission(submission_id, request.user.get('user_id'), finalise_part_response.status_code, 'Part upload finalised successfully')
            
            
            return {
                'message': 'Part upload finalized successfully',
                'object_id': object_id,
                'upload_id': upload_id,
                'part_number': part_number,
                'etag': etag
            }, 200

        except Exception as e:
            logger.exception(f"Error finalising part upload for submission {submission_id}: {str(e)}")
            log_submission(submission_id, request.user.get('user_id'), 500, f'{str(e)}')
            return {'error': f'Failed to finalise part upload: {str(e)}'}, 500


@project_ns.route('/<string:project_id>/submissions/<string:submission_id>/upload/finalise')
class ProjectSubmissionUploadFinalise(Resource):

    ### POST /projects/<project_id>/submissions/<submission_id>/upload/finalise ###

    @api.doc('finalize_upload')
    @require_auth(keycloak_auth)
    @require_permission('upload_submission', resource_type='project', resource_id_arg='project_id')
    def post(self, project_id, submission_id):

        """Finalize complete upload with SCORE (Step 4 of upload process)"""

        try:
            data = request.get_json()
            if not data:
                return {'error': 'No JSON data provided'}, 400

            object_id = data.get('object_id')
            upload_id = data.get('upload_id')
            parts = data.get('parts', [])  

            if not object_id or not upload_id:
                return {'error': 'object_id and upload_id are required'}, 400

            # Validate parts data if provided
            if parts and not isinstance(parts, list):
                return {'error': 'parts must be an array'}, 400

            # Get client token for SCORE API
            score_token = keycloak_auth.get_client_token()
            if not score_token:
                return {'error': 'Failed to authenticate with SCORE service'}, 500

            score_json_headers = {
                'Authorization': f'Bearer {score_token}',
                'Content-Type': 'application/json'
            }

            # Finalize complete upload
            finalize_upload_url = f"{SCORE_URL}/upload/{object_id}"
            finalize_upload_params = {'uploadId': upload_id}
            
            # Include parts data in the request body if provided
            request_body = {}
            if parts:
                request_body['parts'] = parts
            
            if request_body:
                finalize_upload_response = requests.post(
                    finalize_upload_url, 
                    headers=score_json_headers, 
                    params=finalize_upload_params,
                    json=request_body 
                )
            else:
                finalize_upload_response = requests.post(
                    finalize_upload_url, 
                    headers=score_json_headers, 
                    params=finalize_upload_params
                )
            
            if finalize_upload_response.status_code != 200:
                log_submission(submission_id, request.user.get('user_id'), finalize_upload_response.status_code, finalize_upload_response.text)
                return {'error': f'Failed to finalise upload: {finalize_upload_response.status_code} - {finalize_upload_response.text}'}, finalize_upload_response.status_code

            log_submission(submission_id, request.user.get('user_id'), finalize_upload_response.status_code, 'Upload finalised successfully')
            
            # SCORE might return empty response, so handle that
            try:
                response_data = finalize_upload_response.json()
            except:
                # If no JSON response, return success message
                response_data = {
                    'message': 'Upload finalized successfully',
                    'object_id': object_id,
                    'upload_id': upload_id
                }
                
            return response_data, 200

        except Exception as e:
            logger.exception(f"Error finalising upload for submission {submission_id}: {str(e)}")
            log_submission(submission_id, request.user.get('user_id'), 500, f'{str(e)}')
            return {'error': f'Failed to finalise upload: {str(e)}'}, 500
        

@project_ns.route('/<string:project_id>/submissions/<string:submission_id>/publish')
class PublishSubmission(Resource):

    ### POST /projects/<project_id>/submissions/<submission_id>/publish ###

    @api.doc('publish_submission')
    @require_auth(keycloak_auth)
    @require_permission('publish_submission', resource_type='project', resource_id_arg='project_id')
    def post(self, project_id, submission_id):

        """Publish a submission in SONG (proxy endpoint)"""

        try:
            try:
                clean_project_id = str(uuid.UUID(project_id.strip('"')))
                clean_submission_id = str(uuid.UUID(submission_id.strip('"')))
            except ValueError as e:
                return {'error': f'Invalid UUID format: {str(e)}'}, 400

            # get the study_id and analysis_id from the submission record
            with get_db_cursor() as cursor:
                cursor.execute("""
                    SELECT study_id, analysis_id
                    FROM submissions
                    WHERE id = %s AND project_id = %s
                """, (clean_submission_id, clean_project_id))
                
                submission = cursor.fetchone()
                
                if not submission:
                    return {'error': 'Submission not found for this project'}, 404
                
                study_id = submission.get('study_id')
                analysis_id = submission.get('analysis_id')

            # Get client token for SONG API
            song_token = keycloak_auth.get_client_token()
            if not song_token:
                return {'error': 'Failed to authenticate with SONG service'}, 500

            # Set up headers for SONG request
            song_headers = {
                'Authorization': f'Bearer {song_token}',
                'Content-Type': 'application/json'
            }

            # Forward the publish request to SONG
            song_publish_url = f"{SONG_URL}/studies/{study_id}/analysis/publish/{analysis_id}"
            song_response = requests.put(song_publish_url, headers=song_headers)

            print(f"SONG publish response status: {song_response.status_code}")

            # Forward SONG's response directly
            try:
                response_data = song_response.json()
            except Exception:
                response_data = {'message': song_response.text}

            if song_response.status_code != 200:
                log_submission(clean_submission_id, request.user.get('user_id'), song_response.status_code, song_response.text)
            else:
                log_submission(clean_submission_id, request.user.get('user_id'), song_response.status_code, 'Analysis published successfully')            
                
            return response_data, song_response.status_code

        except Exception as e:
            logger.exception(f"Error publishing submission {submission_id} for project {project_id}: {str(e)}")
            log_submission(submission_id, request.user.get('user_id'), 500, f'{str(e)}')
            return {'error': f'Failed to publish analysis: {str(e)}'}, 500


@project_ns.route('/<string:project_id>/submissions/<string:submission_id>/unpublish')
class UnpublishSubmission(Resource):

    ### POST /projects/<project_id>/submissions/<submission_id>/unpublish ###

    @api.doc('unpublish_submission')
    @require_auth(keycloak_auth)
    @require_permission('unpublish_submission', resource_type='project', resource_id_arg='project_id')
    def post(self, project_id, submission_id):

        """Unpublish an analysis in SONG (proxy endpoint)"""
        
        try:
            try:
                clean_project_id = str(uuid.UUID(project_id.strip('"')))
                clean_submission_id = str(uuid.UUID(submission_id.strip('"')))
            except ValueError as e:
                return {'error': f'Invalid UUID format: {str(e)}'}, 400

            # get the study_id and analysis_id from the submission record
            with get_db_cursor() as cursor:
                cursor.execute("""
                    SELECT study_id, analysis_id
                    FROM submissions
                    WHERE id = %s AND project_id = %s
                """, (clean_submission_id, clean_project_id))
                
                submission = cursor.fetchone()
                
                if not submission:
                    return {'error': 'Submission not found for this project'}, 404
                
                study_id = submission.get('study_id')
                analysis_id = submission.get('analysis_id')

            # Get client token for SONG API
            song_token = keycloak_auth.get_client_token()
            if not song_token:
                return {'error': 'Failed to authenticate with SONG service'}, 500

            # Set up headers for SONG request
            song_headers = {
                'Authorization': f'Bearer {song_token}',
                'Content-Type': 'application/json'
            }

            # Forward the unpublish request to SONG
            song_unpublish_url = f"{SONG_URL}/studies/{study_id}/analysis/unpublish/{analysis_id}"
            song_response = requests.put(song_unpublish_url, headers=song_headers)

            print(f"SONG unpublish response status: {song_response.status_code}")

            # Forward SONG's response directly
            try:
                response_data = song_response.json()
            except Exception:
                response_data = {'message': song_response.text}

            if song_response.status_code != 200:
                log_submission(clean_submission_id, request.user.get('user_id'), song_response.status_code, song_response.text)
            else:
                log_submission(clean_submission_id, request.user.get('user_id'), song_response.status_code, 'Analysis unpublished successfully')

            return response_data, song_response.status_code

        except Exception as e:
            logger.exception(f"Error unpublishing submission {submission_id} for project {project_id}: {str(e)}")
            log_submission(submission_id, request.user.get('user_id'), 500, f'{str(e)}')
            return {'error': f'Failed to unpublish analysis: {str(e)}'}, 500
        


@project_ns.route('/<string:project_id>/submissions/<string:submission_id>/files/<string:object_id>')
class ProjectSubmissionFileDetails(Resource):
    ### GET /projects/<project_id>/submissions/<submission_id>/files/<object_id> ###

    @api.doc('get_submission_file_details')
    @require_auth(keycloak_auth)
    @require_permission('view_project_submissions', resource_type='project', resource_id_arg='project_id')
    def get(self, project_id, submission_id, object_id):

        """Get details for a submission file from SCORE (proxy endpoint)"""

        try:
            # Clean and validate UUIDs
            try:
                clean_project_id = str(uuid.UUID(project_id.strip('"')))
                clean_submission_id = str(uuid.UUID(submission_id.strip('"')))
            except ValueError as e:
                return {'error': f'Invalid UUID format: {str(e)}'}, 400

            # Get submission details to find the analysis_id and study_id
            with get_db_cursor() as cursor:
                cursor.execute("""
                    SELECT study_id, analysis_id
                    FROM submissions
                    WHERE id = %s AND project_id = %s
                """, (clean_submission_id, clean_project_id))
                
                submission = cursor.fetchone()
                
                if not submission:
                    return {'error': 'Submission not found for this project'}, 404
                
                study_id = submission.get('study_id')
                analysis_id = submission.get('analysis_id')

            if not analysis_id or not study_id:
                return {'error': 'Submission does not have associated analysis'}, 400

            # Get client token for SONG API
            song_token = keycloak_auth.get_client_token()
            if not song_token:
                return {'error': 'Failed to authenticate with SONG service'}, 500

            song_headers = {
                'Authorization': f'Bearer {song_token}',
                'Content-Type': 'application/json'
            }

            # Get analysis details from SONG to find file size
            song_analysis_url = f"{SONG_URL}/studies/{study_id}/analysis/{analysis_id}"
            song_response = requests.get(song_analysis_url, headers=song_headers)

           

            if song_response.status_code != 200:
                return {'error': f'Failed to get analysis from SONG: {song_response.status_code} - {song_response.text}'}, song_response.status_code

            analysis_data = song_response.json()
            
            # Find the file with matching object_id in the files array
            file_info = None
            files = analysis_data.get('files', [])
            
            for file_obj in files:
                if file_obj.get('objectId') == object_id:
                    file_info = file_obj
                    break
            
            if not file_info:
                return {'error': f'File with object_id {object_id} not found in submission'}, 404

            file_size = file_info.get('fileSize', 0)

           
            
            # Get client token for SCORE API
            score_token = keycloak_auth.get_client_token()
            if not score_token:
                return {'error': 'Failed to authenticate with SCORE service'}, 500

            score_headers = {
                'Authorization': f'Bearer {score_token}',
                'User-Agent': 'Agari-Folio/1.0'
            }

            # Get download URL from SCORE
            score_file_url = f"{SCORE_URL}/download/{object_id}?offset=0&length={file_size}"

            print(f"Requesting download URL from SCORE: {score_file_url}")

            score_response = requests.get(score_file_url, headers=score_headers, allow_redirects=False)

            
            if score_response.status_code == 200:

                file_url = score_response.json().get('parts', [{}])[0].get('url')
                if not file_url:
                    return {'error': 'Download URL not found in SCORE response'}, 500

                return {
                    'file_url': file_url,
                    'object_id': object_id,
                    'file_size': file_size
                }, 200
            
               
            else:
                return {'error': f'Failed to get download URL from SCORE: {score_response.status_code} - {score_response.text}'}, score_response.status_code

        except Exception as e:
            logger.exception(f"Error getting download URL for file {object_id} in submission {submission_id}: {str(e)}")
            return {'error': f'Failed to get download URL: {str(e)}'}, 500



##########################
### STUDIES
##########################


study_ns = api.namespace('studies', description='Study management endpoints')

@study_ns.route('/')
class StudyList(Resource):
    
    ### GET /studies ###

    @study_ns.doc('list_studies')
    def get(self):

        """List all studies (public access)"""
        
        try:
            with get_db_cursor() as cursor:
                cursor.execute("""
                    SELECT *
                    FROM studies 
                    WHERE deleted_at IS NULL 
                    ORDER BY name
                """)
                
                studies = cursor.fetchall()

                return studies

        except Exception as e:
            logger.exception("Error retrieving studies")
            return {'error': f'Database error: {str(e)}'}, 500

    ### POST /studies ###

    @study_ns.doc('create_study')
    @require_auth(keycloak_auth)
    @require_permission('create_study', resource_type='project', resource_id_arg='projectId')
    def post(self):
        """Create a new study"""
        try:
            data = request.get_json()
            if not data:
                return {'error': 'No JSON data provided'}, 400
            
            studyId = data.get('studyId')
            name = data.get('name')
            description = data.get('description')
            projectId = data.get('projectId')
            info = data.get('info')
            
            if not studyId:
                return {'error': 'StudyId is required'}, 400
            if not name:
                return {'error': 'Study name is required'}, 400
            if not projectId:
                return {'error': 'Associated projectId is required'}, 400
    
            ### CHECK IF STUDYID EXISTS IN SONG ###
            app.logger.info(f"Checking if studyId '{studyId}' exists in SONG before creating locally...")
    
            song_token = keycloak_auth.get_client_token()
            if not song_token:
                return {'error': 'Failed to authenticate with SONG service'}, 500
            else:
                app.logger.info("Successfully obtained SONG token")
                print(f"SONG Token: {song_token}")
    
            song_headers = {
                'Authorization': f'Bearer {song_token}',
                'Content-Type': 'application/json'
            }
            
            song_check_url = f"{SONG_URL}/studies/{studyId}"
            app.logger.info(f"Checking SONG for existing studyId at {song_check_url} ...")
            song_response = requests.get(song_check_url, headers=song_headers)
    
            app.logger.info(f"SONG: {song_response.json()}")
    
            if song_response.status_code == 200:
                return {'error': f'Study with studyId "{studyId}" already exists in SONG'}, 200
            elif song_response.status_code == 404:
                print(f"StudyId '{studyId}' does not exist in SONG, proceeding to create locally...")
            else:
                return {'error': f'Error checking study in SONG: {song_response.status_code} - {song_response.text}'}, 500
    
            ### CREATE STUDY IN SONG ###
            song_create_url = f"{SONG_URL}/studies/{studyId}/"
            song_payload = {
                'studyId': studyId,
                'name': name,
                'description': description,
                'info': info or {}
            }
    
            song_response = requests.post(song_create_url, headers=song_headers, json=song_payload)
    
            if song_response.status_code == 200:
                print(f"Successfully created study in SONG: {song_response.json()}")
            else:
                return {'error': f"Failed to create study in SONG: {song_response.status_code} - {song_response.text}"}
    
            ### CREATE STUDY LOCALLY ###
            with get_db_cursor() as cursor:
                cursor.execute("""
                    INSERT INTO studies (study_id, name, description, project_id)
                    VALUES (%s, %s, %s, %s)
                    RETURNING *
                """, (studyId, name, description, projectId))
    
                new_study = cursor.fetchone()
    
                return {
                    'message': 'Study created successfully',
                    'study': new_study
                }, 201
    
        except Exception as e:
            if 'duplicate key value violates unique constraint' in str(e):
                return {'error': f'Study with name "{name}" already exists'}, 409
            logger.exception("Error creating study")
            return {'error': f'Database error: {str(e)}'}, 500

@study_ns.route('/<string:study_id>/analysis')
class StudyAnalysis(Resource):
    
    ### GET /studies/<study_id>/analysis ###

    @study_ns.doc('get_study_analysis')
    @require_auth(keycloak_auth)
    def get(self, study_id):

        """
            Get analysis results for a study from SONG (proxy endpoint)

            Query Parameters:
                - analysisStates: Comma-separated list of analysis states to filter by
        """

        states = request.args.get('analysisStates')
        
        try:
            # Get client token for SONG API
            song_token = keycloak_auth.get_client_token()
            if not song_token:
                return {'error': 'Failed to authenticate with SONG service'}, 500

            # Set up headers for SONG request
            song_headers = {
                'Authorization': f'Bearer {song_token}',
                'Content-Type': 'application/json'
            }

            if states:
                song_analysis_url = f"{SONG_URL}/studies/{study_id}/analysis?analysisStates={states}"
            else:
                song_analysis_url = f"{SONG_URL}/studies/{study_id}/analysis"

            song_response = requests.get(song_analysis_url, headers=song_headers)

            print(f"SONG analysis response status: {song_response.status_code}")
            
            # Forward SONG's response directly
            try:
                response_data = song_response.json()
            except:
                logger.exception("Error parsing SONG response")
                response_data = {'message': song_response.text}
            
            return response_data, song_response.status_code

        except Exception as e:
            logger.exception("Error retrieving analysis")
            return {'error': f'Failed to retrieve analysis results: {str(e)}'}, 500

@study_ns.route('/<string:project_id>/<string:study_id>/analysis/<string:analysis_id>/upload')
class StudyAnalysisUpload(Resource):

    ### POST /studies/<project_id>/<study_id>/analysis/<analysis_id>/upload ###

    @study_ns.doc('upload_analysis_file')
    @require_auth(keycloak_auth)
    @require_permission('submit_to_study', resource_type='project', resource_id_arg='project_id')
    def post(self, project_id, study_id, analysis_id):

        """Upload a file to an analysis in SCORE and MINIO (proxy endpoint)"""

        try:
            print("Form keys:", request.form.keys())
            print("Form data:", request.form)
            # Parse form data
            object_id = request.form.get('object_id')
            overwrite = request.form.get('overwrite', 'true').lower() == 'true'
            
            if not object_id:
                return {'error': 'object_id is required'}, 400
                
            # Get the uploaded file
            if 'file' not in request.files:
                return {'error': 'No file provided'}, 400
                
            file = request.files['file']
            if file.filename == '':
                return {'error': 'No file selected'}, 400

            # Read file data and calculate size/MD5
            file_data = file.read()
            file_size = len(file_data)
            
            import hashlib
            file_md5 = hashlib.md5(file_data).hexdigest()
            
            app.logger.info(f"File: {file.filename}, Size: {file_size}, MD5: {file_md5}")

            # Get client token for SCORE API
            score_token = keycloak_auth.get_client_token()
            if not score_token:
                return {'error': 'Failed to authenticate with SCORE service'}, 500

            score_headers = {
                'Authorization': f'Bearer {score_token}',
                'Content-Type': 'application/x-www-form-urlencoded'
            }

            # Step 1: Initialize upload with SCORE
            init_upload_url = f"{SCORE_URL}/upload/{object_id}/uploads"
            init_data = {
                'fileSize': file_size,
                'md5': file_md5,
                'overwrite': overwrite
            }
            app.logger.info(f"Score URL {init_upload_url}")
            init_response = requests.post(init_upload_url, headers=score_headers, data=init_data)
            app.logger.info(f"Score upload response: {init_response}")
            if init_response.status_code != 200:
                return {'error': f'Failed to initialize upload: {init_response.status_code} - {init_response.text}'}, 500
                
            init_result = init_response.json()
            upload_id = init_result['uploadId']
            presigned_url = init_result['parts'][0]['url']
            object_md5 = init_result['objectMd5']
            
            app.logger.info(f"Upload initialized - Upload ID: {upload_id}")

            # Step 2: Upload file to MinIO using presigned URL
            upload_headers = {'Content-Type': 'text/plain'}
            upload_response = requests.put(presigned_url, headers=upload_headers, data=file_data)
            
            if upload_response.status_code != 200:
                return {'error': f'Failed to upload file to storage: {upload_response.status_code}'}, 500
                
            etag = upload_response.headers.get('ETag', '').strip('"')
            app.logger.info(f"File uploaded to MinIO - ETag: {etag}")

            # Step 3: Finalize part upload
            finalize_part_url = f"{SCORE_URL}/upload/{object_id}/parts"
            finalize_part_params = {
                'partNumber': 1,
                'etag': etag,
                'md5': object_md5,
                'uploadId': upload_id
            }
            
            score_json_headers = {
                'Authorization': f'Bearer {score_token}',
                'Content-Type': 'application/json'
            }
            
            finalize_part_response = requests.post(
                finalize_part_url, 
                headers=score_json_headers, 
                params=finalize_part_params
            )
            
            if finalize_part_response.status_code != 200:
                return {'error': f'Failed to finalize part upload: {finalize_part_response.status_code}'}, 500
                
            app.logger.info("Part upload finalized")

            # Step 4: Finalize complete upload
            finalize_upload_url = f"{SCORE_URL}/upload/{object_id}"
            finalize_upload_params = {'uploadId': upload_id}
            
            finalize_upload_response = requests.post(
                finalize_upload_url, 
                headers=score_json_headers, 
                params=finalize_upload_params
            )
            
            if finalize_upload_response.status_code != 200:
                return {'error': f'Failed to finalize upload: {finalize_upload_response.status_code}'}, 500
                
            app.logger.info("Upload finalized successfully")

            return {
                'message': 'File uploaded successfully',
                'study_id': study_id,
                'project_id': project_id,
                'analysis_id': analysis_id,
                'object_id': object_id,
                'filename': file.filename,
                'file_size': file_size,
                'md5': file_md5,
                'upload_id': upload_id,
                'etag': etag
            }, 200

        except Exception as e:
            logger.exception(f"Error uploading file to analysis {analysis_id} in study {study_id}: {str(e)}")
            return {'error': f'Failed to upload file: {str(e)}'}, 500
        


##########################
### INVITES
##########################

invite_ns = api.namespace('invites', description='Invite management endpoints')


@invite_ns.route('/project/<string:project_id>/<string:user_id>')
class ProjectInviteStatus(Resource):

    ### GET /invites/<user_id> ###

    @api.doc('get_project_invites')
    def get(self, project_id, user_id):
        user = keycloak_auth.get_user(user_id)
        if user.get("attributes"):
            invite = user["attributes"].get(project_id, [""])[0]
        print(invite)


@invite_ns.route('/project/<string:token>/accept')
class ProjectInviteConfirm(Resource):
    ### POST /invites/<token>/accept ###

    @api.doc('accept_project_invite')
    def post(self, token):
        user = keycloak_auth.get_users_by_attribute('invite_token', token)[0]
        user_id = user["user_id"]

        invite_project_id = user["attributes"].get("invite_project_id", [""])[0]
        invite_role = user["attributes"].get(f"invite_role_{invite_project_id}", [""])[0]

        removed_roles = role_user(user_id, invite_project_id, invite_role)
        print(f"Added project_id {invite_project_id} to role {invite_role} for user {user_id}")

        # Remove temp attributes
        keycloak_auth.remove_attribute_value(user_id, 'invite_token', token)
        keycloak_auth.remove_attribute_value(user_id, 'invite_project_id', invite_project_id)
        keycloak_auth.remove_attribute_value(user_id, f'invite_role_{invite_project_id}', invite_role)

        # Get access token for the user
        auth_tokens = keycloak_auth.get_user_auth_tokens(user_id)
        if not auth_tokens:
            return {'error': f'"Failed to obtain auth tokens for user {user_id}'}, 500

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
    ### POST /invites/<token>/accept ###

    @api.doc('accept_organisation_invite')
    def post(self, token):
        user = keycloak_auth.get_users_by_attribute('invite_org_token', token)[0]
        user_id = user["user_id"]

        invite_org_id = user["attributes"].get("invite_org_id", [""])[0]
        invite_org_role = user["attributes"].get(f"invite_org_role_{invite_org_id}", [""])[0]

        # Prepare update data with proper structure
        update_data = {
            'attributes': {
                'organisation_id': [invite_org_id]
            },
            'realm_roles': [f'agari-{invite_org_role}']
        }
        result = keycloak_auth.update_user(user_id, update_data)

        # Remove temp attributes
        keycloak_auth.remove_attribute_value(user_id, 'invite_org_token', token)
        keycloak_auth.remove_attribute_value(user_id, 'invite_org_id', invite_org_id)
        keycloak_auth.remove_attribute_value(user_id, f'invite_org_role_{invite_org_id}', invite_org_role)

        # Get access token for the user
        auth_tokens = keycloak_auth.get_user_auth_tokens(user_id)
        if not auth_tokens:
            return {'error': f'"Failed to obtain access token for user {user_id}'}, 500

        if result.get('success'):
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


if __name__ == '__main__':
    from settings import PORT
    app.run(debug=True, host='0.0.0.0', port=PORT)
