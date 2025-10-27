from flask import Flask,request
from flask_restx import Api, Resource
from auth import keycloak_auth, require_auth, extract_user_info, require_permission, user_has_permission
from permissions import PERMISSIONS
from database import get_db_cursor, test_connection
from routes.templates import template_ns
from settings import OVERTURE_SONG_URL, OVERTURE_SCORE_URL, PORT
import json
from datetime import datetime, date
from decimal import Decimal
import requests


# Custom JSON encoder to handle datetime and other types
class CustomJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.strftime('%Y-%m-%d %H:%M:%S')
        elif isinstance(obj, date):
            return obj.strftime('%Y-%m-%d')
        elif isinstance(obj, Decimal):
            return float(obj)
        return super().default(obj)

app = Flask(__name__)
app.json_encoder = CustomJSONEncoder

song = OVERTURE_SONG_URL
score = OVERTURE_SCORE_URL

app.keycloak_auth = keycloak_auth

api = Api(app, 
    version='1.0', 
    title='Folio API',
    description='API documentation for the Folio application',
    doc='/docs/'
)

# Configure Flask-RESTX to use our custom JSON encoder
app.config['RESTX_JSON'] = {'cls': CustomJSONEncoder}

# Register template namespace
api.add_namespace(template_ns)

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
            return {'error': f'Failed to retrieve users: {str(e)}'}, 500

    ### PUT /users ###
    @user_ns.doc('update_user')
    @require_auth(keycloak_auth)
    @require_permission('change_org_member_roles')
    def put(self):
        """Update a user's attributes (system-admin only)

        Request Body:
        {
            "user_id": "<keycloak_user_id>",
            "attributes": {
                "agari-org-owner": ["org_id1", "org_id2"],
                "agari-org-admin": ["org_id1"],
                "agari-org-viewer": ["org_id2"],
                "project-admin": ["project_id1"],
                "project-contributor": ["project_id1", "project_id2"],
                "project-viewer": ["project_id2"],
                "organisation_id": ["org_id1"]
            },
            "realmRoles": ["role1", "role2"] 
        }
        """
        try:
            data = request.get_json()
            if not data:
                return {'error': 'No JSON data provided'}, 400
            
            user_id = data.get('user_id')
            attributes = data.get('attributes')
            realm_roles = data.get('realmRoles')

            if not user_id:
                return {'error': 'user_id is required'}, 400

            # Check if user exists in Keycloak
            user = keycloak_auth.get_user(user_id)
            if not user:
                return {'error': 'User not found in Keycloak'}, 404

            # Update each attribute
            if realm_roles is not None:
                if not isinstance(realm_roles, list):
                    return {'error': 'realmRoles must be a list'}, 400
                keycloak_auth.update_realm_roles(user_id, realm_roles)

            if attributes is not None:
                for attr, values in attributes.items():
                    if not isinstance(values, list):
                        return {'error': f'Attribute values for {attr} must be a list'}, 400

                # Remove existing values for the attribute
                existing_values = user.get('attributes', {}).get(attr, [])
                for val in existing_values:
                    keycloak_auth.remove_attribute_value(user_id, attr, val)
                
                # Add new values
                for val in values:
                    keycloak_auth.add_attribute_value(user_id, attr, val)
            
            return {'message': 'User details updated successfully'}, 200

        except Exception as e:
            return {'error': f'Failed to update user: {str(e)}'}, 500

    @user_ns.doc('create_user')
    @require_auth(keycloak_auth)
    @require_permission('change_org_member_roles')
    def post(self):
        data = request.get_json()
        if not data:
            return {'error': 'No JSON data provided'}, 400
        
        email = data.get('email')
        redirect_uri = data.get('redirect_uri')
        expiration_seconds = data.get('expiration_seconds', 3600)
        send_email = data.get('send_email', True)

        if not email:
            return {'error': 'Email is required'}, 400
        if not redirect_uri:
            return {'error': 'Redirect is required'}, 400

        admin_token = keycloak_auth.get_admin_token()
        if not admin_token:
            return {'error': 'Failed to authenticate with Keycloak admin'}, 500
        headers = {
            'Authorization': f'Bearer {admin_token}',
            'Content-Type': 'application/json'
        }
        payload = {
            'email': email,
            'client_id': keycloak_auth.client_id,
            'redirect_uri': redirect_uri,
            'expiration_seconds': expiration_seconds,
            'force_create': True,
            'reusable': False,
            'send_email': send_email
        }
        magic_link_url = f"{keycloak_auth.keycloak_url}/realms/{keycloak_auth.realm}/magic-link"

        keycloak_response = requests.post(
            magic_link_url,
            headers=headers,
            json=payload
        )

        if keycloak_response.status_code == 200:
            response_data = keycloak_response.json()
            return {
                'message': 'Magic link sent successfully',
                'email': email,
                'user_id': response_data.get('user_id'),
            }, 200
        else:
            return {
                'error': f'Failed to create magic link.'
            }, 500

##########################
### PROJECTS
##########################

project_ns = api.namespace('projects', description='Project management endpoints')

@project_ns.route('/')
class ProjectList(Resource):

    ### GET /projects ###

    @api.doc('list_projects')
    def get(self):
        
        """List projects based on user permissions"""

        organisation_id = keycloak_auth.get_user_org()

        try:
                
            with get_db_cursor() as cursor:
                    
                if organisation_id is not None:
                    cursor.execute("""
                        SELECT *
                        FROM projects
                        WHERE deleted_at IS NULL
                        AND (privacy = 'public' or privacy = 'semi-private' OR organisation_id = %s)
                        ORDER BY name
                    """, (organisation_id,))
                    
                else:
                    cursor.execute("""
                        SELECT *
                        FROM projects
                        WHERE deleted_at IS NULL
                        AND (privacy = 'public' or privacy = 'semi-private')
                        ORDER BY name
                    """)

                projects = cursor.fetchall()
                print(f"Found {len(projects)} projects")
                for p in projects:
                    print(f"Project '{p['name']}' - org: '{p['organisation_id']}', privacy: '{p['privacy']}'")
                
                return projects

        except Exception as e:
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
                
                return {
                    'message': 'Project created successfully',
                    'project': new_project
                }, 201
                
        except Exception as e:
            if 'duplicate key value violates unique constraint' in str(e):
                return {'error': f'Project with name "{name}" already exists'}, 409
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
                    cursor.execute("""
                        SELECT *
                        FROM projects
                        WHERE id = %s AND deleted_at IS NULL
                        AND (privacy = 'public' OR privacy = 'semi-private')
                        ORDER BY name
                    """, (project_id,))

                project = cursor.fetchone()
                if not project:
                    return {'error': 'Project not found or access denied'}, 404
                else:
                    return project

        except Exception as e:
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
            return {'error': f'Failed to retrieve project users: {str(e)}'}, 500
    
    ### POST /projects/<project_id>/users ###
    ### Body: { "user_id": "<keycloak_user_id>", "role": "project-admin|project-contributor|project-viewer" } ###
    
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

            if not user_id or role not in ['project-admin', 'project-contributor', 'project-viewer']:
                return {'error': 'user_id and valid role (project-admin, project-contributor, project-viewer) are required'}, 400
            
            # Check if user exists in Keycloak
            user = keycloak_auth.get_user(user_id)
            if not user:
                return {'error': 'User not found in Keycloak'}, 404

            # Remove user from all existing project roles first (role hierarchy enforcement)
            removed_roles = []
            for existing_role in ['project-admin', 'project-contributor', 'project-viewer']:
                if keycloak_auth.user_has_attribute(user_id, existing_role, project_id):
                    success = keycloak_auth.remove_attribute_value(user_id, existing_role, project_id)
                    if success:
                        removed_roles.append(existing_role)
                        print(f"Removed project_id {project_id} from role {existing_role} for user {user_id}")
                    else:
                        return {'error': f'Failed to remove existing role {existing_role}'}, 500
            
            # Add the user to the new role
            success = keycloak_auth.add_attribute_value(user_id, role, project_id)
            if not success:
                return {'error': f'Failed to add user to role {role}'}, 500
            
            print(f"Added project_id {project_id} to role {role} for user {user_id}")

            return {
                'message': 'User added to project successfully',
                'user_id': user_id,
                'project_id': project_id,
                'new_role': role,
                'removed_roles': removed_roles
            }, 200

        except Exception as e:
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
            return {'error': f'Failed to remove user from project: {str(e)}'}, 500


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
            
            song_check_url = f"{song}/studies/{studyId}"
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
            song_create_url = f"{song}/studies/{studyId}/"
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
            return {'error': f'Database error: {str(e)}'}, 500

@study_ns.route('/submit/<string:project_id>/<string:study_id>/')
class SongSubmit(Resource):
    
    ### POST /studies/submit/<project_id>/<study_id>/ ###

    @study_ns.doc('submit_study')
    @require_auth(keycloak_auth)
    @require_permission('upload_analysis', resource_type='project', resource_id_arg='project_id')
    def post(self, project_id, study_id):

        """Submit an analysis to SONG (proxy endpoint)"""
        
        try:
            # Get the JSON payload from the request
            data = request.get_json()
            if not data:
                return {'error': 'No JSON data provided'}, 400

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
            song_submit_url = f"{song}/submit/{study_id}/"
            song_response = requests.post(song_submit_url, headers=song_headers, json=data)

            print(f"SONG submit response status: {song_response.status_code}")
            
            # Forward SONG's response directly
            try:
                response_data = song_response.json()
            except:
                response_data = {'message': song_response.text}
            
            return response_data, song_response.status_code

        except Exception as e:
            return {'error': f'Failed to submit analysis: {str(e)}'}, 500
        
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
                song_analysis_url = f"{song}/studies/{study_id}/analysis?analysisStates={states}"
            else:
                song_analysis_url = f"{song}/studies/{study_id}/analysis"

            song_response = requests.get(song_analysis_url, headers=song_headers)

            print(f"SONG analysis response status: {song_response.status_code}")
            
            # Forward SONG's response directly
            try:
                response_data = song_response.json()
            except:
                response_data = {'message': song_response.text}
            
            return response_data, song_response.status_code

        except Exception as e:
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
            init_upload_url = f"{score}/upload/{object_id}/uploads"
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
            finalize_part_url = f"{score}/upload/{object_id}/parts"
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
            finalize_upload_url = f"{score}/upload/{object_id}"
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
            return {'error': f'Failed to upload file: {str(e)}'}, 500
       
@study_ns.route('/<string:study_id>/analysis/publish/<string:analysis_id>')
class StudyAnalysisPublish(Resource):

    ### POST /studies/<study_id>/analysis/publish/<analysis_id> ###

    @study_ns.doc('publish_analysis')
    @require_auth(keycloak_auth)
    def post(self, study_id, analysis_id):

        """Publish an analysis in SONG (proxy endpoint)"""
        
        print('here!')
        
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

            # Forward the publish request to SONG
            song_publish_url = f"{song}/studies/{study_id}/analysis/publish/{analysis_id}"
            song_response = requests.put(song_publish_url, headers=song_headers)

            print(f"SONG publish response status: {song_response.status_code}")

            # Forward SONG's response directly
            try:
                response_data = song_response.json()
            except Exception:
                response_data = {'message': song_response.text}

            return response_data, song_response.status_code

        except Exception as e:
            return {'error': f'Failed to publish analysis: {str(e)}'}, 500


@study_ns.route('/<string:study_id>/analysis/unpublish/<string:analysis_id>/')
class StudyAnalysisUnpublish(Resource):
    
    ### POST /studies/<study_id>/analysis/unpublish/<analysis_id> ###

    @study_ns.doc('unpublish_analysis')
    @require_auth(keycloak_auth)
    def post(self, study_id, analysis_id):

        """Unpublish an analysis in SONG (proxy endpoint)"""
        
        print('here!')

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

            # Forward the unpublish request to SONG
            song_unpublish_url = f"{song}/studies/{study_id}/analysis/unpublish/{analysis_id}"
            song_response = requests.put(song_unpublish_url, headers=song_headers)

            print(f"SONG unpublish response status: {song_response.status_code}")

            # Forward SONG's response directly
            try:
                response_data = song_response.json()
            except Exception:
                response_data = {'message': song_response.text}

            return response_data, song_response.status_code

        except Exception as e:
            return {'error': f'Failed to unpublish analysis: {str(e)}'}, 500


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=PORT)
