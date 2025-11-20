import jwt
import requests
from database import get_db_cursor, test_connection
from functools import wraps
from flask import request, jsonify, current_app
from jwt.exceptions import InvalidTokenError, ExpiredSignatureError
from permissions import PERMISSIONS

AGARI_ORG_ROLES = {"agari-org-viewer": "org-viewer", "agari-org-contributor": "org-contributor", "agari-org-admin": "org-admin", "agari-org-partial": "org-partial", "agari-org-owner": "org-owner"}


class KeycloakAuth:
    def __init__(self, keycloak_url, realm, client_id, client_secret):
        self.keycloak_url = keycloak_url
        self.realm = realm
        self.client_id = client_id
        self.client_secret = client_secret
        self.public_key = None

    ### GET PUBLIC KEY ###

    def get_public_key(self):
        """Fetch public key from Keycloak for token verification"""
        try:
            certs_url = f"{self.keycloak_url}/realms/{self.realm}/protocol/openid_connect/certs"
            response = requests.get(certs_url)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            print(f"Error fetching public key: {e}")
            return None
        
    ### VERIFY TOKEN ###
    
    def verify_token(self, token):
        """Extract user info from JWT token without signature verification"""
        try:
            # Decode token without signature verification for internal services
            payload = jwt.decode(token, options={"verify_signature": False})
            return payload
            
        except Exception as e:
            return {'error': f'Token decode failed: {str(e)}'}
    
    ### GET ADMIN TOKEN ###

    def get_admin_token(self):
        """Get admin access token for Keycloak API calls using service account"""
        try:
            token_url = f"{self.keycloak_url}/realms/{self.realm}/protocol/openid-connect/token"
            data = {
                'grant_type': 'client_credentials',
                'client_id': self.client_id,
                'client_secret': self.client_secret
            }
            
            response = requests.post(token_url, data=data)
            response.raise_for_status()
            token_data = response.json()
            return token_data.get('access_token')
        except requests.RequestException as e:
            print(f"Error getting admin token: {e}")
            return None
        
    ### GET CLIENT TOKEN ###
    
    def get_client_token(self):
        """
        Get client credentials token for service-to-service authentication
        Uses the same client_id and client_secret as the admin token but 
        can be used for different purposes (like SONG API calls)
        
        Returns:
            str: Access token or None if failed
        """
        try:
            token_url = f"{self.keycloak_url}/realms/{self.realm}/protocol/openid-connect/token"
            data = {
                'grant_type': 'client_credentials',
                'client_id': self.client_id,
                'client_secret': self.client_secret
            }
            
            response = requests.post(token_url, data=data)
            response.raise_for_status()
            
            token_data = response.json()
            return token_data.get('access_token')
            
        except requests.RequestException as e:
            current_app.logger.error(f"Error getting client token: {e}")
            return None
        
    ### HELPER METHODS ###

    def _user_has_attribute_value(self, user, attribute_name, attribute_value, exact_match=True):
        
        """
        Check if a user has a specific attribute value (multi-valued attributes)
        
        Args:
            user (dict): User object from Keycloak
            attribute_name (str): The name of the attribute to check
            attribute_value (str): The value to search for
            exact_match (bool): If True, search for exact match; if False, search for partial match
            
        Returns:
            bool: True if user has the attribute value, False otherwise
        """

        user_attributes = user.get('attributes', {})
        
        if attribute_name not in user_attributes:
            return False
        
        attr_values = user_attributes[attribute_name]
        
        # Attributes are stored as lists in Keycloak (multi-valued)
        if isinstance(attr_values, list):
            if exact_match:
                return attribute_value in attr_values
            else:
                return any(attribute_value.lower() in str(val).lower() for val in attr_values)
        else:
            # Fallback for single value (shouldn't happen with new setup)
            if exact_match:
                return str(attr_values) == attribute_value
            else:
                return attribute_value.lower() in str(attr_values).lower()
        
        return False


    def get_realm_roles(self, user_id):
        admin_token = self.get_admin_token()
        if not admin_token:
            return {'realm_roles': [], 'client_roles': []}

        try:
            headers = {
                'Authorization': f'Bearer {admin_token}',
                'Content-Type': 'application/json'
            }

            realm_roles_url = f"{self.keycloak_url}/admin/realms/{self.realm}/users/{user_id}/role-mappings/realm"
            realm_response = requests.get(realm_roles_url, headers=headers)
            realm_response.raise_for_status()

            realm_roles = realm_response.json()

            return [role['name'] for role in realm_roles]
        except requests.RequestException as e:
            return(f"Error fetching realm roles: {e}")


    def _format_user_data(self, user):
        """
        Format user data similar to whoami response

        Args:
            user (dict): User object from Keycloak

        Returns:
            dict: Formatted user data with user_id, username, organisation_id, roles, attributes
        """

        # Extract custom attributes (excluding standard ones)
        user_attributes = {}
        attributes = user.get('attributes', {})

        for key, value in attributes.items():
            if key != 'organisation_id':  # organisation_id is handled separately
                user_attributes[key] = value

        realm_roles = attributes.get('realm_role', None)

        if not realm_roles:
            realm_roles = self.get_realm_roles(user.get('id'))
            from helpers import role_org_member2
            role_org_member2(user["id"], attributes.get('organisation_id')[0], AGARI_ORG_ROLES[realm_roles[0]])
        else:
            realm_roles = [f"agari-{realm_roles[0]}"]

        return {
            'user_id': user.get('id'),
            'username': user.get('username'),
            'email': user.get('email'),
            'organisation_id': attributes.get('organisation_id', [None])[0] if attributes.get('organisation_id') else None,
            'roles': realm_roles,
            'attributes': user_attributes,
            'is_authenticated': True,
        }
    
    ### GET USER ###
    
    def get_user(self, user_id):

        """Fetch user details by user ID from Keycloak"""

        admin_token = self.get_admin_token()
        if not admin_token:
            return None

        try:
            user_url = f"{self.keycloak_url}/admin/realms/{self.realm}/users/{user_id}"

            headers = {
                'Authorization': f'Bearer {admin_token}',
                'Content-Type': 'application/json'
            }
            
            response = requests.get(user_url, headers=headers)
            response.raise_for_status()
            return response.json()
            
        except requests.RequestException as e:
            print(f"Error fetching user {user_id}: {e}")
            return None
        
    ### GET USER ORG ###    

    def get_user_org(self):

        """Extract and verify JWT token from Authorization header"""

        organisation_id = None      

        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                token = auth_header.split(' ')[1] 
                user_info_raw = self.verify_token(token)

                if user_info_raw and 'error' not in user_info_raw:
                    user_info = extract_user_info(user_info_raw)
                    user_org_ids = user_info.get('organisation_id', [])
                    organisation_id = user_org_ids[0] if user_org_ids and len(user_org_ids) > 0 else None
                    
                else:
                    print(f"Token verification failed: {user_info_raw}")
            except Exception as e:
                print(f"Authentication failed: {str(e)}")
                pass
        else:
            print(f"No Authorization header found")

        return organisation_id


    def get_user_projects(self):

        """Extract and verify JWT token from Authorization header"""

        projects_ids = []

        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                token = auth_header.split(' ')[1]
                user_info_raw = self.verify_token(token)

                if user_info_raw and 'error' not in user_info_raw:
                    user_info = extract_user_info(user_info_raw)
                    for role in ["project-admin", "project-contributor", "project-viewer"]:
                        if user_info.get("attributes"):
                            projects_ids.extend(user_info["attributes"].get(role, []))
                else:
                    print(f"Token verification failed: {user_info_raw}")
            except Exception as e:
                print(f"Authentication failed: {str(e)}")
                pass
        else:
            print(f"No Authorization header found")

        return projects_ids
    
    ### GET USER ORGANISATION PROJECTS ###

    def get_user_organisation_projects(self):

        """Extract and verify JWT token from Authorization header"""

        organisation_projects = []

        auth_header = request.headers.get('Authorization')
        if auth_header:
            try:
                token = auth_header.split(' ')[1]
                user_info_raw = self.verify_token(token)

                if user_info_raw and 'error' not in user_info_raw:
                    user_info = extract_user_info(user_info_raw)
                    organisation_id = user_info.get('organisation_id', None)
                else:
                    print(f"Token verification failed: {user_info_raw}")
            except Exception as e:
                print(f"Authentication failed: {str(e)}")
                return []
            
            if organisation_id:
                with get_db_cursor() as cursor:
                    cursor.execute("""
                        SELECT id FROM projects WHERE organisation_id = %s
                    """, (organisation_id[0],))
                    organisation_projects = cursor.fetchall()
                    organisation_projects = [row['id'] for row in organisation_projects]

                return organisation_projects
            
            else:
                print("No organisation_id found for user")
                return []

        else:
            print(f"No Authorization header found")
            return []
    

    ### GET PROJECTS PARENT ORG ###

    def get_project_parent_org(self, project_id):
        """Get the parent organisation ID for a given project ID"""
        with get_db_cursor() as cursor:
            cursor.execute("""
                SELECT organisation_id FROM projects WHERE id = %s
            """, (project_id,))
            result = cursor.fetchone()
            if result:
                return result['organisation_id']
            else:
                return None

    ### GET USERS BY ATTRIBUTE ###

    def get_users_by_attribute(self, attribute_name, attribute_value, exact_match=True):
        """
        Search for users by a specific attribute
        
        Args:
            attribute_name (str): The name of the attribute to search for
            attribute_value (str): The value to search for
            exact_match (bool): If True, search for exact match; if False, search for partial match
            
        Returns:
            list: List of users with simplified format (user_id, username, organisation_id, roles, attributes)
        """
        admin_token = self.get_admin_token()
        if not admin_token:
            return []
        
        try:
            # Keycloak admin API endpoint for users
            users_url = f"{self.keycloak_url}/admin/realms/{self.realm}/users"

            headers = {
                'Authorization': f'Bearer {admin_token}',
                'Content-Type': 'application/json'
            }
            
            # For custom attributes, we need to get all users and filter client-side
            # as Keycloak's search doesn't handle custom attributes well
            params = {'max': 1000}
            
            response = requests.get(users_url, headers=headers, params=params)
            response.raise_for_status()
            
            users = response.json()
            
            # Filter users based on attribute
            filtered_users = []
            for user in users:
                if self._user_has_attribute_value(user, attribute_name, attribute_value, exact_match):
                    # Format user data similar to whoami response
                    user_data = self._format_user_data(user)
                    filtered_users.append(user_data)
            return filtered_users
            
        except requests.RequestException as e:
            print(f"Error searching users by attribute: {e}")
            return []

    ### GET USER ATTRIBUTES ###

    def get_user_attributes(self, user_id):
        """
        Fetch user attributes by user ID from Keycloak
        
        Args:
            user_id (str): The user ID to fetch attributes for
        Returns:
            dict: User attributes or empty dict if none
        """

        user = self.get_user(user_id)
        if user:
            return user.get('attributes', {})
        return {}
    
    ### CHECK USER ATTRIBUTE ###
    
    def user_has_attribute(self, user_id, attribute_name, attribute_value, exact_match=True):
       
       
        admin_token = self.get_admin_token()
        if not admin_token:
            return False
        
        try:
            # Get specific user by ID
            user_url = f"{self.keycloak_url}/admin/realms/{self.realm}/users/{user_id}"
            
            headers = {
                'Authorization': f'Bearer {admin_token}',
                'Content-Type': 'application/json'
            }
            
            response = requests.get(user_url, headers=headers)
            response.raise_for_status()
            
            user = response.json()
            return self._user_has_attribute_value(user, attribute_name, attribute_value, exact_match)
            
        except requests.RequestException as e:
            print(f"Error checking user attribute: {e}")
            return False
    
    ### MODIFY USER ATTRIBUTES ###
    
    def add_attribute_value(self, user_id, attribute_name, value_to_add):
        """
        Add a value to a user's multi-valued attribute
        
        Args:
            user_id (str): The user ID to update
            attribute_name (str): The name of the attribute (e.g., 'project-admin', 'study-contributor')
            value_to_add (str): The value to add (e.g., project ID or study ID)
            
        Returns:
            bool: True if update was successful, False otherwise
        """
        admin_token = self.get_admin_token()
        if not admin_token:
            return False
        
        try:
            # Get current user data
            user_url = f"{self.keycloak_url}/admin/realms/{self.realm}/users/{user_id}"
            
            headers = {
                'Authorization': f'Bearer {admin_token}',
                'Content-Type': 'application/json'
            }
            
            response = requests.get(user_url, headers=headers)
            response.raise_for_status()
            
            user = response.json()
            attributes = user.get('attributes', {})
            
            # Get current attribute values (as list)
            current_values = attributes.get(attribute_name, [])
            
            # Ensure it's a list
            if not isinstance(current_values, list):
                current_values = [current_values] if current_values else []
            
            # Add new value if not already present
            if value_to_add not in current_values:
                current_values.append(value_to_add)
            
            # Update attributes
            attributes[attribute_name] = current_values
            user['attributes'] = attributes
            
            # Send update request
            update_response = requests.put(user_url, headers=headers, json=user)
            update_response.raise_for_status()
            
            return True
            
        except requests.RequestException as e:
            print(f"Error adding attribute value: {e}")
            return False
    
    def remove_attribute_value(self, user_id, attribute_name, value_to_remove):
        """
        Remove a value from a user's multi-valued attribute
        
        Args:
            user_id (str): The user ID to update
            attribute_name (str): The name of the attribute (e.g., 'project-admin', 'study-contributor')
            value_to_remove (str): The value to remove (e.g., project ID or study ID)
            
        Returns:
            bool: True if update was successful, False otherwise
        """
        admin_token = self.get_admin_token()
        if not admin_token:
            return False
        
        try:
            # Get current user data
            user_url = f"{self.keycloak_url}/admin/realms/{self.realm}/users/{user_id}"
            
            headers = {
                'Authorization': f'Bearer {admin_token}',
                'Content-Type': 'application/json'
            }
            
            response = requests.get(user_url, headers=headers)
            response.raise_for_status()
            
            user = response.json()
            attributes = user.get('attributes', {})
            
            # Get current attribute values (as list)
            current_values = attributes.get(attribute_name, [])
            
            # Ensure it's a list
            if not isinstance(current_values, list):
                current_values = [current_values] if current_values else []
            
            # Remove the value if present
            if value_to_remove in current_values:
                current_values.remove(value_to_remove)
            
            # Update attributes
            if current_values:
                attributes[attribute_name] = current_values
            elif attribute_name in attributes:
                # Remove attribute entirely if no values left
                del attributes[attribute_name]
            
            user['attributes'] = attributes
            
            # Send update request
            update_response = requests.put(user_url, headers=headers, json=user)
            update_response.raise_for_status()
            
            return True
            
        except requests.RequestException as e:
            print(f"Error removing attribute value: {e}")
            return False


    def remove_org_attribute(self, user_id, attribute_name="organisation_id"):
        admin_token = self.get_admin_token()
        if not admin_token:
            return False

        try:
            # Get current user data
            user_url = f"{self.keycloak_url}/admin/realms/{self.realm}/users/{user_id}"

            headers = {
                'Authorization': f'Bearer {admin_token}',
                'Content-Type': 'application/json'
            }

            response = requests.get(user_url, headers=headers)
            response.raise_for_status()

            user = response.json()
            attributes = user.get('attributes', {})

            if attribute_name in attributes:
                del attributes[attribute_name]

            user['attributes'] = attributes

            update_response = requests.put(user_url, headers=headers, json=user)
            update_response.raise_for_status()

            return True

        except requests.RequestException as e:
            print(f"Error removing attribute value: {e}")
            return False


    def update_realm_roles(self, user_id, role_names):
        """
        Update a user's realm roles
        
        Args:
            user_id (str): The user ID to update
            role_names (list): List of role names to assign to the user
            
        Returns:
            bool: True if update was successful, False otherwise
        """
        admin_token = self.get_admin_token()
        if not admin_token:
            return False
        
        try:
            # Get current user data
            user_url = f"{self.keycloak_url}/admin/realms/{self.realm}/users/{user_id}"
            
            headers = {
                'Authorization': f'Bearer {admin_token}',
                'Content-Type': 'application/json'
            }
            
            response = requests.get(user_url, headers=headers)
            response.raise_for_status()
            
            user = response.json()
            
            # Fetch all available realm roles
            roles_url = f"{self.keycloak_url}/admin/realms/{self.realm}/roles"
            roles_response = requests.get(roles_url, headers=headers)
            roles_response.raise_for_status()
            
            all_roles = roles_response.json()
            role_map = {role['name']: role for role in all_roles}
            
            # Prepare roles to assign
            roles_to_assign = [role_map[role_name] for role_name in role_names if role_name in role_map]
            
            if not roles_to_assign:
                print(f"No valid roles found to assign for user {user_id}")
                return False
            
            # Assign roles to user
            assign_url = f"{self.keycloak_url}/admin/realms/{self.realm}/users/{user_id}/role-mappings/realm"
            assign_response = requests.post(assign_url, headers=headers, json=roles_to_assign)
            assign_response.raise_for_status()
            
            return True
            
        except requests.RequestException as e:
            print(f"Error updating realm roles: {e}")
            return False


    def remove_realm_roles(self, user_id):
        admin_token = self.get_admin_token()
        if not admin_token:
            return False

        try:
            headers = {
                'Authorization': f'Bearer {admin_token}',
                'Content-Type': 'application/json'
            }
            current_roles_url = f"{self.keycloak_url}/admin/realms/{self.realm}/users/{user_id}/role-mappings/realm"

            current_roles_response = requests.get(current_roles_url, headers=headers)
            current_roles_response.raise_for_status()
            current_roles = current_roles_response.json()

            if not current_roles:
                print(f"User {user_id} has no realm roles to remove")
                return False

            # Remove the roles using DELETE with the role objects
            remove_url = f"{self.keycloak_url}/admin/realms/{self.realm}/users/{user_id}/role-mappings/realm"
            remove_response = requests.delete(remove_url, headers=headers, json=current_roles)
            remove_response.raise_for_status()

            print(f"Successfully removed {current_roles[0]['name']} realm roles from user {user_id}")
            return current_roles[0]["name"]
        except requests.RequestException as e:
            print(f"Error updating realm roles: {e}")
            return False


    ### GET USER INFO BY ID ###

    def get_user_info_by_id(self, user_id):
        """
        Get formatted user information by user ID (similar to extract_user_info but from Keycloak API)
        
        Args:
            user_id (str): The user ID to fetch
            
        Returns:
            dict: Formatted user info or None if user not found
        """
        user = self.get_user(user_id)
        if not user:
            return None
        
        # Extract attributes
        attributes = user.get('attributes', {})
        
        # Get organization_id from attributes (it's stored as a list in Keycloak)
        org_id = None
        if 'organisation_id' in attributes:
            org_id_list = attributes['organisation_id']
            org_id = org_id_list[0] if org_id_list and len(org_id_list) > 0 else None
        
        # Extract custom attributes (excluding standard ones we handle separately)
        user_attributes = {}
        standard_attrs = {'organisation_id', 'name', 'surname', 'title', 'bio', 'preferences', 'accepted_terms'}
        
        for key, value in attributes.items():
            if key not in standard_attrs:
                user_attributes[key] = value
        
        # Get single values from attribute lists for standard fields
        def get_attr_value(attr_name):
            attr_list = attributes.get(attr_name, [])
            return attr_list[0] if attr_list and len(attr_list) > 0 else None
        
        return {
            'user_id': user.get('id'),
            'username': user.get('username'),
            'email': user.get('email'),
            'title': get_attr_value('title'),
            'name': get_attr_value('name'),
            'surname': get_attr_value('surname'),
            'organisation_id': org_id,
            'bio': get_attr_value('bio'),
            'preferences': get_attr_value('preferences'),
            'roles': [],  # Would need separate API call to get user roles
            'attributes': user_attributes,
            'is_authenticated': True,
            'accepted_terms': get_attr_value('accepted_terms') == 'true' if get_attr_value('accepted_terms') else False,
        }


    ### UPDATE USER PROFILE ###
    
    def update_user(self, user_id, update_data):
        """
        Update user profile information including basic properties, email, roles, and attributes
        
        Args:
            user_id (str): The user ID to update
            update_data (dict): Dictionary of fields to update. Can include:
                - Basic fields: 'name', 'surname', 'email', 'title', 'bio'
                - 'realm_roles': list of role names to assign
                - 'attributes': dict of custom attributes to update
                
        Returns:
            dict: Result with success status and any errors
        """
        admin_token = self.get_admin_token()
        if not admin_token:
            return {'success': False, 'error': 'Could not get admin token'}
        
        results = {'success': True, 'updates': {}, 'errors': {}}
        
        try:
            user_url = f"{self.keycloak_url}/admin/realms/{self.realm}/users/{user_id}"
            
            headers = {
                'Authorization': f'Bearer {admin_token}',
                'Content-Type': 'application/json'
            }
            
            # Get current user data
            response = requests.get(user_url, headers=headers)
            response.raise_for_status()
            user = response.json()
            
            # Separate different types of updates
            basic_updates = {}
            realm_roles = update_data.get('realm_roles')
            attributes_update = update_data.get('attributes')
            
            # Extract basic user properties (excluding special fields)
            for key, value in update_data.items():
                if key not in ['realm_roles', 'attributes']:
                    basic_updates[key] = value
            
            # 1. Update basic user properties
            if basic_updates:
                try:
                    for key, value in basic_updates.items():
                        if key in ['name', 'surname']:
                            # These go to attributes in Keycloak
                            if 'attributes' not in user:
                                user['attributes'] = {}
                            user['attributes'][key] = [value] if value else []
                        elif key == 'email':
                            user['email'] = value
                        elif key in ['title', 'bio']:
                            # These also go to attributes
                            if 'attributes' not in user:
                                user['attributes'] = {}
                            user['attributes'][key] = [value] if value else []
                    
                    update_response = requests.put(user_url, headers=headers, json=user)
                    update_response.raise_for_status()
                    results['updates']['basic_properties'] = f"Updated: {', '.join(basic_updates.keys())}"
                except requests.RequestException as e:
                    results['success'] = False
                    results['errors']['basic_properties'] = f"Error updating basic properties: {e}"
            
            # 2. Update realm roles if provided
            if realm_roles is not None:
                try:
                    role_success = self.update_realm_roles(user_id, realm_roles)
                    if role_success:
                        results['updates']['realm_roles'] = f"Updated roles: {', '.join(realm_roles)}" if realm_roles else "Removed all non-default roles"
                    else:
                        results['success'] = False
                        results['errors']['realm_roles'] = "Failed to update realm roles"
                except Exception as e:
                    results['success'] = False
                    results['errors']['realm_roles'] = f"Error updating realm roles: {e}"
            
            # 3. Update custom attributes if provided
            if attributes_update is not None:
                try:
                    current_attributes = self.get_user_attributes(user_id)
                    
                    updated_attrs = []
                    for attr_name, attr_value in attributes_update.items():
                        if attr_value is None:
                            # Remove attribute entirely if value is None
                            current_values = current_attributes.get(attr_name, [])
                            if current_values:
                                for value in current_values:
                                    remove_success = self.remove_attribute_value(user_id, attr_name, value)
                                    if not remove_success:
                                        results['errors'][f'attr_remove_{attr_name}'] = f"Failed to remove attribute {attr_name}"
                                updated_attrs.append(f"removed {attr_name}")
                        else:
                            # Ensure attribute values are lists
                            if not isinstance(attr_value, list):
                                attr_value = [str(attr_value)]
                            
                            # Get current values for this attribute
                            current_values = current_attributes.get(attr_name, [])
                            
                            # Remove values that are no longer needed
                            for current_val in current_values:
                                if current_val not in attr_value:
                                    remove_success = self.remove_attribute_value(user_id, attr_name, current_val)
                                    if not remove_success:
                                        results['errors'][f'attr_remove_{attr_name}_{current_val}'] = f"Failed to remove value {current_val} from {attr_name}"
                            
                            # Add new values
                            for new_val in attr_value:
                                if new_val not in current_values:
                                    add_success = self.add_attribute_value(user_id, attr_name, new_val)
                                    if not add_success:
                                        results['errors'][f'attr_add_{attr_name}_{new_val}'] = f"Failed to add value {new_val} to {attr_name}"
                            
                            updated_attrs.append(attr_name)
                    
                    if updated_attrs:
                        results['updates']['attributes'] = f"Updated attributes: {', '.join(updated_attrs)}"
                    else:
                        results['updates']['attributes'] = "No attribute changes needed"
                        
                except Exception as e:
                    results['success'] = False
                    results['errors']['attributes'] = f"Error updating attributes: {e}"
            
            return results
            
        except requests.RequestException as e:
            return {'success': False, 'error': f"Error fetching user {user_id}: {e}"}
        

    def toggle_user_enabled(self, user_id, enabled):
        admin_token = self.get_admin_token()
        if not admin_token:
            return {'success': False, 'error': 'Could not get admin token'}

        user_url = f"{self.keycloak_url}/admin/realms/{self.realm}/users/{user_id}"

        headers = {
            'Authorization': f'Bearer {admin_token}',
            'Content-Type': 'application/json'
        }

        # Get current user data
        response = requests.get(user_url, headers=headers)
        response.raise_for_status()
        user = response.json()

        user['enabled'] = enabled
        requests.put(user_url, headers=headers, json=user)


    def get_user_access_token(self, user_id):
        """Get an access token for a specific user using token exchange or admin token"""
        try:
            admin_token = self.get_client_token()
            if not admin_token:
                print("Failed to get admin token")
                return None

            token_url = f"{self.keycloak_url}/realms/{self.realm}/protocol/openid-connect/token"
            exchange_data = {
                'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'subject_token': admin_token,
                'requested_subject': user_id,
                'audience': self.client_id,
                'requested_token_type': 'urn:ietf:params:oauth:token-type:access_token'
            }
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded'
            }

            response = requests.post(token_url, data=exchange_data, headers=headers)
            token_data = response.json()
            return token_data.get('access_token')
        except Exception as e:
            print(f"Error getting user access token: {str(e)}")
            return None


    def get_user_auth_tokens(self, user_id):
        """Get an auth token for a specific user using token exchange or admin token"""
        try:
            admin_token = self.get_client_token()
            if not admin_token:
                print("Failed to get admin token")
                return None

            token_url = f"{self.keycloak_url}/realms/{self.realm}/protocol/openid-connect/token"
            exchange_data = {
                'grant_type': 'urn:ietf:params:oauth:grant-type:token-exchange',
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'subject_token': admin_token,
                'requested_subject': user_id,
                'audience': self.client_id,
                'requested_token_type': 'urn:ietf:params:oauth:token-type:refresh_token'
            }
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded'
            }

            response = requests.post(token_url, data=exchange_data, headers=headers)
            token_data = response.json()
            return {
                'access_token': token_data.get('access_token'),
                'refresh_token': token_data.get('refresh_token'),
                'expires_in': token_data.get('expires_in'),
                'refresh_expires_in': token_data.get('refresh_expires_in')
            }
        except Exception as e:
            print(f"Error getting user refresh token: {str(e)}")
            return None


    def change_username(self, user_id, new_username):
        admin_token = self.get_admin_token()
        if not admin_token:
            return {'success': False, 'error': 'Could not get admin token'}
        try:
            # First check if the new username is already taken
            check_url = f"{self.keycloak_url}/admin/realms/{self.realm}/users"
            headers = {
                'Authorization': f'Bearer {admin_token}',
                'Content-Type': 'application/json'
            }

            # Search for existing user with the new username
            check_params = {'username': new_username, 'exact': 'true'}
            check_response = requests.get(check_url, headers=headers, params=check_params)
            check_response.raise_for_status()

            existing_users = check_response.json()
            if existing_users:
                # Check if it's the same user (updating to same username)
                if len(existing_users) == 1 and existing_users[0]['id'] == user_id:
                    return {'success': True, 'message': 'Username is already set to this value'}
                else:
                    return {'success': False, 'error': 'Username already exists'}

            # Get current user data
            user_url = f"{self.keycloak_url}/admin/realms/{self.realm}/users/{user_id}"
            response = requests.get(user_url, headers=headers)
            response.raise_for_status()

            user = response.json()
            old_username = user.get('username')

            # Update the username
            user['username'] = new_username

            # Send update request
            update_response = requests.put(user_url, headers=headers, json=user)
            update_response.raise_for_status()

            return {
                'success': True,
                'message': f'Username changed from "{old_username}" to "{new_username}"',
                'old_username': old_username,
                'new_username': new_username
            }
        except requests.RequestException as e:
            error_msg = f"Error changing username: {e}"
            if hasattr(e, 'response') and e.response is not None:
                try:
                    error_detail = e.response.json()
                    if 'errorMessage' in error_detail:
                        error_msg = f"Keycloak error: {error_detail['errorMessage']}"
                    elif 'error_description' in error_detail:
                        error_msg = f"Keycloak error: {error_detail['error_description']}"
                except:
                    pass
            return {'success': False, 'error': error_msg}
        except Exception as e:
            return {'success': False, 'error': f"Unexpected error: {str(e)}"}


def require_auth(keycloak_auth):

    """Decorator to require authentication"""
    
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            auth_header = request.headers.get('Authorization')
            
            if not auth_header:
                return {'error': 'No authorization header'}, 401
            
            try:
                token = auth_header.split(' ')[1]  # Remove 'Bearer ' prefix
            except IndexError:
                return {'error': 'Invalid authorization header format'}, 401
            
            user_info = keycloak_auth.verify_token(token)
            
            if not user_info or 'error' in user_info:
                error_msg = user_info.get('error', 'Token verification failed') if user_info else 'Token verification failed'
                return {'error': error_msg}, 401
            
            # Add user info to request context
            request.user = user_info
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator

def extract_user_info(token_payload):

    """Extract useful user information from JWT payload"""
    
    realm_roles = []
    if "realm_access" in token_payload and "roles" in token_payload["realm_access"]:
        realm_roles = token_payload["realm_access"]["roles"]
    
    # Extract user attributes - they can be in different places in the JWT
    user_attributes = {}
    
    standard_claims = {
        'iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti', 'typ', 'azp',
        'session_state', 'acr', 'allowed-origins', 'realm_access', 'resource_access',
        'scope', 'sid', 'email_verified', 'preferred_username', 'given_name',
        'family_name', 'email', 'groups', 'name', 'surname', 'title', 'organisation_id',
        'bio', 'preferences', 'accepted_terms'
    }

    for key, value in token_payload.items():
        if key not in standard_claims and not key.startswith(('realm_', 'resource_')):
            user_attributes[key] = value

    return {
        'user_id': token_payload.get('sub'),
        'username': token_payload.get('preferred_username'),
        'email': token_payload.get('email'),
        'title': token_payload.get('title'),
        'name': token_payload.get('name'),
        'surname': token_payload.get('surname'),
        'organisation_id': token_payload.get('organisation_id'),
        'bio': token_payload.get('bio'),
        'preferences': token_payload.get('preferences'),
        'roles': realm_roles,
        'attributes': user_attributes,
        'is_authenticated': True,
        'accepted_terms': token_payload.get('accepted_terms', False),
    }

def user_has_permission(user_info, permission_name, resource_type=None, resource_id=None, parent_project_id=None):
    """
    Unified permission checking function that handles all access control logic.
    Organization checks are performed for org-level roles but not for attribute-based permissions.
    """
    from database import get_db_cursor  # Import here to avoid circular imports
    
    user_roles = user_info.get('roles', [])
    user_id = user_info.get('user_id')
    user_org_id = user_info.get('organisation_id')
    
    access_details = {
        'permission_checked': permission_name,
        'checks_performed': [],
        'access_granted_by': None,
        'reason': None,
        'required_roles': PERMISSIONS.get(permission_name, []),
        'attribute_checks': []
    }

    required_roles = PERMISSIONS.get(permission_name, [])
    if not required_roles:
        access_details['reason'] = f'Permission "{permission_name}" not defined'
        access_details['checks_performed'].append('permission_definition_check')
        return False, access_details

    # 1. Check if user is system admin (bypasses all restrictions)
    access_details['checks_performed'].append('system_admin_check')
    if 'system-admin' in user_roles:
        access_details['access_granted_by'] = 'system_admin_role'
        access_details['reason'] = 'User has system-admin role'
        return True, access_details

    # 2. Check standard org roles (WITH organization check)
    access_details['checks_performed'].append('org_role_check')
    org_roles = ['agari-org-owner', 'agari-org-admin', 'agari-org-contributor', 'agari-org-viewer']
    
    for required_role in required_roles:
        if required_role in org_roles and required_role in user_roles:
            
            # For org roles, user MUST have an organization
            if not user_org_id:
                access_details['reason'] = f'User has org role "{required_role}" but no organisation_id assigned'
                continue  # Skip to next role check
            
            # For org roles, we need to check if the resource belongs to the user's organization
            if resource_id and resource_type and user_org_id:
                try:
                    with get_db_cursor() as cursor:
                        if resource_type == 'project':
                            cursor.execute("""
                                SELECT organisation_id FROM projects 
                                WHERE id = %s AND deleted_at IS NULL
                            """, (resource_id,))
                        elif resource_type == 'study':
                            cursor.execute("""
                                SELECT p.organisation_id FROM studies s
                                JOIN projects p ON s.project_id = p.id
                                WHERE s.id = %s AND s.deleted_at IS NULL AND p.deleted_at IS NULL
                            """, (resource_id,))
                        else:
                            # For other resource types or no resource, allow org role
                            access_details['access_granted_by'] = f'org_role:{required_role}'
                            access_details['reason'] = f'User has org role "{required_role}" (no resource check needed)'
                            return True, access_details
                        
                        result = cursor.fetchone()
                        if result:
                            resource_org_id = result['organisation_id']
                            
                            # Check if user_org_id is in the list or matches directly
                            user_has_org_access = False
                            if isinstance(user_org_id, list):
                                user_has_org_access = resource_org_id in user_org_id
                            else:
                                user_has_org_access = resource_org_id == user_org_id
                            
                            if user_has_org_access:
                                access_details['access_granted_by'] = f'org_role:{required_role}'
                                access_details['reason'] = f'User has org role "{required_role}" and resource belongs to user\'s organisation'
                                return True, access_details
                            else:
                                access_details['reason'] = f'User has org role "{required_role}" but resource belongs to different organisation'
                        else:
                            access_details['reason'] = f'Resource not found for organisation check'
                            
                except Exception as e:
                    access_details['reason'] = f'Database error during organisation check: {str(e)}'
            else:
                # No resource to check, allow org role (e.g., listing resources)
                access_details['access_granted_by'] = f'org_role:{required_role}'
                access_details['reason'] = f'User has org role "{required_role}" (no resource specified)'
                return True, access_details

    # 3. Check attribute-based roles (NO organization check - project-specific permissions)
    if resource_id and user_id:
        access_details['checks_performed'].append('attribute_role_check')
        for required_role in required_roles:
            if required_role.startswith('attr-'):
                attribute_name = required_role[5:]  # Remove 'attr-' prefix
                access_details['attribute_checks'].append({
                    'attribute_name': attribute_name,
                    'resource_id': resource_id,
                    'checked': True
                })
                
                user_attributes = user_info.get('attributes', {})
                has_attribute = False
                
                # Check for the attribute on the resource itself
                if attribute_name in user_attributes:
                    attr_values = user_attributes[attribute_name]
                    if isinstance(attr_values, list):
                        has_attribute = resource_id in attr_values
                    else:
                        has_attribute = str(attr_values) == resource_id
                    access_details['attribute_checks'][-1]['jwt_check'] = 'found' if has_attribute else 'not_found'
                else:
                    access_details['attribute_checks'][-1]['jwt_check'] = 'attribute_not_in_jwt'
                
                # If not found and this is a study, check for project-level attribute
                if not has_attribute and resource_type == 'study' and parent_project_id:
                    # Map study attribute to project attribute (e.g., study-admin -> project-admin)
                    if attribute_name.startswith('study-'):
                        project_attr = 'project-' + attribute_name[len('study-'):]
                        access_details['attribute_checks'][-1]['project_attribute_checked'] = project_attr
                        if project_attr in user_attributes:
                            proj_attr_values = user_attributes[project_attr]
                            if isinstance(proj_attr_values, list):
                                has_attribute = parent_project_id in proj_attr_values
                            else:
                                has_attribute = str(proj_attr_values) == parent_project_id
                            access_details['attribute_checks'][-1]['project_jwt_check'] = 'found' if has_attribute else 'not_found'
                        else:
                            access_details['attribute_checks'][-1]['project_jwt_check'] = 'attribute_not_in_jwt'
                
                if has_attribute:
                    access_details['access_granted_by'] = f'attribute:{attribute_name}'
                    access_details['reason'] = f'User has project-specific attribute "{attribute_name}" for resource {resource_id}'
                    return True, access_details
                else:
                    access_details['attribute_checks'][-1]['result'] = 'not_found'

    # 4. If no access granted
    access_details['reason'] = 'User does not have required permissions'
    return False, access_details

def require_permission(permission_name, resource_type=None, resource_id_arg=None, parent_project_id_arg=None):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            user_info = extract_user_info(request.user)
            
            # Extract resource_id and parent_project_id
            resource_id = None
            parent_project_id = None
            
            # First try to get from URL parameters (kwargs)
            if resource_id_arg:
                resource_id = kwargs.get(resource_id_arg)
            if parent_project_id_arg:
                parent_project_id = kwargs.get(parent_project_id_arg)
            
            # If not found in URL and we have a POST request, try JSON body
            if not resource_id and request.method == 'POST' and resource_id_arg:
                data = request.get_json() or {}
                resource_id = data.get(resource_id_arg)
            
            if not parent_project_id and request.method == 'POST' and parent_project_id_arg:
                data = request.get_json() or {}
                parent_project_id = data.get(parent_project_id_arg)

            has_perm, details = user_has_permission(
                user_info,
                permission_name,
                resource_type=resource_type,
                resource_id=resource_id,
                parent_project_id=parent_project_id
            )
            if not has_perm:
                return {'error': 'Permission denied', 'details': details}, 403
            return f(*args, **kwargs)
        return wrapper
    return decorator    
