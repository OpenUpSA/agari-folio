PERMISSIONS = {
    # System admin
    "system_admin_access": ["system-admin"],

    # User management
    "create_user": ["system-admin", "agari-org-owner", "agari-org-admin"],
    "manage_users": ["system-admin", "agari-org-owner", "agari-org-admin"],
    "view_users": ["system-admin", "agari-org-owner", "agari-org-admin"],

    # Organisation management
    "create_org": ["system-admin"],
    "delete_org": ["system-admin"],
    "manage_org_settings": ["system-admin", "agari-org-owner", "agari-org-admin"],

    # Organisation members management
    "add_org_members": ["system-admin", "agari-org-owner", "agari-org-admin"],
    "remove_org_members": ["system-admin", "agari-org-owner", "agari-org-admin"],
    "change_org_member_roles": ["system-admin", "agari-org-owner", "agari-org-admin"],
    "view_org_members": ["system-admin", "agari-org-owner", "agari-org-admin"],
    "change_org_owner": ["system-admin", "agari-org-owner"],

    # Pathogen management
    "create_pathogen": ["system-admin"],
    "edit_pathogen": ["system-admin"],
    "delete_pathogen": ["system-admin"],
    "view_pathogens": [],

    # Project management
    "create_project": ["system-admin", "agari-org-owner", "agari-org-admin"],
    "edit_projects": ["system-admin", "agari-org-owner", "agari-org-admin"],
    "delete_projects": ["system-admin", "agari-org-owner", "agari-org-admin"],
    "view_projects": [],
    "view_project_users": ["system-admin", "agari-org-owner", "agari-org-admin", "attr-project-admin"],
    "manage_project_users": ["system-admin", "agari-org-owner", "agari-org-admin", "attr-project-admin"],
    "view_project_submissions": ["system-admin", "agari-org-owner", "agari-org-admin", "agari-org-viewer", "attr-project-admin", "attr-project-contributor", "attr-project-viewer"],

    # Study management
    "view_studies": ["system-admin","agari-org-owner", "agari-org-admin", "agari-org-contributor", "agari-org-viewer", "attr-project-admin", "attr-project-contributor", "attr-project-viewer"],   
    "create_study": ["system-admin", "agari-org-owner", "agari-org-admin", "attr-project-admin", "attr-project-contributor"],
    "edit_study": ["system-admin", "agari-org-owner", "agari-org-admin", "attr-project-admin", "attr-project-contributor"],
    "delete_study": ["system-admin", "agari-org-owner", "agari-org-admin", "attr-project-admin", "attr-project-contributor"],
    "list_study_users": ["system-admin", "agari-org-owner", "agari-org-admin", "attr-project-admin"],
    "manage_study_users": ["system-admin", "agari-org-owner", "agari-org-admin", "attr-project-admin"],
    "submit_to_study": ["system-admin", "agari-org-owner", "agari-org-admin", "agari-org-contributor", "attr-project-admin", "attr-project-contributor"],
    "upload_analysis": ["system-admin", "agari-org-owner", "agari-org-admin", "agari-org-contributor", "attr-project-admin", "attr-project-contributor"],
    "upload_submission": ["system-admin", "agari-org-owner", "agari-org-admin", "agari-org-contributor", "attr-project-admin", "attr-project-contributor"],
    "publish_submission": ["system-admin", "agari-org-owner", "agari-org-admin", "agari-org-contributor", "attr-project-admin", "attr-project-contributor"],
    "unpublish_submission": ["system-admin", "agari-org-owner", "agari-org-admin", "agari-org-contributor", "attr-project-admin", "attr-project-contributor"],
    "download_isolates": ["system-admin", "agari-org-owner", "agari-org-admin", "agari-org-contributor", "agari-org-viewer", "attr-project-admin", "attr-project-contributor", "attr-project-viewer"],

    # Other
    "view_activity_log": ["system-admin", "agari-org-owner", "agari-org-admin", "attr-project-admin", "agari-org-partial"],

}