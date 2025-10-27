"""
Templates module for managing spreadsheet template files.
Templates help users prepare TSV data for genomic analysis.
"""

from flask import request, send_file, Response
from flask_restx import Namespace, Resource
from auth import require_auth, extract_user_info, require_permission, keycloak_auth
from database import get_db_cursor
from minio import Minio
from minio.error import S3Error
from settings import (
    MINIO_ENDPOINT_CLEAN,
    MINIO_ACCESS_KEY,
    MINIO_SECRET_KEY,
    MINIO_SECURED,
    MINIO_BUCKET,
)
import io
import uuid
from logging import getLogger

logger = getLogger(__name__)


# Initialize MinIO client
def get_minio_client():
    """Get configured MinIO client instance"""
    return Minio(
        MINIO_ENDPOINT_CLEAN,
        access_key=MINIO_ACCESS_KEY,
        secret_key=MINIO_SECRET_KEY,
        secure=MINIO_SECURED
    )


# Create namespace
template_ns = Namespace("templates", description="Template management endpoints")


@template_ns.route("/")
class TemplateList(Resource):

    @template_ns.doc("list_templates")
    def get(self):
        """List all templates (public access)
        """
        try:

            with get_db_cursor() as cursor:
                query = """
                    SELECT
                        t.id,
                        t.pathogen_id,
                        t.schema_version,
                        t.minio_object_id,
                        t.filename,
                        t.created_at,
                        t.updated_at,
                        p.name as pathogen_name
                    FROM templates t
                    LEFT JOIN pathogens p ON t.pathogen_id = p.id
                    WHERE t.deleted_at IS NULL
                    ORDER BY t.created_at DESC
                """
                cursor.execute(query)
                templates = cursor.fetchall()

                return {"templates": templates}, 200

        except Exception as e:
            return {"error": f"Failed to list templates: {str(e)}"}, 500

    @require_auth(keycloak_auth)
    @require_permission('create_template', resource_type='template')
    @template_ns.doc("create_template")
    def put(self):
        """Create or update a template (requires authentication)

        Multipart form data:
        - pathogen_id: UUID of the pathogen
        - schema_version: Integer version number
        - file: Template file (spreadsheet)
        """
        try:
            # Validate inputs
            pathogen_id = request.form.get("pathogen_id")
            schema_version = request.form.get("schema_version")
            if not pathogen_id or not schema_version:
                return {"error": "pathogen_id and schema_version are required"}, 400

            try:
                schema_version = int(schema_version)
            except ValueError:
                return {"error": "schema_version must be an integer"}, 400

            if "file" not in request.files:
                return {"error": "No file provided"}, 400

            file = request.files["file"]
            if file.filename == "":
                return {"error": "No file selected"}, 400

            file_data = file.read()
            file_size = len(file_data)
            filename = file.filename

            # Generate MinIO object ID
            minio_object_id = f"templates/{uuid.uuid4()}/{filename}"

            minio_client = get_minio_client()

            if not minio_client.bucket_exists(MINIO_BUCKET):
                logger.info(f"Creating bucket: {MINIO_BUCKET}")
                minio_client.make_bucket(MINIO_BUCKET)

            logger.info(f"Uploading template {filename} to MinIO: {minio_object_id}")
            minio_client.put_object(
                MINIO_BUCKET,
                minio_object_id,
                io.BytesIO(file_data),
                file_size,
                content_type=file.content_type or "application/octet-stream",
            )

            # Check if template already exists for this pathogen and version
            with get_db_cursor() as cursor:
                cursor.execute(
                    """
                    SELECT id, minio_object_id FROM templates
                    WHERE pathogen_id = %s AND schema_version = %s AND deleted_at IS NULL
                """,
                    (pathogen_id, schema_version),
                )

                existing = cursor.fetchone()

                if existing:
                    # Update existing template
                    template_id = existing["id"]
                    old_minio_object_id = existing["minio_object_id"]

                    cursor.execute(
                        """
                        UPDATE templates
                        SET minio_object_id = %s, filename = %s, updated_at = CURRENT_TIMESTAMP
                        WHERE id = %s
                    """,
                        (minio_object_id, filename, template_id),
                    )

                    # Delete old file from MinIO
                    try:
                        minio_client.remove_object(
                            MINIO_BUCKET, old_minio_object_id
                        )
                    except S3Error:
                        pass  # Ignore if old file doesn't exist

                    action = "updated"
                else:
                    # Create new template
                    cursor.execute(
                        """
                        INSERT INTO templates (pathogen_id, schema_version, minio_object_id, filename)
                        VALUES (%s, %s, %s, %s)
                        RETURNING id
                    """,
                        (pathogen_id, schema_version, minio_object_id, filename),
                    )
                    template_id = cursor.fetchone()["id"]
                    action = "created"

                # Fetch the template details
                cursor.execute(
                    """
                    SELECT
                        t.id,
                        t.pathogen_id,
                        t.schema_version,
                        t.minio_object_id,
                        t.filename,
                        t.created_at,
                        t.updated_at,
                        p.name as pathogen_name
                    FROM templates t
                    LEFT JOIN pathogens p ON t.pathogen_id = p.id
                    WHERE t.id = %s
                """,
                    (template_id,),
                )

                row = cursor.fetchone()
                row["download_url"] = f"/templates/{row['id']}/download"
                return {
                    "message": f"Template {action} successfully",
                    "template": row,
                }, 200

        except Exception as e:
            logger.exception("Error creating/updating template")
            return {
                "error": f"Failed to create/update template: {e.__class__.__name__}: {str(e)}"
            }, 500


@template_ns.route("/<string:template_id>")
class TemplateDetail(Resource):

    @require_auth(keycloak_auth)
    @require_permission('delete_template', resource_type='template')
    @template_ns.doc("delete_template")
    def delete(self, template_id):
        """Delete a template by ID (system-admin only)

        Query Parameters:
        - hard: true/false (default: false) - If true, permanently delete from database and MinIO
        """
        try:
            # Check if hard delete is requested
            hard_delete = request.args.get('hard', 'false').lower() == 'true'

            with get_db_cursor() as cursor:
                # First get the template details
                cursor.execute(
                    """
                    SELECT id, filename, minio_object_id, deleted_at
                    FROM templates
                    WHERE id = %s
                    """,
                    (template_id,)
                )

                template = cursor.fetchone()

                if not template:
                    return {'error': 'Template not found'}, 404

                if hard_delete:
                    # Hard delete - permanently remove from database and MinIO
                    cursor.execute(
                        """
                        DELETE FROM templates
                        WHERE id = %s
                        RETURNING id, filename, minio_object_id
                        """,
                        (template_id,)
                    )

                    deleted_template = cursor.fetchone()

                    # Delete file from MinIO
                    try:
                        minio_client = get_minio_client()
                        minio_client.remove_object(MINIO_BUCKET, deleted_template['minio_object_id'])
                        logger.info(f"Deleted template file from MinIO: {deleted_template['minio_object_id']}")
                    except S3Error as e:
                        logger.warning(f"Failed to delete file from MinIO: {str(e)}")
                        # Continue anyway - database record is deleted

                    return {
                        'message': f'Template "{deleted_template["filename"]}" permanently deleted',
                        'delete_type': 'hard'
                    }, 200
                else:
                    # Soft delete - set deleted_at timestamp
                    if template['deleted_at']:
                        return {'error': 'Template already deleted'}, 404

                    cursor.execute(
                        """
                        UPDATE templates
                        SET deleted_at = NOW(), updated_at = NOW()
                        WHERE id = %s AND deleted_at IS NULL
                        RETURNING id, filename
                        """,
                        (template_id,)
                    )

                    deleted_template = cursor.fetchone()

                    if not deleted_template:
                        return {'error': 'Template not found or already deleted'}, 404

                    return {
                        'message': f'Template "{deleted_template["filename"]}" deleted (soft delete)',
                        'delete_type': 'soft'
                    }, 200

        except Exception as e:
            logger.exception("Error deleting template")
            return {'error': f'Failed to delete template: {str(e)}'}, 500


@template_ns.route("/<string:template_id>/restore")
class TemplateRestore(Resource):

    @require_auth(keycloak_auth)
    @require_permission('delete_template', resource_type='template')
    @template_ns.doc("restore_template")
    def post(self, template_id):
        """Restore a soft-deleted template (system-admin only)"""
        try:
            with get_db_cursor() as cursor:
                cursor.execute(
                    """
                    UPDATE templates
                    SET deleted_at = NULL, updated_at = NOW()
                    WHERE id = %s AND deleted_at IS NOT NULL
                    RETURNING id, filename, pathogen_id, schema_version, minio_object_id, updated_at
                    """,
                    (template_id,)
                )

                restored_template = cursor.fetchone()

                if not restored_template:
                    return {'error': 'Template not found or not deleted'}, 404

                return {
                    'message': f'Template "{restored_template["filename"]}" restored successfully',
                    'template': restored_template
                }, 200

        except Exception as e:
            if 'duplicate key value violates unique constraint' in str(e):
                return {'error': 'Cannot restore: A template with this pathogen and schema version already exists'}, 409
            logger.exception("Error restoring template")
            return {'error': f'Failed to restore template: {str(e)}'}, 500


@template_ns.route("/<string:template_id>/download")
class TemplateDownload(Resource):

    @template_ns.doc("download_template")
    def get(self, template_id):
        """Download a template file (public access)"""
        try:
            with get_db_cursor() as cursor:
                cursor.execute(
                    """
                    SELECT minio_object_id, filename
                    FROM templates
                    WHERE id = %s AND deleted_at IS NULL
                """,
                    (template_id,),
                )

                row = cursor.fetchone()

                if not row:
                    return {"error": "Template not found"}, 404

                minio_object_id = row["minio_object_id"]
                filename = row["filename"]

            # Get file from MinIO
            minio_client = get_minio_client()

            try:
                response = minio_client.get_object(MINIO_BUCKET, minio_object_id)
                file_data = response.read()
                response.close()
                response.release_conn()

                # Return file as downloadable response
                return Response(
                    file_data,
                    mimetype="application/octet-stream",
                    headers={
                        "Content-Disposition": f'attachment; filename="{filename}"'
                    },
                )

            except S3Error as e:
                return {"error": f"Failed to retrieve file from storage: {str(e)}"}, 500

        except Exception as e:
            return {"error": f"Failed to download template: {str(e)}"}, 500
