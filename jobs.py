import json
from database import get_db_cursor

def add_job(job_type, data):
    """Add a job to the queue"""
    payload = {"job_type": job_type, "data": data}
    
    with get_db_cursor() as cursor:
        cursor.execute("""
            INSERT INTO jobs (payload) 
            VALUES (%s) 
            RETURNING id
        """, (json.dumps(payload),))
        
        job_id = cursor.fetchone()['id']
        print(f"Added job {job_id}: {job_type}")
        return job_id

def get_next_job():
    """Get the next pending job"""
    with get_db_cursor() as cursor:
        cursor.execute("""
            UPDATE jobs 
            SET status = 'in_progress', updated_at = now()
            WHERE id = (
                SELECT id FROM jobs 
                WHERE status = 'pending'
                ORDER BY created_at ASC
                LIMIT 1
                FOR UPDATE SKIP LOCKED
            ) 
            RETURNING *
        """)
        
        job = cursor.fetchone()
        
        if job:
            # Parse the payload to extract job_type
            payload = json.loads(job['payload']) if isinstance(job['payload'], str) else job['payload']
            job['job_type'] = payload.get('job_type', 'unknown')
        
        return job

def mark_job_done(job_id):
    """Mark job as completed"""
    with get_db_cursor() as cursor:
        cursor.execute("""
            UPDATE jobs 
            SET status = 'done', updated_at = now()
            WHERE id = %s
        """, (job_id,))

def mark_job_failed(job_id, error_msg, max_retries=3):
    """Mark job as failed, but retry if under limit
    
    Returns:
        dict: {'permanently_failed': bool, 'retry_count': int, 'error_msg': str}
    """
    with get_db_cursor() as cursor:
        # First, increment retry count and check if we should retry
        cursor.execute("""
            UPDATE jobs 
            SET retry_count = retry_count + 1, updated_at = now()
            WHERE id = %s
            RETURNING retry_count, payload
        """, (job_id,))
        
        result = cursor.fetchone()
        retry_count = result['retry_count']
        payload = result['payload']
        
        if retry_count < max_retries:
            # Still have retries left - put back to pending
            cursor.execute("""
                UPDATE jobs 
                SET status = 'pending', updated_at = now()
                WHERE id = %s
            """, (job_id,))
            print(f"Job {job_id} failed (attempt {retry_count}/{max_retries}). Retrying...")
            return {
                'permanently_failed': False,
                'retry_count': retry_count,
                'error_msg': error_msg,
                'payload': payload
            }
        else:
            # Out of retries - mark as failed permanently
            cursor.execute("""
                UPDATE jobs 
                SET status = 'failed', updated_at = now()
                WHERE id = %s
            """, (job_id,))
            print(f"Job {job_id} failed permanently after {retry_count} attempts: {error_msg}")
            return {
                'permanently_failed': True,
                'retry_count': retry_count,
                'error_msg': error_msg,
                'payload': payload
            }

def get_job_status(job_id):
    """Check job status"""
    with get_db_cursor() as cursor:
        cursor.execute("SELECT * FROM jobs WHERE id = %s", (job_id,))
        return cursor.fetchone()