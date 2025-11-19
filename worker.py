import time
import signal
import sys
import json
import asyncio
from jobs import get_next_job, mark_job_done, mark_job_failed
from database import get_db_cursor
from helpers import check_for_sequence_data, send_to_elastic2

print("Starting job worker...")

# Handle shutdown
def shutdown(signum, frame):
    print("Worker shutting down...")
    sys.exit(0)

signal.signal(signal.SIGTERM, shutdown)
signal.signal(signal.SIGINT, shutdown)

async def process_sequence_validation(job):

    payload = json.loads(job['payload']) if isinstance(job['payload'], str) else job['payload']
    job_data = payload['data']
    submission_id = job_data['submission_id']
    isolate_ids = job_data['isolate_ids']
    
    print(f"Processing sequence validation for submission {submission_id} with {len(isolate_ids)} isolates")
    
    # Get isolates to process
    with get_db_cursor() as cursor:
        # Get isolates that are still validated (haven't been touched since job was queued)
        cursor.execute("""
            SELECT * FROM isolates 
            WHERE id = ANY(%s::uuid[]) AND status = 'validated'
            ORDER BY id
        """, (isolate_ids,))
        
        validated_isolates = cursor.fetchall()
    
    print(f"Found {len(validated_isolates)} isolates still validated and ready for sequence checking")
    
    # Process each isolate
    for isolate in validated_isolates:
        success, result = await check_for_sequence_data(isolate)
        
        with get_db_cursor() as cursor:
            if success:
                # Success - update with object_id, keep status as 'validated'
                cursor.execute("""
                    UPDATE isolates 
                    SET object_id = %s, status = 'validated', updated_at = NOW()
                    WHERE id = %s AND status = 'validated'
                """, (result, isolate['id']))
                print(f"Sequence saved for isolate {isolate['id']}: {result}")
                
                # Get updated isolate data and send to Elasticsearch
                cursor.execute("""
                    SELECT i.*, s.project_id, p.pathogen_id
                    FROM isolates i
                    LEFT JOIN submissions s ON i.submission_id = s.id
                    LEFT JOIN projects p ON s.project_id = p.id
                    WHERE i.id = %s
                """, (isolate['id'],))
                
                updated_isolate = cursor.fetchone()
                if updated_isolate:
                    send_to_elastic2(updated_isolate)
                    print(f"Updated isolate {isolate['id']} sent to Elasticsearch")
                    
            else:
                # Error - set seq_error and change status to sequence_error
                seq_error_data = {
                    "row": isolate["tsv_row"],
                    "seq_error": result
                }
                cursor.execute("""
                    UPDATE isolates 
                    SET seq_error = %s, status = 'error', updated_at = NOW()
                    WHERE id = %s AND status = 'validated'
                """, (json.dumps(seq_error_data), isolate['id']))
                print(f"Sequence error for isolate {isolate['id']}: {result}")
                
                # Get updated isolate data and send to Elasticsearch
                cursor.execute("""
                    SELECT i.*, s.project_id, p.pathogen_id
                    FROM isolates i
                    LEFT JOIN submissions s ON i.submission_id = s.id
                    LEFT JOIN projects p ON s.project_id = p.id
                    WHERE i.id = %s
                """, (isolate['id'],))
                
                updated_isolate = cursor.fetchone()
                if updated_isolate:
                    send_to_elastic2(updated_isolate)
                    print(f"Updated isolate {isolate['id']} with seq_error sent to Elasticsearch")
    
    # After processing all isolates, check final status and update submission
    with get_db_cursor() as cursor:
        cursor.execute("""
            SELECT COUNT(*) as total,
                COUNT(*) FILTER (WHERE status = 'error') as validation_errors,
                COUNT(*) FILTER (WHERE status = 'validated') as validated_isolates
            FROM isolates 
            WHERE submission_id = %s
        """, (submission_id,))
        
        counts = cursor.fetchone()
        
        # Only set to 'validated' if ALL isolates are validated (all-or-nothing approach)
        if counts['validated_isolates'] == counts['total'] and counts['total'] > 0:
            final_status = 'validated'
        else:
            final_status = 'error'
        
        cursor.execute("""
            UPDATE submissions 
            SET status = %s, updated_at = NOW()
            WHERE id = %s
        """, (final_status, submission_id))
        
        print(f"Submission {submission_id} final status: {final_status}")
        print(f"Total isolates: {counts['total']}, Validation errors: {counts['validation_errors']}, Validated: {counts['validated_isolates']}")


def run_sync_job(job):
    """Handle synchronous jobs"""
    if job['job_type'] == 'test_counting':
        # Test job - count to 1000
        import random
        if random.random() < 0.3:  # 30% chance of failure
            raise Exception("Simulated random failure!")
        
        for i in range(1, 1001):
            if i % 200 == 0:
                print(f"Job {job['id']}: Counting... {i}")
            time.sleep(0.005)
    else:
        raise Exception(f"Unknown sync job type: {job['job_type']}")


async def run_async_job(job):
    """Handle asynchronous jobs"""
    if job['job_type'] == 'validate_sequences':
        await process_sequence_validation(job)
    else:
        raise Exception(f"Unknown async job type: {job['job_type']}")


# Main worker loop
while True:
    try:
        # Get next job
        job = get_next_job()
        
        if job:
            print(f"Got job {job['id']} ({job['job_type']}): {job['payload']}")
            
            try:
                # Handle different job types
                if job['job_type'] == 'validate_sequences':
                    # Async job - need event loop
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    try:
                        loop.run_until_complete(run_async_job(job))
                    finally:
                        loop.close()
                else:
                    # Sync job
                    run_sync_job(job)
                
                # Mark as done
                mark_job_done(job['id'])
                print(f"Job {job['id']} completed successfully!")
                
            except Exception as e:
                print(f"Job {job['id']} failed: {e}")
                mark_job_failed(job['id'], str(e))
            
        else:
            print("No jobs found, waiting...")
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("Worker interrupted")
        break
    except Exception as e:
        print(f"Worker error: {e}")
        time.sleep(5)