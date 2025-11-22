#!/usr/bin/env python3

import argparse
import requests
import sys
from typing import Optional

def reindex_batches(folio_url: str, token: str, batch_size: int = 50, initial_offset: int = 0) -> None:
    """
    Reindex samples in batches until completion.
    
    Args:
        folio_url: Base URL for the folio service
        token: Bearer token for authorization
        batch_size: Number of items to process per batch
        initial_offset: Starting offset (default: 0)
    """
    headers = {
        "Authorization": f"Bearer {token}"
    }
    
    offset = initial_offset
    total_processed = 0
    
    print(f"Starting reindex with batch_size={batch_size}, offset={offset}")
    print("-" * 60)
    
    while True:
        url = f"{folio_url}/search/reindex?batch_size={batch_size}&offset={offset}"
        
        try:
            response = requests.post(url, headers=headers)
            response.raise_for_status()
            
            data = response.json()
            
            # Display progress
            message = data.get("message", "")
            processed = data.get("processed", 0)
            reindexed = data.get("reindexed", 0)
            progress = data.get("progress", {})
            has_more = data.get("has_more", False)
            
            total_processed += processed
            
            print(f"Offset {offset}: {message}")
            print(f"  Processed: {processed}, Reindexed: {reindexed}")
            print(f"  Progress: {progress.get('completed', 0)}/{progress.get('total', 0)} ({progress.get('percent', 0):.2f}%)")
            print("-" * 60)
            
            if not has_more:
                print(f"\n✓ Reindexing complete! Total processed: {total_processed}")
                break
            
            # Update offset for next batch
            offset = progress.get("next_offset", offset + batch_size)
            
        except requests.exceptions.RequestException as e:
            print(f"✗ Error during reindex at offset {offset}: {e}", file=sys.stderr)
            sys.exit(1)
        except KeyError as e:
            print(f"✗ Unexpected response format at offset {offset}: {e}", file=sys.stderr)
            sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description="Reindex samples in batches from folio service"
    )
    parser.add_argument(
        "--token",
        required=True,
        help="Bearer token for authorization"
    )
    parser.add_argument(
        "--folio-url",
        default="http://localhost:8000",
        help="Base URL for folio service (default: http://localhost:8000)"
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=50,
        help="Number of items to process per batch (default: 50)"
    )
    parser.add_argument(
        "--offset",
        type=int,
        default=0,
        help="Starting offset (default: 0)"
    )
    
    args = parser.parse_args()
    
    reindex_batches(
        folio_url=args.folio_url.rstrip("/"),
        token=args.token,
        batch_size=args.batch_size,
        initial_offset=args.offset
    )

if __name__ == "__main__":
    main()