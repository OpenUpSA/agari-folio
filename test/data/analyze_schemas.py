#!/usr/bin/env python3
"""
Script to analyze schemas.json and extract latest versions of each pathogen schema
"""
import json
from collections import defaultdict
from pprint import pprint

def analyze_schemas(file_path):
    """Analyze the schemas file and extract latest versions"""
    with open(file_path, 'r') as f:
        data = json.load(f)
    
    # Group schemas by name and find latest version
    schema_versions = defaultdict(list)
    
    for schema in data['resultSet']:
        name = schema['name']
        version = schema['version']
        schema_versions[name].append((version, schema))
    
    # Get latest version of each schema
    latest_schemas = {}
    for name, versions in schema_versions.items():
        # Sort by version number to get the highest
        latest_version = max(versions, key=lambda x: x[0])
        latest_schemas[name] = latest_version[1]
        print(f"{name}: latest version {latest_version[0]}")
    
    return latest_schemas

def extract_sample_properties(schema_data):
    """Extract sample properties from a schema"""
    try:
        # Look for samples array items properties
        schema = schema_data['schema']
        samples = schema['properties']['samples']['items']
        if 'properties' in samples:
            return samples['properties']
        else:
            return {}
    except KeyError as e:
        print(f"Could not extract sample properties: {e}")
        return {}

if __name__ == "__main__":
    schemas_file = "/home/dimee/Work/OpenUp/SANBI/agari-folio/test/data/schemas.json"
    
    print("Analyzing schemas...")
    latest_schemas = analyze_schemas(schemas_file)
    
    print("\nLatest schema versions:")
    for name, schema in latest_schemas.items():
        print(f"\n{name} (v{schema['version']}):")
        props = extract_sample_properties(schema)
        print(f"  Sample properties count: {len(props)}")
        if props:
            print("  Sample properties (first 5):")
            for i, prop_name in enumerate(list(props.keys())[:5]):
                print(f"    - {prop_name}")