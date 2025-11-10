#!/usr/bin/env python3
"""
Script to create TSV files from pathogen schemas
"""
import json
import os
from collections import defaultdict

def get_latest_schemas(file_path):
    """Extract latest version of each main pathogen schema"""
    with open(file_path, 'r') as f:
        data = json.load(f)
    
    # Group schemas by name and find latest version
    schema_versions = defaultdict(list)
    
    for schema in data['resultSet']:
        name = schema['name']
        version = schema['version']
        schema_versions[name].append((version, schema))
    
    # Get latest version of main pathogen schemas (exclude test schemas)
    main_pathogens = [
        'malaria_vector_schema', 'malaria_human_schema', 'sars_cov_schema',
        'klebsiella_schema', 'cholera_schema', 'mpox_schema'
    ]
    
    latest_schemas = {}
    for name in main_pathogens:
        if name in schema_versions:
            latest_version = max(schema_versions[name], key=lambda x: x[0])
            latest_schemas[name] = latest_version[1]
    
    return latest_schemas

def extract_sample_properties(schema_data):
    """Extract sample properties from a schema"""
    try:
        schema = schema_data['schema']
        samples = schema['properties']['samples']['items']
        return samples.get('properties', {})
    except KeyError:
        return {}

def generate_dummy_values(prop_name, prop_def):
    """Generate dummy values based on property definition"""
    if 'enum' in prop_def:
        return prop_def['enum'][0]  # Use first enum value
    elif prop_def.get('type') == 'string':
        if 'pattern' in prop_def:
            # Handle specific patterns
            if prop_name == 'case_id' or prop_name == 'isolate_id':
                return f"SAMPLE_{prop_name.upper()}_001"
            elif prop_name == 'study_id':
                return "STUDY001"
            elif 'date' in prop_name.lower():
                return "2024-01-15"
            else:
                return f"dummy_{prop_name}"
        else:
            return f"dummy_{prop_name}"
    elif prop_def.get('type') == 'number' or prop_def.get('type') == 'integer':
        return 42
    elif prop_def.get('type') == 'boolean':
        return True
    else:
        return f"dummy_{prop_name}"

def create_tsv_files(schema_name, properties, output_dir="tsv_files"):
    """Create 2 TSV files with 3 rows each for a schema"""
    
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Get property names (columns)
    prop_names = list(properties.keys())
    
    # Generate 3 rows of dummy data
    rows = []
    for i in range(3):
        row = {}
        for prop_name, prop_def in properties.items():
            if i == 0:
                row[prop_name] = generate_dummy_values(prop_name, prop_def)
            else:
                # Vary the values slightly for different rows
                base_value = generate_dummy_values(prop_name, prop_def)
                if isinstance(base_value, str) and not base_value.startswith("dummy_"):
                    if "SAMPLE" in base_value:
                        row[prop_name] = base_value.replace("001", f"00{i+1}")
                    elif "STUDY" in base_value:
                        row[prop_name] = base_value.replace("001", f"00{i+1}")
                    elif base_value == "2024-01-15":
                        row[prop_name] = f"2024-01-{15+i}"
                    else:
                        row[prop_name] = f"{base_value}_{i+1}"
                elif isinstance(base_value, (int, float)):
                    row[prop_name] = base_value + i
                else:
                    row[prop_name] = f"{base_value}_{i+1}"
        rows.append(row)
    
    # Create 2 TSV files
    for file_num in range(1, 3):
        filename = f"{schema_name.replace('_schema', '')}_{file_num}.tsv"
        filepath = os.path.join(output_dir, filename)
        
        with open(filepath, 'w') as f:
            # Write header
            f.write('\t'.join(prop_names) + '\n')
            
            # Write data rows
            for row in rows:
                values = [str(row[prop_name]) for prop_name in prop_names]
                f.write('\t'.join(values) + '\n')
        
        print(f"Created {filepath} with {len(prop_names)} columns and {len(rows)} data rows")

def main():
    schemas_file = "/home/dimee/Work/OpenUp/SANBI/agari-folio/test/data/schemas.json"
    
    print("Extracting latest schemas...")
    latest_schemas = get_latest_schemas(schemas_file)
    
    print(f"\nFound {len(latest_schemas)} pathogen schemas")
    
    for schema_name, schema_data in latest_schemas.items():
        print(f"\nProcessing {schema_name}...")
        properties = extract_sample_properties(schema_data)
        print(f"  Found {len(properties)} sample properties")
        
        if properties:
            create_tsv_files(schema_name, properties)
        else:
            print(f"  Warning: No sample properties found for {schema_name}")

if __name__ == "__main__":
    main()