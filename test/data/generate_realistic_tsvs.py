#!/usr/bin/env python3
"""
Script to create realistic TSV files from pathogen schemas based on working examples
"""
import json
import os
import random
from datetime import datetime, timedelta
from collections import defaultdict

def get_latest_schemas(file_path):
    """Extract latest version of each main pathogen schema"""
    with open(file_path, 'r') as f:
        data = json.load(f)
    
    schema_versions = defaultdict(list)
    
    for schema in data['resultSet']:
        name = schema['name']
        version = schema['version']
        schema_versions[name].append((version, schema))
    
    # Get latest version of main pathogen schemas
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

def generate_realistic_values(prop_name, prop_def, pathogen, sample_num):
    """Generate realistic values based on property definition and pathogen type"""
    
    # Handle enum values first
    if 'enum' in prop_def:
        if len(prop_def['enum']) > 1:
            # Choose different enum values for different samples
            return prop_def['enum'][sample_num % len(prop_def['enum'])]
        else:
            return prop_def['enum'][0]
    
    # Handle specific fields with realistic data
    if 'study_id' in prop_name.lower():
        study_prefixes = {
            'cholera': 'NICD',
            'malaria_vector': 'MVEC',
            'malaria_human': 'MHUM', 
            'sars_cov': 'COVID',
            'klebsiella': 'KLEB',
            'mpox': 'MPOX'
        }
        prefix = study_prefixes.get(pathogen, 'STUDY')
        return f"{prefix}-{2024+sample_num:02d}"
    
    elif 'case_id' in prop_name.lower() or 'isolate_id' in prop_name.lower():
        return f"{pathogen.upper()}-{sample_num+1:03d}"
    
    elif 'fasta_header_name' in prop_name.lower():
        return f">{pathogen}_{sample_num+1:03d}_sequence"
    
    elif 'fasta_file_name' in prop_name.lower():
        return f"{pathogen}_{sample_num+1:03d}.fasta"
    
    elif 'date' in prop_name.lower():
        base_date = datetime(2024, 1, 15)
        offset = timedelta(days=sample_num * 7)
        return (base_date + offset).strftime('%Y-%m-%d')
    
    elif 'specimen_collector_sample_id' in prop_name.lower():
        return f"SPEC-{pathogen.upper()}-{sample_num+1:03d}"
    
    elif 'geo_loc_name_country' in prop_name.lower():
        countries = ['South Africa', 'Nigeria', 'Kenya', 'Ghana', 'Uganda']
        return countries[sample_num % len(countries)]
    
    elif 'host_age' in prop_name.lower() or 'subject_age' in prop_name.lower():
        return str(25 + sample_num * 10)
    
    elif 'depth' in prop_name.lower():
        return str(50 + sample_num * 10)
    
    elif prop_name.lower() in ['n50', '%_gc', 'median_read_depth', 'sequencing_depth']:
        if 'n50' in prop_name.lower():
            return f"{2500000 + sample_num * 100000:,} bp"
        elif '%_gc' in prop_name.lower() or 'gc' in prop_name.lower():
            return f"{45 + sample_num}%"
        elif 'depth' in prop_name.lower():
            return f"{50 + sample_num * 20}x"
        else:
            return str(42 + sample_num)
    
    elif 'accession' in prop_name.lower():
        prefixes = ['CP', 'NZ_', 'SAMN', 'SRR']
        prefix = random.choice(prefixes)
        return f"{prefix}{100000 + sample_num * 1000}"
    
    # Handle data types
    elif prop_def.get('type') == 'string':
        if 'pattern' in prop_def:
            # Simple pattern handling
            if prop_name.lower() in ['biosample_accession', 'sra_accession']:
                return f"SAMN{1000000 + sample_num}"
            else:
                return f"{pathogen}_{prop_name}_{sample_num+1:03d}"
        else:
            return f"{pathogen}_{prop_name}_{sample_num+1:03d}"
    
    elif prop_def.get('type') in ['number', 'integer']:
        return str(42 + sample_num)
    
    elif prop_def.get('type') == 'boolean':
        return str(sample_num % 2 == 0).lower()
    
    else:
        return f"{pathogen}_{prop_name}_{sample_num+1:03d}"

def create_realistic_tsv_files(schema_name, properties, output_dir="tsv_files"):
    """Create 2 TSV files with 3 rows each for a schema using realistic data"""
    
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Extract pathogen name
    pathogen = schema_name.replace('_schema', '')
    
    # Get property names (columns)
    prop_names = list(properties.keys())
    
    # Generate 3 rows of realistic data
    rows = []
    for i in range(3):
        row = {}
        for prop_name, prop_def in properties.items():
            row[prop_name] = generate_realistic_values(prop_name, prop_def, pathogen, i)
        rows.append(row)
    
    # Create 2 TSV files
    for file_num in range(1, 3):
        filename = f"{pathogen}_{file_num}.tsv"
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
    output_dir = "/home/dimee/Work/OpenUp/SANBI/agari-folio/test/data/tsv_files"
    
    print("Extracting latest schemas...")
    latest_schemas = get_latest_schemas(schemas_file)
    
    print(f"\nGenerating realistic TSV files for {len(latest_schemas)} pathogen schemas")
    
    for schema_name, schema_data in latest_schemas.items():
        print(f"\nProcessing {schema_name}...")
        properties = extract_sample_properties(schema_data)
        print(f"  Found {len(properties)} sample properties")
        
        if properties:
            create_realistic_tsv_files(schema_name, properties, output_dir)
        else:
            print(f"  Warning: No sample properties found for {schema_name}")

if __name__ == "__main__":
    main()