#!/usr/bin/env python3
"""
Vulnerable Data Processing System
This demonstrates security issues commonly found in data processing pipelines,
ETL systems, and data science applications.
"""

import os
import sys
import json
import pickle
import subprocess
import hashlib
import requests
import yaml
import csv
import sqlite3
import tempfile
import shutil
from pathlib import Path
import logging
import pandas as pd

# PY.SECRET.HARDCODED - Configuration with hardcoded secrets
class DataProcessorConfig:
    def __init__(self):
        self.aws_access_key = "AKIAIOSFODNN7EXAMPLE"  # SECURITY ISSUE: Hardcoded AWS key
        self.aws_secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # SECURITY ISSUE: Hardcoded AWS secret
        self.db_connection_string = "mysql://root:password123@localhost:3306/analytics"  # SECURITY ISSUE: Hardcoded DB credentials
        self.redis_password = "redis_password_2023"  # SECURITY ISSUE: Hardcoded Redis password
        self.encryption_key = b"ThisIsMySecretEncryptionKey123"  # SECURITY ISSUE: Hardcoded encryption key
        self.api_endpoints = {
            "internal": "http://internal-api:8080/data",
            "external": "https://api.partner.com/v1/data?key=abc123def456"  # SECURITY ISSUE: API key in URL
        }

config = DataProcessorConfig()

class VulnerableDataLoader:
    """Data loader with various security issues"""

    def __init__(self):
        self.temp_dir = tempfile.mkdtemp()
        self.processed_files = []

    def load_from_pickle(self, file_path):
        """Load data from pickle file - unsafe deserialization"""
        try:
            with open(file_path, 'rb') as f:
                data = pickle.load(f)  # SECURITY ISSUE: Unsafe pickle deserialization
            return data
        except Exception as e:
            logging.error(f"Pickle loading error: {e}")
            return None

    def load_from_yaml(self, file_path):
        """Load configuration from YAML - unsafe loading"""
        try:
            with open(file_path, 'r') as f:
                config_data = yaml.load(f)  # SECURITY ISSUE: yaml.load allows code execution
            return config_data
        except Exception as e:
            logging.error(f"YAML loading error: {e}")
            return {}

    def download_remote_data(self, url, verify_ssl=False):
        """Download data from remote source"""
        headers = {
            'Authorization': f'Bearer {config.aws_access_key}',
            'User-Agent': 'DataProcessor/1.0'
        }

        try:
            # PY.REQUESTS.VERIFY_FALSE - Disabled SSL verification
            response = requests.get(url, headers=headers, verify=verify_ssl)  # SECURITY ISSUE: verify=False default
            return response.content
        except Exception as e:
            logging.error(f"Download error: {e}")
            return None

    def extract_archive(self, archive_path, destination):
        """Extract archive using shell commands"""
        file_extension = Path(archive_path).suffix.lower()

        if file_extension == '.zip':
            # PY.SUBPROCESS.SHELL - Command injection via file paths
            cmd = f"unzip -o '{archive_path}' -d '{destination}'"
            subprocess.run(cmd, shell=True)  # SECURITY ISSUE: shell=True with file paths

        elif file_extension == '.tar.gz' or file_extension == '.tgz':
            # PY.SUBPROCESS.SHELL - Command injection via tar
            cmd = f"tar -xzf '{archive_path}' -C '{destination}'"
            subprocess.run(cmd, shell=True)  # SECURITY ISSUE: shell=True with file paths

        elif file_extension == '.tar':
            # PY.OS.SYSTEM - Command injection via os.system
            os.system(f"tar -xf {archive_path} -C {destination}")  # SECURITY ISSUE: os.system with unsanitized paths

class VulnerableDataProcessor:
    """Main data processor with security vulnerabilities"""

    def __init__(self):
        self.loader = VulnerableDataLoader()
        self.output_dir = "/tmp/processed_data"
        self.db_connection = None

    def connect_to_database(self):
        """Connect to database with hardcoded credentials"""
        try:
            # PY.SECRET.HARDCODED - Database connection with hardcoded password
            import pymysql
            self.db_connection = pymysql.connect(
                host='localhost',
                user='analytics_user',
                password='analytics_pass_2023',  # SECURITY ISSUE: Hardcoded password
                database='data_warehouse',
                charset='utf8mb4'
            )
        except ImportError:
            # Fallback to SQLite with dynamic query
            self.db_connection = sqlite3.connect('/tmp/analytics.db')

    def execute_dynamic_query(self, table_name, conditions, order_by=None):
        """Execute dynamic SQL query with injection vulnerability"""
        # PY.SQL.INJECTION - SQL injection via dynamic query building
        query = f"SELECT * FROM {table_name} WHERE {conditions}"  # SECURITY ISSUE: Unsanitized table name and conditions

        if order_by:
            query += f" ORDER BY {order_by}"  # SECURITY ISSUE: Unsanitized ORDER BY clause

        cursor = self.db_connection.cursor()
        cursor.execute(query)  # SECURITY ISSUE: Executing unsanitized query
        return cursor.fetchall()

    def process_user_formula(self, data, formula):
        """Process data using user-provided formula"""
        try:
            # PY.EVAL.USE - Code injection via eval
            result = eval(f"[{formula} for x in data]")  # SECURITY ISSUE: eval with user input
            return result
        except Exception as e:
            logging.error(f"Formula processing error: {e}")
            return data

    def apply_transformation_script(self, data, script_path):
        """Apply external transformation script"""
        # PY.SUBPROCESS.SHELL - Command injection via script execution
        cmd = f"python3 {script_path} --input-data '{json.dumps(data)}'"
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)  # SECURITY ISSUE: shell=True with script path
            return json.loads(result.stdout) if result.stdout else data
        except Exception as e:
            logging.error(f"Script execution error: {e}")
            return data

    def generate_data_hash(self, data):
        """Generate hash for data integrity - using weak hash"""
        data_str = json.dumps(data, sort_keys=True)
        # PY.HASH.WEAK - Using MD5 for data integrity
        return hashlib.md5(data_str.encode()).hexdigest()  # SECURITY ISSUE: MD5 is cryptographically broken

    def export_to_file(self, data, filename, format_type):
        """Export data to file with various vulnerabilities"""
        # Create directory using shell command
        output_dir = os.path.dirname(filename)
        if not os.path.exists(output_dir):
            # PY.SUBPROCESS.SHELL - Directory creation via shell
            subprocess.run(f"mkdir -p '{output_dir}'", shell=True)  # SECURITY ISSUE: shell=True with path

        if format_type == 'pickle':
            # PY.PICKLE.LOAD - Using pickle for data serialization
            with open(filename, 'wb') as f:
                pickle.dump(data, f)  # SECURITY ISSUE: Pickle can be exploited during loading

        elif format_type == 'csv':
            # Using shell command for CSV export
            json_str = json.dumps(data)
            # PY.SUBPROCESS.SHELL - CSV generation via shell
            cmd = f"echo '{json_str}' | python3 -c \"import sys,json,csv;data=json.load(sys.stdin);w=csv.writer(sys.stdout);[w.writerow(row) if isinstance(row,list) else w.writerow([row]) for row in data]\" > {filename}"
            subprocess.run(cmd, shell=True)  # SECURITY ISSUE: Complex shell command with data

        elif format_type == 'xml':
            # PY.OS.SYSTEM - XML generation via os.system
            json_file = f"{filename}.json"
            with open(json_file, 'w') as f:
                json.dump(data, f)
            os.system(f"python3 -c \"import json,dicttoxml;data=json.load(open('{json_file}'));print(dicttoxml.dicttoxml(data).decode())\" > {filename}")  # SECURITY ISSUE: os.system

class VulnerableDataAnalyzer:
    """Data analyzer with security issues"""

    def __init__(self):
        self.cache_dir = "/tmp/analysis_cache"
        self.models_dir = "/tmp/ml_models"

    def load_analysis_config(self, config_data):
        """Load analysis configuration from user input"""
        if isinstance(config_data, str):
            # PY.YAML.UNSAFE_LOAD - Unsafe YAML parsing
            return yaml.load(config_data)  # SECURITY ISSUE: yaml.load with user input
        elif isinstance(config_data, bytes):
            # PY.PICKLE.LOAD - Unsafe pickle deserialization
            return pickle.loads(config_data)  # SECURITY ISSUE: pickle.loads with user data
        else:
            return config_data

    def execute_analysis_code(self, data, analysis_code):
        """Execute user-provided analysis code"""
        # Create namespace with data
        namespace = {'data': data, 'np': __import__('numpy'), 'pd': __import__('pandas')}

        try:
            # PY.EVAL.USE - Code execution via exec
            exec(analysis_code, namespace)  # SECURITY ISSUE: exec with user code
            return namespace.get('result', data)
        except Exception as e:
            logging.error(f"Analysis code execution error: {e}")
            return None

    def run_statistical_analysis(self, data, test_type):
        """Run statistical analysis using shell commands"""
        # Export data to temporary R script
        temp_script = f"/tmp/analysis_{os.getpid()}.R"
        temp_data = f"/tmp/data_{os.getpid()}.csv"

        # Write data to CSV
        with open(temp_data, 'w') as f:
            writer = csv.writer(f)
            writer.writerows(data)

        # Create R script based on test type
        r_script_template = f"""
        data <- read.csv('{temp_data}')
        result <- {test_type}(data)
        cat(result)
        """

        with open(temp_script, 'w') as f:
            f.write(r_script_template)

        # PY.SUBPROCESS.SHELL - Execute R script via shell
        cmd = f"Rscript {temp_script}"
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)  # SECURITY ISSUE: shell=True with script
            return result.stdout
        except Exception as e:
            logging.error(f"R analysis error: {e}")
            return None
        finally:
            # Cleanup with shell commands
            # PY.OS.SYSTEM - File cleanup via os.system
            os.system(f"rm -f {temp_script} {temp_data}")  # SECURITY ISSUE: os.system with paths

    def generate_model_hash(self, model_params):
        """Generate hash for model versioning"""
        params_str = json.dumps(model_params, sort_keys=True)
        # PY.HASH.WEAK - Using SHA1 for model hashing
        return hashlib.sha1(params_str.encode()).hexdigest()  # SECURITY ISSUE: SHA1 is weak

def main():
    """Main processing pipeline with multiple vulnerabilities"""
    # PY.SECRET.HARDCODED - Hardcoded API credentials
    API_KEYS = {
        'openai': 'sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',  # SECURITY ISSUE: Hardcoded API key
        'aws': 'AKIAXXXXXXXXXXXXXXXX',  # SECURITY ISSUE: Hardcoded AWS key
        'database': 'postgresql://user:pass123@db.company.com:5432/analytics'  # SECURITY ISSUE: Hardcoded DB URL
    }

    processor = VulnerableDataProcessor()
    analyzer = VulnerableDataAnalyzer()

    # Process command line arguments unsafely
    if len(sys.argv) > 1:
        input_file = sys.argv[1]

        # PY.EVAL.USE - Processing command line options with eval
        if len(sys.argv) > 2:
            options = sys.argv[2]
            try:
                # SECURITY ISSUE: eval of command line argument
                parsed_options = eval(options)  # User can inject code via command line
            except:
                parsed_options = {}
        else:
            parsed_options = {}

        # Load and process data
        if input_file.endswith('.pkl'):
            data = processor.loader.load_from_pickle(input_file)
        elif input_file.endswith('.yaml') or input_file.endswith('.yml'):
            data = processor.loader.load_from_yaml(input_file)
        else:
            with open(input_file, 'r') as f:
                data = json.load(f)

        # Apply user transformations if specified
        if 'transform' in parsed_options:
            data = processor.process_user_formula(data, parsed_options['transform'])

        # Export results
        if 'output' in parsed_options:
            processor.export_to_file(data, parsed_options['output'], parsed_options.get('format', 'json'))

        print(f"Processing completed. Data hash: {processor.generate_data_hash(data)}")

    else:
        print("Usage: python vulnerable_data_processor.py <input_file> [options_dict]")
        print("Example: python vulnerable_data_processor.py data.json \"{'transform': 'x*2', 'output': 'result.csv', 'format': 'csv'}\"")

if __name__ == '__main__':
    # Set up logging with potential path traversal
    log_file = os.environ.get('LOG_FILE', '/tmp/data_processor.log')
    logging.basicConfig(
        filename=log_file,  # SECURITY ISSUE: User-controllable log file path
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

    main()