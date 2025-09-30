#!/usr/bin/env python3
"""
Vulnerable Web Application Demo - Realistic security issues
This simulates a Flask web application with various security vulnerabilities
that might be found in real-world applications.
"""

import os
import sqlite3
import subprocess
import pickle
import hashlib
import requests
import yaml
import json
from flask import Flask, request, render_template_string, redirect, session
from werkzeug.utils import secure_filename
import logging
import tempfile

app = Flask(__name__)

# PY.SECRET.HARDCODED - Multiple hardcoded secrets
app.secret_key = "super_secret_key_12345"  # SECURITY ISSUE: Hardcoded secret key
DATABASE_URL = "postgresql://admin:password123@localhost/mydb"  # SECURITY ISSUE: Hardcoded DB credentials
API_TOKEN = "sk-1234567890abcdef1234567890abcdef"  # SECURITY ISSUE: Hardcoded API token
JWT_SECRET = "my-jwt-secret-key"  # SECURITY ISSUE: Hardcoded JWT secret

# Global configuration with hardcoded values
CONFIG = {
    "db_password": "admin123",  # SECURITY ISSUE: Hardcoded password
    "encryption_key": "my_encryption_key_2023",  # SECURITY ISSUE: Hardcoded encryption key
    "third_party_api_key": "AIzaSyBk9qNX8F7xH3vC2pW1mR5nT8jK9lP0qZ4"  # SECURITY ISSUE: Hardcoded API key
}

# PY.HASH.WEAK - Weak cryptographic functions
def hash_user_password(password):
    """Hash user password with weak algorithm"""
    return hashlib.md5(password.encode()).hexdigest()  # SECURITY ISSUE: MD5 is cryptographically broken

def generate_session_token(user_id):
    """Generate session token with weak hash"""
    data = f"{user_id}:{app.secret_key}"
    return hashlib.sha1(data.encode()).hexdigest()  # SECURITY ISSUE: SHA1 is weak for security

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')

    # PY.SQL.INJECTION - SQL injection vulnerability
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{hash_user_password(password)}'"  # SECURITY ISSUE: SQL injection
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(query)  # SECURITY ISSUE: Executing unsanitized query
    user = cursor.fetchone()

    if user:
        session['user_id'] = user[0]
        return redirect('/dashboard')
    else:
        return "Invalid credentials"

@app.route('/search')
def search():
    """Search functionality with multiple vulnerabilities"""
    query = request.args.get('q', '')

    # PY.EVAL.USE - Code injection via eval
    if query.startswith('calc:'):
        try:
            result = eval(query[5:])  # SECURITY ISSUE: Direct eval of user input
            return f"Calculation result: {result}"
        except:
            return "Invalid calculation"

    # PY.SUBPROCESS.SHELL - Command injection
    search_cmd = f"grep -r '{query}' /var/log/app/"  # SECURITY ISSUE: Unsanitized input in shell command
    try:
        result = subprocess.run(search_cmd, shell=True, capture_output=True, text=True)  # SECURITY ISSUE: shell=True with user input
        return f"Search results: {result.stdout}"
    except Exception as e:
        return f"Search error: {e}"

@app.route('/file_ops')
def file_operations():
    """File operations with command injection"""
    filename = request.args.get('file', '')
    action = request.args.get('action', '')

    # PY.OS.SYSTEM - Command injection via os.system
    if action == 'delete':
        os.system(f"rm -f /uploads/{filename}")  # SECURITY ISSUE: Command injection via os.system
    elif action == 'backup':
        os.system(f"cp /uploads/{filename} /backups/")  # SECURITY ISSUE: Command injection
    elif action == 'permissions':
        subprocess.call(f"chmod 644 /uploads/{filename}", shell=True)  # SECURITY ISSUE: shell=True with user input

    return "File operation completed"

@app.route('/config', methods=['POST'])
def update_config():
    """Configuration update with unsafe deserialization"""
    config_data = request.files.get('config')

    if config_data:
        # PY.YAML.UNSAFE_LOAD - Unsafe YAML loading
        if config_data.filename.endswith('.yaml') or config_data.filename.endswith('.yml'):
            config = yaml.load(config_data.read())  # SECURITY ISSUE: yaml.load allows code execution

        # PY.PICKLE.LOAD - Unsafe pickle deserialization
        elif config_data.filename.endswith('.pkl'):
            config = pickle.loads(config_data.read())  # SECURITY ISSUE: pickle.loads allows code execution

        # Update application config
        CONFIG.update(config)
        return "Configuration updated successfully"

    return "No configuration file provided"

@app.route('/api/data')
def api_proxy():
    """API proxy with SSL verification disabled"""
    target_url = request.args.get('url')
    headers = {'Authorization': f'Bearer {API_TOKEN}'}

    # PY.REQUESTS.VERIFY_FALSE - Disabled SSL verification
    try:
        response = requests.get(target_url, headers=headers, verify=False, timeout=30)  # SECURITY ISSUE: verify=False
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}

@app.route('/template')
def render_user_template():
    """Template rendering with injection vulnerability"""
    template_content = request.args.get('template', 'Hello {{name}}!')
    user_name = request.args.get('name', 'User')

    # SECURITY ISSUE: Server-Side Template Injection (SSTI)
    # This would be caught by a more advanced rule
    return render_template_string(template_content, name=user_name)

@app.route('/export')
def export_data():
    """Data export functionality with multiple issues"""
    format_type = request.args.get('format', 'json')
    table_name = request.args.get('table', 'users')

    # PY.SQL.INJECTION - SQL injection in table name
    query = f"SELECT * FROM {table_name} LIMIT 100"  # SECURITY ISSUE: Table name not sanitized

    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute(query)  # SECURITY ISSUE: Executing unsanitized query
    rows = cursor.fetchall()

    if format_type == 'csv':
        # PY.SUBPROCESS.SHELL - Using shell for CSV generation
        csv_cmd = f"echo '{json.dumps(rows)}' | python3 -c \"import sys,json,csv; data=json.load(sys.stdin); w=csv.writer(sys.stdout); [w.writerow(row) for row in data]\""
        result = subprocess.run(csv_cmd, shell=True, capture_output=True, text=True)  # SECURITY ISSUE: Complex shell command
        return result.stdout

    return json.dumps(rows)

@app.route('/upload', methods=['POST'])
def upload_file():
    """File upload with path traversal vulnerability"""
    if 'file' not in request.files:
        return "No file provided"

    file = request.files['file']
    if file.filename == '':
        return "No file selected"

    # SECURITY ISSUE: Path traversal - not using secure_filename properly
    filename = request.form.get('filename', file.filename)  # User can specify any filename
    upload_path = f"/uploads/{filename}"  # SECURITY ISSUE: No path sanitization

    # Create directory if it doesn't exist using shell command
    dir_path = os.path.dirname(upload_path)
    subprocess.run(f"mkdir -p {dir_path}", shell=True)  # SECURITY ISSUE: shell=True with path

    file.save(upload_path)
    return f"File uploaded to {upload_path}"

@app.route('/logs')
def view_logs():
    """Log viewer with command injection"""
    log_type = request.args.get('type', 'app')
    lines = request.args.get('lines', '100')

    # PY.SUBPROCESS.SHELL - Command injection via log viewing
    log_cmd = f"tail -{lines} /var/log/{log_type}.log"  # SECURITY ISSUE: Unsanitized parameters
    try:
        result = subprocess.run(log_cmd, shell=True, capture_output=True, text=True)  # SECURITY ISSUE: shell=True
        return f"<pre>{result.stdout}</pre>"
    except Exception as e:
        return f"Error reading logs: {e}"

# Helper functions with additional vulnerabilities

def create_user_session(user_data):
    """Create user session with weak randomness"""
    import random
    session_id = str(random.randint(100000, 999999))  # SECURITY ISSUE: Weak randomness for session ID

    # Store session with pickle (vulnerable to deserialization attacks)
    session_file = f"/tmp/session_{session_id}.pkl"
    with open(session_file, 'wb') as f:
        pickle.dump(user_data, f)  # SECURITY ISSUE: Storing sensitive data in pickle

    return session_id

def validate_user_input(user_input):
    """Input validation with dangerous eval"""
    # PY.EVAL.USE - Using eval for input validation
    validation_rules = request.form.get('rules', 'len(input) > 0')
    try:
        # SECURITY ISSUE: eval with user-controlled validation rules
        is_valid = eval(validation_rules.replace('input', repr(user_input)))
        return bool(is_valid)
    except:
        return False

def process_data_transformation(data, transform_code):
    """Data transformation with code execution"""
    try:
        # PY.EVAL.USE - Code injection via data transformation
        transformed = eval(f"[{transform_code} for item in data]")  # SECURITY ISSUE: eval with user code
        return transformed
    except Exception as e:
        logging.error(f"Transformation error: {e}")
        return data

def backup_database():
    """Database backup with hardcoded credentials"""
    # PY.SECRET.HARDCODED - Hardcoded database credentials
    backup_cmd = f"pg_dump -h localhost -U admin -p 5432 myapp_db > backup.sql"

    # Set password via environment (but hardcoded)
    env = os.environ.copy()
    env['PGPASSWORD'] = 'admin_password_2023'  # SECURITY ISSUE: Hardcoded password

    # PY.SUBPROCESS.SHELL - Shell command execution
    subprocess.run(backup_cmd, shell=True, env=env)  # SECURITY ISSUE: shell=True

def generate_report(report_type, params):
    """Report generation with multiple vulnerabilities"""
    # PY.YAML.UNSAFE_LOAD - Loading user-provided configuration
    if 'config' in params:
        config = yaml.load(params['config'])  # SECURITY ISSUE: unsafe yaml.load
    else:
        config = {}

    # PY.SQL.INJECTION - Dynamic query building
    table_filter = params.get('filter', '1=1')
    query = f"SELECT * FROM reports WHERE type='{report_type}' AND {table_filter}"

    # PY.HASH.WEAK - Weak hash for report ID
    report_id = hashlib.md5(f"{report_type}:{str(params)}".encode()).hexdigest()

    return {
        'report_id': report_id,
        'query': query,
        'config': config
    }

if __name__ == '__main__':
    # PY.SECRET.HARDCODED - Debug mode should never be enabled in production
    app.run(debug=True, host='0.0.0.0', port=5000)  # SECURITY ISSUE: Debug mode enabled