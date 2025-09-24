#!/usr/bin/env python3
"""
Example file showing secure coding practices - should have no security warnings
"""

import os
import subprocess
import json
import yaml
import hashlib
import requests
import shlex
import ast
import secrets
from pathlib import Path

# SECURE: Use ast.literal_eval instead of eval
def process_user_formula(formula):
    """Secure: Only evaluates literals, not arbitrary code"""
    try:
        # Only allows literals like numbers, strings, lists, dicts
        return ast.literal_eval(formula)
    except (ValueError, SyntaxError):
        raise ValueError("Invalid formula format")

# SECURE: Use subprocess with list arguments
def list_directory(dirname):
    """Secure: No shell injection possible with list arguments"""
    # Validate input first
    path = Path(dirname)
    if not path.exists():
        raise ValueError("Directory does not exist")

    # Use list arguments - no shell interpretation
    result = subprocess.run(["ls", "-la", str(path)], capture_output=True, text=True)
    return result.stdout

def backup_file(filename):
    """Secure: Use list arguments and validate input"""
    source_path = Path(filename)
    if not source_path.exists():
        raise ValueError("Source file does not exist")

    backup_path = source_path.with_suffix(source_path.suffix + '.bak')
    subprocess.run(["cp", str(source_path), str(backup_path)], check=True)

# SECURE: Use subprocess instead of os.system
def remove_temp_files(pattern):
    """Secure: Use pathlib and specific file operations"""
    temp_dir = Path("/tmp")
    if not temp_dir.exists():
        return

    # Use pathlib glob for safe pattern matching
    for file_path in temp_dir.glob(pattern):
        if file_path.is_file():
            file_path.unlink()

def compress_logs(logdir):
    """Secure: Use subprocess with list arguments"""
    log_path = Path(logdir)
    if not log_path.exists():
        raise ValueError("Log directory does not exist")

    subprocess.run([
        "tar", "-czf", "logs.tar.gz",
        "-C", str(log_path.parent),
        log_path.name
    ], check=True)

# SECURE: Use safe YAML loading
def load_user_config(config_data):
    """Secure: Use yaml.safe_load to prevent code execution"""
    try:
        return yaml.safe_load(config_data)
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML format: {e}")

def parse_yaml_file(filename):
    """Secure: Use safe_load with proper error handling"""
    file_path = Path(filename)
    if not file_path.exists():
        raise ValueError("Config file does not exist")

    with open(file_path) as f:
        try:
            return yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML in {filename}: {e}")

# SECURE: Use JSON instead of pickle for untrusted data
def deserialize_data(json_data):
    """Secure: JSON deserialization is safe"""
    try:
        return json.loads(json_data)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON format: {e}")

def load_cache_file(filename):
    """Secure: Use JSON for data persistence"""
    file_path = Path(filename)
    if not file_path.exists():
        raise ValueError("Cache file does not exist")

    with open(file_path) as f:
        try:
            return json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in cache file: {e}")

# SECURE: Use strong cryptographic algorithms
def hash_user_password(password, salt=None):
    """Secure: Use SHA-256 with salt for password hashing"""
    if salt is None:
        salt = secrets.token_hex(16)

    # In production, use a proper password hashing library like bcrypt
    password_hash = hashlib.sha256((password + salt).encode()).hexdigest()
    return f"{salt}:{password_hash}"

def create_session_token(user_id):
    """Secure: Use cryptographically secure random tokens"""
    # Generate a secure random token
    token_data = f"{user_id}:{secrets.token_hex(32)}"
    return hashlib.sha256(token_data.encode()).hexdigest()

# SECURE: Use proper SSL verification
def fetch_api_data(url):
    """Secure: SSL verification enabled by default"""
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        raise ValueError(f"API request failed: {e}")

def post_user_data(url, data):
    """Secure: POST with proper SSL verification and error handling"""
    try:
        response = requests.post(url, json=data, timeout=30)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        raise ValueError(f"API request failed: {e}")

# SECURE: Load secrets from environment variables
API_SECRET = os.environ.get("API_SECRET")
DATABASE_PASSWORD = os.environ.get("DATABASE_PASSWORD")
JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY")

# Check that required secrets are available
def validate_environment():
    """Ensure all required environment variables are set"""
    required_vars = ["API_SECRET", "DATABASE_PASSWORD", "JWT_SECRET_KEY"]
    missing_vars = [var for var in required_vars if not os.environ.get(var)]

    if missing_vars:
        raise ValueError(f"Missing environment variables: {', '.join(missing_vars)}")

# SECURE: Use parameterized queries (example)
def get_user_by_id(user_id, cursor):
    """Secure: Use parameterized query to prevent SQL injection"""
    query = "SELECT * FROM users WHERE id = %s"
    cursor.execute(query, (user_id,))
    return cursor.fetchone()

def search_users(search_term, cursor):
    """Secure: Use parameterized query with LIKE"""
    query = "SELECT * FROM users WHERE name LIKE %s"
    cursor.execute(query, (f"%{search_term}%",))
    return cursor.fetchall()

# SECURE: Safe file processing
def process_upload(file_data):
    """Secure file processing with proper validation"""
    # Validate file size
    if len(file_data) > 10 * 1024 * 1024:  # 10MB limit
        raise ValueError("File too large")

    # Generate secure temporary filename
    temp_name = secrets.token_hex(16)
    temp_file = Path("/tmp") / f"upload_{temp_name}"

    # Use JSON for data exchange instead of pickle
    try:
        data = json.loads(file_data.decode('utf-8'))
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise ValueError("Invalid file format")

    # Use secure hash for file integrity
    checksum = hashlib.sha256(file_data).hexdigest()

    # Safe file type detection
    result = subprocess.run(
        ["file", "--mime-type", str(temp_file)],
        capture_output=True,
        text=True
    )

    return data, checksum, result.stdout.strip()

def main():
    """Secure main function"""
    try:
        # Validate environment first
        validate_environment()

        # Safe user input processing
        user_input = input("Enter formula (literals only): ")
        try:
            result = process_user_formula(user_input)
            print(f"Result: {result}")
        except ValueError as e:
            print(f"Error: {e}")

        directory = input("Enter directory: ")
        try:
            listing = list_directory(directory)
            print(listing)
        except ValueError as e:
            print(f"Error: {e}")

        config_data = input("Enter YAML config: ")
        try:
            config = load_user_config(config_data)
            print(f"Config loaded: {config}")
        except ValueError as e:
            print(f"Error: {e}")

        password = input("Enter password: ")
        hashed = hash_user_password(password)
        print(f"Password hashed: {hashed[:20]}...")

        url = input("Enter API URL: ")
        try:
            api_data = fetch_api_data(url)
            print(f"API data: {api_data}")
        except ValueError as e:
            print(f"Error: {e}")

    except KeyboardInterrupt:
        print("\nExiting...")
    except Exception as e:
        print(f"Unexpected error: {e}")

if __name__ == "__main__":
    main()