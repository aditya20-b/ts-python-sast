#!/usr/bin/env python3
"""
Example file with various security vulnerabilities for testing ts-sast
"""

import os
import subprocess
import pickle
import yaml
import hashlib
import requests
from flask import request

# PY.EVAL.USE - Code injection vulnerability
def process_user_formula(formula):
    """Dangerous: eval allows arbitrary code execution"""
    return eval(formula)  # VULNERABLE

def execute_user_code(code):
    """Dangerous: exec allows arbitrary code execution"""
    exec(code)  # VULNERABLE

# PY.SUBPROCESS.SHELL - Command injection
def list_directory(dirname):
    """Dangerous: shell=True with user input"""
    subprocess.run(f"ls -la {dirname}", shell=True)  # VULNERABLE

def backup_file(filename):
    """Dangerous: command injection possible"""
    subprocess.call(f"cp {filename} {filename}.bak", shell=True)  # VULNERABLE

# PY.OS.SYSTEM - OS command execution
def remove_temp_files(pattern):
    """Dangerous: direct shell command execution"""
    os.system(f"rm -rf /tmp/{pattern}")  # VULNERABLE

def compress_logs(logdir):
    """Dangerous: os.popen with user input"""
    os.popen(f"tar -czf logs.tar.gz {logdir}")  # VULNERABLE

# PY.YAML.UNSAFE_LOAD - Unsafe deserialization
def load_user_config(config_data):
    """Dangerous: yaml.load without SafeLoader"""
    return yaml.load(config_data)  # VULNERABLE

def parse_yaml_file(filename):
    """Dangerous: yaml.full_load is also unsafe"""
    with open(filename) as f:
        return yaml.full_load(f)  # VULNERABLE

# PY.PICKLE.LOAD - Unsafe deserialization
def deserialize_data(data):
    """Dangerous: pickle deserialization"""
    return pickle.loads(data)  # VULNERABLE

def load_cache_file(filename):
    """Dangerous: pickle.load from file"""
    with open(filename, 'rb') as f:
        return pickle.load(f)  # VULNERABLE

# PY.HASH.WEAK - Weak cryptographic algorithms
def hash_user_password(password):
    """Dangerous: MD5 is cryptographically broken"""
    return hashlib.md5(password.encode()).hexdigest()  # VULNERABLE

def create_session_token(user_id):
    """Dangerous: SHA1 is also weak"""
    return hashlib.sha1(str(user_id).encode()).hexdigest()  # VULNERABLE

# PY.REQUESTS.VERIFY_FALSE - Disabled SSL verification
def fetch_api_data(url):
    """Dangerous: disabled SSL certificate verification"""
    response = requests.get(url, verify=False)  # VULNERABLE
    return response.json()

def post_user_data(url, data):
    """Dangerous: POST with disabled SSL verification"""
    return requests.post(url, json=data, verify=False)  # VULNERABLE

# PY.SECRET.HARDCODED - Hardcoded secrets
API_SECRET = "sk-1234567890abcdefghijklmnopqrstuvwxyz"  # VULNERABLE
DATABASE_PASSWORD = "admin123"  # VULNERABLE
JWT_SECRET_KEY = "my-super-secret-key-dont-tell-anyone"  # VULNERABLE

# AWS credentials (VULNERABLE)
AWS_ACCESS_KEY = "AKIA1234567890123456"  # VULNERABLE
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # VULNERABLE

# SQL injection patterns (would need more sophisticated detection)
def get_user_by_id(user_id):
    """Potential SQL injection via string formatting"""
    query = f"SELECT * FROM users WHERE id = {user_id}"  # VULNERABLE
    # cursor.execute(query) - this would be caught by PY.SQL.INJECTION rule

def search_users(search_term):
    """Potential SQL injection via concatenation"""
    query = "SELECT * FROM users WHERE name LIKE '%" + search_term + "%'"  # VULNERABLE
    # cursor.execute(query)

# Complex vulnerability patterns
def process_upload(file_data):
    """Multiple vulnerabilities in file processing"""
    # Hardcoded path (not a rule we have, but bad practice)
    temp_file = "/tmp/upload_" + str(hash(file_data))

    # Unsafe deserialization
    data = pickle.loads(file_data)  # VULNERABLE

    # Command injection in file processing
    subprocess.run(f"file {temp_file}", shell=True)  # VULNERABLE

    # Weak hash for file integrity
    checksum = hashlib.md5(file_data).hexdigest()  # VULNERABLE

    return data, checksum

def main():
    """Demo main function (don't actually run this!)"""
    # These would all trigger security warnings
    user_input = input("Enter formula: ")
    result = process_user_formula(user_input)

    directory = input("Enter directory: ")
    list_directory(directory)

    config_data = input("Enter YAML config: ")
    config = load_user_config(config_data)

    password = input("Enter password: ")
    hashed = hash_user_password(password)

    url = input("Enter API URL: ")
    api_data = fetch_api_data(url)

if __name__ == "__main__":
    main()