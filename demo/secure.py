#!/usr/bin/env python3
"""
Demo file showing secure alternatives to common security issues
"""

import os
import subprocess
import json
import yaml
import hashlib
import requests
import shlex
import ast

# SECURE: Use ast.literal_eval for safe evaluation
def safe_eval(user_input):
    try:
        result = ast.literal_eval(user_input)  # SECURE: Only evaluates literals
        return result
    except (ValueError, SyntaxError):
        return None

# SECURE: Use subprocess with list arguments
def run_command_safe(filename):
    subprocess.run(["ls", "-la", filename])  # SECURE: No shell injection possible

# SECURE: Use subprocess instead of os.system
def delete_file_safe(filename):
    subprocess.run(["rm", filename])  # SECURE: No shell injection

# SECURE: Use safe YAML loading
def load_config_safe(config_data):
    config = yaml.safe_load(config_data)  # SECURE: Safe YAML loading
    return config

# SECURE: Use JSON instead of pickle for untrusted data
def load_data_safe(json_data):
    obj = json.loads(json_data)  # SECURE: JSON is safe for deserialization
    return obj

# SECURE: Use strong cryptographic hash
def hash_password_safe(password):
    return hashlib.sha256(password.encode()).hexdigest()  # SECURE: Strong hash

# SECURE: Use proper SSL verification
def fetch_data_safe(url):
    response = requests.get(url)  # SECURE: SSL verification enabled by default
    return response.text

# SECURE: Use environment variables for secrets
API_KEY = os.environ.get("API_KEY")  # SECURE: Load from environment
DATABASE_PASSWORD = os.environ.get("DB_PASSWORD")  # SECURE: Load from environment

def main():
    # Demo usage of secure alternatives
    user_data = "{'key': 'value'}"
    safe_result = safe_eval(user_data)

    run_command_safe("test.txt")
    delete_file_safe("temp.log")

    yaml_data = "key: value"
    config = load_config_safe(yaml_data)

    json_data = '{"key": "value"}'
    obj = load_data_safe(json_data)

    password_hash = hash_password_safe("mypassword")

    if API_KEY:  # Check if API key is available
        data = fetch_data_safe("https://api.example.com/data")

if __name__ == "__main__":
    main()
