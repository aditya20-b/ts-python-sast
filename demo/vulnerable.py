#!/usr/bin/env python3
"""
Demo file with various security issues for ts-sast testing
"""

import os
import subprocess
import pickle
import yaml
import hashlib
import requests

# PY.EVAL.USE - Dangerous eval usage
def dangerous_eval(user_input):
    result = eval(user_input)  # SECURITY ISSUE: Code injection
    return result

# PY.SUBPROCESS.SHELL - Shell injection
def run_command(filename):
    subprocess.run(f"ls -la {filename}", shell=True)  # SECURITY ISSUE: Command injection

# PY.OS.SYSTEM - OS system usage
def delete_file(filename):
    os.system(f"rm {filename}")  # SECURITY ISSUE: Command injection

# PY.YAML.UNSAFE_LOAD - Unsafe YAML loading
def load_config(config_data):
    config = yaml.load(config_data)  # SECURITY ISSUE: Code execution via YAML
    return config

# PY.PICKLE.LOAD - Unsafe pickle deserialization
def load_data(data):
    obj = pickle.loads(data)  # SECURITY ISSUE: Code execution via pickle
    return obj

# PY.HASH.WEAK - Weak cryptographic hash
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()  # SECURITY ISSUE: Weak hash

# PY.REQUESTS.VERIFY_FALSE - Disabled SSL verification
def fetch_data(url):
    response = requests.get(url, verify=False)  # SECURITY ISSUE: MITM vulnerability
    return response.text

# PY.SECRET.HARDCODED - Hardcoded secrets
API_KEY = "sk-1234567890abcdef"  # SECURITY ISSUE: Hardcoded secret
DATABASE_PASSWORD = "super_secret_password"  # SECURITY ISSUE: Hardcoded password

def main():
    # Demo usage (don't actually run this!)
    user_data = input("Enter some data: ")
    dangerous_eval(user_data)

    run_command("test.txt")
    delete_file("temp.log")

    yaml_data = "key: value"
    config = load_config(yaml_data)

    pickle_data = b"arbitrary bytes"
    obj = load_data(pickle_data)

    password_hash = hash_password("mypassword")

    data = fetch_data("https://api.example.com/data")

if __name__ == "__main__":
    main()
