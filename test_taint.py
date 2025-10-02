#!/usr/bin/env python3
"""
Test file for taint analysis - contains various taint flows
"""

import os
import subprocess
import shlex

# VULNERABLE: Direct flow from input to os.system
def vulnerable_flow_1():
    user_input = input("Enter command: ")
    os.system(user_input)  # Should detect: USER -> COMMAND_EXEC

# VULNERABLE: Indirect flow through variable
def vulnerable_flow_2():
    user_data = input("Enter filename: ")
    command = f"cat {user_data}"
    os.system(command)  # Should detect: USER -> COMMAND_EXEC

# SAFE: Sanitized with shlex.quote
def safe_flow_1():
    user_input = input("Enter filename: ")
    safe_input = shlex.quote(user_input)
    os.system(f"cat {safe_input}")  # Should be sanitized

# VULNERABLE: Environment variable to eval
def vulnerable_flow_3():
    env_data = os.environ.get("USER_CODE", "")
    eval(env_data)  # Should detect: ENV -> CODE_EVAL

# VULNERABLE: Multiple assignments
def vulnerable_flow_4():
    data = input("Enter data: ")
    temp1 = data
    temp2 = temp1
    temp3 = temp2
    os.system(temp3)  # Should trace through multiple assignments

# VULNERABLE: String concatenation preserves taint
def vulnerable_flow_5():
    prefix = "rm -rf "
    user_path = input("Enter path: ")
    command = prefix + user_path
    os.system(command)  # Should detect taint in concatenation

# VULNERABLE: f-string preserves taint
def vulnerable_flow_6():
    filename = input("Enter filename: ")
    command = f"ls -la {filename}"
    os.system(command)

# SAFE: Type casting sanitizes
def safe_flow_2():
    user_input = input("Enter number: ")
    number = int(user_input)  # Sanitized by type cast
    os.system(f"echo {number}")  # Should be safe

# VULNERABLE: Subprocess with shell=True
def vulnerable_flow_7():
    user_cmd = input("Enter command: ")
    subprocess.run(user_cmd, shell=True)  # Should detect: USER -> COMMAND_EXEC

# SAFE: Subprocess without shell
def safe_flow_3():
    user_file = input("Enter filename: ")
    subprocess.run(["cat", user_file])  # Safe - no shell injection

# VULNERABLE: Augmented assignment
def vulnerable_flow_8():
    base = "ls "
    user_path = input("Enter path: ")
    base += user_path
    os.system(base)  # Should detect taint

if __name__ == "__main__":
    print("This is a test file for taint analysis")
    print("DO NOT RUN - contains deliberately vulnerable code!")
