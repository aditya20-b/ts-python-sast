#!/usr/bin/env python3
"""
Simple test for heuristic detection
"""

import subprocess
import os

# Test 1: Custom exec function (heuristic: "exec" keyword)
def my_exec_command(cmd):
    subprocess.run(cmd, shell=True)

# Test 2: Custom shell function (heuristic: "shell" keyword)
def run_in_shell(command):
    os.system(command)

# Test 3: Custom SQL execute (heuristic: "execute" + "sql")
def execute_sql(query):
    import sqlite3
    conn = sqlite3.connect(':memory:')
    conn.execute(query)

# Test 4: Custom input reader (heuristic: "read" + "input")
def read_user_input():
    return input("Data: ")

# Vulnerable flow
def test():
    user_cmd = read_user_input()
    my_exec_command(user_cmd)
    run_in_shell(user_cmd)
    execute_sql(f"SELECT * FROM users WHERE id = {user_cmd}")
