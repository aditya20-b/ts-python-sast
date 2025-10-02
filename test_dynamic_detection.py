#!/usr/bin/env python3
"""
Test file demonstrating dynamic/heuristic taint detection
Tests custom wrapper functions that aren't in hardcoded lists
"""

import subprocess
import custom_lib  # Imaginary library


# CUSTOM WRAPPER - Should be detected via heuristics!
def execute_shell_command(cmd):
    """
    Custom wrapper around subprocess - NOT in hardcoded list
    Should be detected because:
    1. Contains "execute" and "command" keywords
    2. Module context shows subprocess import
    """
    subprocess.run(cmd, shell=True)


# CUSTOM WRAPPER - Should be detected via heuristics!
def run_system_call(user_command):
    """
    Another custom wrapper - NOT in hardcoded list
    Should be detected because:
    1. Contains "run" and "system" and "call" keywords
    2. Subprocess module is imported
    """
    import os
    os.popen(user_command)


# CUSTOM WRAPPER - Should be detected via heuristics!
def query_database(sql_string):
    """
    Custom SQL function - NOT in hardcoded list
    Should be detected because:
    1. Contains "query" and "database" keywords
    2. Common SQL operation pattern
    """
    # Imaginary database library
    import sqlite3
    conn = sqlite3.connect('test.db')
    cursor = conn.cursor()
    cursor.execute(sql_string)  # Known sink
    conn.close()


# CUSTOM WRAPPER - Should be detected via heuristics!
def execute_sql_query(query):
    """
    Another SQL wrapper - NOT in hardcoded list
    Should be detected because:
    1. Contains "execute" and "sql" and "query" keywords
    """
    import psycopg2  # PostgreSQL library
    conn = psycopg2.connect("dbname=test")
    cur = conn.cursor()
    cur.execute(query)  # Known sink


# CUSTOM SOURCE - Should be detected via heuristics!
def read_user_input():
    """
    Custom input wrapper - NOT in hardcoded list
    Should be detected because:
    1. Contains "read" and "input" keywords
    """
    return input("Enter value: ")


# CUSTOM SOURCE - Should be detected via heuristics!
def get_request_param(key):
    """
    Flask-like request handler - NOT in hardcoded list
    Should be detected because:
    1. Contains "request" and "param" keywords
    2. Common web framework pattern
    """
    from flask import request
    return request.args.get(key)


# VULNERABLE FLOW 1: Custom wrapper to custom wrapper
def vulnerable_custom_flow_1():
    user_data = read_user_input()  # Custom source
    execute_shell_command(user_data)  # Custom sink


# VULNERABLE FLOW 2: Standard source to custom sink
def vulnerable_custom_flow_2():
    cmd = input("Command: ")  # Standard source
    run_system_call(cmd)  # Custom sink


# VULNERABLE FLOW 3: Custom source to standard sink
def vulnerable_custom_flow_3():
    data = read_user_input()  # Custom source
    eval(data)  # Standard sink


# VULNERABLE FLOW 4: SQL injection through custom functions
def vulnerable_custom_flow_4():
    user_query = get_request_param('q')  # Custom web source
    query_database(user_query)  # Custom SQL sink


# VULNERABLE FLOW 5: Nested custom wrappers
def vulnerable_custom_flow_5():
    import os
    param = get_request_param('file')  # Custom source
    sql = f"SELECT * FROM files WHERE name = '{param}'"
    execute_sql_query(sql)  # Custom SQL sink


if __name__ == "__main__":
    print("This tests dynamic/heuristic taint detection")
    print("All custom wrappers should be detected automatically!")
