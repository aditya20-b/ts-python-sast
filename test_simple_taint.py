#!/usr/bin/env python3
"""
Simple test case for taint analysis debugging
"""

import os

def test_simple():
    user_input = input("Enter: ")
    os.system(user_input)
