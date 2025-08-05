#!/usr/bin/env python3
"""
Sample Python code with various issues for CodeScan demonstration.
This file intentionally contains security vulnerabilities, bad practices,
and style issues to showcase CodeScan's capabilities.
"""

import os
import sys
import subprocess
import md5  # Weak hash algorithm
import random  # Weak random for security purposes

# Hardcoded secrets (CRITICAL)
API_KEY = "sk-1234567890abcdef"
DATABASE_URL = "postgresql://user:password123@localhost/db"
JWT_SECRET = "my-super-secret-jwt-key"

# Global variables (not recommended)
global_counter = 0

def process_user_data(user_input, user_id):
    # SQL Injection vulnerability (CRITICAL)
    query = f"SELECT * FROM users WHERE id = {user_id} AND name = '{user_input}'"
    
    # Command injection vulnerability (CRITICAL)
    command = f"ls -la {user_input}"
    os.system(command)
    
    # Weak hash usage (HIGH)
    password_hash = md5.new(user_input.encode()).hexdigest()
    
    return query, password_hash

def calculate_total(items):  # Missing docstring (LOW)
    if items is None:
        return 0
    if len(items) == 0:
        return 0
    if isinstance(items, list):
        if len(items) > 0:
            if all(hasattr(item, 'price') for item in items):
                if all(item.price >= 0 for item in items):  # Too nested (MEDIUM)
                    total = 0
                    for item in items:
                        total += item.price
                    return total
    return None

# Function too complex (MEDIUM)
def complex_function(data, option1, option2, option3, option4):
    result = None
    if option1:
        if data:
            if len(data) > 0:
                if option2:
                    if isinstance(data, list):
                        if option3:
                            if all(isinstance(x, dict) for x in data):
                                if option4:
                                    if 'key' in data[0]:
                                        for item in data:
                                            if 'value' in item:
                                                if item['value'] > 0:
                                                    if result is None:
                                                        result = []
                                                    result.append(item['value'])
                                                else:
                                                    continue
                                            else:
                                                pass
                                    else:
                                        result = "error"
                                else:
                                    result = data
                            else:
                                result = []
                        else:
                            result = data
                    else:
                        result = None
                else:
                    result = data
            else:
                result = []
        else:
            result = None
    else:
        result = False
    return result

# Style issues
def bad_spacing():
    x=1+2  # Missing spaces around operators
    y= 3*4  # Inconsistent spacing
    z =5/6  # More inconsistent spacing
    return x,y,z

# Long line exceeding recommended length
def function_with_very_long_line():
    very_long_variable_name = some_function_with_many_parameters(parameter1, parameter2, parameter3, parameter4, parameter5, parameter6)
    return very_long_variable_name

# Unused import and variables
import json  # Unused import
import datetime as dt  # Unused import

def unused_variables():
    unused_var = "this variable is never used"
    another_unused = 42
    return "done"

# Dangerous eval usage (HIGH)
def dangerous_function(user_code):
    result = eval(user_code)  # Code injection risk
    return result

# Bare except clause (MEDIUM)
def poor_error_handling():
    try:
        risky_operation()
    except:  # Bare except - hides all errors
        pass

def risky_operation():
    # Simulate some risky operation
    return 1 / 0

# Assert in production code (LOW)
def validate_input(value):
    assert value > 0  # Asserts are disabled with -O flag
    return value * 2

# Print statements (LOW - should use logging)
def debug_function():
    print("Debug: entering function")  # Should use logging
    result = complex_calculation()
    print(f"Debug: result is {result}")  # Should use logging
    return result

def complex_calculation():
    return 42

# Missing type hints (LOW)
def add_numbers(a, b):  # Missing type hints
    return a + b

# Mutable default argument (HIGH)
def append_to_list(item, target_list=[]):  # Dangerous mutable default
    target_list.append(item)
    return target_list

class BadClass:  # Missing docstring
    def __init__(self):
        pass
    
    def method_without_docstring(self):  # Missing docstring
        return self

if __name__ == "__main__":
    # XSS vulnerability potential
    user_input = "<script>alert('xss')</script>"
    document_content = f"<div>{user_input}</div>"  # Potential XSS
    
    # Weak random for security (MEDIUM)
    session_token = str(random.random())  # Not cryptographically secure
    
    print(f"API Key: {API_KEY}")  # Exposing secrets
    print("Application started")