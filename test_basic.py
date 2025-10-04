#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Basic test file for GitHub Actions
"""
import sys
import os

def test_python_version():
    """Test that we're using a supported Python version"""
    assert sys.version_info >= (3, 9), f"Python 3.9+ required, got {sys.version}"

def test_imports():
    """Test that main modules can be imported"""
    try:
        import flask
        assert True
    except ImportError:
        assert False, "Flask not available"
    
    try:
        import pandas
        assert True
    except ImportError:
        assert False, "Pandas not available"

def test_file_structure():
    """Test that required files exist"""
    required_files = ['anasayfa.py', 'requirements.txt']
    for file in required_files:
        assert os.path.exists(file), f"Required file {file} not found"

def test_basic_functionality():
    """Basic functionality test"""
    assert 1 + 1 == 2
    assert "hello".upper() == "HELLO"
    assert len([1, 2, 3]) == 3

if __name__ == "__main__":
    test_python_version()
    test_imports()
    test_file_structure()
    test_basic_functionality()
    print("✅ All basic tests passed!")
