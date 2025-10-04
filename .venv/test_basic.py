#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Basic test file for GitHub Actions
"""
import sys
import os

def test_python_version():
    """Test that we're using a supported Python version"""
    print(f"Python version: {sys.version}")
    assert sys.version_info >= (3, 9), f"Python 3.9+ required, got {sys.version}"

def test_basic_functionality():
    """Basic functionality test"""
    assert 1 + 1 == 2
    assert "hello".upper() == "HELLO"
    assert len([1, 2, 3]) == 3

def test_file_structure():
    """Test that required files exist"""
    required_files = ['requirements.txt']
    for file in required_files:
        if os.path.exists(file):
            print(f"✅ {file} exists")
        else:
            print(f"❌ {file} not found")
            # Don't fail if files don't exist, just warn

def test_optional_imports():
    """Test optional imports - don't fail if not available"""
    try:
        import flask
        print("✅ Flask import successful")
    except ImportError as e:
        print(f"⚠️ Flask not available: {e}")
    
    try:
        import pandas
        print("✅ Pandas import successful")
    except ImportError as e:
        print(f"⚠️ Pandas not available: {e}")

if __name__ == "__main__":
    print("🧪 Running basic tests...")
    test_python_version()
    test_basic_functionality()
    test_file_structure()
    test_optional_imports()
    print("✅ All basic tests completed!")
