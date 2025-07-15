#!/usr/bin/env python3
"""Script to fix import paths from src.* to wazuh_mcp_server.*"""

import os
import re
from pathlib import Path

def fix_imports_in_file(file_path):
    """Fix imports in a single file"""
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Replace src. imports with wazuh_mcp_server.
    original_content = content
    content = re.sub(r'from src\.', 'from wazuh_mcp_server.', content)
    content = re.sub(r'import src\.', 'import wazuh_mcp_server.', content)
    
    # Also fix the WazuhMCPServer import specifically
    content = re.sub(r'from wazuh_mcp_server\.wazuh_mcp_server import', 'from wazuh_mcp_server.main import', content)
    
    if content != original_content:
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"Fixed imports in {file_path}")
        return True
    return False

def main():
    """Fix all import paths"""
    project_root = Path(__file__).parent.parent
    test_dir = project_root / "tests"
    
    files_fixed = 0
    for py_file in test_dir.rglob("*.py"):
        if fix_imports_in_file(py_file):
            files_fixed += 1
    
    print(f"Fixed imports in {files_fixed} files")

if __name__ == "__main__":
    main()