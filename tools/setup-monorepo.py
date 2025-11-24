#!/usr/bin/env python3
"""
Wazuh MCP Server - Monorepo Setup Tool
Converts the current dual-branch structure into a monorepo with shared core.
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Dict

class MonorepoConverter:
    """Converts Wazuh MCP Server to monorepo architecture."""
    
    def __init__(self, repo_root: Path):
        self.repo_root = repo_root
        self.packages_dir = repo_root / "packages"
        
    def setup_directory_structure(self):
        """Create the new monorepo directory structure."""
        print("🏗️  Creating monorepo directory structure...")
        
        # Create main packages directory
        self.packages_dir.mkdir(exist_ok=True)
        
        # Create package subdirectories
        for package in ["core", "stdio", "remote"]:
            package_dir = self.packages_dir / package
            package_dir.mkdir(exist_ok=True)
            
            # Create src directory for each package
            src_dir = package_dir / "src"
            src_dir.mkdir(exist_ok=True)
            
            print(f"  ✓ Created packages/{package}/src/")
        
    def extract_core_components(self):
        """Extract shared components to core package."""
        print("📦 Extracting core components...")
        
        # Define what goes into core
        core_modules = [
            "api/",
            "analyzers/", 
            "tools/",
            "utils/",
            "config.py"
        ]
        
        src_dir = Path("src/wazuh_mcp_server")
        core_src = self.packages_dir / "core" / "src" / "wazuh_mcp_core"
        core_src.mkdir(exist_ok=True)
        
        # Copy core modules
        for module in core_modules:
            src_path = src_dir / module
            if src_path.exists():
                dest_path = core_src / module
                if src_path.is_dir():
                    shutil.copytree(src_path, dest_path, dirs_exist_ok=True)
                else:
                    shutil.copy2(src_path, dest_path)
                print(f"  ✓ Extracted {module}")
        
        # Create core __init__.py
        init_file = core_src / "__init__.py"
        init_file.write_text('"""Wazuh MCP Core - Shared library for all transports."""\n__version__ = "1.0.0"\n')
        
    def create_stdio_package(self):
        """Create STDIO transport package."""
        print("📡 Creating STDIO transport package...")
        
        stdio_src = self.packages_dir / "stdio" / "src" / "wazuh_mcp_stdio"
        stdio_src.mkdir(exist_ok=True)
        
        # Copy STDIO-specific files from main branch
        stdio_files = [
            "server.py",
            "main.py", 
            "__init__.py",
            "__version__.py"
        ]
        
        src_dir = Path("src/wazuh_mcp_server")
        for file in stdio_files:
            src_file = src_dir / file
            if src_file.exists():
                dest_file = stdio_src / file
                shutil.copy2(src_file, dest_file)
                print(f"  ✓ Copied {file}")
        
        # Create STDIO-specific transport adapter
        transport_dir = stdio_src / "transport"
        transport_dir.mkdir(exist_ok=True)
        
        adapter_code = '''"""STDIO Transport Adapter for Wazuh MCP."""
import json
from typing import Any, Dict
from wazuh_mcp_core.tools.base import WazuhTool

class STDIOToolAdapter:
    """Adapts core tools for FastMCP STDIO transport."""
    
    def __init__(self, mcp_app):
        self.mcp_app = mcp_app
    
    def register_tool(self, tool_instance: WazuhTool):
        """Register a core tool with FastMCP."""
        @self.mcp_app.tool(**tool_instance.schema)
        async def tool_wrapper(**kwargs) -> str:
            result = await tool_instance.execute(**kwargs)
            return json.dumps(result, indent=2)
        
        return tool_wrapper
'''
        (transport_dir / "adapter.py").write_text(adapter_code)
        (transport_dir / "__init__.py").write_text("")
        
    def create_remote_package(self):
        """Create Remote transport package (from mcp-remote branch)."""
        print("🌐 Creating Remote transport package...")
        
        remote_src = self.packages_dir / "remote" / "src" / "wazuh_mcp_remote"
        remote_src.mkdir(exist_ok=True)
        
        # Note: This would need to be run when on mcp-remote branch
        # or files copied from that branch
        print("  ℹ️  Remote package structure created (files need to be copied from mcp-remote branch)")
        
    def create_pyproject_configs(self):
        """Create pyproject.toml for each package."""
        print("⚙️  Creating package configurations...")
        
        # Core package config
        core_config = '''[build-system]
requires = ["setuptools>=64", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "wazuh-mcp-core"
version = "1.0.0"
description = "Shared core library for Wazuh MCP implementations"
readme = "README.md"
license = {text = "MIT"}
authors = [{name = "GenSec AI Team"}]
keywords = ["wazuh", "security", "mcp", "core"]
requires-python = ">=3.11"
dependencies = [
    "aiohttp>=3.12.14,<4.0.0",
    "pydantic>=2.11.7,<3.0.0",
    "python-dotenv>=1.1.1,<2.0.0",
    "python-dateutil>=2.9.0",
    "psutil>=7.0.0",
]

[project.urls]
Homepage = "https://github.com/gensecaihq/Wazuh-MCP-Server"
Repository = "https://github.com/gensecaihq/Wazuh-MCP-Server"

[tool.setuptools]
package-dir = {"" = "src"}

[tool.setuptools.packages.find]
where = ["src"]
include = ["wazuh_mcp_core*"]
'''
        
        # STDIO package config
        stdio_config = '''[build-system]
requires = ["setuptools>=64", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "wazuh-mcp-stdio"
version = "2.1.0"
description = "FastMCP STDIO transport for Wazuh SIEM integration"
readme = "README.md"
license = {text = "MIT"}
authors = [{name = "GenSec AI Team"}]
keywords = ["wazuh", "security", "mcp", "stdio", "fastmcp"]
requires-python = ">=3.11"
dependencies = [
    "wazuh-mcp-core>=1.0.0,<2.0.0",
    "fastmcp>=2.10.6",
]

[project.scripts]
wazuh-mcp-server = "wazuh_mcp_stdio.main:main"

[project.urls]
Homepage = "https://github.com/gensecaihq/Wazuh-MCP-Server"
Repository = "https://github.com/gensecaihq/Wazuh-MCP-Server"

[tool.setuptools]
package-dir = {"" = "src"}

[tool.setuptools.packages.find]
where = ["src"]
include = ["wazuh_mcp_stdio*"]
'''
        
        # Remote package config
        remote_config = '''[build-system]
requires = ["setuptools>=64", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "wazuh-mcp-remote"
version = "3.0.0"
description = "Remote MCP server with HTTP/SSE transport for Wazuh"
readme = "README.md"
license = {text = "MIT"}
authors = [{name = "GenSec AI Team"}]
keywords = ["wazuh", "security", "mcp", "remote", "sse", "http"]
requires-python = ">=3.11"
dependencies = [
    "wazuh-mcp-core>=1.0.0,<2.0.0",
    "fastapi>=0.115.0",
    "uvicorn[standard]>=0.32.0",
    "prometheus-client>=0.20.0",
    "python-jose[cryptography]>=3.3.0",
    "passlib[bcrypt]>=1.7.4",
]

[project.scripts]
wazuh-mcp-remote = "wazuh_mcp_remote.main:main"

[project.urls]
Homepage = "https://github.com/gensecaihq/Wazuh-MCP-Server"
Repository = "https://github.com/gensecaihq/Wazuh-MCP-Server"

[tool.setuptools]
package-dir = {"" = "src"}

[tool.setuptools.packages.find]
where = ["src"]
include = ["wazuh_mcp_remote*"]
'''
        
        # Write configs
        (self.packages_dir / "core" / "pyproject.toml").write_text(core_config)
        (self.packages_dir / "stdio" / "pyproject.toml").write_text(stdio_config)
        (self.packages_dir / "remote" / "pyproject.toml").write_text(remote_config)
        
        print("  ✓ Created pyproject.toml for all packages")
    
    def create_ci_workflows(self):
        """Create GitHub Actions workflows for each package."""
        print("🔄 Creating CI/CD workflows...")
        
        workflows_dir = Path(".github/workflows")
        workflows_dir.mkdir(parents=True, exist_ok=True)
        
        # Multi-package test workflow
        test_workflow = '''name: Multi-Package Tests

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    strategy:
      matrix:
        package: [core, stdio]
        python-version: ["3.11", "3.12"]
    
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Set up Python ${{ matrix.python-version }}
      uses: actions/setup-python@v4
      with:
        python-version: ${{ matrix.python-version }}
    
    - name: Install dependencies for ${{ matrix.package }}
      run: |
        cd packages/${{ matrix.package }}
        python -m pip install --upgrade pip
        pip install -e .
        pip install pytest pytest-asyncio
    
    - name: Test ${{ matrix.package }}
      run: |
        cd packages/${{ matrix.package }}
        pytest tests/ -v
'''
        
        (workflows_dir / "packages.yml").write_text(test_workflow)
        print("  ✓ Created GitHub Actions workflow")
    
    def update_imports(self):
        """Update import statements to use new package structure."""
        print("🔧 Updating import statements...")
        
        # This would require more sophisticated AST manipulation
        # For now, just create guidance
        guidance = '''
# Import Update Guide

## Old imports (main branch):
from wazuh_mcp_server.api.wazuh_client import WazuhClient
from wazuh_mcp_server.analyzers.security_analyzer import SecurityAnalyzer

## New imports (monorepo):
from wazuh_mcp_core.api.wazuh_client import WazuhClient  
from wazuh_mcp_core.analyzers.security_analyzer import SecurityAnalyzer

# STDIO transport:
from wazuh_mcp_stdio.server import mcp
from wazuh_mcp_stdio.transport.adapter import STDIOToolAdapter

# Remote transport:
from wazuh_mcp_remote.server import app
from wazuh_mcp_remote.transport.adapter import RemoteToolAdapter
'''
        
        (self.packages_dir / "IMPORT_GUIDE.md").write_text(guidance)
        print("  ✓ Created import update guide")
    
    def run_conversion(self):
        """Run the complete monorepo conversion."""
        print("🚀 Starting monorepo conversion...")
        print("="*50)
        
        try:
            self.setup_directory_structure()
            self.extract_core_components() 
            self.create_stdio_package()
            self.create_remote_package()
            self.create_pyproject_configs()
            self.create_ci_workflows()
            self.update_imports()
            
            print("="*50)
            print("✅ Monorepo conversion completed successfully!")
            print(f"📁 New structure created in: {self.packages_dir}")
            print("\n📋 Next steps:")
            print("1. Review the generated package structure")
            print("2. Copy remote branch files to packages/remote/")
            print("3. Update import statements throughout the codebase")
            print("4. Test each package independently")
            print("5. Update documentation")
            
        except Exception as e:
            print(f"❌ Error during conversion: {e}")
            sys.exit(1)

if __name__ == "__main__":
    repo_root = Path(__file__).parent.parent
    converter = MonorepoConverter(repo_root)
    converter.run_conversion()