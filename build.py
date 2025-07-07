#!/usr/bin/env python3
"""
Build script for Wazuh MCP Server package.

This script helps build and distribute the package to PyPI.
"""

import os
import sys
import shutil
import subprocess
import argparse
from pathlib import Path


def run_command(command, check=True):
    """Run a shell command and return the result."""
    print(f"Running: {command}")
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    
    if check and result.returncode != 0:
        print(f"Command failed with exit code {result.returncode}")
        print(f"STDOUT: {result.stdout}")
        print(f"STDERR: {result.stderr}")
        sys.exit(1)
    
    return result


def clean_build_artifacts():
    """Clean up build artifacts."""
    print("🧹 Cleaning build artifacts...")
    
    artifacts = [
        "build/",
        "dist/",
        "*.egg-info/",
        "**/__pycache__/",
        "**/*.pyc",
        "**/*.pyo",
    ]
    
    for pattern in artifacts:
        for path in Path(".").glob(pattern):
            if path.is_dir():
                shutil.rmtree(path)
                print(f"   Removed directory: {path}")
            else:
                path.unlink()
                print(f"   Removed file: {path}")


def run_tests():
    """Run the test suite."""
    print("🧪 Running tests...")
    
    # Install test dependencies
    run_command("pip install -e .[testing]")
    
    # Run pytest
    result = run_command("python -m pytest tests/ -v", check=False)
    
    if result.returncode != 0:
        print("❌ Tests failed!")
        return False
    
    print("✅ All tests passed!")
    return True


def run_linting():
    """Run code linting and formatting checks."""
    print("🔍 Running linting checks...")
    
    # Install dev dependencies
    run_command("pip install -e .[dev]")
    
    # Run ruff
    print("   Running ruff...")
    ruff_result = run_command("ruff check src/", check=False)
    
    # Run black check
    print("   Running black...")
    black_result = run_command("black --check src/", check=False)
    
    # Run mypy
    print("   Running mypy...")
    mypy_result = run_command("mypy src/wazuh_mcp_server/", check=False)
    
    if ruff_result.returncode != 0 or black_result.returncode != 0 or mypy_result.returncode != 0:
        print("❌ Linting checks failed!")
        return False
    
    print("✅ All linting checks passed!")
    return True


def fix_formatting():
    """Auto-fix code formatting."""
    print("🔧 Fixing code formatting...")
    
    # Install dev dependencies
    run_command("pip install -e .[dev]")
    
    # Run black
    run_command("black src/")
    
    # Run ruff with auto-fix
    run_command("ruff check src/ --fix")
    
    print("✅ Code formatting fixed!")


def build_package():
    """Build the package."""
    print("📦 Building package...")
    
    # Clean first
    clean_build_artifacts()
    
    # Install build dependencies
    run_command("pip install build twine")
    
    # Build the package
    run_command("python -m build")
    
    print("✅ Package built successfully!")


def check_package():
    """Check the built package for issues."""
    print("🔍 Checking package...")
    
    # Check with twine
    run_command("twine check dist/*")
    
    print("✅ Package check passed!")


def upload_to_test_pypi():
    """Upload package to Test PyPI."""
    print("🚀 Uploading to Test PyPI...")
    
    # Build and check first
    build_package()
    check_package()
    
    # Upload to Test PyPI
    run_command("twine upload --repository testpypi dist/*")
    
    print("✅ Package uploaded to Test PyPI!")
    print("📋 Test installation with:")
    print("   pip install --index-url https://test.pypi.org/simple/ wazuh-mcp-server")


def upload_to_pypi():
    """Upload package to PyPI."""
    print("🚀 Uploading to PyPI...")
    
    # Build and check first
    build_package()
    check_package()
    
    # Confirm upload
    response = input("Are you sure you want to upload to PyPI? (yes/no): ")
    if response.lower() != "yes":
        print("Upload cancelled.")
        return
    
    # Upload to PyPI
    run_command("twine upload dist/*")
    
    print("✅ Package uploaded to PyPI!")
    print("📋 Install with:")
    print("   pip install wazuh-mcp-server")


def install_locally():
    """Install the package locally for testing."""
    print("📥 Installing package locally...")
    
    # Install in development mode
    run_command("pip install -e .")
    
    print("✅ Package installed locally!")
    print("📋 Test with:")
    print("   python -c 'from wazuh_mcp_server import WazuhAPIClient; print(\"Import successful!\")'")


def create_requirements_lock():
    """Create locked requirements file."""
    print("🔒 Creating requirements lock file...")
    
    # Install the package
    run_command("pip install -e .")
    
    # Generate requirements
    run_command("pip freeze > requirements-lock.txt")
    
    print("✅ Requirements lock file created!")


def validate_setup():
    """Validate the package setup."""
    print("✅ Validating package setup...")
    
    # Check that all required files exist
    required_files = [
        "pyproject.toml",
        "README.md",
        "LICENSE",
        "MANIFEST.in",
        "src/wazuh_mcp_server/__init__.py",
        "src/wazuh_mcp_server/__version__.py",
    ]
    
    missing_files = []
    for file_path in required_files:
        if not Path(file_path).exists():
            missing_files.append(file_path)
    
    if missing_files:
        print(f"❌ Missing required files: {missing_files}")
        return False
    
    # Check version consistency
    from src.wazuh_mcp_server.__version__ import __version__
    
    # Read version from pyproject.toml
    with open("pyproject.toml", "r") as f:
        content = f.read()
        if f'version = "{__version__}"' not in content:
            print(f"❌ Version mismatch between __version__.py ({__version__}) and pyproject.toml")
            return False
    
    print("✅ Package setup validation passed!")
    return True


def main():
    """Main build script entry point."""
    parser = argparse.ArgumentParser(description="Build script for Wazuh MCP Server")
    parser.add_argument("command", choices=[
        "clean", "test", "lint", "fix", "build", "check", 
        "install", "validate", "lock", "test-pypi", "pypi"
    ], help="Command to run")
    
    args = parser.parse_args()
    
    print("🚀 Wazuh MCP Server Build Script")
    print("=" * 50)
    
    if args.command == "clean":
        clean_build_artifacts()
    elif args.command == "test":
        success = run_tests()
        if not success:
            sys.exit(1)
    elif args.command == "lint":
        success = run_linting()
        if not success:
            sys.exit(1)
    elif args.command == "fix":
        fix_formatting()
    elif args.command == "build":
        build_package()
    elif args.command == "check":
        check_package()
    elif args.command == "install":
        install_locally()
    elif args.command == "validate":
        success = validate_setup()
        if not success:
            sys.exit(1)
    elif args.command == "lock":
        create_requirements_lock()
    elif args.command == "test-pypi":
        upload_to_test_pypi()
    elif args.command == "pypi":
        upload_to_pypi()
    
    print("\n✅ Build script completed successfully!")


if __name__ == "__main__":
    main()
