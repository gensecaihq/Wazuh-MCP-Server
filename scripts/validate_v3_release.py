#!/usr/bin/env python3
"""
Validation script for Wazuh MCP Server v3.0.0 release.
Ensures all components are properly implemented and tested.
"""

import os
import sys
import subprocess
import json
import tempfile
from pathlib import Path
from typing import List, Dict, Any, Tuple
import importlib.util


def run_command(cmd: List[str], cwd: Path = None) -> Tuple[int, str, str]:
    """Run a command and return exit code, stdout, stderr."""
    try:
        result = subprocess.run(
            cmd, 
            cwd=cwd, 
            capture_output=True, 
            text=True,
            timeout=60
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return 1, "", "Command timed out"
    except Exception as e:
        return 1, "", str(e)


def check_version_consistency() -> bool:
    """Check that version is consistent across all files."""
    print("🔍 Checking version consistency...")
    
    project_root = Path(__file__).parent.parent
    version_files = {
        "pyproject.toml": r'version = "3.0.0"',
        "src/wazuh_mcp_server/__version__.py": r'__version__ = "3.0.0"',
        "Dockerfile": r'LABEL version="3.0.0"',
        "CHANGELOG.md": r"## v3.0.0",
        "RELEASE_NOTES_v3.0.0.md": r"**Version**: 3.0.0"
    }
    
    all_correct = True
    for file_path, expected_content in version_files.items():
        full_path = project_root / file_path
        if not full_path.exists():
            print(f"❌ Version file missing: {file_path}")
            all_correct = False
            continue
        
        content = full_path.read_text()
        if expected_content not in content:
            print(f"❌ Version mismatch in {file_path}")
            all_correct = False
        else:
            print(f"✅ Version correct in {file_path}")
    
    return all_correct


def check_import_paths() -> bool:
    """Check that all import paths are fixed."""
    print("\n🔍 Checking import paths...")
    
    project_root = Path(__file__).parent.parent
    test_files = list((project_root / "tests").rglob("*.py"))
    
    incorrect_imports = []
    for test_file in test_files:
        content = test_file.read_text()
        if "from src." in content or "import src." in content:
            incorrect_imports.append(test_file.relative_to(project_root))
    
    if incorrect_imports:
        print(f"❌ Found {len(incorrect_imports)} files with incorrect imports:")
        for file_path in incorrect_imports:
            print(f"   - {file_path}")
        return False
    else:
        print(f"✅ All {len(test_files)} test files have correct imports")
        return True


def check_required_files() -> bool:
    """Check that all required files exist."""
    print("\n🔍 Checking required files...")
    
    project_root = Path(__file__).parent.parent
    required_files = [
        # Core v3.0.0 files
        "src/wazuh_mcp_server/transport/__init__.py",
        "src/wazuh_mcp_server/transport/base.py",
        "src/wazuh_mcp_server/transport/stdio_transport.py",
        "src/wazuh_mcp_server/transport/http_transport.py", 
        "src/wazuh_mcp_server/transport/sse_transport.py",
        "src/wazuh_mcp_server/auth/__init__.py",
        "src/wazuh_mcp_server/auth/models.py",
        "src/wazuh_mcp_server/auth/oauth2.py",
        "src/wazuh_mcp_server/auth/middleware.py",
        "src/wazuh_mcp_server/remote_server.py",
        
        # Docker files
        "Dockerfile",
        "docker-compose.yml",
        ".dockerignore",
        "docker/entrypoint.sh",
        
        # Requirements
        "requirements-v3.txt",
        
        # Tests
        "tests/v3/test_transport_layer.py",
        "tests/v3/test_oauth2_auth.py",
        "tests/v3/test_remote_server.py",
        "tests/v3/test_docker_integration.py",
        
        # Documentation
        "docs/v3/README_v3.md",
        "RELEASE_NOTES_v3.0.0.md",
        
        # Release artifacts
        "CHANGELOG.md"
    ]
    
    missing_files = []
    for file_path in required_files:
        full_path = project_root / file_path
        if not full_path.exists():
            missing_files.append(file_path)
        else:
            print(f"✅ {file_path}")
    
    if missing_files:
        print(f"\n❌ Missing {len(missing_files)} required files:")
        for file_path in missing_files:
            print(f"   - {file_path}")
        return False
    else:
        print(f"\n✅ All {len(required_files)} required files present")
        return True


def check_docker_files() -> bool:
    """Check Docker configuration files."""
    print("\n🔍 Checking Docker configuration...")
    
    project_root = Path(__file__).parent.parent
    
    # Check Dockerfile
    dockerfile = project_root / "Dockerfile"
    dockerfile_content = dockerfile.read_text()
    
    dockerfile_checks = {
        "Multi-stage build": "FROM python:3.11-slim-bullseye as builder",
        "Production stage": "FROM python:3.11-slim-bullseye as production",
        "Non-root user": "useradd",
        "Health check": "HEALTHCHECK",
        "Proper labels": "LABEL maintainer=",
        "Exposed ports": "EXPOSE 8443",
        "Tini init": "tini"
    }
    
    all_checks_pass = True
    for check_name, expected_content in dockerfile_checks.items():
        if expected_content in dockerfile_content:
            print(f"✅ Dockerfile {check_name}")
        else:
            print(f"❌ Dockerfile missing {check_name}")
            all_checks_pass = False
    
    # Check docker-compose.yml
    compose_file = project_root / "docker-compose.yml"
    compose_content = compose_file.read_text()
    
    compose_checks = {
        "Main service": "wazuh-mcp-server:",
        "Redis service": "redis:",
        "Prometheus service": "prometheus:",
        "Security settings": "no-new-privileges:true",
        "Health checks": "healthcheck:",
        "Resource limits": "limits:",
        "Networks": "networks:"
    }
    
    for check_name, expected_content in compose_checks.items():
        if expected_content in compose_content:
            print(f"✅ docker-compose.yml {check_name}")
        else:
            print(f"❌ docker-compose.yml missing {check_name}")
            all_checks_pass = False
    
    # Check entrypoint script
    entrypoint = project_root / "docker" / "entrypoint.sh"
    if entrypoint.exists() and os.access(entrypoint, os.X_OK):
        print("✅ Entrypoint script executable")
    else:
        print("❌ Entrypoint script not executable")
        all_checks_pass = False
    
    return all_checks_pass


def check_requirements() -> bool:
    """Check requirements files."""
    print("\n🔍 Checking requirements...")
    
    project_root = Path(__file__).parent.parent
    requirements_file = project_root / "requirements-v3.txt"
    
    if not requirements_file.exists():
        print("❌ requirements-v3.txt missing")
        return False
    
    content = requirements_file.read_text()
    
    required_packages = [
        "fastapi==",
        "uvicorn==", 
        "aiohttp==",
        "sse-starlette==",
        "authlib==",
        "python-jose",
        "prometheus-client==",
        "pytest==",
        "docker=="
    ]
    
    all_present = True
    for package in required_packages:
        if package in content:
            print(f"✅ {package.rstrip('=')}")
        else:
            print(f"❌ Missing {package.rstrip('=')}")
            all_present = False
    
    return all_present


def run_tests() -> bool:
    """Run the test suite."""
    print("\n🧪 Running test suite...")
    
    project_root = Path(__file__).parent.parent
    
    # Check if pytest is available
    exit_code, stdout, stderr = run_command(["python", "-m", "pytest", "--version"], project_root)
    if exit_code != 0:
        print("❌ pytest not available")
        return False
    
    # Run v3 tests
    exit_code, stdout, stderr = run_command([
        "python", "-m", "pytest", 
        "tests/v3/",
        "-v",
        "--tb=short"
    ], project_root)
    
    if exit_code == 0:
        print("✅ All v3.0.0 tests passed")
        return True
    else:
        print(f"❌ Tests failed:")
        print(stderr)
        return False


def check_code_quality() -> bool:
    """Check code quality with basic linting."""
    print("\n🔍 Checking code quality...")
    
    project_root = Path(__file__).parent.parent
    
    # Check Python syntax
    python_files = list((project_root / "src").rglob("*.py"))
    python_files.extend(list((project_root / "tests" / "v3").rglob("*.py")))
    
    syntax_errors = []
    for py_file in python_files:
        try:
            with open(py_file, 'r') as f:
                compile(f.read(), py_file, 'exec')
            print(f"✅ {py_file.relative_to(project_root)}")
        except SyntaxError as e:
            syntax_errors.append((py_file, e))
            print(f"❌ {py_file.relative_to(project_root)}: {e}")
    
    if syntax_errors:
        print(f"\n❌ Found {len(syntax_errors)} syntax errors")
        return False
    else:
        print(f"\n✅ All {len(python_files)} Python files have valid syntax")
        return True


def check_documentation() -> bool:
    """Check documentation completeness."""
    print("\n📖 Checking documentation...")
    
    project_root = Path(__file__).parent.parent
    
    # Check v3 README
    v3_readme = project_root / "docs" / "v3" / "README_v3.md"
    if not v3_readme.exists():
        print("❌ v3.0.0 README missing")
        return False
    
    readme_content = v3_readme.read_text()
    
    required_sections = [
        "# Wazuh MCP Server v3.0.0",
        "## 🆕 What's New in v3.0.0",
        "### Remote MCP Support",
        "### Docker Production Deployment",
        "## 📋 Quick Start",
        "## 🔧 Configuration",
        "## 🔐 Authentication & Security",
        "## 🔌 Claude Code Integration"
    ]
    
    all_sections_present = True
    for section in required_sections:
        if section in readme_content:
            print(f"✅ {section}")
        else:
            print(f"❌ Missing section: {section}")
            all_sections_present = False
    
    # Check release notes
    release_notes = project_root / "RELEASE_NOTES_v3.0.0.md"
    if release_notes.exists():
        print("✅ Release notes present")
    else:
        print("❌ Release notes missing")
        all_sections_present = False
    
    # Check changelog
    changelog = project_root / "CHANGELOG.md"
    changelog_content = changelog.read_text()
    if "## v3.0.0" in changelog_content:
        print("✅ Changelog updated")
    else:
        print("❌ Changelog not updated")
        all_sections_present = False
    
    return all_sections_present


def check_security() -> bool:
    """Basic security checks."""
    print("\n🔐 Running security checks...")
    
    project_root = Path(__file__).parent.parent
    
    # Check for hardcoded secrets
    sensitive_patterns = [
        "password = ",
        "secret = ",
        "api_key = ",
        "token = "
    ]
    
    python_files = list((project_root / "src").rglob("*.py"))
    security_issues = []
    
    for py_file in python_files:
        content = py_file.read_text().lower()
        for pattern in sensitive_patterns:
            if pattern in content and "example" not in content and "test" not in content:
                security_issues.append((py_file, pattern))
    
    if security_issues:
        print(f"⚠️  Found {len(security_issues)} potential security issues:")
        for file_path, pattern in security_issues:
            print(f"   - {file_path.relative_to(project_root)}: {pattern}")
    else:
        print("✅ No obvious security issues found")
    
    # Check Docker security
    dockerfile = project_root / "Dockerfile"
    dockerfile_content = dockerfile.read_text()
    
    security_checks = {
        "Non-root user": "USER " in dockerfile_content or "useradd" in dockerfile_content,
        "No ADD instruction": "ADD " not in dockerfile_content,
        "Explicit user": "USER wazuh-mcp" in dockerfile_content
    }
    
    docker_secure = True
    for check_name, check_result in security_checks.items():
        if check_result:
            print(f"✅ Docker {check_name}")
        else:
            print(f"❌ Docker {check_name}")
            docker_secure = False
    
    return len(security_issues) == 0 and docker_secure


def main():
    """Main validation function."""
    print("🚀 Wazuh MCP Server v3.0.0 Release Validation")
    print("=" * 50)
    
    checks = [
        ("Version Consistency", check_version_consistency),
        ("Import Paths", check_import_paths),
        ("Required Files", check_required_files),
        ("Docker Configuration", check_docker_files),
        ("Requirements", check_requirements),
        ("Code Quality", check_code_quality),
        ("Documentation", check_documentation),
        ("Security", check_security),
        ("Tests", run_tests)
    ]
    
    results = {}
    for check_name, check_func in checks:
        try:
            result = check_func()
            results[check_name] = result
        except Exception as e:
            print(f"\n❌ {check_name} check failed with error: {e}")
            results[check_name] = False
    
    # Summary
    print("\n" + "=" * 50)
    print("📊 VALIDATION SUMMARY")
    print("=" * 50)
    
    passed = sum(results.values())
    total = len(results)
    
    for check_name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{check_name:.<30} {status}")
    
    print(f"\nOverall: {passed}/{total} checks passed")
    
    if passed == total:
        print("\n🎉 ALL CHECKS PASSED! v3.0.0 is ready for release!")
        return 0
    else:
        print(f"\n⚠️  {total - passed} checks failed. Please fix issues before release.")
        return 1


if __name__ == "__main__":
    sys.exit(main())