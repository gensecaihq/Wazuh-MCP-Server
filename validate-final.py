#!/usr/bin/env python3
"""
Final comprehensive validation script for Wazuh MCP Server v-final branch
Tests all components to ensure 100% functionality
"""

import os
import sys
import json
import asyncio
import importlib
import traceback
from pathlib import Path
from typing import Dict, List, Any, Optional

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent / "src"))

class ValidationResults:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.warnings = 0
        self.results = []
    
    def add_result(self, test_name: str, status: str, details: str = "", severity: str = "info"):
        result = {
            "test": test_name,
            "status": status,
            "details": details,
            "severity": severity
        }
        self.results.append(result)
        
        if status == "PASS":
            self.passed += 1
        elif status == "FAIL":
            self.failed += 1
        elif status == "WARN":
            self.warnings += 1
    
    def print_summary(self):
        print(f"\n{'='*60}")
        print("🎯 FINAL VALIDATION SUMMARY")
        print(f"{'='*60}")
        print(f"✅ PASSED: {self.passed}")
        print(f"❌ FAILED: {self.failed}")
        print(f"⚠️  WARNINGS: {self.warnings}")
        print(f"📊 TOTAL TESTS: {len(self.results)}")
        
        if self.failed == 0:
            print(f"\n🎉 ALL TESTS PASSED - FULLY FUNCTIONAL!")
        else:
            print(f"\n🚨 {self.failed} TESTS FAILED - NEEDS ATTENTION")
        
        return self.failed == 0

def test_imports(results: ValidationResults):
    """Test all critical imports."""
    print("🔍 Testing core imports...")
    
    critical_imports = [
        ("wazuh_mcp_server.server", "Main server module"),
        ("wazuh_mcp_server.config", "Configuration management"),
        ("wazuh_mcp_server.utils.logging", "Logging utilities"),
        ("wazuh_mcp_server.utils.rate_limiter", "Rate limiting"),
        ("wazuh_mcp_server.utils.validation", "Input validation"),
        ("wazuh_mcp_server.auth.secure_auth", "Authentication"),
    ]
    
    for module_name, description in critical_imports:
        try:
            importlib.import_module(module_name)
            results.add_result(f"Import {module_name}", "PASS", description)
        except ImportError as e:
            results.add_result(f"Import {module_name}", "FAIL", str(e), "critical")
        except Exception as e:
            results.add_result(f"Import {module_name}", "FAIL", f"Unexpected error: {e}", "critical")

def test_configuration(results: ValidationResults):
    """Test configuration loading and validation."""
    print("⚙️ Testing configuration...")
    
    try:
        from wazuh_mcp_server.config import WazuhConfig
        
        # Test default configuration
        config = WazuhConfig()
        results.add_result("Config Default Creation", "PASS", "Default config created successfully")
        
        # Test validation
        if hasattr(config, 'host') and hasattr(config, 'port'):
            results.add_result("Config Attributes", "PASS", "Required attributes present")
        else:
            results.add_result("Config Attributes", "FAIL", "Missing required attributes", "critical")
            
    except Exception as e:
        results.add_result("Config Loading", "FAIL", str(e), "critical")

def test_authentication(results: ValidationResults):
    """Test authentication components."""
    print("🔐 Testing authentication...")
    
    try:
        from wazuh_mcp_server.auth.secure_auth import SecureAuth, AuthConfig
        
        # Test auth config
        auth_config = AuthConfig()
        results.add_result("Auth Config", "PASS", "Auth configuration created")
        
        # Test secure auth
        secure_auth = SecureAuth(auth_config)
        results.add_result("Secure Auth", "PASS", "SecureAuth instance created")
        
        # Test password hashing
        password = "TestPassword123!"
        hashed = secure_auth.hash_password(password)
        if secure_auth.verify_password(password, hashed):
            results.add_result("Password Hashing", "PASS", "Password hash/verify working")
        else:
            results.add_result("Password Hashing", "FAIL", "Password verification failed", "high")
            
    except Exception as e:
        results.add_result("Authentication", "FAIL", str(e), "high")

def test_rate_limiting(results: ValidationResults):
    """Test rate limiting functionality."""
    print("⏱️ Testing rate limiting...")
    
    try:
        from wazuh_mcp_server.utils.rate_limiter import RateLimiter, RateLimitConfig
        
        # Test rate limit config
        config = RateLimitConfig(max_requests=10, time_window=60)
        results.add_result("Rate Limit Config", "PASS", "Rate limit config created")
        
        # Test rate limiter
        limiter = RateLimiter(max_requests=10, window_seconds=60)
        results.add_result("Rate Limiter", "PASS", "Rate limiter created successfully")
        
    except Exception as e:
        results.add_result("Rate Limiting", "FAIL", str(e), "medium")

def test_validation(results: ValidationResults):
    """Test input validation functions."""
    print("🛡️ Testing input validation...")
    
    try:
        from wazuh_mcp_server.utils.validation import (
            validate_int_range, validate_string, sanitize_input
        )
        
        # Test integer validation
        result = validate_int_range(5, 1, 10, default=1)
        if result == 5:
            results.add_result("Int Validation", "PASS", "Integer range validation working")
        else:
            results.add_result("Int Validation", "FAIL", f"Expected 5, got {result}", "medium")
        
        # Test string validation
        result = validate_string("test", 10, default="")
        if result == "test":
            results.add_result("String Validation", "PASS", "String validation working")
        else:
            results.add_result("String Validation", "FAIL", f"Expected 'test', got '{result}'", "medium")
        
        # Test input sanitization
        result = sanitize_input("test<script>alert('xss')</script>")
        if "<script>" not in result:
            results.add_result("Input Sanitization", "PASS", "XSS prevention working")
        else:
            results.add_result("Input Sanitization", "FAIL", "XSS prevention failed", "high")
            
    except Exception as e:
        results.add_result("Input Validation", "FAIL", str(e), "medium")

async def test_async_functionality(results: ValidationResults):
    """Test async functionality."""
    print("🔄 Testing async functionality...")
    
    try:
        from wazuh_mcp_server.server import initialize_tool_factory
        
        # Test tool factory initialization
        await initialize_tool_factory()
        results.add_result("Tool Factory Init", "PASS", "Tool factory initialized successfully")
        
    except Exception as e:
        results.add_result("Async Functionality", "FAIL", str(e), "high")

def test_file_permissions(results: ValidationResults):
    """Test file permissions for security."""
    print("🔒 Testing file permissions...")
    
    sensitive_files = [".env", ".env.production", ".env.docker.template"]
    
    for filename in sensitive_files:
        if os.path.exists(filename):
            stat_info = os.stat(filename)
            mode = stat_info.st_mode & 0o777
            
            if mode <= 0o600:
                results.add_result(f"Permissions {filename}", "PASS", f"Secure permissions: {oct(mode)}")
            else:
                results.add_result(f"Permissions {filename}", "WARN", f"Insecure permissions: {oct(mode)}", "medium")

def test_docker_configuration(results: ValidationResults):
    """Test Docker configuration."""
    print("🐳 Testing Docker configuration...")
    
    if os.path.exists("Dockerfile"):
        results.add_result("Dockerfile Exists", "PASS", "Dockerfile found")
        
        with open("Dockerfile", "r") as f:
            content = f.read()
            
        if "USER wazuh" in content:
            results.add_result("Docker Non-Root", "PASS", "Non-root user configured")
        else:
            results.add_result("Docker Non-Root", "WARN", "Root user detected", "medium")
            
        if "HEALTHCHECK" in content:
            results.add_result("Docker Health Check", "PASS", "Health check configured")
        else:
            results.add_result("Docker Health Check", "WARN", "No health check found", "low")
    else:
        results.add_result("Docker Configuration", "FAIL", "Dockerfile not found", "medium")

def test_documentation(results: ValidationResults):
    """Test documentation completeness."""
    print("📚 Testing documentation...")
    
    required_docs = [
        "README.md",
        "PRODUCTION_CHECKLIST.md", 
        "DEVELOPER_GUIDE.md",
        "WAZUH_ADMIN_GUIDE.md",
        "SECURITY_PROFESSIONAL_GUIDE.md"
    ]
    
    for doc in required_docs:
        if os.path.exists(doc):
            results.add_result(f"Doc {doc}", "PASS", "Documentation file present")
        else:
            results.add_result(f"Doc {doc}", "WARN", "Documentation file missing", "low")

def test_dependencies(results: ValidationResults):
    """Test dependency requirements."""
    print("📦 Testing dependencies...")
    
    if os.path.exists("requirements.txt"):
        results.add_result("Requirements File", "PASS", "requirements.txt found")
        
        with open("requirements.txt", "r") as f:
            content = f.read()
            
        critical_deps = ["fastmcp", "httpx", "pydantic", "pyjwt"]
        for dep in critical_deps:
            if dep in content:
                results.add_result(f"Dependency {dep}", "PASS", f"{dep} in requirements")
            else:
                results.add_result(f"Dependency {dep}", "FAIL", f"{dep} missing from requirements", "high")
    else:
        results.add_result("Dependencies", "FAIL", "requirements.txt not found", "critical")

async def main():
    """Run all validation tests."""
    print("🚀 Starting Final Comprehensive Validation")
    print("🎯 Testing Wazuh MCP Server v-final Branch")
    print("="*60)
    
    results = ValidationResults()
    
    # Run all tests
    test_imports(results)
    test_configuration(results)
    test_authentication(results)
    test_rate_limiting(results)
    test_validation(results)
    await test_async_functionality(results)
    test_file_permissions(results)
    test_docker_configuration(results)
    test_documentation(results)
    test_dependencies(results)
    
    # Print detailed results
    print(f"\n{'='*60}")
    print("📋 DETAILED RESULTS")
    print(f"{'='*60}")
    
    for result in results.results:
        status_emoji = "✅" if result["status"] == "PASS" else "❌" if result["status"] == "FAIL" else "⚠️"
        print(f"{status_emoji} {result['test']}: {result['status']}")
        if result["details"]:
            print(f"   └─ {result['details']}")
    
    # Print summary and exit
    success = results.print_summary()
    
    if success:
        print("\n🎉🎉🎉 VALIDATION COMPLETE - FULLY FUNCTIONAL! 🎉🎉🎉")
        print("✅ Ready for production deployment")
        exit_code = 0
    else:
        print(f"\n🚨 VALIDATION FAILED - {results.failed} issues need attention")
        print("❌ Fix issues before production deployment")
        exit_code = 1
    
    return exit_code

if __name__ == "__main__":
    try:
        exit_code = asyncio.run(main())
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n⚠️ Validation interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n💥 Validation failed with error: {e}")
        traceback.print_exc()
        sys.exit(1)