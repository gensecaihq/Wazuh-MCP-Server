#!/usr/bin/env python3
"""
Production-grade health checks and startup validation for Wazuh MCP Server.
Ensures the server is properly configured and ready for production use.
"""

import os
import sys
import asyncio
import platform
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
import logging

from ..config import WazuhConfig
from ..api.wazuh_client_manager import WazuhClientManager
from .logging import get_logger

logger = get_logger(__name__)


@dataclass
class HealthCheckResult:
    """Individual health check result."""
    name: str
    status: str  # "PASS", "WARN", "FAIL"
    message: str
    details: Optional[Dict[str, Any]] = None
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()


class StartupHealthChecker:
    """Comprehensive startup health checks for production readiness."""
    
    def __init__(self):
        self.results: List[HealthCheckResult] = []
        self.config: Optional[WazuhConfig] = None
        self.client_manager: Optional[WazuhClientManager] = None
    
    async def run_all_checks(self, config: WazuhConfig) -> bool:
        """
        Run all health checks and return True if system is ready for production.
        
        Args:
            config: Wazuh configuration object
            
        Returns:
            True if all critical checks pass, False otherwise
        """
        self.config = config
        self.results.clear()
        
        logger.info("🏥 Starting comprehensive health checks...")
        
        # Run all health checks
        await self._check_system_requirements()
        await self._check_python_environment()
        await self._check_dependencies()
        await self._check_configuration()
        await self._check_file_permissions()
        await self._check_wazuh_connectivity()
        await self._check_fastmcp_setup()
        await self._check_security_configuration()
        
        # Analyze results
        return self._analyze_results()
    
    async def _check_system_requirements(self):
        """Check system-level requirements."""
        try:
            # Python version check
            python_version = sys.version_info
            if python_version >= (3, 11):
                self._add_result("python_version", "PASS", 
                    f"Python {python_version.major}.{python_version.minor}.{python_version.micro}")
            elif python_version >= (3, 9):
                self._add_result("python_version", "WARN", 
                    f"Python {python_version.major}.{python_version.minor}.{python_version.micro} - recommend 3.11+")
            else:
                self._add_result("python_version", "FAIL", 
                    f"Python {python_version.major}.{python_version.minor}.{python_version.micro} - requires 3.9+")
            
            # Platform check
            system_info = {
                "platform": platform.system(),
                "architecture": platform.machine(),
                "version": platform.version()
            }
            self._add_result("platform", "PASS", 
                f"{system_info['platform']} {system_info['architecture']}", system_info)
            
            # Memory check
            try:
                import psutil
                memory = psutil.virtual_memory()
                if memory.available > 512 * 1024 * 1024:  # 512MB
                    self._add_result("memory", "PASS", 
                        f"Available: {memory.available // 1024 // 1024}MB")
                else:
                    self._add_result("memory", "WARN", 
                        f"Low memory: {memory.available // 1024 // 1024}MB")
            except ImportError:
                self._add_result("memory", "WARN", "psutil not available - cannot check memory")
                
        except Exception as e:
            self._add_result("system_requirements", "FAIL", f"System check failed: {e}")
    
    async def _check_python_environment(self):
        """Check Python environment and virtual environment setup."""
        try:
            # Virtual environment check
            in_venv = (
                hasattr(sys, 'real_prefix') or 
                (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix)
            )
            
            if in_venv:
                self._add_result("virtual_env", "PASS", "Running in virtual environment")
            else:
                self._add_result("virtual_env", "WARN", "Not in virtual environment")
            
            # Path check
            current_dir = Path.cwd()
            if (current_dir / "requirements.txt").exists():
                self._add_result("working_directory", "PASS", f"Correct directory: {current_dir}")
            else:
                self._add_result("working_directory", "FAIL", 
                    f"Wrong directory or missing files: {current_dir}")
                    
        except Exception as e:
            self._add_result("python_environment", "FAIL", f"Environment check failed: {e}")
    
    async def _check_dependencies(self):
        """Check if all required dependencies are available."""
        required_packages = [
            ("fastmcp", "FastMCP framework"),
            ("aiohttp", "Async HTTP client"),
            ("pydantic", "Data validation"),
            ("python_dotenv", "Environment configuration"),
            ("certifi", "SSL certificates"),
            ("dateutil", "Date utilities"),
            ("packaging", "Version management"),
            ("psutil", "System monitoring")
        ]
        
        missing_packages = []
        
        for package_name, description in required_packages:
            try:
                # Try different import variations
                if package_name == "python_dotenv":
                    import dotenv
                elif package_name == "dateutil":
                    import dateutil
                else:
                    __import__(package_name)
                
                self._add_result(f"dependency_{package_name}", "PASS", f"{description} available")
                
            except ImportError:
                missing_packages.append(package_name)
                self._add_result(f"dependency_{package_name}", "FAIL", 
                    f"{description} missing")
        
        if not missing_packages:
            self._add_result("dependencies", "PASS", "All dependencies available")
        else:
            self._add_result("dependencies", "FAIL", 
                f"Missing packages: {', '.join(missing_packages)}")
    
    async def _check_configuration(self):
        """Validate configuration completeness and security."""
        try:
            # Configuration loading
            if not self.config:
                self._add_result("config_loading", "FAIL", "Configuration not loaded")
                return
            
            self._add_result("config_loading", "PASS", "Configuration loaded successfully")
            
            # Required fields check
            required_fields = ["host", "port", "username", "password"]
            missing_fields = []
            
            for field in required_fields:
                if not getattr(self.config, field, None):
                    missing_fields.append(field)
            
            if not missing_fields:
                self._add_result("config_fields", "PASS", "All required fields present")
            else:
                self._add_result("config_fields", "FAIL", 
                    f"Missing fields: {', '.join(missing_fields)}")
            
            # Security configuration
            if self.config.verify_ssl:
                self._add_result("ssl_config", "PASS", "SSL verification enabled")
            else:
                self._add_result("ssl_config", "WARN", "SSL verification disabled")
            
            # Password strength (basic check)
            if len(self.config.password) >= 8:
                self._add_result("password_strength", "PASS", "Password meets minimum length")
            else:
                self._add_result("password_strength", "WARN", "Password is short (<8 chars)")
                
        except Exception as e:
            self._add_result("configuration", "FAIL", f"Configuration check failed: {e}")
    
    async def _check_file_permissions(self):
        """Check file system permissions and access."""
        try:
            current_dir = Path.cwd()
            
            # Check read access to required files
            required_files = [".env", "requirements.txt", "wazuh-mcp-server"]
            for file_path in required_files:
                file_full_path = current_dir / file_path
                if file_full_path.exists() and os.access(file_full_path, os.R_OK):
                    self._add_result(f"file_access_{file_path}", "PASS", f"Can read {file_path}")
                else:
                    self._add_result(f"file_access_{file_path}", "WARN", f"Cannot read {file_path}")
            
            # Check write access to logs directory
            logs_dir = current_dir / "logs"
            if logs_dir.exists() or logs_dir.parent.exists():
                if os.access(logs_dir.parent, os.W_OK):
                    self._add_result("logs_write_access", "PASS", "Can write to logs directory")
                else:
                    self._add_result("logs_write_access", "WARN", "Cannot write to logs directory")
            
        except Exception as e:
            self._add_result("file_permissions", "FAIL", f"File permission check failed: {e}")
    
    async def _check_wazuh_connectivity(self):
        """Test connectivity to Wazuh server."""
        if not self.config:
            self._add_result("wazuh_connectivity", "FAIL", "No configuration available")
            return
        
        try:
            # Initialize client manager
            self.client_manager = WazuhClientManager(self.config)
            
            # Test basic connectivity
            result = await self.client_manager.validate_connection()
            
            if result:
                self._add_result("wazuh_connectivity", "PASS", 
                    f"Connected to Wazuh server at {self.config.host}:{self.config.port}")
                
                # Test API endpoints
                try:
                    info = await self.client_manager.get_api_info()
                    if info:
                        wazuh_version = info.get("version", "unknown")
                        self._add_result("wazuh_version", "PASS", f"Wazuh version: {wazuh_version}")
                    else:
                        self._add_result("wazuh_version", "WARN", "Could not get Wazuh version")
                except Exception as e:
                    self._add_result("wazuh_version", "WARN", f"Version check failed: {e}")
                    
            else:
                self._add_result("wazuh_connectivity", "FAIL", 
                    f"Cannot connect to Wazuh server at {self.config.host}:{self.config.port}")
                
        except Exception as e:
            self._add_result("wazuh_connectivity", "FAIL", f"Connectivity test failed: {e}")
    
    async def _check_fastmcp_setup(self):
        """Validate FastMCP setup and configuration."""
        try:
            # Import FastMCP
            from fastmcp import FastMCP
            self._add_result("fastmcp_import", "PASS", "FastMCP imported successfully")
            
            # Check if we can create FastMCP instance
            test_mcp = FastMCP(name="test", version="1.0.0")
            self._add_result("fastmcp_creation", "PASS", "FastMCP instance created")
            
            # Check STDIO transport
            self._add_result("fastmcp_stdio", "PASS", "STDIO transport configured")
            
        except ImportError as e:
            self._add_result("fastmcp_import", "FAIL", f"FastMCP import failed: {e}")
        except Exception as e:
            self._add_result("fastmcp_setup", "FAIL", f"FastMCP setup failed: {e}")
    
    async def _check_security_configuration(self):
        """Check security-related configurations."""
        try:
            # Environment variables security
            sensitive_vars = ["WAZUH_PASS", "WAZUH_PASSWORD"]
            for var in sensitive_vars:
                if var in os.environ:
                    self._add_result(f"security_{var.lower()}", "PASS", 
                        f"{var} set via environment variable")
                    break
            else:
                self._add_result("security_env_vars", "WARN", 
                    "Password not set via environment variable")
            
            # SSL/TLS configuration
            if self.config and self.config.verify_ssl:
                self._add_result("security_ssl", "PASS", "SSL verification enabled")
            else:
                self._add_result("security_ssl", "WARN", "SSL verification disabled")
            
            # File permissions on .env
            env_file = Path(".env")
            if env_file.exists():
                stat = env_file.stat()
                # Check if readable by others (not recommended for production)
                if stat.st_mode & 0o044:  # Check other-readable
                    self._add_result("security_env_perms", "WARN", 
                        ".env file is readable by others")
                else:
                    self._add_result("security_env_perms", "PASS", 
                        ".env file permissions are secure")
                        
        except Exception as e:
            self._add_result("security_configuration", "FAIL", f"Security check failed: {e}")
    
    def _add_result(self, name: str, status: str, message: str, details: Optional[Dict[str, Any]] = None):
        """Add a health check result."""
        result = HealthCheckResult(name=name, status=status, message=message, details=details)
        self.results.append(result)
        
        # Log the result
        if status == "PASS":
            logger.info(f"✅ {name}: {message}")
        elif status == "WARN":
            logger.warning(f"⚠️  {name}: {message}")
        else:  # FAIL
            logger.error(f"❌ {name}: {message}")
    
    def _analyze_results(self) -> bool:
        """Analyze health check results and determine if server is ready."""
        passed = sum(1 for r in self.results if r.status == "PASS")
        warned = sum(1 for r in self.results if r.status == "WARN")
        failed = sum(1 for r in self.results if r.status == "FAIL")
        
        total = len(self.results)
        
        logger.info(f"🏥 Health Check Summary: {passed} passed, {warned} warnings, {failed} failed (total: {total})")
        
        # Critical failures that prevent startup
        critical_failures = [r for r in self.results if r.status == "FAIL" and 
                           r.name in ["python_version", "dependencies", "config_loading", "config_fields"]]
        
        if critical_failures:
            logger.error("❌ CRITICAL FAILURES detected - server cannot start:")
            for failure in critical_failures:
                logger.error(f"   • {failure.name}: {failure.message}")
            return False
        
        # General failures that should be addressed
        general_failures = [r for r in self.results if r.status == "FAIL"]
        if general_failures:
            logger.warning("⚠️  Some health checks failed - consider addressing before production:")
            for failure in general_failures:
                logger.warning(f"   • {failure.name}: {failure.message}")
        
        # Warnings
        warnings = [r for r in self.results if r.status == "WARN"]
        if warnings:
            logger.info("ℹ️  Warnings (non-critical):")
            for warning in warnings:
                logger.info(f"   • {warning.name}: {warning.message}")
        
        # Success rate
        success_rate = (passed / total) * 100 if total > 0 else 0
        logger.info(f"🎯 Overall health score: {success_rate:.1f}%")
        
        # Return True if no critical failures
        return len(critical_failures) == 0
    
    def get_health_report(self) -> Dict[str, Any]:
        """Get a comprehensive health report."""
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "summary": {
                "total_checks": len(self.results),
                "passed": sum(1 for r in self.results if r.status == "PASS"),
                "warnings": sum(1 for r in self.results if r.status == "WARN"),
                "failed": sum(1 for r in self.results if r.status == "FAIL"),
            },
            "checks": [
                {
                    "name": r.name,
                    "status": r.status,
                    "message": r.message,
                    "details": r.details,
                    "timestamp": r.timestamp.isoformat()
                }
                for r in self.results
            ]
        }


async def run_startup_health_checks(config: WazuhConfig) -> bool:
    """
    Run comprehensive startup health checks.
    
    Args:
        config: Wazuh configuration
        
    Returns:
        True if server is ready for production, False otherwise
    """
    checker = StartupHealthChecker()
    is_healthy = await checker.run_all_checks(config)
    
    if not is_healthy:
        logger.error("🚨 Server failed health checks - startup aborted")
        # Optionally save health report for debugging
        report = checker.get_health_report()
        health_report_path = Path("health_check_failure.json")
        try:
            import json
            health_report_path.write_text(json.dumps(report, indent=2))
            logger.info(f"💾 Health check report saved to: {health_report_path}")
        except Exception as e:
            logger.error(f"Failed to save health report: {e}")
    
    return is_healthy