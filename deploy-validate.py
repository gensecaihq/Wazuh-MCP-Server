#!/usr/bin/env python3
"""
Wazuh MCP Server Deployment Validation Script
Validates the deployment configuration and readiness
"""

import os
import sys
import json
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional

def print_header(title: str):
    """Print a formatted header"""
    print("\n" + "=" * 80)
    print(f"📋 {title.upper()}")
    print("=" * 80)

def print_check(message: str, status: bool, details: str = ""):
    """Print a check result"""
    icon = "✅" if status else "❌"
    print(f"{icon} {message}")
    if details:
        print(f"   └─ {details}")

def check_docker_availability() -> bool:
    """Check if Docker is available and running"""
    print_header("Docker Environment Check")
    
    try:
        # Check if docker command exists
        result = subprocess.run(['docker', '--version'], 
                              capture_output=True, text=True, timeout=5)
        docker_available = result.returncode == 0
        print_check("Docker command available", docker_available, result.stdout.strip() if docker_available else "Docker not found in PATH")
        
        if not docker_available:
            return False
        
        # Check if Docker daemon is running
        result = subprocess.run(['docker', 'info'], 
                              capture_output=True, text=True, timeout=10)
        daemon_running = result.returncode == 0
        print_check("Docker daemon running", daemon_running, 
                   "Docker daemon is accessible" if daemon_running else "Docker daemon not running")
        
        # Check Docker Compose
        result = subprocess.run(['docker', 'compose', 'version'], 
                              capture_output=True, text=True, timeout=5)
        compose_available = result.returncode == 0
        print_check("Docker Compose available", compose_available, 
                   result.stdout.strip() if compose_available else "Docker Compose not found")
        
        return daemon_running and compose_available
        
    except subprocess.TimeoutExpired:
        print_check("Docker check", False, "Docker command timed out")
        return False
    except Exception as e:
        print_check("Docker check", False, f"Error: {e}")
        return False

def check_file_structure() -> bool:
    """Check if required files and directories exist"""
    print_header("File Structure Check")
    
    required_files = [
        'Dockerfile',
        'compose.yml',
        'requirements.txt',
        'pyproject.toml',
        'src/wazuh_mcp_server/__init__.py',
        'src/wazuh_mcp_server/server.py',
        'src/wazuh_mcp_server/config.py',
        'wazuh-mcp-server',
        'validate-production.py',
        'configure.py'
    ]
    
    required_dirs = [
        'src',
        'src/wazuh_mcp_server',
        'src/wazuh_mcp_server/api',
        'src/wazuh_mcp_server/utils',
        'tests',
        'docker',
        'logs',
        'config',
        'config/certs'
    ]
    
    all_good = True
    
    for file_path in required_files:
        exists = Path(file_path).is_file()
        print_check(f"File: {file_path}", exists)
        if not exists:
            all_good = False
    
    for dir_path in required_dirs:
        exists = Path(dir_path).is_dir()
        print_check(f"Directory: {dir_path}", exists)
        if not exists:
            all_good = False
    
    return all_good

def check_configuration_files() -> Dict[str, Any]:
    """Check configuration files"""
    print_header("Configuration Files Check")
    
    config_status = {
        'env_file_exists': False,
        'env_file_configured': False,
        'docker_env_exists': False,
        'templates_exist': False
    }
    
    # Check .env file
    env_file = Path('.env')
    config_status['env_file_exists'] = env_file.exists()
    print_check(".env file exists", config_status['env_file_exists'])
    
    if config_status['env_file_exists']:
        try:
            with open('.env', 'r') as f:
                content = f.read()
                # Check if basic required variables are set
                required_vars = ['WAZUH_HOST', 'WAZUH_USER', 'WAZUH_PASS']
                configured_vars = []
                for var in required_vars:
                    if f"{var}=" in content and f"{var}=your-" not in content:
                        configured_vars.append(var)
                
                config_status['env_file_configured'] = len(configured_vars) == len(required_vars)
                print_check(".env file configured", config_status['env_file_configured'],
                           f"Configured: {', '.join(configured_vars)}")
        except Exception as e:
            print_check(".env file readable", False, str(e))
    
    # Check Docker environment file
    docker_env = Path('docker/.env.docker')
    config_status['docker_env_exists'] = docker_env.exists()
    print_check("Docker .env file exists", config_status['docker_env_exists'])
    
    # Check templates
    templates = ['.env.production.template', '.env.docker.template']
    template_count = sum(1 for t in templates if Path(t).exists())
    config_status['templates_exist'] = template_count == len(templates)
    print_check(f"Configuration templates ({template_count}/{len(templates)})", 
               config_status['templates_exist'])
    
    return config_status

def check_python_environment() -> bool:
    """Check Python environment and dependencies"""
    print_header("Python Environment Check")
    
    # Check Python version
    python_version = sys.version_info
    version_ok = python_version >= (3, 10)
    print_check(f"Python version {python_version.major}.{python_version.minor}.{python_version.micro}", 
               version_ok, "Requires Python 3.10+" if not version_ok else "Version compatible")
    
    # Check if requirements.txt exists
    req_file = Path('requirements.txt')
    if not req_file.exists():
        print_check("requirements.txt exists", False)
        return False
    
    print_check("requirements.txt exists", True)
    
    # Try to parse requirements
    try:
        with open('requirements.txt', 'r') as f:
            requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        
        print_check("Requirements file readable", True, f"{len(requirements)} packages listed")
        
        # Check if core dependencies are listed
        core_deps = ['fastmcp', 'httpx', 'pydantic', 'python-dotenv']
        found_deps = []
        for req in requirements:
            package = req.split('==')[0].split('>=')[0].split('[')[0]
            if package in core_deps:
                found_deps.append(package)
        
        deps_ok = len(found_deps) >= len(core_deps) - 1  # Allow for some flexibility
        print_check("Core dependencies listed", deps_ok, f"Found: {', '.join(found_deps)}")
        
        return version_ok and deps_ok
        
    except Exception as e:
        print_check("Requirements parsing", False, str(e))
        return False

def check_dockerfile() -> bool:
    """Check Dockerfile validity"""
    print_header("Dockerfile Check")
    
    dockerfile = Path('Dockerfile')
    if not dockerfile.exists():
        print_check("Dockerfile exists", False)
        return False
    
    print_check("Dockerfile exists", True)
    
    try:
        with open('Dockerfile', 'r') as f:
            content = f.read()
        
        # Check for required instructions
        required_instructions = ['FROM', 'WORKDIR', 'COPY', 'RUN', 'EXPOSE', 'ENTRYPOINT']
        found_instructions = []
        
        for instruction in required_instructions:
            if f"\n{instruction} " in content or content.startswith(f"{instruction} "):
                found_instructions.append(instruction)
        
        instructions_ok = len(found_instructions) >= 5  # Allow some flexibility
        print_check("Required Docker instructions", instructions_ok, 
                   f"Found: {', '.join(found_instructions)}")
        
        # Check for multi-stage build
        multi_stage = content.count('FROM ') >= 2 or 'as builder' in content
        print_check("Multi-stage build", multi_stage, "Optimized build process")
        
        # Check for security practices
        security_checks = {
            'non_root_user': 'USER ' in content,
            'health_check': 'HEALTHCHECK' in content,
            'minimal_base': 'slim' in content or 'alpine' in content
        }
        
        for check, status in security_checks.items():
            print_check(f"Security: {check.replace('_', ' ')}", status)
        
        return instructions_ok
        
    except Exception as e:
        print_check("Dockerfile readable", False, str(e))
        return False

def check_compose_file() -> bool:
    """Check Docker Compose file"""
    print_header("Docker Compose Check")
    
    compose_file = Path('compose.yml')
    if not compose_file.exists():
        # Try docker-compose.yml as fallback
        compose_file = Path('docker-compose.yml')
    
    if not compose_file.exists():
        print_check("Compose file exists", False, "Neither compose.yml nor docker-compose.yml found")
        return False
    
    print_check(f"Compose file exists ({compose_file.name})", True)
    
    try:
        with open(compose_file, 'r') as f:
            content = f.read()
        
        # Check for required sections
        required_sections = ['services:', 'wazuh-mcp-server:', 'environment:', 'ports:', 'healthcheck:']
        found_sections = []
        
        for section in required_sections:
            if section in content:
                found_sections.append(section.rstrip(':'))
        
        sections_ok = len(found_sections) >= 4
        print_check("Required compose sections", sections_ok, 
                   f"Found: {', '.join(found_sections)}")
        
        # Check for Docker Compose v2 features
        v2_features = ['name:', 'profiles:', 'networks:', 'volumes:']
        v2_count = sum(1 for feature in v2_features if feature in content)
        print_check("Docker Compose v2 features", v2_count >= 2, 
                   f"Using {v2_count} v2 features")
        
        return sections_ok
        
    except Exception as e:
        print_check("Compose file readable", False, str(e))
        return False

def provide_recommendations(config_status: Dict[str, Any]) -> None:
    """Provide deployment recommendations"""
    print_header("Deployment Recommendations")
    
    recommendations = []
    
    if not config_status.get('env_file_configured', False):
        recommendations.append("🔧 Run 'python3 configure.py' to set up your Wazuh configuration")
    
    if not Path('.env').exists():
        recommendations.append("📝 Create .env file: cp .env.production.template .env")
    
    recommendations.extend([
        "🔍 Test Wazuh connectivity: python3 validate-production.py --quick",
        "🐳 Build image: docker build -t wazuh-mcp-server:latest .",
        "🚀 Deploy: docker compose up -d",
        "📊 Monitor: docker compose logs -f wazuh-mcp-server",
        "💾 Backup: Keep your .env file secure and backed up"
    ])
    
    print("\nNext steps:")
    for i, rec in enumerate(recommendations, 1):
        print(f"{i:2d}. {rec}")

def main():
    """Main validation function"""
    print("🛡️  WAZUH MCP SERVER - DEPLOYMENT VALIDATION")
    print("=" * 80)
    print("This script validates your deployment setup and configuration.")
    print("=" * 80)
    
    checks = {
        'docker': check_docker_availability(),
        'files': check_file_structure(),
        'python': check_python_environment(),
        'dockerfile': check_dockerfile(),
        'compose': check_compose_file()
    }
    
    config_status = check_configuration_files()
    checks['config'] = config_status.get('env_file_exists', False)
    
    print_header("Validation Summary")
    
    passed_checks = sum(1 for check in checks.values() if check)
    total_checks = len(checks)
    
    for check_name, status in checks.items():
        print_check(f"{check_name.capitalize()} validation", status)
    
    print(f"\n📊 Overall Status: {passed_checks}/{total_checks} checks passed")
    
    if passed_checks == total_checks:
        print("\n🎉 All checks passed! Your deployment is ready.")
        print("   Run: docker compose up -d")
    elif passed_checks >= total_checks - 1:
        print("\n⚠️  Almost ready! Please address the remaining issue(s).")
    else:
        print("\n❌ Several issues need to be resolved before deployment.")
    
    provide_recommendations(config_status)
    
    return passed_checks == total_checks

if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n❌ Validation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Validation failed: {e}")
        sys.exit(1)