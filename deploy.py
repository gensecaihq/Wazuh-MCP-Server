#!/usr/bin/env python3
"""
OS-Agnostic Deployment Script for Wazuh MCP Server v4.0.6
Works on Windows, macOS, and Linux with Docker installed.
"""

import os
import sys
import subprocess
import time
import json
import secrets
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict

# ANSI colors (will be stripped on Windows if not supported)
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    CYAN = '\033[0;36m'
    NC = '\033[0m'  # No Color

    @classmethod
    def strip_colors(cls):
        """Strip colors for Windows without ANSI support"""
        cls.RED = cls.GREEN = cls.YELLOW = cls.BLUE = cls.CYAN = cls.NC = ''


# Detect Windows without ANSI support
if sys.platform == 'win32' and not os.environ.get('ANSICON'):
    Colors.strip_colors()


def print_header():
    """Print deployment header"""
    print(f"{Colors.CYAN}{'=' * 70}{Colors.NC}")
    print(f"{Colors.CYAN}   WAZUH MCP REMOTE SERVER - PRODUCTION DEPLOYMENT{Colors.NC}")
    print(f"{Colors.CYAN}   Version: 4.0.6 | OS-Agnostic Docker Deployment{Colors.NC}")
    print(f"{Colors.CYAN}{'=' * 70}{Colors.NC}\n")


def print_step(message: str):
    """Print step message"""
    print(f"{Colors.BLUE}▶ {message}{Colors.NC}")


def print_success(message: str):
    """Print success message"""
    print(f"{Colors.GREEN}✅ {message}{Colors.NC}")


def print_warning(message: str):
    """Print warning message"""
    print(f"{Colors.YELLOW}⚠️  {message}{Colors.NC}")


def print_error(message: str):
    """Print error message"""
    print(f"{Colors.RED}❌ {message}{Colors.NC}")


def run_command(cmd: List[str], check: bool = True, capture_output: bool = False) -> Optional[subprocess.CompletedProcess]:
    """Run a command and return result"""
    try:
        if capture_output:
            result = subprocess.run(cmd, capture_output=True, text=True, check=check)
            return result
        else:
            subprocess.run(cmd, check=check)
            return None
    except subprocess.CalledProcessError as e:
        if check:
            print_error(f"Command failed: {' '.join(cmd)}")
            print_error(f"Error: {e}")
            sys.exit(1)
        return None
    except FileNotFoundError:
        print_error(f"Command not found: {cmd[0]}")
        sys.exit(1)


def check_docker():
    """Check if Docker is installed and running"""
    print_step("Checking Docker installation...")

    # Check docker command
    result = run_command(['docker', '--version'], capture_output=True)
    if result:
        print_success(f"Docker found: {result.stdout.strip()}")

    # Check docker compose
    result = run_command(['docker', 'compose', 'version'], capture_output=True)
    if result:
        print_success(f"Docker Compose found: {result.stdout.strip()}")

    # Check if Docker daemon is running
    result = run_command(['docker', 'info'], check=False, capture_output=True)
    if result and result.returncode == 0:
        print_success("Docker daemon is running")
    else:
        print_error("Docker daemon is not running. Please start Docker first.")
        sys.exit(1)


def setup_environment():
    """Setup environment configuration"""
    print_step("Setting up environment configuration...")

    env_file = Path('.env')
    env_example = Path('.env.example')

    if not env_file.exists():
        if env_example.exists():
            # Copy .env.example to .env
            with open(env_example, 'r') as src:
                content = src.read()
            with open(env_file, 'w') as dst:
                dst.write(content)
            print_success("Created .env from .env.example")
        else:
            print_error(".env file not found and no .env.example template available")
            sys.exit(1)

    # Validate required variables
    required_vars = ['WAZUH_HOST', 'WAZUH_USER', 'WAZUH_PASS']
    missing_vars = []

    with open(env_file, 'r') as f:
        env_content = f.read()

    for var in required_vars:
        if f"{var}=" not in env_content or f"{var}=your-" in env_content:
            missing_vars.append(var)

    if missing_vars:
        print_error("Please configure the following variables in .env:")
        for var in missing_vars:
            print(f"  - {var}")
        print(f"\nEdit the .env file and run this script again.")
        sys.exit(1)

    print_success("Environment configuration validated")


def generate_api_key() -> str:
    """Generate a secure API key"""
    print_step("Generating API key for client authentication...")

    # Generate secure random key
    random_bytes = secrets.token_bytes(32)
    api_key = f"wazuh_{random_bytes.hex()[:32]}"

    print()
    print_success(f"Generated API key: {api_key}")
    print_warning("Save this API key securely - it won't be shown again")
    print(f"{Colors.CYAN}Use this key to authenticate with the MCP server{Colors.NC}")
    print()

    # Save to secure file
    api_key_file = Path('.api_key')
    with open(api_key_file, 'w') as f:
        f.write(f"API_KEY={api_key}\n")

    # Set permissions (works on Unix-like systems, silently fails on Windows)
    try:
        os.chmod(api_key_file, 0o600)
    except:
        pass  # Windows doesn't support chmod

    print_success("API key saved to .api_key")

    return api_key


def build_and_deploy():
    """Build and deploy the MCP server"""
    print_step("Building and deploying MCP server...")

    # Set build metadata
    os.environ['BUILD_DATE'] = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
    os.environ['VERSION'] = os.environ.get('VERSION', '4.0.6')
    os.environ['PYTHON_VERSION'] = os.environ.get('PYTHON_VERSION', '3.13')

    # Build with Docker Compose
    print_step("Building container image...")
    run_command(['docker', 'compose', 'build', '--pull'])

    # Deploy with health check wait
    print_step("Starting MCP server with health checks...")
    run_command(['docker', 'compose', 'up', '-d', '--wait', '--wait-timeout', '120'])

    print_success("MCP server deployed successfully")


def wait_for_services():
    """Wait for services to be ready"""
    print_step("Waiting for services to be ready...")

    max_attempts = 30
    port = os.environ.get('MCP_PORT', '3000')

    for attempt in range(1, max_attempts + 1):
        try:
            # Try to connect to health endpoint
            import urllib.request
            req = urllib.request.Request(f'http://localhost:{port}/health')
            urllib.request.urlopen(req, timeout=2)
            print()
            print_success("Services are ready")
            return True
        except:
            print('.', end='', flush=True)
            time.sleep(2)

    print()
    print_error("Services failed to start within timeout")
    print_step("Showing last 50 log lines:")
    run_command(['docker', 'compose', 'logs', '--tail=50'])
    return False


def run_health_checks() -> bool:
    """Run health checks"""
    print_step("Running health checks...")

    port = os.environ.get('MCP_PORT', '3000')

    try:
        import urllib.request
        import json as json_lib

        req = urllib.request.Request(f'http://localhost:{port}/health')
        with urllib.request.urlopen(req, timeout=5) as response:
            data = json_lib.loads(response.read().decode())
            if data.get('status') == 'healthy':
                print_success("MCP server is healthy")
                return True
            else:
                print_error("MCP server health check failed")
                return False
    except Exception as e:
        print_error(f"MCP server health check failed: {e}")
        return False


def show_deployment_info(api_key: str):
    """Show deployment information"""
    print_step("Deployment complete! Here's your service information:")

    port = os.environ.get('MCP_PORT', '3000')

    print()
    print(f"{Colors.CYAN}🔗 Service URLs:{Colors.NC}")
    print(f"  • MCP Server: http://localhost:{port}")
    print(f"  • Health Check: http://localhost:{port}/health")
    print(f"  • Metrics: http://localhost:{port}/metrics")
    print(f"  • API Docs: http://localhost:{port}/docs")
    print()

    print(f"{Colors.CYAN}🔑 Authentication:{Colors.NC}")
    print(f"  • API Key: {api_key}")
    print(f"  • Get JWT Token:")
    print(f'    curl -X POST http://localhost:{port}/auth/token \\')
    print(f'      -H "Content-Type: application/json" \\')
    print(f'      -d \'{{"api_key":"{api_key}"}}\'')
    print()

    print(f"{Colors.CYAN}📊 Monitoring:{Colors.NC}")
    print("  • Container Status: docker compose ps")
    print("  • Live Logs: docker compose logs -f")
    print(f"  • Metrics: curl http://localhost:{port}/metrics")
    print()

    print(f"{Colors.CYAN}🔧 Management:{Colors.NC}")
    print("  • Stop: docker compose down")
    print("  • Restart: docker compose restart")
    print(f"  • Update: python {sys.argv[0]} deploy")
    print()

    print(f"{Colors.CYAN}🤖 Claude Desktop Configuration:{Colors.NC}")
    print("  Add this to your Claude Desktop config:")
    print('  {')
    print('    "mcpServers": {')
    print('      "wazuh-security": {')
    print(f'        "url": "http://localhost:{port}/mcp",')
    print('        "headers": {')
    print('          "Authorization": "Bearer YOUR_JWT_TOKEN_HERE",')
    print('          "MCP-Protocol-Version": "2025-11-25"')
    print('        }')
    print('      }')
    print('    }')
    print('  }')
    print()


def stop_services():
    """Stop services"""
    print_step("Stopping services...")
    run_command(['docker', 'compose', 'down'])
    print_success("Services stopped")


def restart_services():
    """Restart services"""
    print_step("Restarting services...")
    run_command(['docker', 'compose', 'restart'])
    print_success("Services restarted")


def show_logs():
    """Show logs"""
    run_command(['docker', 'compose', 'logs', '-f'])


def show_status():
    """Show status"""
    print(f"{Colors.CYAN}Service Status:{Colors.NC}")
    run_command(['docker', 'compose', 'ps'])

    print(f"\n{Colors.CYAN}Resource Usage:{Colors.NC}")
    run_command(['docker', 'stats', '--no-stream', '--format',
                 'table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}',
                 'wazuh-mcp-remote-server'])


def cleanup():
    """Cleanup resources"""
    print_step("Cleaning up resources...")
    run_command(['docker', 'compose', 'down', '--volumes', '--remove-orphans', '--timeout', '30'])
    print_success("Cleanup completed")


def main_deploy():
    """Main deployment function"""
    print_header()

    try:
        # Run deployment steps
        check_docker()
        setup_environment()
        api_key = generate_api_key()
        build_and_deploy()

        if wait_for_services():
            if run_health_checks():
                print_success("All health checks passed")
                show_deployment_info(api_key)
                print_success("Deployment completed successfully!")
                return 0
            else:
                print_error("Some health checks failed, check logs for details")
                run_command(['docker', 'compose', 'logs', '--tail=20'])
                return 1
        else:
            return 1

    except KeyboardInterrupt:
        print()
        print_warning("Deployment interrupted by user")
        return 1
    except Exception as e:
        print_error(f"Deployment failed: {e}")
        print_step("Cleaning up...")
        run_command(['docker', 'compose', 'down', '--remove-orphans'], check=False)
        return 1


def print_usage():
    """Print usage information"""
    print("Usage: python deploy.py [COMMAND]")
    print("\nCommands:")
    print("  deploy   - Deploy the MCP server (default)")
    print("  stop     - Stop all services")
    print("  restart  - Restart the MCP server")
    print("  logs     - Follow service logs")
    print("  status   - Show service status and resource usage")
    print("  cleanup  - Stop services and clean up resources")
    print("\nExamples:")
    print("  python deploy.py")
    print("  python deploy.py deploy")
    print("  python deploy.py stop")
    print("  python deploy.py logs")


if __name__ == '__main__':
    command = sys.argv[1] if len(sys.argv) > 1 else 'deploy'

    commands = {
        'deploy': main_deploy,
        'stop': lambda: stop_services() or 0,
        'restart': lambda: restart_services() or 0,
        'logs': lambda: show_logs() or 0,
        'status': lambda: show_status() or 0,
        'cleanup': lambda: cleanup() or 0,
        'help': lambda: print_usage() or 0,
        '--help': lambda: print_usage() or 0,
        '-h': lambda: print_usage() or 0,
    }

    if command in commands:
        sys.exit(commands[command]())
    else:
        print_error(f"Unknown command: {command}")
        print_usage()
        sys.exit(1)
