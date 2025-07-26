#!/usr/bin/env python3
"""
Wazuh MCP Server Interactive Configuration Setup
This script helps you configure your Wazuh MCP Server deployment with your specific settings.
"""

import os
import sys
import json
import re
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime

def print_banner():
    """Print the configuration banner"""
    print("=" * 80)
    print("🛡️  WAZUH MCP SERVER - INTERACTIVE CONFIGURATION SETUP")
    print("=" * 80)
    print("This script will help you configure your Wazuh MCP Server deployment.")
    print("You can press Enter to use default values shown in [brackets].")
    print("=" * 80)
    print()

def validate_ip_or_hostname(value: str) -> bool:
    """Validate IP address or hostname format"""
    if not value:
        return False
    
    # Check if it's an IP address
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ip_pattern, value):
        # Validate IP octets
        octets = value.split('.')
        return all(0 <= int(octet) <= 255 for octet in octets)
    
    # Check if it's a valid hostname
    hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-\.]*[a-zA-Z0-9])?$'
    return bool(re.match(hostname_pattern, value)) and len(value) <= 253

def validate_port(value: str) -> bool:
    """Validate port number"""
    try:
        port = int(value)
        return 1 <= port <= 65535
    except ValueError:
        return False

def get_user_input(prompt: str, default: str = "", validator=None, required: bool = True) -> str:
    """Get user input with validation"""
    while True:
        if default:
            user_input = input(f"{prompt} [{default}]: ").strip()
            if not user_input:
                user_input = default
        else:
            user_input = input(f"{prompt}: ").strip()
        
        if not user_input and required:
            print("❌ This field is required. Please enter a value.")
            continue
        
        if not user_input and not required:
            return ""
        
        if validator and not validator(user_input):
            print("❌ Invalid format. Please try again.")
            continue
        
        return user_input

def get_yes_no(prompt: str, default: bool = True) -> bool:
    """Get yes/no input from user"""
    default_str = "Y/n" if default else "y/N"
    while True:
        response = input(f"{prompt} [{default_str}]: ").strip().lower()
        if not response:
            return default
        if response in ['y', 'yes', 'true', '1']:
            return True
        elif response in ['n', 'no', 'false', '0']:
            return False
        else:
            print("❌ Please enter 'y' for yes or 'n' for no.")

def configure_wazuh_server() -> Dict[str, Any]:
    """Configure Wazuh server settings"""
    print("📡 1. WAZUH SERVER CONFIGURATION")
    print("-" * 40)
    
    config = {}
    
    # Wazuh Server
    print("\n🔹 Wazuh Manager Server:")
    config['WAZUH_HOST'] = get_user_input(
        "Enter Wazuh Manager hostname or IP address",
        validator=validate_ip_or_hostname
    )
    
    config['WAZUH_PORT'] = get_user_input(
        "Enter Wazuh API port",
        default="55000",
        validator=validate_port
    )
    
    config['WAZUH_USER'] = get_user_input(
        "Enter Wazuh API username",
        default="mcp-api-user"
    )
    
    config['WAZUH_PASS'] = get_user_input(
        "Enter Wazuh API password"
    )
    
    # Distributed setup
    print("\n🔹 Distributed Setup (Optional):")
    has_separate_indexer = get_yes_no(
        "Do you have a separate Wazuh Indexer server?",
        default=False
    )
    
    if has_separate_indexer:
        config['WAZUH_INDEXER_HOST'] = get_user_input(
            "Enter Wazuh Indexer hostname or IP address",
            validator=validate_ip_or_hostname
        )
        
        config['WAZUH_INDEXER_PORT'] = get_user_input(
            "Enter Wazuh Indexer port",
            default="9200",
            validator=validate_port
        )
        
        config['WAZUH_INDEXER_USER'] = get_user_input(
            "Enter Wazuh Indexer username",
            default="admin"
        )
        
        config['WAZUH_INDEXER_PASS'] = get_user_input(
            "Enter Wazuh Indexer password"
        )
        
        config['USE_INDEXER_FOR_ALERTS'] = "true"
        config['USE_INDEXER_FOR_VULNERABILITIES'] = "true"
    else:
        config['WAZUH_INDEXER_HOST'] = ""
        config['WAZUH_INDEXER_PORT'] = "9200"
        config['WAZUH_INDEXER_USER'] = ""
        config['WAZUH_INDEXER_PASS'] = ""
        config['USE_INDEXER_FOR_ALERTS'] = "false"
        config['USE_INDEXER_FOR_VULNERABILITIES'] = "false"
    
    return config

def configure_mcp_transport() -> Dict[str, Any]:
    """Configure MCP transport settings"""
    print("\n📱 2. MCP TRANSPORT CONFIGURATION")
    print("-" * 40)
    
    config = {}
    
    print("\nTransport modes (you can change this later using three methods):")
    print("  • stdio: For desktop integration (recommended for Claude Desktop)")
    print("  • http:  For remote access and web interfaces")
    print("\nMethod 1 (Highest Priority): Command-line arguments")
    print("  ./wazuh-mcp-server --stdio   or   ./wazuh-mcp-server --http")
    print("Method 2 (Recommended): Environment variables")
    print("  export MCP_TRANSPORT=stdio   or   export MCP_TRANSPORT=http")
    print("Method 3 (Default): Defaults to stdio if nothing specified")
    
    transport_mode = get_user_input(
        "Choose default transport mode (stdio/http)",
        default="stdio"
    ).lower()
    
    while transport_mode not in ['stdio', 'http']:
        print("❌ Please choose either 'stdio' or 'http'")
        transport_mode = get_user_input(
            "Choose default transport mode (stdio/http)",
            default="stdio"
        ).lower()
    
    config['MCP_TRANSPORT'] = transport_mode
    
    if transport_mode == 'http':
        config['MCP_HOST'] = get_user_input(
            "Enter MCP server host",
            default="0.0.0.0"
        )
        
        config['MCP_PORT'] = get_user_input(
            "Enter MCP server port",
            default="3000",
            validator=validate_port
        )
        
        config['DOMAIN'] = get_user_input(
            "Enter domain name for external access",
            default="localhost",
            required=False
        )
    else:
        config['MCP_HOST'] = "0.0.0.0"
        config['MCP_PORT'] = "3000"
        config['DOMAIN'] = "localhost"
    
    return config

def configure_ssl_security() -> Dict[str, Any]:
    """Configure SSL/TLS security settings"""
    print("\n🔒 3. SSL/TLS SECURITY CONFIGURATION")
    print("-" * 40)
    
    config = {}
    
    config['VERIFY_SSL'] = "true" if get_yes_no(
        "Enable SSL certificate verification? (Recommended for production)",
        default=True
    ) else "false"
    
    if config['VERIFY_SSL'] == "false":
        print("⚠️  WARNING: SSL verification disabled. Only use for testing!")
        config['ALLOW_SELF_SIGNED'] = "true" if get_yes_no(
            "Allow self-signed certificates?",
            default=True
        ) else "false"
    else:
        config['ALLOW_SELF_SIGNED'] = "false"
    
    has_custom_certs = get_yes_no(
        "Do you have custom SSL certificates to configure?",
        default=False
    )
    
    if has_custom_certs:
        config['CA_BUNDLE_PATH'] = get_user_input(
            "Enter CA bundle path",
            default="/app/config/certs/ca-bundle.pem",
            required=False
        )
        
        config['CLIENT_CERT_PATH'] = get_user_input(
            "Enter client certificate path",
            default="/app/config/certs/client.crt",
            required=False
        )
        
        config['CLIENT_KEY_PATH'] = get_user_input(
            "Enter client key path",
            default="/app/config/certs/client.key",
            required=False
        )
    else:
        config['CA_BUNDLE_PATH'] = ""
        config['CLIENT_CERT_PATH'] = ""
        config['CLIENT_KEY_PATH'] = ""
    
    config['SSL_TIMEOUT'] = get_user_input(
        "Enter SSL timeout (seconds)",
        default="30",
        validator=lambda x: x.isdigit() and int(x) > 0
    )
    
    return config

def configure_performance() -> Dict[str, Any]:
    """Configure performance settings"""
    print("\n⚡ 4. PERFORMANCE CONFIGURATION")
    print("-" * 40)
    
    config = {}
    
    print("\n🔹 Query Limits:")
    config['MAX_ALERTS_PER_QUERY'] = get_user_input(
        "Maximum alerts per query",
        default="1000",
        validator=lambda x: x.isdigit() and int(x) > 0
    )
    
    config['MAX_VULNERABILITIES_PER_QUERY'] = get_user_input(
        "Maximum vulnerabilities per query",
        default="500",
        validator=lambda x: x.isdigit() and int(x) > 0
    )
    
    print("\n🔹 Connection Settings:")
    config['MAX_CONNECTIONS'] = get_user_input(
        "Maximum concurrent connections",
        default="25",
        validator=lambda x: x.isdigit() and int(x) > 0
    )
    
    config['REQUEST_TIMEOUT_SECONDS'] = get_user_input(
        "Request timeout (seconds)",
        default="30",
        validator=lambda x: x.isdigit() and int(x) > 0
    )
    
    print("\n🔹 Rate Limiting:")
    config['MAX_REQUESTS_PER_MINUTE'] = get_user_input(
        "Maximum requests per minute",
        default="100",
        validator=lambda x: x.isdigit() and int(x) > 0
    )
    
    print("\n🔹 Caching:")
    enable_caching = get_yes_no("Enable response caching?", default=True)
    config['ENABLE_RESPONSE_CACHING'] = "true" if enable_caching else "false"
    
    if enable_caching:
        config['CACHE_TTL_SECONDS'] = get_user_input(
            "Cache TTL (seconds)",
            default="300",
            validator=lambda x: x.isdigit() and int(x) > 0
        )
    else:
        config['CACHE_TTL_SECONDS'] = "0"
    
    return config

def configure_external_apis() -> Dict[str, Any]:
    """Configure external API integrations"""
    print("\n🌐 5. EXTERNAL API INTEGRATIONS (Optional)")
    print("-" * 40)
    
    config = {}
    
    has_external_apis = get_yes_no(
        "Do you want to configure external threat intelligence APIs?",
        default=False
    )
    
    if has_external_apis:
        print("\n🔹 Threat Intelligence APIs:")
        
        config['VIRUSTOTAL_API_KEY'] = get_user_input(
            "Enter VirusTotal API key",
            required=False
        )
        
        config['SHODAN_API_KEY'] = get_user_input(
            "Enter Shodan API key",
            required=False
        )
        
        config['ABUSEIPDB_API_KEY'] = get_user_input(
            "Enter AbuseIPDB API key",
            required=False
        )
        
        config['OTX_API_KEY'] = get_user_input(
            "Enter AlienVault OTX API key",
            required=False
        )
    else:
        config['VIRUSTOTAL_API_KEY'] = ""
        config['SHODAN_API_KEY'] = ""
        config['ABUSEIPDB_API_KEY'] = ""
        config['OTX_API_KEY'] = ""
    
    return config

def configure_logging_monitoring() -> Dict[str, Any]:
    """Configure logging and monitoring"""
    print("\n📊 6. LOGGING AND MONITORING")
    print("-" * 40)
    
    config = {}
    
    print("\nLog levels: DEBUG, INFO, WARNING, ERROR, CRITICAL")
    log_level = get_user_input(
        "Choose log level",
        default="INFO"
    ).upper()
    
    while log_level not in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
        print("❌ Please choose a valid log level")
        log_level = get_user_input(
            "Choose log level (DEBUG/INFO/WARNING/ERROR/CRITICAL)",
            default="INFO"
        ).upper()
    
    config['LOG_LEVEL'] = log_level
    
    config['STRUCTURED_LOGGING'] = "true" if get_yes_no(
        "Enable structured logging (JSON format)?",
        default=True
    ) else "false"
    
    config['ENABLE_METRICS'] = "true" if get_yes_no(
        "Enable metrics collection?",
        default=True
    ) else "false"
    
    config['ENABLE_HEALTH_CHECKS'] = "true" if get_yes_no(
        "Enable health checks?",
        default=True
    ) else "false"
    
    return config

def configure_docker_settings() -> Dict[str, Any]:
    """Configure Docker-specific settings"""
    print("\n🐳 7. DOCKER DEPLOYMENT SETTINGS")
    print("-" * 40)
    
    config = {}
    
    config['VERSION'] = get_user_input(
        "Enter version tag",
        default="v2.0.0"
    )
    
    config['NETWORK_NAME'] = get_user_input(
        "Enter Docker network name",
        default="wazuh-mcp-network"
    )
    
    config['SUBNET'] = get_user_input(
        "Enter Docker subnet",
        default="172.20.0.0/16"
    )
    
    config['LOGS_DIR'] = get_user_input(
        "Enter logs directory path",
        default="./logs"
    )
    
    config['CONFIG_DIR'] = get_user_input(
        "Enter config directory path",
        default="./config"
    )
    
    return config

def generate_env_file(config: Dict[str, Any], filepath: str):
    """Generate .env file from configuration"""
    timestamp = datetime.now().isoformat()
    
    content = f"""# Wazuh MCP Server Configuration
# Generated on: {timestamp}
# This file contains your customized Wazuh MCP Server settings

# ================================================================
# WAZUH SERVER CONFIGURATION
# ================================================================
WAZUH_HOST={config['WAZUH_HOST']}
WAZUH_PORT={config['WAZUH_PORT']}
WAZUH_USER={config['WAZUH_USER']}
WAZUH_PASS={config['WAZUH_PASS']}
WAZUH_API_VERSION=v4

# ================================================================
# WAZUH INDEXER CONFIGURATION (Distributed Setup)
# ================================================================
WAZUH_INDEXER_HOST={config['WAZUH_INDEXER_HOST']}
WAZUH_INDEXER_PORT={config['WAZUH_INDEXER_PORT']}
WAZUH_INDEXER_USER={config['WAZUH_INDEXER_USER']}
WAZUH_INDEXER_PASS={config['WAZUH_INDEXER_PASS']}
USE_INDEXER_FOR_ALERTS={config['USE_INDEXER_FOR_ALERTS']}
USE_INDEXER_FOR_VULNERABILITIES={config['USE_INDEXER_FOR_VULNERABILITIES']}

# ================================================================
# MCP TRANSPORT CONFIGURATION
# ================================================================
MCP_TRANSPORT={config['MCP_TRANSPORT']}
MCP_HOST={config['MCP_HOST']}
MCP_PORT={config['MCP_PORT']}
DOMAIN={config['DOMAIN']}

# ================================================================
# SSL/TLS SECURITY CONFIGURATION
# ================================================================
VERIFY_SSL={config['VERIFY_SSL']}
ALLOW_SELF_SIGNED={config['ALLOW_SELF_SIGNED']}
SSL_TIMEOUT={config['SSL_TIMEOUT']}
CA_BUNDLE_PATH={config['CA_BUNDLE_PATH']}
CLIENT_CERT_PATH={config['CLIENT_CERT_PATH']}
CLIENT_KEY_PATH={config['CLIENT_KEY_PATH']}

# ================================================================
# PERFORMANCE CONFIGURATION
# ================================================================
MAX_ALERTS_PER_QUERY={config['MAX_ALERTS_PER_QUERY']}
MAX_VULNERABILITIES_PER_QUERY={config['MAX_VULNERABILITIES_PER_QUERY']}
MAX_CONNECTIONS={config['MAX_CONNECTIONS']}
REQUEST_TIMEOUT_SECONDS={config['REQUEST_TIMEOUT_SECONDS']}
MAX_REQUESTS_PER_MINUTE={config['MAX_REQUESTS_PER_MINUTE']}
ENABLE_RESPONSE_CACHING={config['ENABLE_RESPONSE_CACHING']}
CACHE_TTL_SECONDS={config['CACHE_TTL_SECONDS']}

# ================================================================
# EXTERNAL API INTEGRATIONS
# ================================================================
VIRUSTOTAL_API_KEY={config['VIRUSTOTAL_API_KEY']}
SHODAN_API_KEY={config['SHODAN_API_KEY']}
ABUSEIPDB_API_KEY={config['ABUSEIPDB_API_KEY']}
OTX_API_KEY={config['OTX_API_KEY']}

# ================================================================
# LOGGING AND MONITORING
# ================================================================
LOG_LEVEL={config['LOG_LEVEL']}
STRUCTURED_LOGGING={config['STRUCTURED_LOGGING']}
ENABLE_METRICS={config['ENABLE_METRICS']}
ENABLE_HEALTH_CHECKS={config['ENABLE_HEALTH_CHECKS']}

# ================================================================
# DOCKER DEPLOYMENT SETTINGS
# ================================================================
VERSION={config['VERSION']}
BUILD_DATE={timestamp}
NETWORK_NAME={config['NETWORK_NAME']}
SUBNET={config['SUBNET']}
GATEWAY={config['SUBNET'].replace('0.0/16', '0.1')}
LOGS_DIR={config['LOGS_DIR']}
CONFIG_DIR={config['CONFIG_DIR']}

# ================================================================
# ADDITIONAL PRODUCTION SETTINGS
# ================================================================
ENVIRONMENT=production
DEPLOYMENT_STAGE=prod
PYTHONUNBUFFERED=1
PYTHONDONTWRITEBYTECODE=1
TZ=UTC

# Rate limiting
BURST_REQUEST_SIZE=20
RATE_LIMIT_WINDOW_SECONDS=60

# Security hardening
ENABLE_INPUT_VALIDATION=true
ENABLE_OUTPUT_SANITIZATION=true
ENABLE_AUDIT_LOGGING=true

# AI and analysis features
ENABLE_AI_ANALYSIS=true
ENABLE_ML_ANALYSIS=true
ENABLE_COMPLIANCE_CHECKING=true
ENABLE_THREAT_HUNTING=true

# Compliance frameworks
ENABLE_PCI_DSS_CHECKS=true
ENABLE_HIPAA_CHECKS=true
ENABLE_SOX_CHECKS=true
ENABLE_GDPR_CHECKS=true
ENABLE_NIST_CHECKS=true
"""
    
    with open(filepath, 'w') as f:
        f.write(content)

def generate_docker_compose_env(config: Dict[str, Any], filepath: str):
    """Generate Docker Compose environment file"""
    content = f"""# Docker Compose Environment Variables
# Source this file before running docker-compose

# Wazuh Server Configuration
export WAZUH_HOST={config['WAZUH_HOST']}
export WAZUH_PORT={config['WAZUH_PORT']}
export WAZUH_USER={config['WAZUH_USER']}
export WAZUH_PASS={config['WAZUH_PASS']}

# Wazuh Indexer Configuration
export WAZUH_INDEXER_HOST={config['WAZUH_INDEXER_HOST']}
export WAZUH_INDEXER_PORT={config['WAZUH_INDEXER_PORT']}
export WAZUH_INDEXER_USER={config['WAZUH_INDEXER_USER']}
export WAZUH_INDEXER_PASS={config['WAZUH_INDEXER_PASS']}

# MCP Configuration
export MCP_TRANSPORT={config['MCP_TRANSPORT']}
export MCP_PORT={config['MCP_PORT']}
export DOMAIN={config['DOMAIN']}

# Docker Configuration
export VERSION={config['VERSION']}
export BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
export NETWORK_NAME={config['NETWORK_NAME']}
export SUBNET={config['SUBNET']}
export LOGS_DIR={config['LOGS_DIR']}
export CONFIG_DIR={config['CONFIG_DIR']}

# Security Configuration
export VERIFY_SSL={config['VERIFY_SSL']}
export LOG_LEVEL={config['LOG_LEVEL']}
"""
    
    with open(filepath, 'w') as f:
        f.write(content)

def create_directory_structure(config: Dict[str, Any]):
    """Create necessary directory structure"""
    directories = [
        config['LOGS_DIR'],
        config['CONFIG_DIR'],
        f"{config['CONFIG_DIR']}/certs",
        "./data",
        "./backups"
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)
        print(f"✅ Created directory: {directory}")

def generate_quick_start_guide(config: Dict[str, Any]):
    """Generate a quick start guide"""
    guide = f"""# Quick Start Guide

## Your Configuration Summary

**Wazuh Server:** {config['WAZUH_HOST']}:{config['WAZUH_PORT']}
**Transport Mode:** {config['MCP_TRANSPORT']}
**SSL Verification:** {config['VERIFY_SSL']}
**Log Level:** {config['LOG_LEVEL']}

## Next Steps

### 1. Verify Configuration
```bash
# Test your Wazuh connection
python3 validate-production.py --quick
```

### 2. Start with Docker Compose (Recommended)
```bash
# Build and start the services
docker compose up -d

# Check logs
docker compose logs -f wazuh-mcp-server

# Check health
docker compose ps
```

### 3. Start with Docker Run
```bash
# Build the image
docker build -t wazuh-mcp-server:latest .

# Run the container
docker run -d \\
  --name wazuh-mcp-server \\
  --env-file .env \\
  --restart unless-stopped \\
  wazuh-mcp-server:latest
```

### 4. For Desktop Integration
Add this to your MCP client configuration:

```json
{{
  "mcpServers": {{
    "wazuh": {{
      "command": "docker",
      "args": ["exec", "-i", "wazuh-mcp-server", "./wazuh-mcp-server", "--stdio"],
      "env": {{}}
    }}
  }}
}}
```

### 5. Troubleshooting
```bash
# Check container status
docker ps

# View logs
docker logs wazuh-mcp-server

# Test connection
curl -k https://{config['WAZUH_HOST']}:{config['WAZUH_PORT']}/

# Validate setup
docker exec wazuh-mcp-server python3 validate-production.py
```

## Security Reminders

- Keep your .env file secure and never commit it to version control
- Use strong passwords for Wazuh API users
- Enable SSL verification in production
- Regularly update your certificates
- Monitor logs for suspicious activity

## Support

- Documentation: See README.md and WAZUH_CONFIGURATION_GUIDE.md
- Issues: https://github.com/gensecaihq/Wazuh-MCP-Server/issues
"""
    
    with open("QUICK_START.md", 'w') as f:
        f.write(guide)

def main():
    """Main configuration function"""
    try:
        print_banner()
        
        # Collect all configuration
        config = {}
        config.update(configure_wazuh_server())
        config.update(configure_mcp_transport())
        config.update(configure_ssl_security())
        config.update(configure_performance())
        config.update(configure_external_apis())
        config.update(configure_logging_monitoring())
        config.update(configure_docker_settings())
        
        print("\n" + "=" * 80)
        print("📝 GENERATING CONFIGURATION FILES")
        print("=" * 80)
        
        # Generate configuration files
        generate_env_file(config, '.env')
        print("✅ Generated: .env")
        
        generate_docker_compose_env(config, '.env.compose')
        print("✅ Generated: .env.compose")
        
        # Create directory structure
        create_directory_structure(config)
        
        # Generate quick start guide
        generate_quick_start_guide(config)
        print("✅ Generated: QUICK_START.md")
        
        print("\n" + "=" * 80)
        print("🎉 CONFIGURATION COMPLETE!")
        print("=" * 80)
        print()
        print("Your Wazuh MCP Server has been configured with the following:")
        print(f"• Wazuh Server: {config['WAZUH_HOST']}:{config['WAZUH_PORT']}")
        print(f"• Transport Mode: {config['MCP_TRANSPORT']}")
        print(f"• SSL Verification: {config['VERIFY_SSL']}")
        print(f"• Log Level: {config['LOG_LEVEL']}")
        
        if config['WAZUH_INDEXER_HOST']:
            print(f"• Wazuh Indexer: {config['WAZUH_INDEXER_HOST']}:{config['WAZUH_INDEXER_PORT']}")
        
        print("\nNext steps:")
        print("1. Review the generated .env file")
        print("2. Read QUICK_START.md for deployment instructions")
        print("3. Run: python3 validate-production.py --quick")
        print("4. Start your deployment: docker compose up -d")
        print()
        print("For detailed configuration help, see WAZUH_CONFIGURATION_GUIDE.md")
        print("=" * 80)
        
    except KeyboardInterrupt:
        print("\n\n❌ Configuration cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Configuration failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()