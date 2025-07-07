# Wazuh MCP Server

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Wazuh Compatible](https://img.shields.io/badge/Wazuh-4.8%2B-orange.svg)](https://wazuh.com/)

A production-grade Model Context Protocol (MCP) server that integrates Wazuh SIEM with Claude Desktop, enabling natural language security operations and analysis.

## 🌟 Features

### 🛡️ **Comprehensive Security Integration**
- **Real-time Security Monitoring**: Direct access to Wazuh alerts and events
- **Agent Management**: Monitor and manage Wazuh agents across your infrastructure
- **Vulnerability Analysis**: Comprehensive vulnerability scanning and reporting
- **Compliance Reporting**: PCI DSS, GDPR, HIPAA, and custom compliance frameworks
- **Rule & Decoder Management**: Create and modify Wazuh rules and decoders

### 🔍 **Advanced Analytics**
- **Threat Intelligence**: AI-powered security analysis and correlation
- **Incident Response**: Automated incident detection and response workflows
- **Risk Assessment**: Comprehensive security posture analysis
- **Forensic Analysis**: Deep dive into security events and attack patterns

### 🏗️ **Enterprise-Grade Architecture**
- **Production Ready**: Robust error handling and retry mechanisms
- **Secure by Default**: HTTPS-only connections with SSL/TLS validation
- **High Performance**: Async I/O and connection pooling
- **Comprehensive Logging**: Structured logging with security event tracking

## 🚀 Quick Start

### Prerequisites
- Python 3.9 or higher
- Wazuh Server 4.8+ with API access
- Wazuh Indexer (OpenSearch) for advanced features
- Claude Desktop application

### Installation

#### Option 1: Install from PyPI (Recommended)
```bash
pip install wazuh-mcp-server
```

#### Option 2: Install directly from GitHub
```bash
pip install git+https://github.com/socfortress/Wazuh-MCP-Server.git
```

#### Option 3: Install from GitHub Release
Download the `.whl` file from the [latest release](https://github.com/socfortress/Wazuh-MCP-Server/releases) and install:
```bash
pip install wazuh_mcp_server-<version>-py3-none-any.whl
```

#### Option 4: Development Installation
1. **Clone the repository**
   ```bash
   git clone https://github.com/socfortress/Wazuh-MCP-Server.git
   cd Wazuh-MCP-Server
   ```

2. **Run the installation script**
   ```bash
   python3 install.py
   ```

## 📦 Python Package Installation

### **Option 1: Install as a Package**

For using Wazuh MCP Server in your own Python applications:

```bash
# Install from PyPI (when published)
pip install wazuh-mcp-server

# Or install from source
pip install git+https://github.com/gensecaihq/Wazuh-MCP-Server.git
```

**Quick Start Example:**
```python
import asyncio
from wazuh_mcp_server import create_client

async def main():
    # Configure via environment variables or .env file
    client = await create_client()
    
    # Get recent alerts
    alerts = await client.get_alerts(limit=10)
    print(f"Found {len(alerts['alerts'])} alerts")
    
    # Analyze threats
    threats = await client.analyze_threats(time_range=3600)
    print(f"Risk level: {threats['risk_assessment']['risk_level']}")
    
    await client.close()

asyncio.run(main())
```

📖 **See [PACKAGE_USAGE.md](PACKAGE_USAGE.md) for complete API documentation and examples.**

### **Option 2: MCP Server Installation**

For direct integration with Claude Desktop and MCP protocol:

## 🔧 **Post-Installation Configuration**

### **Step 1: Configure Wazuh Connection**

1. **Edit the configuration file**
   ```bash
   # Edit .env file with your Wazuh details
   nano .env
   ```

2. **Update required fields** with your actual Wazuh server details:
   ```env
   # Wazuh Manager Configuration (REQUIRED)
   WAZUH_HOST=your-wazuh-server.com     # Your Wazuh server IP/hostname
   WAZUH_PORT=55000                     # Default Wazuh API port
   WAZUH_USER=your-username             # Valid Wazuh API username
   WAZUH_PASS=your-password             # Valid Wazuh API password

   # Wazuh Indexer Configuration (OPTIONAL - for advanced features)
   WAZUH_INDEXER_HOST=your-indexer-host.com
   WAZUH_INDEXER_PORT=9200
   WAZUH_INDEXER_USER=your-indexer-username
   WAZUH_INDEXER_PASS=your-indexer-password

   # Security Settings
   VERIFY_SSL=false                     # Set to true for production with valid certs
   WAZUH_ALLOW_SELF_SIGNED=true         # Set to false for production
   ```

### **Step 2: Test the Connection**

1. **Activate virtual environment**
   ```bash
   source venv/bin/activate
   ```

2. **Test MCP server connection**
   ```bash
   python src/wazuh_mcp_server/main.py --stdio
   ```

3. **Run connection validation**
   ```bash
   python src/wazuh_mcp_server/scripts/connection_validator.py
   ```

4. **Comprehensive setup validation**
   ```bash
   python validate_setup.py
   ```

### **Step 3: Claude Desktop Integration**

1. **Locate Claude Desktop settings file:**
   - **Linux**: `~/.config/Claude/settings.json`
   - **macOS**: `~/Library/Application Support/Claude/settings.json`
   - **Windows**: `%APPDATA%\Claude\settings.json`

2. **Add Wazuh MCP Server configuration:**
   ```json
   {
     "mcpServers": {
       "wazuh": {
         "command": "python",
         "args": ["/full/path/to/Wazuh-MCP-Server/src/wazuh_mcp_server/main.py", "--stdio"],
         "env": {
           "LOG_LEVEL": "INFO"
         }
       }
     }
   }
   ```
   
   **Important**: Replace `/full/path/to/Wazuh-MCP-Server` with your actual project directory path.

3. **Restart Claude Desktop** completely for changes to take effect.

### **Step 4: Test Integration**

1. **Open Claude Desktop** and start a new conversation
2. **Test basic functionality** with these example queries:
   - "Show me recent security alerts"
   - "List all Wazuh agents"
   - "What's the current security status of my infrastructure?"
   - "Check for failed login attempts"

### **Step 5: Verify Full Functionality**

1. **Check all systems are working:**
   ```bash
   python validate_setup.py
   ```

2. **Monitor logs for issues:**
   ```bash
   tail -f logs/wazuh-mcp.log
   ```

3. **Test advanced features** (if Indexer is configured):
   - Security analytics queries
   - Compliance reporting
   - Advanced threat hunting

## 📋 Supported Operations

### 🔍 **Security Monitoring**
- Real-time alert monitoring
- Security event analysis
- Threat detection and correlation
- Attack pattern identification

### 👥 **Agent Management**
- Agent status monitoring
- Agent configuration management
- Group management
- Performance metrics

### 🛠️ **Rule & Configuration Management**
- Custom rule creation and modification
- Decoder management
- Configuration templates
- Rule testing and validation

### 📊 **Compliance & Reporting**
- PCI DSS compliance reports
- GDPR compliance monitoring
- HIPAA compliance tracking
- Custom compliance frameworks
- Executive dashboards

### 🔎 **Vulnerability Management**
- Vulnerability scanning results
- Risk prioritization
- Patch management tracking
- Remediation workflows

## 🏗️ Project Structure

```
Wazuh-MCP-Server/
├── src/wazuh_mcp_server/          # Main application code
│   ├── api/                       # Wazuh API clients
│   ├── analyzers/                 # Security and compliance analyzers
│   ├── scripts/                   # Utility scripts
│   ├── utils/                     # Helper utilities
│   ├── config.py                  # Configuration management
│   └── main.py                    # Main server entry point
├── tests/                         # Test suite
├── docs/                          # Documentation
├── .env                          # Environment configuration
├── requirements.txt              # Python dependencies
├── install.py                   # Installation script
├── validate_setup.py            # Setup validation tool
└── pyproject.toml               # Python package configuration
```

## 🔧 Advanced Configuration

### SSL/TLS Security
For production deployments, enable SSL verification:
```env
VERIFY_SSL=true
WAZUH_ALLOW_SELF_SIGNED=false
```

### Custom CA Certificates
```env
WAZUH_CA_BUNDLE_PATH=/path/to/ca-bundle.pem
WAZUH_CLIENT_CERT_PATH=/path/to/client.crt
WAZUH_CLIENT_KEY_PATH=/path/to/client.key
```

### Performance Tuning
```env
WAZUH_MAX_CONNECTIONS=20
WAZUH_REQUEST_TIMEOUT=30
WAZUH_RATE_LIMIT=10
LOG_LEVEL=INFO
```

## 🧪 Testing

Run the test suite:
```bash
source venv/bin/activate
python -m pytest tests/ -v
```

Test connection to your Wazuh server:
```bash
python src/wazuh_mcp_server/scripts/test_connection.py
```

## 📚 Documentation

- [API Reference](docs/API_REFERENCE.md) - Complete API documentation
- [Configuration Reference](docs/CONFIGURATION_REFERENCE.md) - Detailed configuration options
- [Local Setup Guide](docs/LOCAL_SETUP.md) - Step-by-step setup instructions

## 🛡️ Security Considerations

### Production Deployment
- Use dedicated service accounts with minimal required permissions
- Enable SSL/TLS verification (`VERIFY_SSL=true`)
- Use proper CA-signed certificates in production
- Regularly rotate API credentials
- Monitor access logs and security events
- Set appropriate file permissions (600) on `.env` file

### Network Security
- Ensure Wazuh API endpoints are properly secured
- Use firewalls to restrict access to Wazuh services
- Consider VPN or private network connections
- Enable audit logging on Wazuh servers

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔧 **Quick Troubleshooting**

### Common Issues and Solutions

#### ❌ **Authentication Failed (HTTP 401)**
```bash
# Check credentials in .env file
grep -E "WAZUH_(USER|PASS)" .env
# Test connection
python src/wazuh_mcp_server/scripts/connection_validator.py
```

#### ❌ **SSL Certificate Verification Failed**
```env
# For self-signed certificates, set in .env:
VERIFY_SSL=false
WAZUH_ALLOW_SELF_SIGNED=true
```

#### ❌ **Claude Desktop Not Recognizing MCP Server**
```bash
# Validate JSON syntax
python -m json.tool ~/.config/Claude/settings.json
# Use absolute paths in settings.json
pwd  # Copy this path for Claude Desktop configuration
```

#### ❌ **Python Module Not Found**
```bash
# Check virtual environment
source venv/bin/activate
python -c "import wazuh_mcp_server; print('✅ Module found')"
```

### 🔍 **Diagnostic Commands**

```bash
# Comprehensive validation
python validate_setup.py

# Test connections
python src/wazuh_mcp_server/scripts/connection_validator.py

# Check logs
tail -f logs/wazuh-mcp.log

# Manual MCP server test
python src/wazuh_mcp_server/main.py --stdio
```

### 📚 **Documentation References**

- **Complete Setup Guide**: [docs/LOCAL_SETUP.md](docs/LOCAL_SETUP.md)
- **Configuration Options**: [docs/CONFIGURATION_REFERENCE.md](docs/CONFIGURATION_REFERENCE.md)
- **API Reference**: [docs/API_REFERENCE.md](docs/API_REFERENCE.md)

## 🆘 Support

- **Issues**: [GitHub Issues](https://github.com/gensecaihq/Wazuh-MCP-Server/issues)
- **Discussions**: [GitHub Discussions](https://github.com/gensecaihq/Wazuh-MCP-Server/discussions)
- **Documentation**: [Project Documentation](docs/)

## 🔄 Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and updates.

---

**Made with ❤️ for the security community**

Transform your Wazuh SIEM into an AI-powered security operations center with natural language queries and advanced analytics through Claude Desktop.