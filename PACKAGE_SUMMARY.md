# Wazuh MCP Server - Package Conversion Summary

## 🎯 What We've Accomplished

This repository has been successfully converted into a pip-installable Python package that can be used in other applications. Here's what was added:

## 📁 New Files Created

### 1. **Package Structure Files**
- `setup.py` - Alternative setup script for compatibility
- `MANIFEST.in` - Specifies additional files to include in the package
- `build.py` - Comprehensive build and deployment script
- `INSTALLATION.md` - Detailed installation and deployment guide
- `PACKAGE_USAGE.md` - Complete API documentation and usage examples

### 2. **API Client Module**
- `src/wazuh_mcp_server/api_client.py` - High-level programmatic API for easy integration

### 3. **Example Applications**
- `examples/package_usage.py` - Comprehensive examples showing how to use the package

### 4. **Documentation**
- Updated `README.md` with package installation instructions
- Detailed guides for both package usage and MCP server deployment

## 🚀 How to Use as a Package

### Installation Options

```bash
# Option 1: Install from source
pip install git+https://github.com/gensecaihq/Wazuh-MCP-Server.git

# Option 2: Local development
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server
pip install -e .

# Option 3: When published to PyPI
pip install wazuh-mcp-server
```

### Quick Start

```python
import asyncio
from wazuh_mcp_server import create_client

async def main():
    # Load config from environment variables
    client = await create_client()
    
    # Get recent security alerts
    alerts = await client.get_alerts(limit=10)
    print(f"Found {len(alerts['alerts'])} alerts")
    
    # Perform threat analysis
    threats = await client.analyze_threats(time_range=3600)
    print(f"Current risk level: {threats['risk_assessment']['risk_level']}")
    
    # Check compliance
    compliance = await client.check_compliance("pci_dss")
    print(f"PCI DSS compliance: {compliance['overall_score']:.1f}%")
    
    await client.close()

asyncio.run(main())
```

## 🎛️ Available APIs

### Core Classes
- `WazuhAPIClient` - Main API client for programmatic access
- `WazuhConfig` - Configuration management with validation
- `create_client()` - Convenience function for quick setup

### Key Methods
- `get_alerts()` - Retrieve security alerts with filtering
- `get_agents()` - Get agent information and health status
- `analyze_threats()` - Perform comprehensive threat analysis
- `check_compliance()` - Run compliance assessments (PCI DSS, GDPR, etc.)
- `get_vulnerabilities()` - Get vulnerability information
- `get_security_events()` - Retrieve and analyze security events

### Supported Compliance Frameworks
- PCI DSS
- GDPR
- HIPAA
- NIST
- ISO 27001

## 🛠️ Development Workflow

### Building the Package

```bash
# Validate setup
python build.py validate

# Run tests
python build.py test

# Check code quality
python build.py lint

# Build package
python build.py build

# Install locally for testing
python build.py install
```

### Publishing to PyPI

```bash
# Upload to Test PyPI
python build.py test-pypi

# Upload to production PyPI (after testing)
python build.py pypi
```

## 🔧 Integration Examples

### Flask Web Application

```python
from flask import Flask, jsonify
from wazuh_mcp_server import create_client
import asyncio

app = Flask(__name__)

@app.route('/api/security-dashboard')
def security_dashboard():
    async def get_data():
        client = await create_client()
        try:
            alerts = await client.get_alerts(limit=20)
            agents = await client.get_agents()
            threats = await client.analyze_threats(time_range=3600)
            
            return {
                'alerts': len(alerts['alerts']),
                'active_agents': agents['summary']['active'],
                'risk_level': threats['risk_assessment']['risk_level']
            }
        finally:
            await client.close()
    
    result = asyncio.run(get_data())
    return jsonify(result)
```

### Custom Security Dashboard

```python
class SecurityDashboard:
    def __init__(self):
        self.client = None
    
    async def initialize(self):
        self.client = await create_client()
    
    async def get_summary(self):
        # Parallel data fetching
        alerts_task = self.client.get_alerts(limit=50)
        agents_task = self.client.get_agents()
        threats_task = self.client.analyze_threats(time_range=3600)
        
        alerts, agents, threats = await asyncio.gather(
            alerts_task, agents_task, threats_task
        )
        
        return {
            'alerts': alerts,
            'agents': agents,
            'threats': threats
        }
```

## 🔒 Security Features

- **Secure by Default** - HTTPS-only connections with SSL validation
- **Credential Management** - Environment variable and .env file support
- **Error Handling** - Comprehensive error handling with specific exception types
- **Input Validation** - Pydantic-based configuration validation
- **Rate Limiting** - Built-in rate limiting and connection pooling

## 📊 Monitoring and Analysis

- **Real-time Alerts** - Access to Wazuh alerts with filtering and pagination
- **Threat Intelligence** - AI-powered threat analysis and risk scoring
- **Compliance Reporting** - Automated compliance assessments
- **Vulnerability Management** - Comprehensive vulnerability analysis
- **Agent Health Monitoring** - Agent status and health assessment

## 🔄 Backward Compatibility

The package maintains full backward compatibility:
- **MCP Server Mode** - Still works as an MCP server for Claude Desktop
- **Original APIs** - All original functionality is preserved
- **Configuration** - Same configuration options and environment variables

## 📚 Documentation

- `README.md` - Overview and quick start
- `PACKAGE_USAGE.md` - Complete API documentation with examples
- `INSTALLATION.md` - Detailed installation and deployment guide
- `examples/package_usage.py` - Comprehensive usage examples
- `docs/` - Additional documentation for specific features

## 🎯 Next Steps

1. **Test the package** in your environment:
   ```bash
   pip install -e .
   python examples/package_usage.py
   ```

2. **Publish to PyPI** (when ready):
   ```bash
   python build.py test-pypi  # Test first
   python build.py pypi       # Production release
   ```

3. **Integrate into your application** using the examples and documentation provided

4. **Contribute** improvements and report issues on GitHub

The Wazuh MCP Server is now a full-featured, pip-installable Python package that can be easily integrated into any Python application while maintaining its original MCP server capabilities!
