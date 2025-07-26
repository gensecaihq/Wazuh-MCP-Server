# 🛠️ Tools & Utilities

This directory contains utility scripts and tools for managing, testing, and configuring the Wazuh MCP Server.

## 📁 Available Tools

### Configuration & Setup

- **`configure.py`** - Interactive configuration wizard for Wazuh connection settings
- **`deploy-validate.py`** - Deployment validation and environment checks

### Testing & Validation

- **`test-functionality.py`** - Comprehensive functionality testing suite
- **`validate-production.py`** - Production readiness assessment and validation

## 🚀 Usage

### Interactive Configuration

```bash
# Run configuration wizard
python3 tools/configure.py

# Configure with specific parameters
python3 tools/configure.py --host wazuh-manager.local --user api-user
```

### Testing & Validation

```bash
# Basic functionality test
python3 tools/test-functionality.py

# Quick production validation
python3 tools/validate-production.py --quick

# Comprehensive production audit
python3 tools/validate-production.py --full

# Deployment validation
python3 tools/deploy-validate.py
```

## 🔧 Tool Descriptions

### `configure.py`
Interactive configuration wizard that helps set up Wazuh connection parameters, validates connectivity, and generates environment files.

**Features:**
- Interactive prompts for all configuration options
- Real-time connectivity testing
- Automatic .env file generation
- Validation of Wazuh API credentials
- Support for both Manager and Indexer configuration

### `test-functionality.py`
Comprehensive testing suite that validates all MCP server functionality, Wazuh API integration, and system compatibility.

**Tests Include:**
- MCP protocol compliance
- Wazuh API connectivity
- All 20 security tools functionality
- Resource endpoint validation
- Error handling verification
- Performance benchmarks

### `validate-production.py`
Production readiness assessment tool that performs comprehensive checks for deployment readiness.

**Validation Areas:**
- Security configuration audit
- Performance optimization checks
- Dependency validation
- Container health verification
- Network connectivity tests
- Resource utilization analysis

### `deploy-validate.py`
Deployment validation tool for verifying successful installation and configuration.

**Checks:**
- Docker installation and configuration
- Container deployment status
- Environment variable validation
- Network connectivity verification
- Service health monitoring

## 📋 Requirements

### Python Dependencies
```bash
pip install -r requirements.txt
```

### System Requirements
- Python 3.8+
- Docker (for container-based validation)
- Network access to Wazuh infrastructure
- Appropriate permissions for Docker operations

## 🔍 Examples

### Complete Setup Workflow

```bash
# 1. Configure Wazuh connection
python3 tools/configure.py

# 2. Validate deployment
python3 tools/deploy-validate.py

# 3. Test functionality
python3 tools/test-functionality.py

# 4. Production readiness check
python3 tools/validate-production.py --full
```

### Quick Health Check

```bash
# Quick validation of running system
python3 tools/validate-production.py --quick
```

### Troubleshooting Mode

```bash
# Verbose testing with detailed output
python3 tools/test-functionality.py --verbose

# Debug mode for deployment issues
python3 tools/deploy-validate.py --debug
```

## 🐛 Troubleshooting

### Common Issues

**Import Errors:**
```bash
# Ensure you're in the project root directory
cd /path/to/Wazuh-MCP-Server
python3 tools/test-functionality.py
```

**Permission Errors:**
```bash
# Ensure Docker group membership (Linux)
sudo usermod -aG docker $USER
newgrp docker
```

**Network Connectivity:**
- Verify Wazuh Manager/Indexer accessibility
- Check firewall rules and port availability
- Validate SSL certificates if using HTTPS

### Debug Mode

All tools support verbose/debug modes for detailed troubleshooting:

```bash
# Enable debug output
python3 tools/configure.py --debug
python3 tools/test-functionality.py --verbose
python3 tools/validate-production.py --debug
```

## 📈 Performance

### Benchmarking

```bash
# Performance benchmarks
python3 tools/test-functionality.py --benchmark

# Load testing
python3 tools/validate-production.py --load-test
```

### Optimization

```bash
# Performance optimization recommendations
python3 tools/validate-production.py --optimize
```

## 🤝 Contributing

- Add new tools following the existing patterns
- Include comprehensive help documentation
- Provide both interactive and command-line modes
- Add appropriate error handling and validation
- Update this README when adding new tools