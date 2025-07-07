# Wazuh MCP Server - Package Installation Guide

This guide provides step-by-step instructions for building, installing, and using the Wazuh MCP Server as a pip package.

## Table of Contents

1. [Development Setup](#development-setup)
2. [Building the Package](#building-the-package)
3. [Installing the Package](#installing-the-package)
4. [Testing the Installation](#testing-the-installation)
5. [Publishing to PyPI](#publishing-to-pypi)
6. [Using in Your Application](#using-in-your-application)
7. [Troubleshooting](#troubleshooting)

## Development Setup

### 1. Clone and Prepare the Repository

```bash
# Clone the repository
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server

# Create a virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -e ".[dev]"
```

### 2. Verify Development Environment

```bash
# Run the build script to validate setup
python build.py validate

# Run tests
python build.py test

# Check code quality
python build.py lint
```

## Building the Package

### 1. Clean and Build

```bash
# Clean previous builds
python build.py clean

# Build the package
python build.py build
```

### 2. Check the Built Package

```bash
# Verify package integrity
python build.py check

# List contents of dist/ directory
ls -la dist/
```

You should see files like:
- `wazuh_mcp_server-1.1.0-py3-none-any.whl`
- `wazuh_mcp_server-1.1.0.tar.gz`

## Installing the Package

### Option 1: Install from Local Build

```bash
# Install the wheel file
pip install dist/wazuh_mcp_server-1.1.0-py3-none-any.whl

# Or install from source
pip install .
```

### Option 2: Install in Development Mode

```bash
# Install in editable mode (recommended for development)
pip install -e .

# With optional dependencies
pip install -e ".[dev,testing]"
```

### Option 3: Install from GitHub

```bash
# Install directly from GitHub
pip install git+https://github.com/gensecaihq/Wazuh-MCP-Server.git

# Install specific branch or tag
pip install git+https://github.com/gensecaihq/Wazuh-MCP-Server.git@main
```

## Testing the Installation

### 1. Basic Import Test

```bash
python -c "
from wazuh_mcp_server import WazuhAPIClient, WazuhConfig, create_client
print('✅ Import successful!')
print(f'Available classes: WazuhAPIClient, WazuhConfig, create_client')
"
```

### 2. Version Check

```bash
python -c "
from wazuh_mcp_server import __version__
print(f'Wazuh MCP Server version: {__version__}')
"
```

### 3. Configuration Test

```bash
python -c "
from wazuh_mcp_server import WazuhConfig
config = WazuhConfig(
    host='test-server.com',
    username='test-user',
    password='test-password'
)
print(f'✅ Configuration created: {config.host}')
"
```

### 4. Run Example Script

```bash
# Run the comprehensive example
cd examples/
python package_usage.py
```

## Publishing to PyPI

### 1. Create PyPI Account

- Create accounts on [Test PyPI](https://test.pypi.org/) and [PyPI](https://pypi.org/)
- Generate API tokens for authentication

### 2. Configure Credentials

```bash
# Create ~/.pypirc file
cat > ~/.pypirc << EOF
[distutils]
index-servers =
    pypi
    testpypi

[pypi]
username = __token__
password = pypi-your-api-token-here

[testpypi]
repository = https://test.pypi.org/legacy/
username = __token__
password = pypi-your-test-api-token-here
EOF
```

### 3. Upload to Test PyPI

```bash
# Upload to Test PyPI first
python build.py test-pypi
```

### 4. Test Installation from Test PyPI

```bash
# Create a new virtual environment
python3 -m venv test_env
source test_env/bin/activate

# Install from Test PyPI
pip install --index-url https://test.pypi.org/simple/ \
    --extra-index-url https://pypi.org/simple/ \
    wazuh-mcp-server

# Test the installation
python -c "from wazuh_mcp_server import WazuhAPIClient; print('✅ Test PyPI installation works!')"
```

### 5. Upload to Production PyPI

```bash
# Upload to production PyPI
python build.py pypi
```

## Using in Your Application

### 1. Install in Your Project

```bash
# Add to your project's requirements.txt
echo "wazuh-mcp-server>=1.1.0" >> requirements.txt

# Install
pip install -r requirements.txt
```

### 2. Basic Usage Example

Create a file `my_security_app.py`:

```python
import asyncio
from wazuh_mcp_server import create_client

async def main():
    # Initialize client from environment variables
    client = await create_client()
    
    try:
        # Get recent alerts
        alerts = await client.get_alerts(limit=10)
        print(f"Found {len(alerts['alerts'])} recent alerts")
        
        # Get agent status
        agents = await client.get_agents()
        print(f"Active agents: {agents['summary']['active']}")
        
        # Analyze threats
        threats = await client.analyze_threats(time_range=3600)
        print(f"Risk level: {threats['risk_assessment']['risk_level']}")
        
    finally:
        await client.close()

if __name__ == "__main__":
    asyncio.run(main())
```

### 3. Environment Configuration

Create a `.env` file:

```bash
WAZUH_HOST=your-wazuh-server.com
WAZUH_USER=your-username
WAZUH_PASS=your-password
VERIFY_SSL=false
DEBUG=false
LOG_LEVEL=INFO
```

### 4. Run Your Application

```bash
python my_security_app.py
```

## Troubleshooting

### Common Installation Issues

#### 1. Import Errors

```bash
# Error: No module named 'wazuh_mcp_server'
# Solution: Ensure the package is installed
pip list | grep wazuh-mcp-server
pip install wazuh-mcp-server
```

#### 2. Dependency Conflicts

```bash
# Error: Conflicting dependencies
# Solution: Use a clean virtual environment
python3 -m venv clean_env
source clean_env/bin/activate
pip install wazuh-mcp-server
```

#### 3. SSL Certificate Issues

```python
# Error: SSL certificate verification failed
# Solution: Configure SSL properly
from wazuh_mcp_server import WazuhConfig

config = WazuhConfig(
    host="your-server.com",
    username="user",
    password="pass",
    verify_ssl=False,  # Disable for testing only
    # Or provide custom CA bundle
    ca_bundle_path="/path/to/ca-bundle.pem"
)
```

#### 4. Connection Timeouts

```python
# Error: Connection timeout
# Solution: Increase timeout settings
config = WazuhConfig(
    host="your-server.com",
    username="user", 
    password="pass",
    request_timeout_seconds=60,  # Increase timeout
    max_connections=5  # Reduce concurrent connections
)
```

### Build Issues

#### 1. Missing Dependencies

```bash
# Error: Missing build dependencies
# Solution: Install build requirements
pip install build twine wheel
```

#### 2. Test Failures

```bash
# Error: Tests fail during build
# Solution: Fix tests or skip them temporarily
python build.py test
# Or run specific tests
python -m pytest tests/test_specific.py -v
```

#### 3. Linting Errors

```bash
# Error: Code style issues
# Solution: Auto-fix formatting
python build.py fix

# Or manually fix issues
python build.py lint
```

### Runtime Issues

#### 1. Configuration Errors

```python
# Error: Configuration validation failed
# Solution: Check all required settings
from wazuh_mcp_server import WazuhConfig

try:
    config = WazuhConfig.from_env()
except Exception as e:
    print(f"Configuration error: {e}")
    # Check environment variables
    import os
    print(f"WAZUH_HOST: {os.getenv('WAZUH_HOST')}")
    print(f"WAZUH_USER: {os.getenv('WAZUH_USER')}")
```

#### 2. API Authentication Errors

```python
# Error: 401 Unauthorized
# Solution: Verify credentials and permissions
async def test_auth():
    from wazuh_mcp_server import create_client
    try:
        client = await create_client()
        info = await client.initialize()
        print("✅ Authentication successful")
        await client.close()
    except Exception as e:
        print(f"❌ Authentication failed: {e}")
```

#### 3. Memory Issues with Large Queries

```python
# Error: Out of memory
# Solution: Use pagination and limits
async def get_large_dataset():
    client = await create_client()
    
    all_alerts = []
    offset = 0
    batch_size = 100
    
    while True:
        alerts = await client.get_alerts(
            limit=batch_size,
            # Add offset parameter if supported
        )
        
        if not alerts['alerts']:
            break
            
        all_alerts.extend(alerts['alerts'])
        offset += batch_size
        
        # Process in batches to avoid memory issues
        if len(all_alerts) >= 1000:
            # Process batch
            process_alerts(all_alerts)
            all_alerts = []
    
    await client.close()
```

## Performance Optimization

### 1. Connection Pooling

```python
# Use connection pooling for high-throughput applications
config = WazuhConfig(
    host="your-server.com",
    username="user",
    password="pass",
    max_connections=20,  # Increase connection pool
    pool_size=10
)
```

### 2. Caching

```python
import asyncio
from datetime import datetime, timedelta

class CachedWazuhClient:
    def __init__(self):
        self.client = None
        self.cache = {}
        self.cache_ttl = 300  # 5 minutes
    
    async def get_alerts_cached(self, **kwargs):
        cache_key = str(kwargs)
        now = datetime.utcnow()
        
        if cache_key in self.cache:
            cached_data, cached_time = self.cache[cache_key]
            if now - cached_time < timedelta(seconds=self.cache_ttl):
                return cached_data
        
        # Fetch fresh data
        alerts = await self.client.get_alerts(**kwargs)
        self.cache[cache_key] = (alerts, now)
        return alerts
```

### 3. Parallel Operations

```python
async def get_dashboard_data():
    client = await create_client()
    
    # Fetch data in parallel
    alerts_task = client.get_alerts(limit=50)
    agents_task = client.get_agents()
    threats_task = client.analyze_threats(time_range=3600)
    
    alerts, agents, threats = await asyncio.gather(
        alerts_task, agents_task, threats_task,
        return_exceptions=True
    )
    
    await client.close()
    return alerts, agents, threats
```

## Next Steps

1. **Read the full documentation**: Check out `PACKAGE_USAGE.md` for detailed API documentation
2. **Explore examples**: Look at the `examples/` directory for more usage patterns
3. **Contribute**: See `CONTRIBUTING.md` for guidelines on contributing to the project
4. **Report issues**: Use the GitHub issue tracker for bugs and feature requests

For more help, visit the [GitHub repository](https://github.com/gensecaihq/Wazuh-MCP-Server) or check the documentation.
