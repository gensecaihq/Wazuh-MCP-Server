# Package Installation and Usage Guide

This guide explains how to install and use the Wazuh MCP Server as a pip package.

## Installation Methods

### Method 1: Install from GitHub (Recommended)
```bash
pip install git+https://github.com/socfortress/Wazuh-MCP-Server.git
```

### Method 2: Install from PyPI (when published)
```bash
pip install wazuh-mcp-server
```

### Method 3: Install from Local Build
```bash
# Clone the repository
git clone https://github.com/socfortress/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server

# Build the package
python build_package.py

# Install the built package
pip install dist/*.whl
```

## Quick Start

### 1. Command Line Usage
After installation, you can use the command-line tools:

```bash
# Start the MCP server
wazuh-mcp-server --help

# Test connection to Wazuh
wazuh-mcp-test
```

### 2. Python Module Usage
```python
# Import the main components
from wazuh_mcp_server import main
from wazuh_mcp_server.config import WazuhConfig
from wazuh_mcp_server.api_client import WazuhAPIClient

# Create a configuration
config = WazuhConfig(
    host="your-wazuh-host",
    port=55000,
    username="your-username",
    password="your-password"
)

# Create an API client
client = WazuhAPIClient(config)

# Use the client for Wazuh operations
# (See the main documentation for detailed API usage)
```

### 3. Environment Configuration
Create a `.env` file in your project directory:

```env
WAZUH_HOST=your-wazuh-host
WAZUH_PORT=55000
WAZUH_USERNAME=your-username
WAZUH_PASSWORD=your-password
WAZUH_PROTOCOL=https
```

## Testing the Installation

Run the test script to verify everything is working:

```bash
python -c "
import sys
try:
    from wazuh_mcp_server import main
    from wazuh_mcp_server.__version__ import __version__
    print(f'✅ Wazuh MCP Server {__version__} installed successfully!')
except ImportError as e:
    print(f'❌ Installation issue: {e}')
    sys.exit(1)
"
```

## Integration Examples

### Using in a Python Application
```python
import asyncio
from wazuh_mcp_server.main import WazuhMCPServer
from wazuh_mcp_server.config import WazuhConfig

async def main():
    # Configure the server
    config = WazuhConfig.from_env()  # Load from environment variables
    
    # Create and start the server
    server = WazuhMCPServer(config)
    await server.start()

if __name__ == "__main__":
    asyncio.run(main())
```

### Using with Docker
```dockerfile
FROM python:3.11-slim

# Install the package
RUN pip install git+https://github.com/socfortress/Wazuh-MCP-Server.git

# Copy your configuration
COPY .env /app/.env

# Set working directory
WORKDIR /app

# Run the server
CMD ["wazuh-mcp-server"]
```

### Using in requirements.txt
Add to your `requirements.txt`:
```txt
# Option 1: From GitHub
git+https://github.com/socfortress/Wazuh-MCP-Server.git

# Option 2: From PyPI (when available)
# wazuh-mcp-server>=1.1.0
```

## Development Installation

For development purposes:

```bash
# Clone the repository
git clone https://github.com/socfortress/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server

# Install in editable mode with development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Build the package
python build_package.py
```

## Troubleshooting

### Common Issues

1. **Import Error**: Make sure the package is installed:
   ```bash
   pip list | grep wazuh-mcp-server
   ```

2. **Connection Issues**: Verify your Wazuh configuration:
   ```bash
   wazuh-mcp-test
   ```

3. **Permission Issues**: Ensure proper authentication credentials:
   ```bash
   # Check your .env file or environment variables
   echo $WAZUH_HOST
   ```

### Getting Help

- Check the [main documentation](../README.md)
- Review the [API reference](../docs/API_REFERENCE.md)
- Look at [configuration options](../docs/CONFIGURATION_REFERENCE.md)
- See [examples](../examples/) for usage patterns

## Uninstallation

To remove the package:
```bash
pip uninstall wazuh-mcp-server
```

## Contributing

If you want to contribute to the package:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test with `python build_package.py`
5. Submit a pull request

For more details, see [CONTRIBUTING.md](../CONTRIBUTING.md).
