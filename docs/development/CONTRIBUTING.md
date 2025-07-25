# Contributing to Wazuh MCP Server

Thank you for your interest in contributing to the Wazuh MCP Server! This document provides guidelines and instructions for contributing to this project.

## 📚 Complete Documentation Suite

For comprehensive guidance based on your role:

- **🧑‍💻 [Developer Guide](../../DEVELOPER_GUIDE.md)** - Complete developer contribution guide with architecture, coding standards, and workflows
- **🔧 [Wazuh Admin Guide](../../WAZUH_ADMIN_GUIDE.md)** - Production deployment and configuration for Wazuh administrators  
- **🛡️ [Security Professional Guide](../../SECURITY_PROFESSIONAL_GUIDE.md)** - AI-enhanced security operations and threat analysis
- **📖 [Main README](../../README.md)** - Project overview and quick start guide

This document provides a quick reference for contributors. For detailed information, please refer to the **[Developer Guide](../../DEVELOPER_GUIDE.md)**.

## 🎯 How to Contribute

### Reporting Issues
- Use GitHub Issues to report bugs or request features
- Search existing issues before creating new ones
- Provide detailed reproduction steps for bugs
- Include system information (OS, Python version, Wazuh version)

### Submitting Pull Requests
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes following our coding standards
4. Add tests for your changes
5. Ensure all tests pass
6. Update documentation if needed
7. Commit with clear messages
8. Push to your fork
9. Create a Pull Request

## 🛠️ Development Setup

### Prerequisites
- Python 3.9+
- Docker and Docker Compose (for testing production mode)
- Git

### Local Development
```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server

# Run the installation script
python3 scripts/install.py

# Set up environment
# Edit .env with your test Wazuh server details
nano .env

# Activate virtual environment
source venv/bin/activate

# Run tests
pytest

# Run linting
ruff check src/
black --check src/

# Test the MCP server
python src/wazuh_mcp_server/main.py --stdio

# Validate setup
python scripts/validate_setup.py
```

## 📝 Coding Standards

### Python Code Style
- Follow PEP 8
- Use Black for formatting
- Use Ruff for linting
- Maximum line length: 88 characters
- Use type hints where possible

### Code Organization
- Keep functions focused and small
- Use descriptive variable and function names
- Add docstrings to all public functions
- Group imports: standard library, third-party, local

### Example Code Style
```python
"""Module for handling Wazuh API connections."""

import asyncio
from typing import Dict, Any, Optional

from wazuh_mcp_server.utils import get_logger

logger = get_logger(__name__)


async def fetch_alerts(
    limit: int = 100, 
    level: Optional[int] = None
) -> Dict[str, Any]:
    """Fetch security alerts from Wazuh API.
    
    Args:
        limit: Maximum number of alerts to fetch
        level: Alert severity level filter
        
    Returns:
        Dictionary containing alert data
        
    Raises:
        APIError: When API request fails
    """
    # Implementation here
    pass
```

## 🧪 Testing

### Test Requirements
- All new features must include tests
- Aim for 80%+ code coverage
- Test both success and error cases
- Use meaningful test names

### Test Structure
```bash
tests/
├── __init__.py
├── conftest.py              # Shared fixtures
├── fixtures/
│   └── mock_data.py         # Test data
├── test_config.py           # Configuration tests
├── test_wazuh_integration.py # API integration tests
└── test_security_analyzer.py # Analysis tests
```

### Writing Tests
```python
import pytest
from unittest.mock import AsyncMock, patch

from wazuh_mcp_server.api.wazuh_client import WazuhAPIClient


@pytest.mark.asyncio
async def test_fetch_alerts_success(mock_wazuh_config):
    """Test successful alert fetching."""
    client = WazuhAPIClient(mock_wazuh_config)
    
    with patch.object(client, '_request') as mock_request:
        mock_request.return_value = {"data": {"affected_items": []}}
        
        result = await client.get_alerts(limit=10)
        
        assert "data" in result
        mock_request.assert_called_once()
```

## 📚 Documentation

### Documentation Standards
- Update README.md for user-facing changes
- Add docstrings to all public APIs
- Update relevant setup guides in `docs/`
- Include code examples for new features

### Documentation Structure
- **README.md** - Main project documentation and quick start
- **docs/LOCAL_SETUP.md** - Local development setup guide
- **docs/API_REFERENCE.md** - Complete API documentation
- **docs/CONFIGURATION_REFERENCE.md** - Configuration options
- **validate_setup.py** - Setup validation and troubleshooting

## 🔒 Security

### Security Guidelines
- Never commit credentials or secrets
- Use environment variables for configuration
- Validate all user inputs
- Follow secure coding practices
- Report security issues privately

### Reporting Security Issues
For security vulnerabilities, email: security@wazuh-mcp-server.org
- Do not open public issues for security problems
- Provide detailed reproduction steps
- Allow time for fixes before disclosure

## 🏷️ Versioning

We use [Semantic Versioning](https://semver.org/):
- **MAJOR** - Breaking changes
- **MINOR** - New features (backward compatible)
- **PATCH** - Bug fixes (backward compatible)

## 📋 Code Review Process

### Pull Request Requirements
- [ ] All tests pass
- [ ] Code follows style guidelines
- [ ] Documentation updated
- [ ] Changelog updated
- [ ] No merge conflicts
- [ ] Approved by maintainer

### Review Criteria
- Code quality and maintainability
- Test coverage and quality
- Documentation completeness
- Performance impact
- Security considerations

## 🌟 Recognition

Contributors are recognized in:
- GitHub contributors list
- CHANGELOG.md release notes
- Project documentation

## 📞 Getting Help

- **GitHub Discussions** - General questions and ideas
- **GitHub Issues** - Bug reports and feature requests
- **Documentation** - Check docs/ directory first

## 🎉 Thank You!

Your contributions help make Wazuh MCP Server better for everyone. We appreciate your time and effort!