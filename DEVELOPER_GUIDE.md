# Wazuh MCP Server - Developer Contribution Guide

A comprehensive guide for developers contributing to the Wazuh MCP Server project, including architecture overview, development setup, coding standards, and contribution workflows.

## 📋 Table of Contents

- [Project Overview](#project-overview)
- [Architecture & Design](#architecture--design)
- [Development Environment Setup](#development-environment-setup)
- [Code Standards & Best Practices](#code-standards--best-practices)
- [Development Workflow](#development-workflow)
- [Testing Guidelines](#testing-guidelines)
- [Security Development](#security-development)
- [Performance Optimization](#performance-optimization)
- [Documentation Standards](#documentation-standards)
- [Contribution Process](#contribution-process)
- [Troubleshooting Development Issues](#troubleshooting-development-issues)

---

## 🔍 Project Overview

### Mission Statement
Provide a production-ready, secure, and highly performant MCP server that enables AI-powered security operations through Wazuh SIEM integration.

### Key Design Principles
- **Security First**: All code must follow security best practices
- **Performance**: Optimized for high-throughput environments
- **Reliability**: Robust error handling and recovery
- **Modularity**: Clean, maintainable architecture
- **Testability**: Comprehensive test coverage required

### Technology Stack
- **Core Framework**: FastMCP 2.10.6+
- **Language**: Python 3.10+
- **HTTP Client**: httpx with HTTP/2 support
- **Async Framework**: asyncio
- **Validation**: Pydantic v1/v2 compatible
- **Security**: JWT, SSL/TLS validation
- **Testing**: pytest, pytest-asyncio
- **Code Quality**: Black, Ruff, mypy

---

## 🏗️ Architecture & Design

### System Architecture

```
┌─────────────────────────────────────────┐
│            Client Layer                 │
│  ├─ Claude Desktop (STDIO)             │
│  ├─ HTTP/SSE Clients                   │
│  └─ Custom MCP Clients                 │
└─────────────────────────────────────────┘
               │
┌─────────────────────────────────────────┐
│          Transport Layer                │
│  ├─ STDIO Transport                    │
│  ├─ HTTP/SSE Transport                 │
│  └─ Protocol Negotiation               │
└─────────────────────────────────────────┘
               │
┌─────────────────────────────────────────┐
│           MCP Server Core               │
│  ├─ Tool Registry                      │
│  ├─ Request Router                     │
│  ├─ Authentication                     │
│  ├─ Rate Limiting                      │
│  └─ Error Handling                     │
└─────────────────────────────────────────┘
               │
┌─────────────────────────────────────────┐
│         Business Logic Layer           │
│  ├─ Security Analyzers                 │
│  ├─ Compliance Checkers               │
│  ├─ Statistics Processors             │
│  └─ Alert Processors                   │
└─────────────────────────────────────────┘
               │
┌─────────────────────────────────────────┐
│           API Client Layer              │
│  ├─ Wazuh API Client                   │
│  ├─ Wazuh Indexer Client               │
│  ├─ Connection Pool Manager            │
│  └─ Authentication Manager             │
└─────────────────────────────────────────┘
               │
┌─────────────────────────────────────────┐
│          Wazuh Infrastructure           │
│  ├─ Wazuh Manager (API)                │
│  ├─ Wazuh Indexer (Elasticsearch)      │
│  └─ Agent Network                      │
└─────────────────────────────────────────┘
```

### Core Components

#### 1. **Server Core** (`src/wazuh_mcp_server/server.py`)
- FastMCP server initialization
- Transport configuration (STDIO/HTTP)
- Tool registration and management
- Global error handling

#### 2. **Configuration Management** (`src/wazuh_mcp_server/config.py`)
- Environment variable handling
- Configuration validation
- SSL/TLS settings management
- Performance tuning parameters

#### 3. **API Clients** (`src/wazuh_mcp_server/api/`)
- **wazuh_client.py**: Main Wazuh API client
- **wazuh_indexer_client.py**: Elasticsearch/OpenSearch client
- **wazuh_client_manager.py**: Connection pooling and lifecycle
- **wazuh_field_mappings.py**: Field mapping utilities

#### 4. **Tool Implementations** (`src/wazuh_mcp_server/tools/`)
- **base.py**: Base tool class with common functionality
- **agents.py**: Agent management tools
- **alerts.py**: Alert retrieval and analysis
- **vulnerabilities.py**: Vulnerability assessment
- **statistics.py**: Performance and health metrics
- **cluster.py**: Cluster status and management

#### 5. **Security & Authentication** (`src/wazuh_mcp_server/auth/`)
- **secure_auth.py**: JWT token management
- Password validation and hashing
- API key management

#### 6. **Analyzers** (`src/wazuh_mcp_server/analyzers/`)
- **security_analyzer.py**: AI-powered security analysis
- **compliance_analyzer.py**: Compliance checking logic

#### 7. **Utilities** (`src/wazuh_mcp_server/utils/`)
- **logging.py**: Structured logging
- **validation.py**: Input validation and sanitization
- **error_handling.py**: Error standardization
- **rate_limiter.py**: Request rate limiting
- **ssl_config.py**: SSL/TLS configuration

### Data Flow

1. **Request Reception**: Client sends MCP request via STDIO or HTTP
2. **Authentication**: Validate credentials and permissions
3. **Rate Limiting**: Check request limits per client
4. **Input Validation**: Sanitize and validate all inputs
5. **Tool Routing**: Route to appropriate tool handler
6. **Business Logic**: Execute security analysis or data retrieval
7. **API Communication**: Interact with Wazuh Manager/Indexer
8. **Response Processing**: Format and validate response
9. **Error Handling**: Standardize errors and logging
10. **Response Delivery**: Return structured response to client

---

## 🛠️ Development Environment Setup

### Prerequisites

- **Python**: 3.10 or higher
- **Git**: Latest version
- **Docker**: For integration testing (optional but recommended)
- **VS Code/PyCharm**: Recommended IDEs

### Initial Setup

```bash
# 1. Clone repository
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server

# 2. Create virtual environment
python3 -m venv dev-env
source dev-env/bin/activate  # On Windows: dev-env\Scripts\activate

# 3. Install development dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt  # If available

# 4. Install development tools
pip install pytest pytest-asyncio pytest-cov
pip install black ruff mypy
pip install pre-commit

# 5. Setup pre-commit hooks
pre-commit install

# 6. Setup environment configuration
cp .env.development .env
# Edit .env with your test Wazuh server details

# 7. Validate setup
python3 validate-production.py --dev
```

### Development Dependencies

Create `requirements-dev.txt`:

```text
# Testing
pytest>=7.0.0
pytest-asyncio>=0.21.0
pytest-cov>=4.0.0
pytest-mock>=3.10.0

# Code Quality
black>=23.0.0
ruff>=0.1.0
mypy>=1.5.0
isort>=5.12.0

# Development Tools
pre-commit>=3.0.0
bandit>=1.7.5
safety>=2.3.0

# Documentation
mkdocs>=1.5.0
mkdocs-material>=9.0.0

# Debugging
ipdb>=0.13.0
pytest-xdist>=3.3.0
```

### IDE Configuration

#### VS Code Settings (`.vscode/settings.json`)

```json
{
  "python.defaultInterpreterPath": "./dev-env/bin/python",
  "python.formatting.provider": "black",
  "python.linting.enabled": true,
  "python.linting.ruffEnabled": true,
  "python.linting.mypyEnabled": true,
  "python.testing.pytestEnabled": true,
  "python.testing.pytestPath": "./dev-env/bin/pytest",
  "files.exclude": {
    "**/__pycache__": true,
    "**/*.pyc": true,
    ".pytest_cache": true,
    ".mypy_cache": true,
    ".ruff_cache": true
  },
  "python.analysis.typeCheckingMode": "strict"
}
```

#### PyCharm Configuration

1. Set Python interpreter to `./dev-env/bin/python`
2. Enable Black formatter
3. Configure Ruff as external tool
4. Setup pytest as test runner

---

## 📐 Code Standards & Best Practices

### Python Code Style

We follow PEP 8 with these specific guidelines:

#### Formatting Standards
- **Line Length**: 88 characters (Black default)
- **Indentation**: 4 spaces (no tabs)
- **Quotes**: Double quotes for strings, single for single characters
- **Import Organization**: Standard library, third-party, local imports

#### Naming Conventions
```python
# Classes: PascalCase
class WazuhAPIClient:
    pass

# Functions/Methods: snake_case
def get_security_alerts():
    pass

# Variables: snake_case
alert_count = 10

# Constants: UPPER_SNAKE_CASE
MAX_RETRY_ATTEMPTS = 3

# Private methods: _leading_underscore
def _validate_internal_state():
    pass

# Protected methods: _single_underscore
def _process_response(self, response):
    pass
```

#### Type Hints (Required)
```python
from typing import Dict, List, Optional, Union, Any
from datetime import datetime

async def fetch_alerts(
    limit: int = 100,
    level: Optional[int] = None,
    start_time: Optional[datetime] = None
) -> Dict[str, Any]:
    """Fetch security alerts with proper typing."""
    pass

# Use Union for multiple types
def process_agent_id(agent_id: Union[str, int]) -> str:
    return str(agent_id)

# Use generics for containers
def get_agent_list() -> List[Dict[str, Any]]:
    return []
```

#### Docstring Standards (Google Style)
```python
async def analyze_security_threats(
    alerts: List[Dict[str, Any]],
    severity_threshold: int = 5,
    include_analysis: bool = True
) -> Dict[str, Any]:
    """Analyze security threats from alerts using AI-powered analysis.
    
    This function processes security alerts and provides AI-enhanced analysis
    including threat classification, risk scoring, and recommendations.
    
    Args:
        alerts: List of alert dictionaries from Wazuh API
        severity_threshold: Minimum severity level to include (1-15)
        include_analysis: Whether to include AI analysis in response
        
    Returns:
        Dictionary containing:
            - threat_summary: High-level threat analysis
            - recommendations: List of recommended actions
            - risk_score: Overall risk score (0-100)
            - processed_count: Number of alerts processed
            
    Raises:
        ValidationError: When alerts format is invalid
        APIError: When external API calls fail
        AnalysisError: When AI analysis fails
        
    Example:
        >>> alerts = await client.get_alerts(limit=50)
        >>> analysis = await analyze_security_threats(
        ...     alerts=alerts,
        ...     severity_threshold=7,
        ...     include_analysis=True
        ... )
        >>> print(f"Risk Score: {analysis['risk_score']}")
    """
    pass
```

### Error Handling Standards

#### Custom Exception Hierarchy
```python
# Base exceptions (src/wazuh_mcp_server/utils/exceptions.py)
class WazuhMCPError(Exception):
    """Base exception for all Wazuh MCP Server errors."""
    pass

class ConfigurationError(WazuhMCPError):
    """Configuration related errors."""
    pass

class AuthenticationError(WazuhMCPError):
    """Authentication and authorization errors."""
    pass

class APIError(WazuhMCPError):
    """Wazuh API communication errors."""
    pass

class ValidationError(WazuhMCPError):
    """Input validation errors."""
    pass

class RateLimitError(WazuhMCPError):
    """Rate limiting errors."""
    pass
```

#### Error Handling Patterns
```python
import logging
from typing import Optional
from ..utils.exceptions import APIError, ValidationError

logger = logging.getLogger(__name__)

async def safe_api_call(
    endpoint: str,
    params: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Safely call Wazuh API with proper error handling."""
    try:
        # Input validation
        if not endpoint:
            raise ValidationError("Endpoint cannot be empty")
            
        # API call with timeout
        response = await self._make_request(endpoint, params)
        
        # Response validation
        if not response or 'data' not in response:
            raise APIError(f"Invalid response from {endpoint}")
            
        return response
        
    except httpx.TimeoutException as e:
        logger.error(f"Timeout calling {endpoint}: {e}")
        raise APIError(f"Request timeout for {endpoint}")
        
    except httpx.HTTPStatusError as e:
        logger.error(f"HTTP error {e.response.status_code} for {endpoint}")
        raise APIError(f"HTTP {e.response.status_code}: {e.response.text}")
        
    except Exception as e:
        logger.exception(f"Unexpected error calling {endpoint}")
        raise APIError(f"Failed to call {endpoint}: {str(e)}")
```

### Logging Standards

```python
import logging
from ..utils.logging import get_logger

# Get structured logger
logger = get_logger(__name__)

class WazuhAPIClient:
    def __init__(self):
        self.logger = get_logger(f"{__name__}.{self.__class__.__name__}")
    
    async def get_alerts(self, limit: int = 100) -> Dict[str, Any]:
        """Get alerts with comprehensive logging."""
        
        # Info logging for operations
        self.logger.info(
            "Fetching alerts",
            extra={"limit": limit, "operation": "get_alerts"}
        )
        
        try:
            response = await self._api_call("/alerts", {"limit": limit})
            
            # Success logging with metrics
            self.logger.info(
                "Successfully fetched alerts",
                extra={
                    "alert_count": len(response.get("data", [])),
                    "limit": limit,
                    "response_size": len(str(response))
                }
            )
            
            return response
            
        except Exception as e:
            # Error logging with context
            self.logger.error(
                "Failed to fetch alerts",
                extra={
                    "error": str(e),
                    "error_type": type(e).__name__,
                    "limit": limit
                },
                exc_info=True
            )
            raise
```

### Security Coding Standards

#### Input Validation
```python
import re
import html
from typing import Any

def validate_agent_id(agent_id: str) -> str:
    """Validate and sanitize agent ID."""
    if not isinstance(agent_id, str):
        raise ValidationError("Agent ID must be string")
    
    # Remove any non-alphanumeric characters
    sanitized = re.sub(r'[^a-zA-Z0-9]', '', agent_id)
    
    if not sanitized:
        raise ValidationError("Agent ID cannot be empty after sanitization")
    
    if len(sanitized) > 10:
        raise ValidationError("Agent ID too long")
    
    return sanitized

def sanitize_output(data: Any) -> Any:
    """Sanitize output data to prevent XSS."""
    if isinstance(data, str):
        return html.escape(data)
    elif isinstance(data, dict):
        return {k: sanitize_output(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [sanitize_output(item) for item in data]
    return data
```

#### Secure Configuration
```python
import os
from typing import Optional

class SecureConfig:
    """Secure configuration handling."""
    
    @staticmethod
    def get_secret(key: str, default: Optional[str] = None) -> str:
        """Get secret from environment with validation."""
        value = os.getenv(key, default)
        
        if not value:
            raise ConfigurationError(f"Required secret {key} not found")
        
        # Validate secret strength
        if key.endswith('_PASS') and len(value) < 12:
            raise ConfigurationError(f"Password {key} too weak")
        
        return value
    
    @staticmethod
    def mask_sensitive_data(data: Dict[str, Any]) -> Dict[str, Any]:
        """Mask sensitive data in logs."""
        sensitive_keys = {'password', 'token', 'key', 'secret'}
        
        result = {}
        for k, v in data.items():
            if any(sensitive in k.lower() for sensitive in sensitive_keys):
                result[k] = '***masked***'
            else:
                result[k] = v
        
        return result
```

---

## 🔄 Development Workflow

### Git Workflow

We use GitFlow with these branches:

- **main**: Production-ready code
- **develop**: Integration branch for features
- **feature/***: Individual feature development
- **hotfix/***: Critical bug fixes
- **release/***: Release preparation

#### Branch Naming Conventions
```bash
# Features
feature/add-threat-analysis
feature/improve-error-handling
feature/update-authentication

# Bug fixes
bugfix/fix-connection-timeout
bugfix/resolve-memory-leak

# Hotfixes
hotfix/security-patch-jwt
hotfix/critical-api-fix

# Documentation
docs/update-api-reference
docs/add-security-guide
```

#### Commit Message Standards

Follow Conventional Commits:

```bash
# Format: type(scope): description

# Feature commits
feat(api): add threat analysis endpoint
feat(auth): implement JWT refresh token rotation
feat(tools): add vulnerability assessment tool

# Bug fix commits
fix(client): resolve connection timeout issues
fix(validation): prevent SQL injection in filters
fix(logging): fix memory leak in log rotation

# Documentation commits
docs(readme): update installation instructions
docs(api): add endpoint documentation
docs(security): update security guidelines

# Refactoring commits
refactor(auth): simplify token validation logic
refactor(tools): extract common base functionality

# Test commits
test(integration): add Wazuh API integration tests
test(unit): improve coverage for validators

# Chore commits
chore(deps): update FastMCP to 2.10.6
chore(ci): update GitHub Actions workflow
```

### Development Process

#### 1. Feature Development
```bash
# 1. Create feature branch
git checkout develop
git pull origin develop
git checkout -b feature/add-new-tool

# 2. Implement feature with tests
# 3. Run quality checks
make lint
make test
make security-check

# 4. Commit changes
git add .
git commit -m "feat(tools): add agent health monitoring tool"

# 5. Push and create PR
git push origin feature/add-new-tool
# Create Pull Request via GitHub
```

#### 2. Code Review Process

All code must be reviewed before merging:

**Review Checklist:**
- [ ] Code follows style guidelines
- [ ] All tests pass
- [ ] Security review completed
- [ ] Documentation updated
- [ ] Performance impact assessed
- [ ] Backward compatibility maintained

**Security Review:**
- [ ] Input validation implemented
- [ ] No secrets in code
- [ ] Error handling doesn't leak information
- [ ] Authentication/authorization checked
- [ ] SQL injection prevention
- [ ] XSS prevention

#### 3. Quality Gates

Before merging, code must pass:

```bash
# Code formatting
black --check src/
isort --check-only src/

# Linting
ruff check src/
mypy src/

# Security scanning
bandit -r src/
safety check

# Testing
pytest tests/ --cov=src --cov-report=html

# Integration testing
python3 validate-production.py --test
```

### Makefile for Development

Create `Makefile`:

```makefile
.PHONY: help install lint test security-check format clean dev-setup

help:
	@echo "Available commands:"
	@echo "  install       Install dependencies"
	@echo "  dev-setup     Setup development environment"
	@echo "  format        Format code with Black and isort"
	@echo "  lint          Run linting checks"
	@echo "  test          Run tests with coverage"
	@echo "  security-check Security scanning"
	@echo "  clean         Clean build artifacts"

install:
	pip install -r requirements.txt
	pip install -r requirements-dev.txt

dev-setup: install
	pre-commit install
	cp .env.development .env

format:
	black src/ tests/
	isort src/ tests/

lint:
	ruff check src/ tests/
	mypy src/
	black --check src/ tests/
	isort --check-only src/ tests/

test:
	pytest tests/ --cov=src --cov-report=html --cov-report=term

security-check:
	bandit -r src/
	safety check
	python3 validate-production.py --security

clean:
	find . -type d -name "__pycache__" -delete
	find . -type f -name "*.pyc" -delete
	rm -rf .pytest_cache .mypy_cache .ruff_cache
	rm -rf htmlcov/ .coverage

ci-check: lint test security-check
	@echo "All CI checks passed!"
```

---

## 🧪 Testing Guidelines

### Testing Architecture

```
tests/
├── unit/                           # Unit tests
│   ├── test_config.py             # Configuration testing
│   ├── test_validation.py         # Input validation
│   ├── test_auth.py               # Authentication logic
│   └── test_analyzers.py          # Analysis logic
├── integration/                    # Integration tests
│   ├── test_wazuh_integration.py  # Wazuh API integration
│   ├── test_server.py             # MCP server integration
│   └── test_end_to_end.py         # Full workflow tests
├── fixtures/                      # Test data and mocks
│   ├── mock_data.py               # Mock Wazuh responses
│   ├── test_configs.py            # Test configurations
│   └── certificates/              # Test SSL certificates
├── performance/                   # Performance tests
│   ├── test_load.py               # Load testing
│   └── test_memory.py             # Memory usage tests
└── conftest.py                    # Pytest configuration
```

### Unit Testing Standards

#### Test Structure
```python
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from datetime import datetime, timedelta

from wazuh_mcp_server.analyzers.security_analyzer import SecurityAnalyzer
from wazuh_mcp_server.utils.exceptions import ValidationError, APIError

class TestSecurityAnalyzer:
    """Test suite for SecurityAnalyzer class."""
    
    @pytest.fixture
    def analyzer(self):
        """Create SecurityAnalyzer instance for testing."""
        return SecurityAnalyzer()
    
    @pytest.fixture
    def sample_alerts(self):
        """Sample alert data for testing."""
        return [
            {
                "id": "001",
                "level": 10,
                "description": "Authentication failure",
                "timestamp": "2024-01-01T12:00:00Z",
                "agent": {"id": "001", "name": "web-server"}
            },
            {
                "id": "002", 
                "level": 7,
                "description": "Suspicious network activity",
                "timestamp": "2024-01-01T12:05:00Z",
                "agent": {"id": "002", "name": "db-server"}
            }
        ]
    
    @pytest.mark.asyncio
    async def test_analyze_threats_success(self, analyzer, sample_alerts):
        """Test successful threat analysis."""
        result = await analyzer.analyze_threats(sample_alerts)
        
        assert "threat_summary" in result
        assert "risk_score" in result
        assert "recommendations" in result
        assert isinstance(result["risk_score"], (int, float))
        assert 0 <= result["risk_score"] <= 100
    
    @pytest.mark.asyncio
    async def test_analyze_threats_empty_alerts(self, analyzer):
        """Test analysis with empty alert list."""
        result = await analyzer.analyze_threats([])
        
        assert result["threat_summary"] == "No threats detected"
        assert result["risk_score"] == 0
        assert result["recommendations"] == []
    
    @pytest.mark.asyncio
    async def test_analyze_threats_invalid_input(self, analyzer):
        """Test analysis with invalid input."""
        with pytest.raises(ValidationError):
            await analyzer.analyze_threats("invalid")
    
    @pytest.mark.asyncio
    async def test_analyze_threats_api_error(self, analyzer, sample_alerts):
        """Test handling of API errors during analysis."""
        with patch.object(analyzer, '_call_analysis_api') as mock_api:
            mock_api.side_effect = APIError("Analysis service unavailable")
            
            with pytest.raises(APIError):
                await analyzer.analyze_threats(sample_alerts)
    
    def test_calculate_risk_score(self, analyzer, sample_alerts):
        """Test risk score calculation."""
        score = analyzer._calculate_risk_score(sample_alerts)
        
        assert isinstance(score, (int, float))
        assert 0 <= score <= 100
        
        # Test with high severity alerts
        high_severity_alerts = [
            {"level": 15, "description": "Critical security event"}
        ]
        high_score = analyzer._calculate_risk_score(high_severity_alerts)
        assert high_score > score
```

#### Mock Usage Patterns
```python
@pytest.mark.asyncio
async def test_wazuh_api_client_with_mocks():
    """Test Wazuh API client with comprehensive mocking."""
    
    # Mock httpx client
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "data": {"affected_items": [], "total_affected_items": 0}
    }
    
    with patch('httpx.AsyncClient') as mock_client:
        mock_client.return_value.__aenter__.return_value.get.return_value = mock_response
        
        config = WazuhConfig(
            host="test.com",
            user="test",
            password="test"
        )
        client = WazuhAPIClient(config)
        
        result = await client.get_alerts(limit=10)
        
        assert "data" in result
        mock_client.return_value.__aenter__.return_value.get.assert_called_once()
```

### Integration Testing

#### Wazuh API Integration Tests
```python
import pytest
import asyncio
from typing import Dict, Any

from wazuh_mcp_server.api.wazuh_client import WazuhAPIClient
from wazuh_mcp_server.config import WazuhConfig

@pytest.mark.integration
@pytest.mark.asyncio
class TestWazuhIntegration:
    """Integration tests for Wazuh API communication."""
    
    @pytest.fixture(scope="class")
    def wazuh_config(self):
        """Get test Wazuh configuration."""
        return WazuhConfig.from_env(prefix="TEST_")
    
    @pytest.fixture(scope="class")
    async def wazuh_client(self, wazuh_config):
        """Create authenticated Wazuh client."""
        client = WazuhAPIClient(wazuh_config)
        await client.authenticate()
        yield client
        await client.close()
    
    async def test_authentication(self, wazuh_client):
        """Test Wazuh API authentication."""
        assert wazuh_client.is_authenticated
        assert wazuh_client.token is not None
    
    async def test_get_agents(self, wazuh_client):
        """Test agent retrieval."""
        agents = await wazuh_client.get_agents(limit=5)
        
        assert "data" in agents
        assert "affected_items" in agents["data"]
        assert isinstance(agents["data"]["affected_items"], list)
    
    async def test_get_alerts(self, wazuh_client):
        """Test alert retrieval."""
        alerts = await wazuh_client.get_alerts(limit=10)
        
        assert "data" in alerts
        # Test alert structure
        if alerts["data"]["affected_items"]:
            alert = alerts["data"]["affected_items"][0]
            assert "id" in alert
            assert "level" in alert
    
    async def test_connection_resilience(self, wazuh_config):
        """Test connection resilience and retry logic."""
        client = WazuhAPIClient(wazuh_config)
        
        # Test multiple rapid connections
        tasks = [client.get_agents(limit=1) for _ in range(5)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Should handle concurrent requests gracefully
        success_count = sum(1 for r in results if not isinstance(r, Exception))
        assert success_count >= 3  # Allow some failures
        
        await client.close()
```

### Performance Testing

```python
import pytest
import asyncio
import time
import psutil
from typing import List

@pytest.mark.performance
class TestPerformance:
    """Performance testing suite."""
    
    @pytest.mark.asyncio
    async def test_alert_retrieval_performance(self, wazuh_client):
        """Test alert retrieval performance."""
        start_time = time.time()
        
        # Retrieve 1000 alerts
        alerts = await wazuh_client.get_alerts(limit=1000)
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Should complete within 10 seconds
        assert duration < 10.0
        
        # Memory usage should be reasonable
        process = psutil.Process()
        memory_mb = process.memory_info().rss / 1024 / 1024
        assert memory_mb < 500  # Less than 500MB
    
    @pytest.mark.asyncio
    async def test_concurrent_requests(self, wazuh_client):
        """Test concurrent request handling."""
        start_time = time.time()
        
        # Make 20 concurrent requests
        tasks = [
            wazuh_client.get_agents(limit=10) 
            for _ in range(20)
        ]
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        end_time = time.time()
        duration = end_time - start_time
        
        # Should handle concurrency efficiently
        assert duration < 15.0
        
        # Most requests should succeed
        success_count = sum(1 for r in results if not isinstance(r, Exception))
        assert success_count >= 15
    
    def test_memory_leak_detection(self):
        """Test for memory leaks during repeated operations."""
        import gc
        
        initial_objects = len(gc.get_objects())
        
        # Simulate repeated operations
        for _ in range(100):
            config = WazuhConfig(host="test", user="test", password="test")
            client = WazuhAPIClient(config)
            del client
            
        gc.collect()
        final_objects = len(gc.get_objects())
        
        # Object count shouldn't grow significantly
        growth = final_objects - initial_objects
        assert growth < 50  # Allow some growth but not excessive
```

### Test Configuration

#### conftest.py
```python
import pytest
import asyncio
import os
from unittest.mock import MagicMock

from wazuh_mcp_server.config import WazuhConfig

@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()

@pytest.fixture
def mock_wazuh_config():
    """Mock Wazuh configuration for testing."""
    return WazuhConfig(
        host="test.wazuh.com",
        port=55000,
        user="test_user",
        password="test_password",
        verify_ssl=False,
        timeout=30
    )

@pytest.fixture
def mock_wazuh_response():
    """Mock Wazuh API response."""
    return {
        "data": {
            "affected_items": [
                {
                    "id": "001",
                    "name": "test-agent",
                    "status": "active",
                    "last_keepalive": "2024-01-01T12:00:00Z"
                }
            ],
            "total_affected_items": 1,
            "failed_items": []
        },
        "message": "Success",
        "error": 0
    }

# Skip integration tests if no test environment
def pytest_configure(config):
    """Configure pytest with custom markers."""
    if not os.getenv("TEST_WAZUH_HOST"):
        config.option.markexpr = "not integration"

# Custom markers
pytest_plugins = []
```

### Test Data Management

```python
# tests/fixtures/mock_data.py
from datetime import datetime, timedelta
from typing import Dict, List, Any

class MockWazuhData:
    """Generate mock Wazuh data for testing."""
    
    @staticmethod
    def generate_alerts(count: int = 10, min_level: int = 1) -> List[Dict[str, Any]]:
        """Generate mock alert data."""
        alerts = []
        base_time = datetime.now()
        
        for i in range(count):
            alert = {
                "id": f"alert_{i:03d}",
                "level": min_level + (i % 10),
                "description": f"Test security event {i}",
                "timestamp": (base_time - timedelta(minutes=i)).isoformat(),
                "rule": {
                    "id": f"rule_{i % 5}",
                    "description": f"Test rule {i % 5}"
                },
                "agent": {
                    "id": f"00{i % 3}",
                    "name": f"test-agent-{i % 3}",
                    "ip": f"192.168.1.{100 + (i % 50)}"
                },
                "location": f"/var/log/test{i % 3}.log"
            }
            alerts.append(alert)
        
        return alerts
    
    @staticmethod
    def generate_agents(count: int = 5) -> List[Dict[str, Any]]:
        """Generate mock agent data."""
        agents = []
        
        for i in range(count):
            agent = {
                "id": f"00{i}",
                "name": f"test-agent-{i}",
                "ip": f"192.168.1.{100 + i}",
                "status": "active" if i % 2 == 0 else "disconnected",
                "os": {
                    "platform": "ubuntu",
                    "version": "20.04"
                },
                "version": "4.8.0",
                "last_keepalive": datetime.now().isoformat(),
                "node_name": "master"
            }
            agents.append(agent)
        
        return agents
```

---

## 🔒 Security Development

### Security-First Development Principles

1. **Defense in Depth**: Multiple layers of security controls
2. **Principle of Least Privilege**: Minimal permissions required
3. **Input Validation**: All inputs validated and sanitized
4. **Output Encoding**: All outputs properly encoded
5. **Secure Defaults**: Secure configurations by default
6. **Fail Securely**: Failures should not compromise security

### Secure Coding Practices

#### Input Validation
```python
import re
import ipaddress
from typing import Any, Union
from ..utils.exceptions import ValidationError

class SecurityValidator:
    """Security-focused input validation."""
    
    # Dangerous patterns to block
    SQL_INJECTION_PATTERNS = [
        r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER)\b)",
        r"(--|#|/\*|\*/)",
        r"(\bOR\b.*=.*)",
        r"(;.*\bEXEC\b)"
    ]
    
    XSS_PATTERNS = [
        r"<script[^>]*>.*?</script>",
        r"javascript:",
        r"on\w+\s*=",
        r"<iframe[^>]*>.*?</iframe>"
    ]
    
    @classmethod
    def validate_agent_id(cls, agent_id: str) -> str:
        """Validate agent ID with security checks."""
        if not isinstance(agent_id, str):
            raise ValidationError("Agent ID must be string")
        
        # Check for dangerous patterns
        cls._check_sql_injection(agent_id)
        cls._check_xss(agent_id)
        
        # Sanitize and validate format
        sanitized = re.sub(r'[^a-zA-Z0-9_-]', '', agent_id)
        
        if not sanitized:
            raise ValidationError("Agent ID contains only invalid characters")
        
        if len(sanitized) > 50:
            raise ValidationError("Agent ID too long")
        
        return sanitized
    
    @classmethod
    def validate_ip_address(cls, ip: str) -> str:
        """Validate IP address with security checks."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Block private/internal IPs for external queries
            if ip_obj.is_private or ip_obj.is_loopback:
                raise ValidationError("Private IP addresses not allowed")
            
            return str(ip_obj)
            
        except ipaddress.AddressValueError:
            raise ValidationError(f"Invalid IP address: {ip}")
    
    @classmethod
    def _check_sql_injection(cls, value: str) -> None:
        """Check for SQL injection patterns."""
        for pattern in cls.SQL_INJECTION_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                raise ValidationError("Potentially dangerous SQL pattern detected")
    
    @classmethod
    def _check_xss(cls, value: str) -> None:
        """Check for XSS patterns."""
        for pattern in cls.XSS_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                raise ValidationError("Potentially dangerous XSS pattern detected")
```

#### Authentication Security
```python
import jwt
import bcrypt
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

class SecureAuthentication:
    """Secure authentication implementation."""
    
    def __init__(self, secret_key: str):
        self.secret_key = secret_key
        self.algorithm = "HS256"
        self.token_expiry = timedelta(minutes=30)
    
    def hash_password(self, password: str) -> str:
        """Hash password securely using bcrypt."""
        salt = bcrypt.gensalt(rounds=12)
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    def verify_password(self, password: str, hashed: str) -> bool:
        """Verify password against hash."""
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    
    def generate_token(self, user_id: str, permissions: List[str]) -> str:
        """Generate secure JWT token."""
        now = datetime.utcnow()
        
        payload = {
            "sub": user_id,
            "iat": now,
            "exp": now + self.token_expiry,
            "jti": secrets.token_urlsafe(16),  # Unique token ID
            "permissions": permissions,
            "iss": "wazuh-mcp-server"
        }
        
        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)
    
    def verify_token(self, token: str) -> Dict[str, Any]:
        """Verify and decode JWT token."""
        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm],
                options={"verify_exp": True, "verify_iat": True}
            )
            
            # Additional security checks
            if not payload.get("sub"):
                raise jwt.InvalidTokenError("Missing subject")
            
            if not payload.get("jti"):
                raise jwt.InvalidTokenError("Missing token ID")
            
            return payload
            
        except jwt.ExpiredSignatureError:
            raise AuthenticationError("Token expired")
        except jwt.InvalidTokenError as e:
            raise AuthenticationError(f"Invalid token: {e}")
```

#### Secure Configuration
```python
import os
import secrets
from typing import Optional, Dict, Any

class SecureConfigManager:
    """Secure configuration management."""
    
    @staticmethod
    def generate_secret_key() -> str:
        """Generate cryptographically secure secret key."""
        return secrets.token_urlsafe(32)
    
    @staticmethod
    def validate_config(config: Dict[str, Any]) -> None:
        """Validate configuration for security issues."""
        
        # Check for default/weak passwords
        if config.get("WAZUH_PASS") in ["admin", "password", "123456"]:
            raise ConfigurationError("Weak password detected")
        
        # Ensure SSL is enabled in production
        if os.getenv("ENVIRONMENT") == "production" and not config.get("VERIFY_SSL", True):
            raise ConfigurationError("SSL verification disabled in production")
        
        # Check secret key strength
        secret_key = config.get("JWT_SECRET_KEY")
        if secret_key and len(secret_key) < 32:
            raise ConfigurationError("JWT secret key too short")
    
    @staticmethod
    def mask_sensitive_config(config: Dict[str, Any]) -> Dict[str, Any]:
        """Mask sensitive configuration for logging."""
        sensitive_keys = {
            "password", "pass", "secret", "key", "token", "auth"
        }
        
        masked = {}
        for key, value in config.items():
            if any(sensitive in key.lower() for sensitive in sensitive_keys):
                masked[key] = "***masked***"
            else:
                masked[key] = value
        
        return masked
```

### Security Testing

```python
import pytest
from unittest.mock import patch

class TestSecurity:
    """Security-focused tests."""
    
    def test_sql_injection_prevention(self):
        """Test SQL injection prevention."""
        malicious_inputs = [
            "'; DROP TABLE users; --",
            "1' OR '1'='1",
            "UNION SELECT * FROM passwords",
            "admin'/**/OR/**/1=1--"
        ]
        
        validator = SecurityValidator()
        
        for malicious_input in malicious_inputs:
            with pytest.raises(ValidationError):
                validator.validate_agent_id(malicious_input)
    
    def test_xss_prevention(self):
        """Test XSS prevention."""
        xss_payloads = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>",
            "<iframe src='javascript:alert(1)'></iframe>"
        ]
        
        validator = SecurityValidator()
        
        for payload in xss_payloads:
            with pytest.raises(ValidationError):
                validator.validate_agent_id(payload)
    
    def test_password_security(self):
        """Test password hashing and verification."""
        auth = SecureAuthentication("test-secret")
        
        password = "SecurePassword123!"
        hashed = auth.hash_password(password)
        
        # Hash should be different from original
        assert hashed != password
        
        # Verification should work
        assert auth.verify_password(password, hashed)
        
        # Wrong password should fail
        assert not auth.verify_password("wrong", hashed)
    
    def test_jwt_token_security(self):
        """Test JWT token security."""
        auth = SecureAuthentication("test-secret-key")
        
        # Generate token
        token = auth.generate_token("user123", ["read"])
        
        # Verify token
        payload = auth.verify_token(token)
        assert payload["sub"] == "user123"
        assert "read" in payload["permissions"]
        
        # Invalid token should fail
        with pytest.raises(AuthenticationError):
            auth.verify_token("invalid.token.here")
```

---

## ⚡ Performance Optimization

### Performance Monitoring

```python
import time
import asyncio
import psutil
from typing import Dict, Any, Callable
from functools import wraps

class PerformanceMonitor:
    """Performance monitoring and optimization utilities."""
    
    @staticmethod
    def measure_execution_time(func: Callable) -> Callable:
        """Decorator to measure function execution time."""
        
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            start_time = time.perf_counter()
            try:
                result = await func(*args, **kwargs)
                return result
            finally:
                end_time = time.perf_counter()
                duration = end_time - start_time
                logger.info(
                    f"Function {func.__name__} took {duration:.4f} seconds",
                    extra={"function": func.__name__, "duration": duration}
                )
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            start_time = time.perf_counter()
            try:
                result = func(*args, **kwargs)
                return result
            finally:
                end_time = time.perf_counter()
                duration = end_time - start_time
                logger.info(
                    f"Function {func.__name__} took {duration:.4f} seconds",
                    extra={"function": func.__name__, "duration": duration}
                )
        
        return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper
    
    @staticmethod
    def get_system_metrics() -> Dict[str, Any]:
        """Get current system performance metrics."""
        process = psutil.Process()
        
        return {
            "cpu_percent": process.cpu_percent(),
            "memory_mb": process.memory_info().rss / 1024 / 1024,
            "memory_percent": process.memory_percent(),
            "open_files": len(process.open_files()),
            "connections": len(process.connections()),
            "threads": process.num_threads()
        }
```

### Caching Strategy

```python
import asyncio
import time
from typing import Any, Dict, Optional, Callable
from dataclasses import dataclass
from functools import wraps

@dataclass
class CacheEntry:
    """Cache entry with expiration."""
    value: Any
    expires_at: float
    
    @property
    def is_expired(self) -> bool:
        return time.time() > self.expires_at

class AsyncCache:
    """High-performance async cache implementation."""
    
    def __init__(self, default_ttl: int = 300):
        self._cache: Dict[str, CacheEntry] = {}
        self._locks: Dict[str, asyncio.Lock] = {}
        self.default_ttl = default_ttl
    
    async def get(self, key: str) -> Optional[Any]:
        """Get value from cache."""
        entry = self._cache.get(key)
        
        if entry is None or entry.is_expired:
            if key in self._cache:
                del self._cache[key]
            return None
        
        return entry.value
    
    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Set value in cache with TTL."""
        expires_at = time.time() + (ttl or self.default_ttl)
        self._cache[key] = CacheEntry(value, expires_at)
    
    async def get_or_set(
        self, 
        key: str, 
        factory: Callable[[], Any], 
        ttl: Optional[int] = None
    ) -> Any:
        """Get from cache or set using factory function."""
        
        # Check cache first
        value = await self.get(key)
        if value is not None:
            return value
        
        # Use lock to prevent duplicate work
        if key not in self._locks:
            self._locks[key] = asyncio.Lock()
        
        async with self._locks[key]:
            # Double-check cache after acquiring lock
            value = await self.get(key)
            if value is not None:
                return value
            
            # Generate value and cache it
            if asyncio.iscoroutinefunction(factory):
                value = await factory()
            else:
                value = factory()
            
            await self.set(key, value, ttl)
            return value
    
    def cache_decorator(self, ttl: Optional[int] = None, key_func: Optional[Callable] = None):
        """Decorator for caching function results."""
        
        def decorator(func: Callable) -> Callable:
            @wraps(func)
            async def wrapper(*args, **kwargs):
                # Generate cache key
                if key_func:
                    cache_key = key_func(*args, **kwargs)
                else:
                    cache_key = f"{func.__name__}:{hash((args, tuple(kwargs.items())))}"
                
                return await self.get_or_set(
                    cache_key,
                    lambda: func(*args, **kwargs),
                    ttl
                )
            
            return wrapper
        return decorator

# Global cache instance
cache = AsyncCache()

# Usage example
@cache.cache_decorator(ttl=600)  # Cache for 10 minutes
async def get_wazuh_alerts(limit: int = 100) -> Dict[str, Any]:
    """Cached alert retrieval."""
    # Expensive API call
    return await wazuh_client.get_alerts(limit=limit)
```

### Connection Pool Optimization

```python
import asyncio
import httpx
from typing import Optional, Dict, Any

class OptimizedHTTPClient:
    """Optimized HTTP client with connection pooling."""
    
    def __init__(
        self,
        max_connections: int = 100,
        max_keepalive_connections: int = 20,
        keepalive_expiry: int = 30,
        timeout: int = 30
    ):
        # Connection limits
        limits = httpx.Limits(
            max_connections=max_connections,
            max_keepalive_connections=max_keepalive_connections,
            keepalive_expiry=keepalive_expiry
        )
        
        # Timeout configuration
        timeout_config = httpx.Timeout(
            connect=timeout,
            read=timeout,
            write=timeout,
            pool=timeout
        )
        
        # HTTP/2 support for better performance
        self.client = httpx.AsyncClient(
            limits=limits,
            timeout=timeout_config,
            http2=True,
            verify=True
        )
    
    async def request(
        self,
        method: str,
        url: str,
        **kwargs
    ) -> httpx.Response:
        """Make optimized HTTP request."""
        
        # Add compression support
        headers = kwargs.get("headers", {})
        headers.update({
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive"
        })
        kwargs["headers"] = headers
        
        return await self.client.request(method, url, **kwargs)
    
    async def close(self):
        """Close client connections."""
        await self.client.aclose()
```

### Query Optimization

```python
class OptimizedWazuhQueries:
    """Optimized Wazuh API queries."""
    
    @staticmethod
    def build_efficient_alert_query(
        limit: int = 100,
        level_threshold: int = 5,
        time_range_hours: int = 24
    ) -> Dict[str, Any]:
        """Build optimized alert query parameters."""
        
        from datetime import datetime, timedelta
        
        # Time range optimization
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=time_range_hours)
        
        # Optimized query parameters
        params = {
            "limit": min(limit, 1000),  # Cap limit for performance
            "offset": 0,
            "select": "id,level,description,timestamp,rule.id,agent.id",  # Only needed fields
            "q": f"level>={level_threshold}",
            "sort": "-timestamp",  # Most recent first
            "search": f"timestamp>{start_time.strftime('%Y-%m-%d %H:%M:%S')}"
        }
        
        return params
    
    @staticmethod
    async def batch_agent_queries(
        client,
        agent_ids: List[str],
        batch_size: int = 50
    ) -> List[Dict[str, Any]]:
        """Batch agent queries for better performance."""
        
        results = []
        
        # Process in batches to avoid overwhelming the API
        for i in range(0, len(agent_ids), batch_size):
            batch_ids = agent_ids[i:i + batch_size]
            
            # Use comma-separated IDs for efficient querying
            id_filter = ",".join(batch_ids)
            
            batch_result = await client.get_agents(
                q=f"id={id_filter}",
                select="id,name,status,last_keepalive,version"
            )
            
            results.extend(batch_result.get("data", {}).get("affected_items", []))
            
            # Small delay to avoid rate limiting
            await asyncio.sleep(0.1)
        
        return results
```

### Memory Optimization

```python
import gc
import weakref
from typing import Iterator, Any

class MemoryOptimizer:
    """Memory optimization utilities."""
    
    @staticmethod
    def process_large_datasets(
        data: Iterator[Any],
        batch_size: int = 1000
    ) -> Iterator[List[Any]]:
        """Process large datasets in memory-efficient batches."""
        
        batch = []
        for item in data:
            batch.append(item)
            
            if len(batch) >= batch_size:
                yield batch
                batch = []
                
                # Force garbage collection after each batch
                gc.collect()
        
        # Yield remaining items
        if batch:
            yield batch
    
    @staticmethod
    def track_memory_usage(func: Callable) -> Callable:
        """Decorator to track memory usage of functions."""
        
        @wraps(func)
        async def wrapper(*args, **kwargs):
            import psutil
            
            process = psutil.Process()
            start_memory = process.memory_info().rss
            
            try:
                result = await func(*args, **kwargs)
                return result
            finally:
                end_memory = process.memory_info().rss
                memory_diff = (end_memory - start_memory) / 1024 / 1024  # MB
                
                logger.info(
                    f"Function {func.__name__} memory usage: {memory_diff:.2f} MB",
                    extra={"function": func.__name__, "memory_mb": memory_diff}
                )
        
        return wrapper
```

---

## 📖 Documentation Standards

### Code Documentation

#### Module Documentation
```python
"""Wazuh API Client Module.

This module provides a comprehensive client for interacting with the Wazuh
REST API. It includes authentication, connection pooling, error handling,
and response caching for optimal performance.

Example:
    Basic usage:
        >>> config = WazuhConfig.from_env()
        >>> client = WazuhAPIClient(config)
        >>> alerts = await client.get_alerts(limit=100)

    Advanced usage with custom parameters:
        >>> alerts = await client.get_alerts(
        ...     limit=500,
        ...     level_threshold=7,
        ...     time_range_hours=24
        ... )

Classes:
    WazuhAPIClient: Main API client for Wazuh interactions
    WazuhClientManager: Connection pool manager
    AuthenticationManager: Handles JWT token management

Functions:
    create_optimized_client: Factory function for optimized client creation

Constants:
    DEFAULT_TIMEOUT: Default request timeout in seconds
    MAX_RETRY_ATTEMPTS: Maximum number of retry attempts
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any, Union
from datetime import datetime, timedelta

# Module-level constants
DEFAULT_TIMEOUT = 30
MAX_RETRY_ATTEMPTS = 3
API_VERSION = "v4"
```

#### Class Documentation
```python
class WazuhAPIClient:
    """Asynchronous client for Wazuh REST API interactions.
    
    This client provides a high-level interface for interacting with Wazuh
    Manager's REST API. It handles authentication, request optimization,
    error handling, and response caching automatically.
    
    The client supports both single Wazuh Manager setups and distributed
    configurations with separate Wazuh Manager and Indexer instances.
    
    Attributes:
        config (WazuhConfig): Configuration object with connection details
        session (httpx.AsyncClient): HTTP client session for API requests
        auth_manager (AuthenticationManager): Handles authentication tokens
        is_authenticated (bool): Current authentication status
        
    Example:
        Basic client usage:
            >>> config = WazuhConfig(
            ...     host="wazuh.company.com",
            ...     user="api-user",
            ...     password="secure-password"
            ... )
            >>> client = WazuhAPIClient(config)
            >>> await client.authenticate()
            >>> alerts = await client.get_alerts(limit=100)
            >>> await client.close()
            
        Context manager usage (recommended):
            >>> async with WazuhAPIClient(config) as client:
            ...     alerts = await client.get_alerts(limit=100)
            ...     agents = await client.get_agents()
    """
    
    def __init__(
        self,
        config: WazuhConfig,
        session: Optional[httpx.AsyncClient] = None
    ):
        """Initialize Wazuh API client.
        
        Args:
            config: Configuration object containing connection details
            session: Optional pre-configured HTTP client session
            
        Raises:
            ConfigurationError: If configuration is invalid
            ConnectionError: If initial connection setup fails
        """
        pass
```

#### Function Documentation
```python
async def get_security_alerts(
    self,
    limit: int = 100,
    level_threshold: int = 5,
    time_range_hours: int = 24,
    agent_ids: Optional[List[str]] = None,
    include_details: bool = True
) -> Dict[str, Any]:
    """Retrieve security alerts from Wazuh with filtering options.
    
    Fetches security alerts from the Wazuh Manager API with comprehensive
    filtering options. Results are automatically cached for performance
    and can be filtered by severity level, time range, and specific agents.
    
    Args:
        limit: Maximum number of alerts to retrieve (1-10000, default: 100)
        level_threshold: Minimum alert severity level (1-15, default: 5)
        time_range_hours: Hours to look back for alerts (1-168, default: 24)
        agent_ids: Optional list of specific agent IDs to filter by
        include_details: Whether to include full alert details or summary only
        
    Returns:
        Dictionary containing:
            - alerts: List of alert objects
            - total_count: Total number of matching alerts
            - filtered_count: Number of alerts after applying filters
            - time_range: Time range used for query
            - metadata: Query metadata and performance info
            
        Alert object structure:
            - id: Unique alert identifier
            - level: Severity level (1-15)
            - description: Human-readable alert description
            - timestamp: ISO format timestamp
            - rule: Rule information (id, description, etc.)
            - agent: Agent information (id, name, ip, etc.)
            - location: Log file location
            - full_log: Complete log entry (if include_details=True)
            
    Raises:
        ValidationError: If input parameters are invalid
        AuthenticationError: If API authentication fails
        APIError: If Wazuh API request fails
        RateLimitError: If rate limit is exceeded
        
    Example:
        Basic usage:
            >>> alerts = await client.get_security_alerts(limit=50)
            >>> print(f"Found {alerts['total_count']} alerts")
            
        Advanced filtering:
            >>> alerts = await client.get_security_alerts(
            ...     limit=200,
            ...     level_threshold=10,
            ...     time_range_hours=6,
            ...     agent_ids=["001", "002", "003"],
            ...     include_details=False
            ... )
            
        Processing results:
            >>> for alert in alerts['alerts']:
            ...     if alert['level'] >= 12:
            ...         print(f"Critical alert: {alert['description']}")
    
    Note:
        - Results are cached for 5 minutes to improve performance
        - Large queries (limit > 1000) may take longer to process
        - Rate limiting applies: max 60 requests per minute per client
        - Time range is limited to 7 days (168 hours) maximum
    """
    pass
```

### API Documentation

Create comprehensive API documentation:

```markdown
# Wazuh MCP Server API Reference

## Overview

The Wazuh MCP Server provides a Model Context Protocol (MCP) interface for 
interacting with Wazuh security infrastructure. This API enables AI-powered 
security analysis and operations through Claude and other MCP-compatible clients.

## Authentication

### JWT Authentication (HTTP Mode)

```http
POST /auth/login
Content-Type: application/json

{
  "username": "api-user",
  "password": "secure-password"
}
```

Response:
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "token_type": "bearer",
  "expires_in": 1800,
  "refresh_token": "refresh_token_here"
}
```

### Using Authentication Token

Include the token in requests:
```http
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
```

## Available Tools

### Security Analysis Tools

#### get_security_alerts

Retrieve and analyze security alerts from Wazuh.

**Parameters:**
- `limit` (integer, optional): Maximum alerts to retrieve (default: 100)
- `level_threshold` (integer, optional): Minimum severity level (default: 5)
- `time_range_hours` (integer, optional): Hours to look back (default: 24)

**Example Request:**
```json
{
  "method": "tools/call",
  "params": {
    "name": "get_security_alerts",
    "arguments": {
      "limit": 50,
      "level_threshold": 7,
      "time_range_hours": 12
    }
  }
}
```

**Example Response:**
```json
{
  "content": [
    {
      "type": "text",
      "text": "🚨 Security Alert Analysis\n\n**Summary:** Found 15 high-severity alerts...\n\n**Critical Alerts:**\n- Authentication failure from 192.168.1.100\n- Malware detection on agent-001\n\n**Recommendations:**\n1. Block suspicious IP address\n2. Investigate compromised agent\n3. Review authentication logs"
    }
  ]
}
```

[Continue with all available tools...]

## Error Handling

All API errors follow this format:

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid agent ID format",
    "details": {
      "field": "agent_id",
      "value": "invalid_id",
      "expected": "alphanumeric string, 3-8 characters"
    },
    "request_id": "req_123456789"
  }
}
```

### Error Codes

- `VALIDATION_ERROR`: Input validation failed
- `AUTHENTICATION_ERROR`: Authentication required or failed
- `AUTHORIZATION_ERROR`: Insufficient permissions
- `RATE_LIMIT_ERROR`: Rate limit exceeded
- `API_ERROR`: Wazuh API communication error
- `INTERNAL_ERROR`: Internal server error
```

### User Guide Documentation

Create user-friendly guides:

```markdown
# Getting Started with Wazuh MCP Server

## What is Wazuh MCP Server?

The Wazuh MCP Server bridges your Wazuh security infrastructure with AI 
assistants like Claude, enabling intelligent security operations through 
natural language interactions.

## Quick Start

### 1. Installation

[Installation steps...]

### 2. Basic Usage Examples

#### Check Recent Security Alerts

Simply ask Claude:
> "Show me the latest security alerts from Wazuh"

Claude will use the MCP server to:
- Retrieve recent alerts from your Wazuh deployment
- Analyze them for threats and patterns
- Provide actionable recommendations

#### Monitor Agent Health

Ask Claude:
> "Are all my Wazuh agents online and healthy?"

You'll get:
- Current status of all agents
- Health metrics and performance data
- Alerts for any offline or problematic agents

#### Investigate Security Incidents

For deeper analysis:
> "Analyze the authentication failures from the last 6 hours and suggest response actions"

This provides:
- Detailed analysis of failed login attempts
- Pattern recognition for potential attacks
- Specific response recommendations

[Continue with more examples...]
```

---

## 🤝 Contribution Process

### Step-by-Step Contribution Guide

#### 1. Setting Up Your Environment

```bash
# Fork the repository on GitHub
# Clone your fork
git clone https://github.com/YOUR_USERNAME/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server

# Add upstream remote
git remote add upstream https://github.com/gensecaihq/Wazuh-MCP-Server.git

# Setup development environment
make dev-setup

# Verify setup
make ci-check
```

#### 2. Planning Your Contribution

**Before starting work:**
1. Check existing issues and pull requests
2. Create or comment on an issue to discuss your proposal
3. Get feedback from maintainers
4. Ensure your contribution aligns with project goals

**Types of contributions welcome:**
- Bug fixes
- Feature enhancements
- Security improvements
- Performance optimizations
- Documentation improvements
- Test coverage improvements

#### 3. Development Workflow

```bash
# Create feature branch
git checkout develop
git pull upstream develop
git checkout -b feature/your-feature-name

# Make your changes
# - Follow coding standards
# - Add comprehensive tests
# - Update documentation
# - Add security considerations

# Test your changes
make test
make lint
make security-check

# Commit with conventional commit format
git add .
git commit -m "feat(scope): description of changes"

# Push to your fork
git push origin feature/your-feature-name
```

#### 4. Creating a Pull Request

**Pull Request Template:**

```markdown
## Description
Brief description of changes and motivation.

## Type of Change
- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that causes existing functionality to change)
- [ ] Documentation update

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests added/updated
- [ ] Manual testing completed
- [ ] Performance impact assessed

## Security Considerations
- [ ] Security review completed
- [ ] No secrets exposed
- [ ] Input validation implemented
- [ ] Authentication/authorization checked

## Documentation
- [ ] Code comments added
- [ ] API documentation updated
- [ ] User guide updated
- [ ] CHANGELOG.md updated

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Tests pass locally
- [ ] No merge conflicts
- [ ] Linked to relevant issues

## Screenshots (if applicable)
[Add screenshots here]

## Additional Notes
[Any additional information]
```

#### 5. Code Review Process

**What reviewers look for:**
- Code quality and maintainability
- Security considerations
- Test coverage and quality
- Documentation completeness
- Performance implications
- Backward compatibility

**Review workflow:**
1. Automated checks (CI/CD pipeline)
2. Security scan (automated)
3. Manual code review (maintainer)
4. Testing verification
5. Final approval and merge

#### 6. After Your PR is Merged

```bash
# Update your local repository
git checkout develop
git pull upstream develop

# Delete feature branch
git branch -d feature/your-feature-name
git push origin --delete feature/your-feature-name

# Update your fork
git push origin develop
```

### Contribution Guidelines

#### Code Quality Standards

**Required before submission:**
- [ ] All tests pass
- [ ] Code coverage > 80%
- [ ] No linting errors
- [ ] Security scan passes
- [ ] Documentation updated
- [ ] Performance impact assessed

#### Security Requirements

**All contributions must:**
- Follow secure coding practices
- Include input validation
- Not expose sensitive information
- Pass security scanning
- Include appropriate error handling

#### Testing Requirements

**Test coverage expectations:**
- New features: 90%+ test coverage
- Bug fixes: Tests that reproduce the bug
- Refactoring: Maintain existing coverage
- Critical components: 95%+ coverage

### Recognition and Community

#### Contributor Recognition

Contributors are recognized through:
- GitHub contributors page
- CHANGELOG.md mentions
- Annual contributor highlights
- Community Discord/forum recognition

#### Getting Help

**Resources available:**
- GitHub Discussions for questions
- Discord community server
- Documentation wiki
- Regular contributor office hours

**How to get support:**
1. Check existing documentation
2. Search GitHub issues
3. Ask in GitHub Discussions
4. Join Discord community
5. Tag maintainers for urgent issues

---

## 🔧 Troubleshooting Development Issues

### Common Development Problems

#### Environment Setup Issues

**Problem: Virtual environment activation fails**
```bash
# Solution: Recreate virtual environment
rm -rf dev-env
python3 -m venv dev-env
source dev-env/bin/activate
pip install -r requirements.txt
```

**Problem: Dependencies conflict**
```bash
# Solution: Clean install
pip freeze > current_packages.txt
pip uninstall -r current_packages.txt -y
pip install -r requirements.txt
```

#### Testing Issues

**Problem: Tests fail with import errors**
```bash
# Solution: Install package in development mode
pip install -e .

# Or add src to Python path
export PYTHONPATH="${PYTHONPATH}:${PWD}/src"
```

**Problem: Async tests hanging**
```python
# Solution: Proper async test cleanup
@pytest.fixture(autouse=True)
async def cleanup():
    yield
    # Clean up any remaining async tasks
    tasks = [t for t in asyncio.all_tasks() if not t.done()]
    for task in tasks:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
```

#### Performance Issues

**Problem: Slow test execution**
```bash
# Solution: Run tests in parallel
pytest -n auto  # Requires pytest-xdist

# Or run specific test categories
pytest tests/unit/  # Fast unit tests only
```

**Problem: Memory leaks in development**
```python
# Solution: Implement proper cleanup
import gc
import weakref

class ResourceManager:
    def __init__(self):
        self._resources = weakref.WeakSet()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        for resource in self._resources:
            if hasattr(resource, 'close'):
                resource.close()
        gc.collect()
```

#### Integration Issues

**Problem: Wazuh connection fails in tests**
```python
# Solution: Mock external dependencies
@pytest.fixture
def mock_wazuh_client():
    with patch('wazuh_mcp_server.api.wazuh_client.WazuhAPIClient') as mock:
        mock.return_value.get_alerts.return_value = MOCK_ALERTS
        mock.return_value.authenticate.return_value = True
        yield mock.return_value
```

### Debugging Techniques

#### Debug Logging

```python
# Enable debug logging
import logging
logging.basicConfig(level=logging.DEBUG)

# Or use environment variable
export LOG_LEVEL=DEBUG
```

#### Interactive Debugging

```python
# Add breakpoints for debugging
import ipdb; ipdb.set_trace()

# Or use standard pdb
import pdb; pdb.set_trace()
```

#### Performance Profiling

```python
# Profile slow functions
import cProfile
import pstats

def profile_function(func):
    profiler = cProfile.Profile()
    profiler.enable()
    result = func()
    profiler.disable()
    
    stats = pstats.Stats(profiler)
    stats.sort_stats('cumulative')
    stats.print_stats(10)  # Top 10 slowest functions
    
    return result
```

### Development Tools

#### Recommended VS Code Extensions

```json
{
  "recommendations": [
    "ms-python.python",
    "ms-python.black-formatter",
    "charliermarsh.ruff",
    "ms-python.mypy-type-checker",
    "ms-python.pylint",
    "njpwerner.autodocstring",
    "streetsidesoftware.code-spell-checker"
  ]
}
```

#### Git Hooks for Quality

```bash
# .git/hooks/pre-commit
#!/bin/bash
set -e

echo "Running pre-commit checks..."

# Code formatting
black --check src/ tests/
isort --check-only src/ tests/

# Linting
ruff check src/ tests/
mypy src/

# Tests
pytest tests/unit/ -x

echo "All checks passed!"
```

### Getting Support

#### Documentation Resources

- **API Reference**: Complete API documentation
- **Architecture Guide**: System design and components
- **Security Guide**: Security best practices
- **Performance Guide**: Optimization techniques

#### Community Support

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: Questions and general discussion
- **Discord Server**: Real-time community chat
- **Stack Overflow**: Tagged questions (use `wazuh-mcp-server`)

#### Direct Support

For urgent issues or security concerns:
- **Security Issues**: security@wazuh-mcp-server.org
- **Maintainer Contact**: maintainers@wazuh-mcp-server.org

---

**Thank you for contributing to Wazuh MCP Server! Your contributions help make security operations more intelligent and accessible.**