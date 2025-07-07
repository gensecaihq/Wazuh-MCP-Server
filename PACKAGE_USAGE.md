# Installing and Using Wazuh MCP Server as a Python Package

This guide explains how to install and use the Wazuh MCP Server as a pip package in your own Python applications.

## Installation

### Option 1: Install from PyPI (when published)

```bash
pip install wazuh-mcp-server
```

### Option 2: Install from source

```bash
# Clone the repository
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server

# Install the package
pip install .

# Or install in development mode
pip install -e .
```

### Option 3: Install with optional dependencies

```bash
# Install with development tools
pip install "wazuh-mcp-server[dev]"

# Install with testing tools
pip install "wazuh-mcp-server[testing]"

# Install with Docker support
pip install "wazuh-mcp-server[docker]"
```

## Quick Start

### 1. Basic Usage

```python
import asyncio
from wazuh_mcp_server import WazuhAPIClient, WazuhConfig

async def main():
    # Configure connection
    config = WazuhConfig(
        host="your-wazuh-server.com",
        port=55000,
        username="your-username",
        password="your-password",
        verify_ssl=False  # Set to True in production
    )
    
    # Create and initialize client
    client = WazuhAPIClient(config)
    await client.initialize()
    
    # Get recent alerts
    alerts = await client.get_alerts(limit=10)
    print(f"Found {len(alerts['alerts'])} alerts")
    
    # Clean up
    await client.close()

# Run the example
asyncio.run(main())
```

### 2. Using Environment Variables

Create a `.env` file or set environment variables:

```bash
WAZUH_HOST=your-wazuh-server.com
WAZUH_USER=your-username
WAZUH_PASS=your-password
VERIFY_SSL=false
```

Then use the convenience function:

```python
import asyncio
from wazuh_mcp_server import create_client

async def main():
    # Automatically loads from environment
    client = await create_client()
    
    # Get security events
    events = await client.get_security_events(time_range=3600)
    print(f"Security events in last hour: {events['total_events']}")
    
    await client.close()

asyncio.run(main())
```

## Core Features

### 1. Alert Management

```python
# Get recent alerts with filtering
alerts = await client.get_alerts(
    limit=100,
    level="high",           # Filter by severity
    time_range=3600,        # Last hour
    agent_id="001",         # Specific agent
    rule_id="5712"          # Specific rule
)

# Access alert data
for alert in alerts['alerts']:
    print(f"Alert: {alert['rule']['description']}")
    print(f"Agent: {alert['agent']['name']}")
    print(f"Timestamp: {alert['timestamp']}")
```

### 2. Agent Monitoring

```python
# Get agent information
agents = await client.get_agents(status="active")

# Check agent health
for agent in agents['agents']:
    health = agent['health_assessment']
    print(f"Agent {agent['name']}: {health['status']} (Score: {health['score']})")

# Get summary statistics
summary = agents['summary']
print(f"Active agents: {summary['active']}")
print(f"Platform distribution: {summary['platform_distribution']}")
```

### 3. Threat Analysis

```python
# Perform comprehensive threat analysis
threat_analysis = await client.analyze_threats(
    time_range=3600,              # Analysis window
    include_patterns=True,        # Include attack patterns
    include_recommendations=True  # Include security recommendations
)

# Access risk assessment
risk = threat_analysis['risk_assessment']
print(f"Risk Level: {risk['risk_level']}")
print(f"Overall Score: {risk['overall_score']}")
print(f"Confidence: {risk['confidence']}")

# Get recommendations
for recommendation in threat_analysis.get('recommendations', []):
    print(f"Recommendation: {recommendation}")
```

### 4. Compliance Checking

```python
# Check compliance against various frameworks
frameworks = ["pci_dss", "hipaa", "gdpr", "nist", "iso27001"]

for framework in frameworks:
    report = await client.check_compliance(
        framework=framework,
        include_evidence=True,
        include_recommendations=True
    )
    
    print(f"{framework.upper()} Compliance: {report['overall_score']:.1f}%")
    print(f"Status: {report['status']}")
```

### 5. Vulnerability Management

```python
# Get vulnerabilities for all agents
vulnerabilities = await client.get_vulnerabilities(limit=100)

# Check summary
summary = vulnerabilities['summary']
print(f"Total vulnerabilities: {summary['total_vulnerabilities']}")
print(f"Critical: {summary['critical_count']}")
print(f"High: {summary['high_count']}")

# Get vulnerabilities for specific agent
agent_vulns = await client.get_vulnerabilities(
    agent_id="001",
    severity="critical"
)
```

## Advanced Usage

### 1. Custom Integration Class

```python
import asyncio
from datetime import datetime
from wazuh_mcp_server import create_client

class SecurityDashboard:
    def __init__(self):
        self.client = None
        self.data = {}
    
    async def initialize(self):
        self.client = await create_client()
        await self.refresh_data()
    
    async def refresh_data(self):
        # Gather data in parallel
        alerts_task = self.client.get_alerts(limit=50)
        agents_task = self.client.get_agents()
        threats_task = self.client.analyze_threats(time_range=3600)
        
        alerts, agents, threats = await asyncio.gather(
            alerts_task, agents_task, threats_task
        )
        
        self.data = {
            'alerts': alerts,
            'agents': agents,
            'threats': threats,
            'last_updated': datetime.utcnow()
        }
    
    def get_summary(self):
        return {
            'total_alerts': len(self.data['alerts']['alerts']),
            'active_agents': self.data['agents']['summary']['active'],
            'risk_level': self.data['threats']['risk_assessment']['risk_level']
        }
    
    async def close(self):
        if self.client:
            await self.client.close()

# Usage
dashboard = SecurityDashboard()
await dashboard.initialize()
summary = dashboard.get_summary()
await dashboard.close()
```

### 2. Error Handling

```python
from wazuh_mcp_server import WazuhAPIClient, ValidationError, APIError

try:
    client = await create_client()
    alerts = await client.get_alerts(limit=10000)  # Large request
    
except ValidationError as e:
    print(f"Validation error: {e}")
except APIError as e:
    print(f"API error: {e}")
except Exception as e:
    print(f"Unexpected error: {e}")
finally:
    if 'client' in locals():
        await client.close()
```

### 3. Configuration Options

```python
from wazuh_mcp_server import WazuhConfig

# Advanced configuration
config = WazuhConfig(
    # Server settings
    host="wazuh-server.com",
    port=55000,
    username="api-user",
    password="secure-password",
    
    # SSL settings
    verify_ssl=True,
    ca_bundle_path="/path/to/ca-bundle.pem",
    client_cert_path="/path/to/client.pem",
    client_key_path="/path/to/client.key",
    
    # Indexer settings (for Wazuh 4.8+)
    indexer_host="wazuh-indexer.com",
    indexer_port=9200,
    indexer_username="indexer-user",
    indexer_password="indexer-password",
    
    # Performance settings
    max_alerts_per_query=1000,
    request_timeout_seconds=30,
    max_connections=10,
    
    # Feature flags
    enable_external_intel=True,
    enable_ml_analysis=True,
    enable_compliance_checking=True,
    
    # External API keys (optional)
    virustotal_api_key="your-vt-key",
    shodan_api_key="your-shodan-key",
    
    # Logging
    debug=False,
    log_level="INFO"
)
```

## Environment Variables

You can configure the client using environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `WAZUH_HOST` | Wazuh server hostname | Required |
| `WAZUH_PORT` | Wazuh API port | 55000 |
| `WAZUH_USER` | API username | Required |
| `WAZUH_PASS` | API password | Required |
| `VERIFY_SSL` | Enable SSL verification | false |
| `WAZUH_INDEXER_HOST` | Indexer hostname | Same as WAZUH_HOST |
| `WAZUH_INDEXER_PORT` | Indexer port | 9200 |
| `WAZUH_INDEXER_USER` | Indexer username | Same as WAZUH_USER |
| `WAZUH_INDEXER_PASS` | Indexer password | Same as WAZUH_PASS |
| `MAX_ALERTS_PER_QUERY` | Max alerts per request | 1000 |
| `REQUEST_TIMEOUT_SECONDS` | Request timeout | 30 |
| `DEBUG` | Enable debug logging | false |
| `LOG_LEVEL` | Logging level | INFO |

## API Reference

### WazuhAPIClient Methods

- `initialize()` - Initialize connections
- `get_alerts(limit, level, time_range, agent_id)` - Retrieve alerts
- `get_agents(status, platform, version)` - Get agent information
- `analyze_threats(time_range, category)` - Perform threat analysis
- `check_compliance(framework)` - Run compliance checks
- `get_vulnerabilities(agent_id, severity)` - Get vulnerability data
- `get_security_events(event_type, time_range)` - Get security events
- `close()` - Clean up connections

### Response Formats

All methods return dictionaries with consistent structure:

```python
{
    "data": [...],           # Main data array
    "total_items": 100,      # Total count
    "summary": {...},        # Summary statistics
    "timestamp": "2024-...", # Query timestamp
    "query_info": {...}      # Query parameters
}
```

## Integration Examples

### Flask Web Application

```python
from flask import Flask, jsonify
from wazuh_mcp_server import create_client
import asyncio

app = Flask(__name__)

@app.route('/api/alerts')
def get_alerts():
    async def fetch_alerts():
        client = await create_client()
        try:
            alerts = await client.get_alerts(limit=20)
            return alerts
        finally:
            await client.close()
    
    result = asyncio.run(fetch_alerts())
    return jsonify(result)

@app.route('/api/security-status')
def security_status():
    async def fetch_status():
        client = await create_client()
        try:
            # Get data in parallel
            alerts_task = client.get_alerts(limit=10)
            agents_task = client.get_agents()
            threats_task = client.analyze_threats(time_range=3600)
            
            alerts, agents, threats = await asyncio.gather(
                alerts_task, agents_task, threats_task
            )
            
            return {
                'alerts_count': len(alerts['alerts']),
                'active_agents': agents['summary']['active'],
                'risk_level': threats['risk_assessment']['risk_level']
            }
        finally:
            await client.close()
    
    result = asyncio.run(fetch_status())
    return jsonify(result)
```

### Scheduled Security Reports

```python
import asyncio
import schedule
import time
from wazuh_mcp_server import create_client

async def generate_daily_report():
    client = await create_client()
    try:
        # Get 24-hour data
        alerts = await client.get_alerts(time_range=24*3600)
        threats = await client.analyze_threats(time_range=24*3600)
        compliance = await client.check_compliance("pci_dss")
        
        # Generate report
        report = {
            'date': time.strftime('%Y-%m-%d'),
            'alerts_count': len(alerts['alerts']),
            'risk_level': threats['risk_assessment']['risk_level'],
            'compliance_score': compliance['overall_score']
        }
        
        # Save or send report
        print(f"Daily Report: {report}")
        
    finally:
        await client.close()

# Schedule daily reports
schedule.every().day.at("08:00").do(lambda: asyncio.run(generate_daily_report()))

while True:
    schedule.run_pending()
    time.sleep(60)
```

## Error Handling

The package provides specific exception types for different error conditions:

```python
from wazuh_mcp_server import (
    WazuhAPIClient,
    ValidationError,    # Invalid parameters
    APIError,          # Wazuh API errors
    ConfigurationError # Configuration issues
)

try:
    client = await create_client()
    # ... your code ...
    
except ValidationError as e:
    # Handle validation errors (invalid parameters)
    print(f"Invalid request: {e}")
    
except APIError as e:
    # Handle API errors (connection, authentication, etc.)
    print(f"API error: {e}")
    
except ConfigurationError as e:
    # Handle configuration errors
    print(f"Configuration error: {e}")
    
except Exception as e:
    # Handle unexpected errors
    print(f"Unexpected error: {e}")
```

## Performance Tips

1. **Reuse client instances** when possible to avoid repeated initialization
2. **Use appropriate limits** for large queries to avoid timeouts
3. **Implement connection pooling** for high-throughput applications
4. **Cache results** when data doesn't change frequently
5. **Use parallel requests** with `asyncio.gather()` for independent operations

## Security Considerations

1. **Always use environment variables** for credentials
2. **Enable SSL verification** in production environments
3. **Use strong passwords** and consider certificate-based authentication
4. **Implement proper error handling** to avoid credential leakage
5. **Log security events** appropriately without exposing sensitive data

For more examples and advanced usage, see the `examples/` directory in the repository.
