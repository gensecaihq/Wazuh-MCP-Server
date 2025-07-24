# Claude Desktop Setup Guide

## Prerequisites

- Wazuh MCP Server installed and running
- Claude Desktop application
- Wazuh API credentials

## Configuration Steps

### 1. Locate Claude Desktop Config

**macOS:**
```bash
~/Library/Application Support/Claude/claude_desktop_config.json
```

**Windows:**
```
%APPDATA%\Claude\claude_desktop_config.json
```

**Linux:**
```bash
~/.config/Claude/claude_desktop_config.json
```

### 2. Add MCP Server Configuration

#### For Docker Installation

```json
{
  "mcpServers": {
    "wazuh": {
      "command": "docker",
      "args": ["exec", "-i", "wazuh-mcp-server", 
               "python", "-m", "wazuh_mcp_server.main", "--stdio"]
    }
  }
}
```

#### For Manual Installation

```json
{
  "mcpServers": {
    "wazuh": {
      "command": "/path/to/venv/bin/python",
      "args": ["-m", "wazuh_mcp_server.main", "--stdio"],
      "env": {
        "WAZUH_API_URL": "https://your-wazuh:55000",
        "WAZUH_API_USERNAME": "your-username",
        "WAZUH_API_PASSWORD": "your-password"
      }
    }
  }
}
```

### 3. Restart Claude Desktop

After saving the configuration, restart Claude Desktop for changes to take effect.

## Verification

1. **Check Connection:**
   ```
   You: List available Wazuh tools
   Claude: I can see the following Wazuh tools are available...
   ```

2. **Test a Tool:**
   ```
   You: Check the health of all Wazuh agents
   Claude: I'll check the health status of all Wazuh agents...
   ```

## Usage Examples

### Security Monitoring
```
You: Show me critical alerts from the last hour
Claude: I'll search for critical alerts from the last hour...

You: Which agents have vulnerabilities?
Claude: Let me check for agents with vulnerabilities...
```

### Compliance Checking
```
You: Check PCI-DSS compliance status
Claude: I'll check the PCI-DSS compliance status...

You: Show me CIS benchmark failures
Claude: Let me retrieve CIS benchmark failures...
```

### Threat Analysis
```
You: Analyze threats targeting web servers
Claude: I'll analyze threats targeting your web servers...

You: Check for indicators of compromise
Claude: I'll check for any indicators of compromise...
```

## Troubleshooting

### MCP Server Not Found

1. Verify server is running:
   ```bash
   docker ps  # Should show wazuh-mcp-server
   ```

2. Check logs:
   ```bash
   docker-compose logs wazuh-mcp-server
   ```

### Authentication Errors

1. Verify credentials in `.env`:
   ```bash
   cat .env | grep WAZUH_API
   ```

2. Test API connection:
   ```bash
   curl -u user:pass https://wazuh:55000/security/user/authenticate
   ```

### No Tools Available

1. Restart Claude Desktop
2. Check configuration file syntax
3. Verify server health:
   ```bash
   curl -k https://localhost:8443/health
   ```

## Tips

- Use natural language - Claude understands context
- Be specific about time ranges and filters
- Ask for analysis and recommendations
- Request comparisons and trends

## Next Steps

- [View all available tools](tools.md)
- [See more usage examples](examples.md)
- [Learn best practices](best-practices.md)