# Installation Guide

## Requirements

- Docker 20.10+ and Docker Compose 2.0+
- OR Python 3.9+ (for manual installation)
- Wazuh 4.5+ with API access
- 1GB free disk space

## Quick Install (Docker)

```bash
# 1. Clone repository
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server

# 2. Configure
cp .env.production .env
vim .env  # Add WAZUH_API_URL, USERNAME, PASSWORD

# 3. Deploy
./scripts/deploy-production.sh

# 4. Verify
curl -k https://localhost:8443/health
```

## Manual Installation

```bash
# 1. Clone repository
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server

# 2. Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements-prod.txt

# 4. Configure
cp .env.production .env
vim .env  # Add your Wazuh API credentials

# 5. Run
python -m wazuh_mcp_server.main
```

## Configuration

### Required Environment Variables

```bash
WAZUH_API_URL=https://your-wazuh:55000
WAZUH_API_USERNAME=your-api-user
WAZUH_API_PASSWORD=your-api-password
```

### Optional Settings

```bash
# Server
MCP_SERVER_MODE=auto      # auto|stdio|remote
MCP_SERVER_PORT=8443      # HTTPS port

# Security
OAUTH_ENABLED=true        # OAuth 2.0
JWT_SECRET_KEY=           # Auto-generated

# Performance
MAX_CONNECTIONS=1000
WORKER_PROCESSES=4
```

## Claude Desktop Integration

Add to Claude Desktop configuration:

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

For manual installation:
```json
{
  "mcpServers": {
    "wazuh": {
      "command": "/path/to/venv/bin/python",
      "args": ["-m", "wazuh_mcp_server.main", "--stdio"]
    }
  }
}
```

## Verification

1. Check health endpoint:
   ```bash
   curl -k https://localhost:8443/health
   ```

2. View logs:
   ```bash
   docker-compose logs -f
   ```

3. Test in Claude Desktop:
   ```
   You: List available Wazuh tools
   Claude: I'll show you the available Wazuh tools...
   ```

## Next Steps

- [Configure Claude Desktop](claude-desktop-setup.md)
- [View available tools](tools.md)
- [See usage examples](examples.md)