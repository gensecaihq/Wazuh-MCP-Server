# 🚀 Wazuh MCP Server - Quick Start Guide

## Prerequisites
- Docker and Docker Compose installed
- Access to a Wazuh Manager (4.8.0+)
- Wazuh API credentials

## 🎯 Quick Setup (3 Steps)

### 1️⃣ Clone and Configure
```bash
# Clone the repository
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server

# Run configuration wizard
./scripts/configure.sh
```

The configuration wizard will ask for:
- **Wazuh Manager hostname/IP** (required)
- **API username** (required) 
- **API password** (required)
- Optional: Indexer settings (if you have Wazuh Indexer)

### 2️⃣ Start the Server
```bash
# Quick start (builds and runs)
./scripts/quick-start.sh

# Or manually:
docker compose up -d
```

### 3️⃣ Configure Claude Desktop
Add to your Claude Desktop settings:

```json
{
  "mcpServers": {
    "wazuh": {
      "command": "docker",
      "args": ["exec", "-i", "wazuh-mcp-server", "./wazuh-mcp-server", "--stdio"]
    }
  }
}
```

## ✅ That's It!
You can now use Wazuh commands in Claude:
- "Show me recent critical alerts"
- "What's the status of my agents?"
- "Search for authentication failures"

## 📋 Common Commands

```bash
# Check server status
docker compose ps

# View logs
docker compose logs -f

# Stop server
docker compose down

# Restart server
docker compose restart

# Reconfigure
./scripts/configure.sh
```

## 🔧 Manual Configuration (Optional)

If you prefer manual setup:

1. Copy the example config:
   ```bash
   cp config/wazuh.env.example config/wazuh.env
   ```

2. Edit `config/wazuh.env` with your settings:
   ```env
   WAZUH_HOST=your-wazuh-manager.com
   WAZUH_USER=your-username
   WAZUH_PASS=your-password
   ```

3. Start the server:
   ```bash
   docker compose up -d
   ```

## 🆘 Troubleshooting

### Connection Issues
```bash
# Test Wazuh connectivity
curl -k "https://${WAZUH_HOST}:55000/security/user/authenticate" \
  -u "${WAZUH_USER}:${WAZUH_PASS}"
```

### Container Issues
```bash
# Full diagnostic
./install/verify-installation.sh

# Check container health
docker compose ps
docker logs wazuh-mcp-server
```

### Configuration Issues
- Ensure your Wazuh API user has read permissions
- Check firewall allows connection to Wazuh Manager port 55000
- Verify SSL certificates if using VERIFY_SSL=true

## 📚 Next Steps
- [Full Documentation](../README.md)
- [Production Deployment Guide](./guides/PRODUCTION_DEPLOYMENT.md)
- [Advanced Configuration](./guides/CONFIGURATION.md)