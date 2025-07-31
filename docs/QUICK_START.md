# 🚀 Wazuh MCP Server - Quick Start Guide

**Get your Wazuh MCP Server running in under 2 minutes.**

## Prerequisites
- Docker 20.10+ and Docker Compose 2.0+
- Network access to your Wazuh Manager
- Wazuh API credentials

## ⚡ 1-Minute Setup

### Step 1: Clone and Configure
```bash
# Clone the repository
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server

# Run interactive configuration
./configure-wazuh.sh
```

The script will prompt for:
- **Wazuh Manager hostname/IP**
- **API username** 
- **API password**
- Optional settings (ports, SSL)

### Step 2: That's It! 
The configuration script automatically starts your server.

**Server is now running at:** `http://localhost:3000`

## 🔌 Connect to Claude Desktop

To use with Claude Desktop:

1. **Enable STDIO mode:**
   ```bash
   echo "MCP_TRANSPORT=stdio" >> .env.wazuh
   docker compose restart
   ```

2. **Add to Claude Desktop config:**
   ```json
   {
     "mcpServers": {
       "wazuh": {
         "command": "docker",
         "args": ["compose", "exec", "wazuh-mcp-server", "./wazuh-mcp-server", "--stdio"],
         "cwd": "/path/to/Wazuh-MCP-Server"
       }
     }
   }
   ```

## 📋 Essential Commands

```bash
# Check server status
docker compose ps

# View real-time logs
docker compose logs -f

# Stop server
docker compose down

# Restart server
docker compose restart

# Health check
curl http://localhost:3000/health

# Run tests
docker compose exec wazuh-mcp-server python3 test-functionality.py
```

## 🔧 Manual Setup (Alternative)

If you prefer manual configuration:

1. **Create config file:**
   ```bash
   cp config/wazuh.env.example .env.wazuh
   ```

2. **Edit with your settings:**
   ```env
   WAZUH_HOST=your-wazuh-manager.com
   WAZUH_USER=your-api-username
   WAZUH_PASS=your-api-password
   ```

3. **Start server:**
   ```bash
   docker compose up -d
   ```

## 🚨 Quick Troubleshooting

**Server won't start?**
```bash
# Check logs
docker compose logs wazuh-mcp-server

# Test Wazuh connection
docker compose exec wazuh-mcp-server curl -k https://YOUR_WAZUH_HOST:55000
```

**Connection refused?**
- Verify `WAZUH_HOST` is reachable
- Check firewall allows port 55000
- Confirm Wazuh API is enabled

**Authentication failed?**
- Verify username/password in Wazuh
- Check API user permissions
- Test: `curl -k https://WAZUH_HOST:55000 -u USERNAME:PASSWORD`

## ✅ Verification

Your server is working correctly if:
- ✅ `curl http://localhost:3000/health` returns `{"status": "healthy"}`
- ✅ Container shows "Running" in `docker compose ps`
- ✅ Logs show "FastMCP server started" message

## 📚 What's Next?

- **Use the tools:** 20 security analysis tools are now available
- **View documentation:** [Full README](../README.md)
- **Advanced config:** [Configuration Guide](guides/CONFIGURATION.md)
- **Production setup:** Ready to deploy anywhere with Docker