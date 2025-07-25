# Docker Setup for Wazuh MCP Server

## 🚀 One-Command Setup

```bash
# 1. Configure your Wazuh settings
cp .env.docker.template .env
# Edit .env with your Wazuh server details

# 2. Start the server
docker compose up -d

# 3. Done! Your server is running
```

## 📁 Files in this Directory

- **`entrypoint.sh`** - Docker container startup script
- **`.env.docker`** - Default environment configuration for containers
- **`README.md`** - This file

## 🔧 Quick Commands

```bash
# View logs
docker compose logs --follow

# Check status  
docker compose ps

# Restart
docker compose restart

# Stop
docker compose down

# Execute commands
docker compose exec wazuh-mcp-server bash
```

## 📖 Full Documentation

See [DOCKER_USAGE.md](../DOCKER_USAGE.md) for complete Docker usage guide.

## 🆘 Need Help?

1. Check logs: `docker compose logs wazuh-mcp-server`
2. Verify config: `docker compose config`
3. Test manually: `docker compose exec wazuh-mcp-server ./wazuh-mcp-server --help`

For detailed troubleshooting, see the main [DOCKER_USAGE.md](../DOCKER_USAGE.md) guide.