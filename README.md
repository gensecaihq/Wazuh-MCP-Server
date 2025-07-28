# 🛡️ Wazuh MCP Server

**Production-grade Docker-only FastMCP server for Wazuh SIEM integration with comprehensive security analysis capabilities.**

> 🐳 **Docker-Only Deployment** - Eliminates all local OS environment challenges by running everything in a container.

## 📋 Prerequisites

**Only Docker Required:**
- 🐳 **Docker 20.10+** and **Docker Compose 2.0+** 
- 🌐 Network access to your Wazuh Manager
- 💾 500MB RAM and 1GB disk space

**Wazuh Infrastructure:**
- **Wazuh Manager 4.8.0+** with API enabled (tested up to 4.12.0+)
- **Wazuh Indexer 4.8.0+** (recommended for enhanced features)
- Valid Wazuh API credentials (username/password)

## 🚀 Quick Deploy

### 🏆 Option 1: Pre-Built Image (Fastest - No Build Required)

**⚡ One Command Deploy:**
```bash
curl -fsSL https://raw.githubusercontent.com/gensecaihq/Wazuh-MCP-Server/main/deploy-prebuilt.sh | bash -s -- your-wazuh-host.com api-username api-password
```

**🔧 Or Download and Run:**
```bash
curl -O https://raw.githubusercontent.com/gensecaihq/Wazuh-MCP-Server/main/deploy-prebuilt.sh
chmod +x deploy-prebuilt.sh
./deploy-prebuilt.sh your-wazuh-host.com api-username api-password
```

**📖 See [PREBUILT_IMAGE.md](PREBUILT_IMAGE.md) for complete pre-built image documentation.**

---

### 🛠️ Option 2: Build from Source

**Step 1: Get the Project**
```bash
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server
```

**Step 2: Configure and Deploy**
```bash
# Interactive setup
./configure-wazuh.sh

# Or one-liner
./quick-deploy.sh your-wazuh-host.com api-username api-password
```

**Step 3: Access Your Server**
```
🌐 Server URL: http://localhost:3000
🏥 Health Check: http://localhost:3000/health
```

## 📊 Capabilities

### 🔧 20 Security Tools Available (4.8-4.12+ Compatible)

**Core Security Operations:**
- `get_wazuh_alerts` - Real-time security alerts with filtering
- `search_wazuh_logs` - Advanced log search across all sources
- `get_agent_status` - Agent health and connectivity monitoring
- `get_vulnerability_summary` - Comprehensive vulnerability assessment
- `get_cluster_status` - Wazuh infrastructure health monitoring

**Incident & Response Management:**
- `get_security_incidents` - View and track security incidents
- `create_security_incident` - Create new incident tickets
- `update_security_incident` - Update incident status and details
- `execute_active_response` - Automated threat response actions

**Detection & Analytics:**
- `get_wazuh_rules` - Detection rules management
- `analyze_rule_coverage` - Rule effectiveness analysis
- `get_rule_decoders` - Log parsing decoder management
- `advanced_wazuh_query` - Complex multi-field queries
- `multi_field_search` - Advanced search capabilities
- `get_enhanced_analytics` - Predictive security analytics
- `analyze_security_threats` - AI-powered threat analysis

**Monitoring & Intelligence:**
- `get_realtime_alerts` - Live alert monitoring dashboards
- `get_live_dashboard_data` - Real-time security metrics
- `get_cdb_lists` - Threat intelligence and blacklists
- `get_fim_events` - File integrity monitoring events

### 📡 2 Real-time Resources
- `wazuh://status/server` - Live server status and health
- `wazuh://dashboard/summary` - Security metrics dashboard

## 🏗️ Architecture

```
MCP Client → Docker Container → Wazuh Manager API → Security Data
(Claude)         ↓                    ↓                    ↓
            FastMCP Server → Wazuh Indexer → Enhanced Analytics
                               (Optional)
```

**Container Architecture:**
- 🐳 **Base**: Python 3.12 slim
- 🔒 **Security**: Non-root user, minimal attack surface
- 📦 **Dependencies**: All included (FastMCP, httpx, pydantic, uvicorn)
- 🛡️ **Monitoring**: Built-in health checks and validation tools
- ⚡ **Performance**: Optimized for production workloads

## 🔧 Configuration

### Required Settings (Only 3)
```bash
WAZUH_HOST=your-wazuh-manager.domain.com  # Wazuh Manager hostname/IP
WAZUH_USER=your-api-username              # Wazuh API username  
WAZUH_PASS=your-api-password              # Wazuh API password
```

### Optional Settings (Smart Defaults)
```bash
WAZUH_PORT=55000          # Wazuh API port
MCP_PORT=3000            # Server port (HTTP/SSE mode)
MCP_TRANSPORT=http       # Transport mode (http/stdio)
VERIFY_SSL=true          # SSL certificate verification
```

## 🛠️ Container Management

### Essential Commands
```bash
# View real-time logs
docker compose logs -f

# Check container status  
docker compose ps

# Stop the server
docker compose down

# Restart the server
docker compose restart

# Update to latest version
git pull && docker compose up -d --build
```

### Health & Testing
```bash
# Health check
curl http://localhost:3000/health

# Run functionality tests
docker compose exec wazuh-mcp-server python3 test-functionality.py

# Run production validation
docker compose exec wazuh-mcp-server python3 validate-production.py --full

# Container shell access
docker compose exec wazuh-mcp-server bash
```

## 🔄 Transport Modes

### HTTP/SSE Mode (Default - Recommended)
**Best for web clients, remote access, and production deployments.**
```bash
# Default mode - no changes needed
docker compose up -d
# Access at: http://localhost:3000
```

### STDIO Mode
**For Claude Desktop direct integration.**
```bash
# Enable STDIO mode
echo "MCP_TRANSPORT=stdio" >> .env.wazuh
docker compose up -d
```

## 🌍 Cross-Platform Deployment

### Any OS with Docker
```bash
# Linux, macOS, Windows - same commands
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server
./configure-wazuh.sh
```

### Cloud Deployment
```bash
# Works on any cloud VM (AWS, Azure, GCP, etc.)
curl -fsSL https://get.docker.com | sh
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server
./configure-wazuh.sh
# Configure cloud firewall for port 3000 if needed
```

## 🔒 Security Features

- 🛡️ **Container Security**: Non-root user, minimal base image
- 🔐 **SSL/TLS**: Certificate verification enabled by default
- 📊 **Monitoring**: Built-in health checks and metrics
- 🚨 **Validation**: Production readiness verification tools
- 🔍 **Audit**: Comprehensive security analysis capabilities

## 🚨 Troubleshooting

### Container Issues
```bash
# Check container logs
docker compose logs -f

# Verify configuration
docker compose config

# Test Wazuh connectivity
docker compose exec wazuh-mcp-server curl -k https://YOUR_WAZUH_HOST:55000
```

### Network Issues
```bash
# Test network connectivity
docker compose exec wazuh-mcp-server ping your-wazuh-host

# Check port availability
docker compose ps
```

### Configuration Issues
```bash
# Reconfigure
./configure-wazuh.sh

# Or edit directly
nano .env.wazuh
docker compose restart
```

## 📚 Documentation

- 🏆 **[Pre-Built Image Guide](PREBUILT_IMAGE.md)** - Use ready-to-deploy Docker image (fastest)
- 📖 **[Complete Docker Guide](DOCKER_DEPLOY.md)** - Build from source instructions
- 🎯 **[Deployment Summary](DEPLOYMENT_SUMMARY.md)** - Technical overview and achievements
- 🔧 **[Configuration Examples](config/wazuh.env.example)** - Configuration templates

## 🤝 Support

**If you encounter issues:**
1. Check logs: `docker compose logs -f`
2. Verify Wazuh connectivity
3. Run health checks: `curl http://localhost:3000/health`
4. Review troubleshooting section above

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**🐳 Docker-Only Deployment - Zero OS Dependencies!**

*Everything runs in a container. Just install Docker and deploy anywhere.*