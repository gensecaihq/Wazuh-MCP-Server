# 🛡️ Wazuh MCP Server

Production-grade FastMCP server for Wazuh SIEM integration with comprehensive security analysis. Connects to Wazuh Manager and Indexer for complete SIEM capabilities.

## 📋 Prerequisites

### Wazuh Infrastructure Requirements

**Wazuh Manager (Required)**
- Wazuh Manager 4.8.0+ with API enabled (tested up to 4.12.0+)
- API authentication credentials (username/password)
- Network connectivity on port 55000 (default)
- Valid SSL certificate (recommended for production)
- REST API v4.8+ features enabled
- Auto SSL negotiation support (4.8+)

**Wazuh Indexer (Recommended for Enhanced Features)**
- Wazuh Indexer 4.8.0+ for advanced search and analytics (4.12+ recommended)
- Network connectivity on port 9200 (default)  
- Authentication credentials if security is enabled
- Enables enhanced analytics, vulnerability data, and performance improvements
- Required for full compliance reporting and advanced threat analysis
- CTI (Cyber Threat Intelligence) integration support (4.12+)

### System Requirements

**Docker Requirements:**
- **Linux**: Docker 20.10+ and Docker Compose 2.0+, 2GB RAM, 5GB disk space
- **macOS**: Docker Desktop 4.0+, macOS 10.15+, 4GB RAM, 10GB disk space
- **Windows**: Docker Desktop 4.0+, Windows 10 Pro/Enterprise/Education or Windows 11, 4GB RAM, 20GB disk space

**Wazuh MCP Server:**
- 512MB RAM minimum, 1GB recommended (additional to Docker requirements)
- Network access to Wazuh infrastructure
- MCP client (Claude Desktop, Continue, etc.)

## 🚀 Quick Deploy

### Step 1: Install Docker (Automated - Recommended)

Our automated scripts install Docker, Docker Compose, and set up the complete Wazuh MCP Server environment:

**🐧 Linux (Debian/Ubuntu/Mint/Pop!_OS):**
```bash
curl -fsSL https://raw.githubusercontent.com/gensecaihq/Wazuh-MCP-Server/main/install/install-docker-debian.sh | bash
```
*Supports: Debian 11+, Ubuntu 20.04+, Linux Mint, Pop!_OS, Elementary OS*

**🐧 Linux (RHEL/CentOS/Fedora/Rocky/AlmaLinux):**
```bash
curl -fsSL https://raw.githubusercontent.com/gensecaihq/Wazuh-MCP-Server/main/install/install-docker-redhat.sh | bash
```
*Supports: RHEL 8+, CentOS 8+, Fedora 36+, Rocky Linux, AlmaLinux*

**🍎 macOS (Intel & Apple Silicon):**
```bash
curl -fsSL https://raw.githubusercontent.com/gensecaihq/Wazuh-MCP-Server/main/install/install-docker-macos.sh | bash
```
*Supports: macOS 10.15+ (Catalina), includes Claude Desktop integration helper*

**🪟 Windows (PowerShell as Administrator):**
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
iwr -useb https://raw.githubusercontent.com/gensecaihq/Wazuh-MCP-Server/main/install/install-docker-windows.ps1 | iex
```
*Supports: Windows 10 Pro/Enterprise/Education, Windows 11, includes WSL2 setup*

#### What the Scripts Install:
- ✅ **Docker Engine** (latest stable version)
- ✅ **Docker Compose** (V2 plugin)
- ✅ **Wazuh MCP Server** (complete project setup)
- ✅ **System Configuration** (optimized settings, user permissions)
- ✅ **Deployment Scripts** (ready-to-use helpers)
- ✅ **Claude Desktop Integration** (configuration helpers)

#### Manual Installation Alternative:
If you prefer manual installation or need custom Docker setup, see [DOCKER_INSTALLATION_GUIDE.md](docs/guides/DOCKER_INSTALLATION_GUIDE.md) for detailed instructions.

### Step 2: Clone Repository (if not done by installation script)
```bash
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server
```

### Step 3: Configure Wazuh Connection

**Automated Configuration (Recommended):**
```bash
# Run the configuration wizard
./scripts/configure.sh
```

This will guide you through setting up:
- Wazuh Manager connection (required)
- Optional Wazuh Indexer settings
- Advanced settings if needed

**Quick Start Alternative:**
```bash
# Run quick start script (includes configuration)
./scripts/quick-start.sh
```

**Manual Configuration (if preferred):**
```bash
# Copy and edit the configuration template
cp config/wazuh.env.example config/wazuh.env
nano config/wazuh.env  # Edit with your settings
```

### Step 4: Start the Server

```bash
# Start with Docker Compose
docker compose up -d

# Or use the quick start script
./scripts/quick-start.sh
```

The server defaults to STDIO mode for Claude Desktop. For HTTP/remote access, see [Advanced Configuration](#advanced-configuration).

### Step 5: Verify Installation & Deployment

**Complete Installation Verification:**
```bash
# Run comprehensive verification (checks Docker, project, configuration)
./install/verify-installation.sh
```

**Manual Verification Steps:**
```bash
# Check Docker installation
docker --version
docker compose version
docker run hello-world

# Check container status
docker compose ps

# View logs
docker compose logs wazuh-mcp-server

# Test functionality
python3 tools/test-functionality.py

# Production readiness check
python3 tools/validate-production.py --quick
```

**Troubleshooting:**
If verification fails, see [DOCKER_INSTALLATION_GUIDE.md](docs/guides/DOCKER_INSTALLATION_GUIDE.md#troubleshooting) for platform-specific troubleshooting.

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
MCP Client → FastMCP Server → Wazuh Manager API → Security Data
(Claude)         ↓              ↓                    ↓
            Docker Container → Wazuh Indexer → Enhanced Analytics
                               (Optional)
```

**Production Architecture:**
- 🐳 **Containerized Deployment** - Zero host dependencies
- 🌍 **OS Agnostic** - Linux, macOS, Windows via Docker
- 🔒 **Security Hardened** - Non-root execution, SSL verification
- ⚡ **High Performance** - Async operations, connection pooling
- 📈 **Scalable Design** - Resource limits, health monitoring
- 🔄 **Dual Transport** - STDIO for desktop, HTTP/SSE for remote

## ⚙️ Configuration

### Quick Configuration

Run the configuration wizard:
```bash
./scripts/configure.sh
```

This will create `config/wazuh.env` with your settings.

### Configuration File Structure

All settings are stored in `config/wazuh.env`:

```env
# Required Settings
WAZUH_HOST=your-wazuh-manager.com
WAZUH_USER=your-api-username
WAZUH_PASS=your-api-password

# Optional Settings (with defaults)
WAZUH_PORT=55000
VERIFY_SSL=true

# Wazuh Indexer (if available)
WAZUH_INDEXER_HOST=your-wazuh-indexer.com
WAZUH_INDEXER_USER=admin
WAZUH_INDEXER_PASS=your-indexer-password
```

### Advanced Configuration

For advanced users who need to customize further:

1. **Transport Mode**: Default is STDIO for Claude Desktop
   - Set `MCP_TRANSPORT=http` in config for remote access
   
2. **Performance Tuning**: Rarely needed
   - `MAX_ALERTS_PER_QUERY` (default: 1000)
   - `REQUEST_TIMEOUT_SECONDS` (default: 30)
   - `MAX_CONNECTIONS` (default: 10)

3. **Manual Configuration**: Edit `config/wazuh.env` directly

See [Full Configuration Guide](docs/guides/CONFIGURATION.md) for all options.

## 💡 Usage Examples

```
"Show me recent critical alerts"
"Create incident for brute force attack on server-01" 
"Execute firewall-block on agent 001"
"Search logs for authentication failures"
"Generate security trends with predictions"
"What's my agent health status?"
```

## 🎯 MCP Client Integration

### Claude Desktop Configuration

After starting the server, add this to your Claude Desktop settings:

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

### Other MCP Clients

For Continue.dev, Cursor, or custom clients using HTTP mode:

1. Configure for HTTP mode:
   ```bash
   echo "MCP_TRANSPORT=http" >> config/wazuh.env
   docker compose up -d
   ```

2. Add to client configuration:
   ```json
   {
     "mcpServers": {
       "wazuh": {
         "url": "http://localhost:3000",
         "transport": "http"
       }
     }
   }
   ```

## 🔍 Testing & Validation

### Quick Deployment Test
```bash
# Basic functionality test
./scripts/test-server.sh

# Production readiness validation
./scripts/validate-production.sh
```

##### Manual Testing
```bash
# Test Wazuh connectivity
curl -k "https://${WAZUH_HOST}:${WAZUH_PORT}/security/user/authenticate" \
  -u "${WAZUH_USER}:${WAZUH_PASS}"

# Check container logs
docker compose logs wazuh-mcp-server -f
```

## 🚨 Troubleshooting

### Docker Installation Issues

**Docker Not Installed/Working:**
- Run the appropriate installation script for your OS (see Step 1 above)
- For detailed troubleshooting, see [DOCKER_INSTALLATION_GUIDE.md](docs/guides/DOCKER_INSTALLATION_GUIDE.md#troubleshooting)
- Verify installation: `./install/verify-installation.sh`

**Platform-Specific Docker Issues:**

**Linux:**
```bash
# Permission denied errors
sudo usermod -aG docker $USER
newgrp docker

# Docker daemon not running
sudo systemctl start docker
sudo systemctl enable docker
```

**macOS:**
- Ensure Docker Desktop is running
- Check system requirements (macOS 10.15+, 4GB RAM)
- Restart Docker Desktop if needed

**Windows:**
- Run PowerShell as Administrator
- Ensure WSL2 is properly configured
- Check Windows edition compatibility

### Wazuh MCP Server Issues

**Connection Errors:**
- Verify Wazuh Manager is accessible on specified port
- Check firewall rules and network connectivity
- Validate SSL certificates if VERIFY_SSL=true

**Authentication Failures:**
- Confirm API user exists in Wazuh Manager
- Verify user has sufficient read permissions
- Check password special characters are properly escaped

**Container Issues:**
```bash
# Full diagnostic
./install/verify-installation.sh

# Rebuild container
docker compose build --no-cache
docker compose up -d

# Check resource usage
docker stats wazuh-mcp-server

# View detailed logs
docker compose logs wazuh-mcp-server --tail=100

# Check container health
docker compose ps
docker inspect wazuh-mcp-server
```

## 💡 Usage Examples

Once connected to your MCP client, try these commands:

```
"Show me recent critical alerts"
"What's the status of agent 001?"
"Create incident for brute force attack on server-01"
"Execute firewall-block on compromised agent"
"Search logs for authentication failures in last 24 hours"
"Generate security analytics with trend predictions"
"What vulnerabilities exist in my environment?" (uses 4.8+ centralized detection)
"Show me CTI threat intelligence for this CVE" (4.12+ feature)
"Analyze threat landscape with CTI data" (4.12+ enhanced)
"Show me file integrity violations"
"Check for new Wazuh version updates" (4.8+ feature)
"Get detailed vulnerability info with package conditions" (4.12+ feature)
```

## 📚 Documentation

- **[DOCKER_INSTALLATION_GUIDE.md](docs/guides/DOCKER_INSTALLATION_GUIDE.md)** - Complete Docker installation guide for all platforms
- **[PRODUCTION_DEPLOYMENT.md](docs/guides/PRODUCTION_DEPLOYMENT.md)** - Production deployment and configuration guide
- **[LICENSE](LICENSE)** - MIT License
- **[Contributing Guidelines](.github/CONTRIBUTING.md)** - Development setup and contribution guide

### Quick Links
- [Quick Start Guide](docs/QUICK_START.md) - Get started in 3 steps
- [Configuration Guide](docs/guides/CONFIGURATION.md) - All configuration options
- [Production Deployment](docs/guides/PRODUCTION_DEPLOYMENT.md) - Enterprise setup
- [Docker Installation](docs/guides/DOCKER_INSTALLATION_GUIDE.md) - Platform-specific Docker setup

## 🤝 Support

- **Issues**: [GitHub Issues](https://github.com/gensecaihq/Wazuh-MCP-Server/issues)
- **Documentation**: [Project Wiki](https://github.com/gensecaihq/Wazuh-MCP-Server/wiki)
- **Community**: [Discussions](https://github.com/gensecaihq/Wazuh-MCP-Server/discussions)