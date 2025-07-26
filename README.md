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
curl -fsSL https://raw.githubusercontent.com/gensecaihq/Wazuh-MCP-Server/main/scripts/install-docker-debian.sh | bash
```
*Supports: Debian 11+, Ubuntu 20.04+, Linux Mint, Pop!_OS, Elementary OS*

**🐧 Linux (RHEL/CentOS/Fedora/Rocky/AlmaLinux):**
```bash
curl -fsSL https://raw.githubusercontent.com/gensecaihq/Wazuh-MCP-Server/main/scripts/install-docker-redhat.sh | bash
```
*Supports: RHEL 8+, CentOS 8+, Fedora 36+, Rocky Linux, AlmaLinux*

**🍎 macOS (Intel & Apple Silicon):**
```bash
curl -fsSL https://raw.githubusercontent.com/gensecaihq/Wazuh-MCP-Server/main/scripts/install-docker-macos.sh | bash
```
*Supports: macOS 10.15+ (Catalina), includes Claude Desktop integration helper*

**🪟 Windows (PowerShell as Administrator):**
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
iwr -useb https://raw.githubusercontent.com/gensecaihq/Wazuh-MCP-Server/main/scripts/install-docker-windows.ps1 | iex
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
If you prefer manual installation or need custom Docker setup, see [DOCKER_INSTALLATION_GUIDE.md](DOCKER_INSTALLATION_GUIDE.md) for detailed instructions.

### Step 2: Clone Repository (if not done by installation script)
```bash
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server
```

### Step 3: Configure Wazuh Connection

**Option A: Environment Variables (Recommended for Docker)**
```bash
# Required: Wazuh Manager settings
export WAZUH_HOST=wazuh-manager.local
export WAZUH_USER=wazuh-api
export WAZUH_PASS=SecureApiPassword123

# Optional: Wazuh Manager port (default: 55000)
export WAZUH_PORT=55000

# Recommended: Wazuh Indexer for 4.8+ enhanced capabilities
export WAZUH_INDEXER_HOST=wazuh-indexer.local
export WAZUH_INDEXER_PORT=9200
export WAZUH_INDEXER_USER=admin
export WAZUH_INDEXER_PASS=SecureIndexerPass123

# Enable 4.8+ specific features
export USE_INDEXER_FOR_VULNERABILITIES=true
export ENABLE_CENTRALIZED_VULNERABILITY_DETECTION=true

# Enable 4.12+ enhanced features
export ENABLE_CTI_INTEGRATION=true
export ENABLE_PACKAGE_CONDITION_FIELDS=true
export USE_UTC_TIMESTAMPS=true
```

**Option B: Create .env File (Alternative)**
```bash
# Create .env file in project root
cat > .env << EOF
WAZUH_HOST=wazuh-manager.local
WAZUH_USER=wazuh-api
WAZUH_PASS=SecureApiPassword123
WAZUH_PORT=55000
WAZUH_INDEXER_HOST=wazuh-indexer.local
WAZUH_INDEXER_PORT=9200
WAZUH_INDEXER_USER=admin
WAZUH_INDEXER_PASS=SecureIndexerPass123
USE_INDEXER_FOR_VULNERABILITIES=true
ENABLE_CENTRALIZED_VULNERABILITY_DETECTION=true
ENABLE_CTI_INTEGRATION=true
ENABLE_PACKAGE_CONDITION_FIELDS=true
USE_UTC_TIMESTAMPS=true
EOF
```

**Option C: Docker Compose Environment (Production)**
```bash
# Edit compose.yml environment section or create .env file
# The compose.yml will automatically use .env file if present
```

### Step 4: Choose Transport Mode

You can select transport mode using **three methods** (in order of precedence):

**Method 1: Command-Line Arguments (Highest Priority)**
```bash
# STDIO mode (for Claude Desktop integration)
docker compose run --rm wazuh-mcp-server ./wazuh-mcp-server --stdio

# HTTP/SSE mode (for remote access)
docker compose run --rm wazuh-mcp-server ./wazuh-mcp-server --http
```

**Method 2: Environment Variables (Recommended for Docker)**
```bash
# STDIO mode (default, recommended for Claude Desktop)
export MCP_TRANSPORT=stdio
docker compose up -d

# HTTP/SSE mode (for remote clients)
export MCP_TRANSPORT=http
export MCP_PORT=3000
docker compose up -d
```

**Method 3: Default Behavior**
- Defaults to STDIO mode if no arguments or environment variables are set
- Perfect for Claude Desktop integration out-of-the-box

### Step 5: Verify Installation & Deployment

**Complete Installation Verification:**
```bash
# Run comprehensive verification (checks Docker, project, configuration)
./scripts/verify-installation.sh
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
python3 test-functionality.py

# Production readiness check
python3 validate-production.py --quick
```

**Troubleshooting:**
If verification fails, see [DOCKER_INSTALLATION_GUIDE.md](DOCKER_INSTALLATION_GUIDE.md#troubleshooting) for platform-specific troubleshooting.

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

### Where to Configure Settings

**For Docker Deployment (Recommended):**
1. **Create `.env` file** in project root directory
2. **Set environment variables** before running `docker compose up -d`
3. **Edit `compose.yml`** environment section (advanced users)

**For Local Development:**
1. **Create `.env` file** in project root directory
2. **Set environment variables** in your shell
3. **Pass via MCP client configuration** (Claude Desktop)

### Required Environment Variables

**Wazuh Manager Connection:**
```bash
WAZUH_HOST=wazuh-manager.local          # Wazuh Manager hostname/IP
WAZUH_USER=wazuh-api                    # API username with read permissions
WAZUH_PASS=SecureApiPassword123         # API user password
```

### Optional Environment Variables

**Wazuh Manager Settings:**
```bash
WAZUH_PORT=55000                        # Wazuh API port (default: 55000)
VERIFY_SSL=true                        # SSL certificate verification (default: true)
```

**Wazuh Indexer Settings (Required for 4.8+ Full Features):**
```bash
WAZUH_INDEXER_HOST=wazuh-indexer.local               # Indexer hostname/IP
WAZUH_INDEXER_PORT=9200                              # Indexer port (default: 9200)
WAZUH_INDEXER_USER=indexer-user                      # Indexer username
WAZUH_INDEXER_PASS=indexer-password                  # Indexer password
USE_INDEXER_FOR_ALERTS=true                          # Enable indexer for alerts
USE_INDEXER_FOR_VULNERABILITIES=true                 # Required for 4.8+ vulnerability detection
ENABLE_CENTRALIZED_VULNERABILITY_DETECTION=true      # Use 4.8+ centralized vulnerability feeds
ENABLE_CTI_INTEGRATION=true                          # Enable 4.12+ CTI threat intelligence
ENABLE_PACKAGE_CONDITION_FIELDS=true                 # Enable 4.12+ enhanced package conditions
USE_UTC_TIMESTAMPS=true                              # Use 4.12+ UTC timestamp format
```

**MCP Transport Configuration:**
```bash
MCP_TRANSPORT=stdio                     # Transport mode: stdio|http
MCP_HOST=0.0.0.0                       # HTTP server host (http mode only)
MCP_PORT=3000                          # HTTP server port (http mode only)
```

**Performance Tuning:**
```bash
MAX_ALERTS_PER_QUERY=1000              # Maximum alerts per request
REQUEST_TIMEOUT_SECONDS=30             # API request timeout
MAX_CONNECTIONS=10                      # Connection pool size
```

### Transport Mode Selection

You can select between STDIO and HTTP/SSE transport using **three methods**:

#### 1. Command-Line Arguments (Highest Priority)
```bash
# Available command-line options:
./wazuh-mcp-server --stdio     # STDIO mode (explicit)
./wazuh-mcp-server --local     # STDIO mode (alias)
./wazuh-mcp-server --http      # HTTP/SSE mode
./wazuh-mcp-server --remote    # HTTP/SSE mode (alias)
./wazuh-mcp-server --server    # HTTP/SSE mode (alias)
./wazuh-mcp-server             # Uses environment variable or defaults to STDIO
```

#### 2. Environment Variables (Recommended)
```bash
export MCP_TRANSPORT=stdio     # STDIO mode
export MCP_TRANSPORT=http      # HTTP/SSE mode
```

#### 3. Default Behavior
- If no arguments or environment variables are set, defaults to **STDIO mode**
- Perfect for Claude Desktop integration without additional configuration

#### Mode Comparison

**STDIO Mode (Recommended for Desktop):**
- ✅ Direct integration with Claude Desktop
- ✅ Low latency, secure local communication
- ✅ Ideal for single-user scenarios
- ✅ Zero network configuration required

**HTTP/SSE Mode (For Remote Access):**
- ✅ Web-based access for remote clients
- ✅ Supports multiple concurrent connections
- ✅ Ideal for team/server deployments
- ✅ RESTful API access available

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

### Claude Desktop (STDIO Mode)

**Option 1: Docker Container Integration**
```json
{
  "mcpServers": {
    "wazuh": {
      "command": "docker",
      "args": ["exec", "wazuh-mcp-server", "./wazuh-mcp-server", "--stdio"]
    }
  }
}
```

**Option 2: Direct Binary (After Local Install)**
```json
{
  "mcpServers": {
    "wazuh": {
      "command": "/path/to/wazuh-mcp-server",
      "args": ["--stdio"],
      "env": {
        "WAZUH_HOST": "wazuh-manager.local",
        "WAZUH_USER": "wazuh-api",
        "WAZUH_PASS": "SecureApiPassword123"
      }
    }
  }
}
```

### HTTP/SSE Mode Integration

**Continue.dev, Cursor, or Custom Clients:**
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

### Remote HTTP Access

**Method 1: Environment Variables**
```bash
# Start in HTTP mode
export MCP_TRANSPORT=http
export MCP_HOST=0.0.0.0
export MCP_PORT=3000
docker compose up -d

# Access from remote client
curl http://localhost:3000/health
```

**Method 2: Command-Line Arguments**
```bash
# Start with command-line arguments
docker compose run --rm -p 3000:3000 wazuh-mcp-server ./wazuh-mcp-server --http

# Test connection
curl http://localhost:3000/health
```

**Method 3: Docker Compose Override**
```bash
# Create docker-compose.override.yml
cat > docker-compose.override.yml << EOF
services:
  wazuh-mcp-server:
    environment:
      - MCP_TRANSPORT=http
      - MCP_PORT=3000
    ports:
      - "3000:3000"
    command: ["./wazuh-mcp-server", "--http"]
EOF

docker compose up -d
```

## 🔍 Testing & Validation

### Quick Deployment Test
```bash
# Basic functionality test
python3 test-functionality.py

# Production readiness validation
python3 validate-production.py --quick

# Full production audit
python3 validate-production.py --full
```

### Manual Testing
```bash
# Test Wazuh connectivity
curl -k "https://${WAZUH_HOST}:${WAZUH_PORT}/security/user/authenticate" \
  -u "${WAZUH_USER}:${WAZUH_PASS}"

# Test MCP server health (HTTP mode)
curl http://localhost:3000/health

# Check container logs
docker compose logs wazuh-mcp-server -f
```

## 🚨 Troubleshooting

### Docker Installation Issues

**Docker Not Installed/Working:**
- Run the appropriate installation script for your OS (see Step 1 above)
- For detailed troubleshooting, see [DOCKER_INSTALLATION_GUIDE.md](DOCKER_INSTALLATION_GUIDE.md#troubleshooting)
- Verify installation: `./scripts/verify-installation.sh`

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
./scripts/verify-installation.sh

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

- **[DOCKER_INSTALLATION_GUIDE.md](DOCKER_INSTALLATION_GUIDE.md)** - Complete Docker installation guide for all platforms
- **[PRODUCTION_DEPLOYMENT.md](PRODUCTION_DEPLOYMENT.md)** - Production deployment and configuration guide
- **[LICENSE](LICENSE)** - MIT License
- **[Contributing Guidelines](.github/CONTRIBUTING.md)** - Development setup and contribution guide

### Installation Scripts
- `scripts/install-docker-debian.sh` - Automated Docker installation for Debian/Ubuntu systems
- `scripts/install-docker-redhat.sh` - Automated Docker installation for RHEL/CentOS/Fedora systems  
- `scripts/install-docker-macos.sh` - Automated Docker installation for macOS systems
- `scripts/install-docker-windows.ps1` - Automated Docker installation for Windows systems
- `scripts/verify-installation.sh` - Cross-platform installation verification script

## 🤝 Support

- **Issues**: [GitHub Issues](https://github.com/gensecaihq/Wazuh-MCP-Server/issues)
- **Documentation**: [Project Wiki](https://github.com/gensecaihq/Wazuh-MCP-Server/wiki)
- **Community**: [Discussions](https://github.com/gensecaihq/Wazuh-MCP-Server/discussions)