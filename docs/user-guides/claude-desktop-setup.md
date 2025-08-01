# Claude Desktop Setup Guide - Wazuh MCP Server

This comprehensive guide walks you through connecting your Wazuh MCP Server (FastMCP STDIO) to Claude Desktop.

## 📋 Prerequisites

- ✅ Docker installed (for Docker deployment) OR Python 3.11+ (for manual installation)
- ✅ Wazuh MCP Server deployed and running
- ✅ Claude Desktop application installed
- ✅ Valid Wazuh server credentials configured

## 🚀 Quick Setup

### Option 1: Docker Deployment (Recommended)

1. **Deploy Wazuh MCP Server:**
```bash
./deploy-docker.sh
```

2. **Add to Claude Desktop config:**
```json
{
  "mcpServers": {
    "wazuh": {
      "command": "docker",
      "args": ["exec", "-i", "wazuh-mcp-server", "python3", "wazuh-mcp-server", "--stdio"]
    }
  }
}
```

### Option 2: Manual Installation

1. **Install dependencies:**
```bash
pip install -r requirements.txt
```

2. **Add to Claude Desktop config:**
```json
{
  "mcpServers": {
    "wazuh": {
      "command": "python3",
      "args": ["/absolute/path/to/Wazuh-MCP-Server/wazuh-mcp-server", "--stdio"]
    }
  }
}
```

## 📁 Configuration File Locations

### Windows
**File Location:**
```
%APPDATA%\Claude\claude_desktop_config.json
```

**Full Path Example:**
```
C:\Users\YourUsername\AppData\Roaming\Claude\claude_desktop_config.json
```

**How to Access:**
1. Press `Win + R`
2. Type `%APPDATA%\Claude`
3. Create `claude_desktop_config.json` if it doesn't exist

### macOS
**File Location:**
```
~/.config/claude/claude_desktop_config.json
```

**Full Path Example:**
```
/Users/YourUsername/.config/claude/claude_desktop_config.json
```

**How to Access:**
1. Open Terminal
2. Run: `mkdir -p ~/.config/claude`
3. Create/edit: `nano ~/.config/claude/claude_desktop_config.json`

### Linux
**File Location:**
```
~/.config/claude/claude_desktop_config.json
```

**Full Path Example:**
```
/home/yourusername/.config/claude/claude_desktop_config.json
```

**How to Access:**
1. Open terminal
2. Run: `mkdir -p ~/.config/claude`
3. Create/edit: `nano ~/.config/claude/claude_desktop_config.json`

## 🔧 Detailed Configuration Steps

### Step 1: Create/Edit Configuration File

#### First Time Setup (New File)

Create the configuration file with this content:

**For Docker Deployment:**
```json
{
  "mcpServers": {
    "wazuh": {
      "command": "docker",
      "args": ["exec", "-i", "wazuh-mcp-server", "python3", "wazuh-mcp-server", "--stdio"]
    }
  }
}
```

**For Manual Installation:**
```json
{
  "mcpServers": {
    "wazuh": {
      "command": "python3",
      "args": ["/Users/yourusername/Wazuh-MCP-Server/wazuh-mcp-server", "--stdio"]
    }
  }
}
```

#### Existing Configuration (Adding to Existing Servers)

If you already have MCP servers configured:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/yourusername/Desktop"]
    },
    "wazuh": {
      "command": "docker",
      "args": ["exec", "-i", "wazuh-mcp-server", "python3", "wazuh-mcp-server", "--stdio"]
    }
  }
}
```

### Step 2: Validate JSON Syntax

**Common JSON Errors to Avoid:**

❌ **Trailing comma:**
```json
{
  "mcpServers": {
    "wazuh": {
      "command": "docker",
      "args": ["exec", "-i", "wazuh-mcp-server", "python3", "wazuh-mcp-server", "--stdio"],
    }
  }
}
```

❌ **Missing comma between servers:**
```json
{
  "mcpServers": {
    "server1": { "command": "cmd1" }
    "wazuh": { "command": "docker" }
  }
}
```

✅ **Correct syntax:**
```json
{
  "mcpServers": {
    "server1": { "command": "cmd1" },
    "wazuh": { "command": "docker", "args": ["exec", "-i", "wazuh-mcp-server", "python3", "wazuh-mcp-server", "--stdio"] }
  }
}
```

**Validate your JSON using:**
- Online JSON validator: https://jsonlint.com/
- VS Code with JSON extension
- Command line: `python3 -m json.tool < claude_desktop_config.json`

### Step 3: Verify Server is Running

**For Docker Deployment:**
```bash
# Check container status
docker ps | grep wazuh-mcp-server

# Check container logs
docker logs wazuh-mcp-server

# Test server health
docker exec -it wazuh-mcp-server python3 -c "from wazuh_mcp_server.server import mcp; print('Server healthy')"
```

**For Manual Installation:**
```bash
# Test server startup
python3 /path/to/wazuh-mcp-server --stdio

# Should show: "Starting Wazuh MCP Server with FastMCP (STDIO mode)..."
```

### Step 4: Restart Claude Desktop Properly

#### Windows
1. **Close Claude Desktop completely:**
   - Right-click Claude Desktop in system tray
   - Select "Exit" or "Quit"
   - Wait 5 seconds

2. **Restart Claude Desktop:**
   - Launch from Start Menu or desktop shortcut

#### macOS
1. **Quit Claude Desktop completely:**
   - Press `Cmd + Q` while Claude Desktop is active
   - OR: Claude menu → Quit Claude
   - Wait 5 seconds

2. **Restart Claude Desktop:**
   - Launch from Applications folder or Dock

#### Linux
1. **Close Claude Desktop:**
   - Close the application window
   - Check if process is still running: `ps aux | grep claude`
   - Kill if necessary: `killall claude-desktop`

2. **Restart Claude Desktop:**
   - Launch from application menu or terminal

## 🧪 Testing the Connection

### Step 1: Verify MCP Server Appears

After restarting Claude Desktop, the Wazuh MCP Server should be available. Look for:
- No error messages in Claude Desktop
- Server appears in Claude's available tools

### Step 2: Test with Sample Queries

Try these test queries to verify the connection:

**Basic Connection Test:**
```
Validate the connection to Wazuh server
```

**Agent Status:**
```
Show me the current status of all Wazuh agents
```

**Recent Alerts:**
```
Get the most recent security alerts from the last 2 hours
```

**Vulnerability Check:**
```
Show me critical vulnerabilities from all monitored systems
```

**Security Analysis:**
```
Perform a risk assessment on agent 001
```

**Compliance Check:**
```
Run a PCI-DSS compliance check on the environment
```

### Step 3: Expected Responses

✅ **Successful connection:** Claude will query the Wazuh server and return structured data

❌ **Connection failed:** Claude will show error messages or say the server is unavailable

## 🔍 Troubleshooting

### Common Issues and Solutions

#### 1. "Server not found" or "Command failed"

**Possible Causes:**
- Incorrect file path in configuration
- Docker container not running
- JSON syntax errors

**Solutions:**
```bash
# For Docker: Check container status
docker ps | grep wazuh-mcp-server

# For Docker: Restart container
docker-compose restart wazuh-mcp-server

# For Manual: Check Python path
which python3

# For Manual: Test server directly
python3 /path/to/wazuh-mcp-server --stdio
```

#### 2. "Permission denied"

**Solutions:**
```bash
# Make script executable
chmod +x /path/to/wazuh-mcp-server

# Check Docker permissions
docker exec wazuh-mcp-server ls -la /app/wazuh-mcp-server
```

#### 3. "Module not found" errors

**For Docker Deployment:**
```bash
# Rebuild container with dependencies
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

**For Manual Installation:**
```bash
# Reinstall dependencies
pip install -r requirements.txt --upgrade
```

#### 4. JSON Configuration Errors

**Validate JSON syntax:**
```bash
# Test JSON validity
python3 -c "import json; json.load(open('claude_desktop_config.json'))"
```

**Common fixes:**
- Remove trailing commas
- Use double quotes, not single quotes
- Ensure proper escaping of backslashes in Windows paths

#### 5. Claude Desktop Not Recognizing Changes

**Solutions:**
1. **Complete restart procedure:**
   - Close Claude Desktop completely
   - Wait 10 seconds
   - Restart Claude Desktop

2. **Clear Claude Desktop cache:**
   - Windows: Delete `%APPDATA%\Claude\cache\`
   - macOS/Linux: Delete `~/.config/claude/cache/`

3. **Check file permissions:**
   ```bash
   # Ensure config file is readable
   chmod 644 ~/.config/claude/claude_desktop_config.json
   ```

### Debug Mode

Enable debug logging by setting environment variables:

**For Docker:**
```bash
# Add to docker-compose.yml
environment:
  - LOG_LEVEL=DEBUG
```

**For Manual:**
```bash
export LOG_LEVEL=DEBUG
python3 wazuh-mcp-server --stdio
```

### Getting Help

If you're still having issues:

1. **Check logs:**
   - Docker: `docker logs wazuh-mcp-server`
   - Manual: Check console output when running the server

2. **Verify requirements:**
   - Docker version: `docker --version`
   - Python version: `python3 --version`
   - Dependencies: `pip list | grep fastmcp`

3. **Test components separately:**
   - Test Wazuh connectivity
   - Test FastMCP server startup
   - Test Claude Desktop configuration syntax

## 💡 Advanced Configuration

### Environment Variables

Pass custom environment variables to the MCP server:

```json
{
  "mcpServers": {
    "wazuh": {
      "command": "docker",
      "args": ["exec", "-i", "wazuh-mcp-server", "python3", "wazuh-mcp-server", "--stdio"],
      "env": {
        "LOG_LEVEL": "DEBUG",
        "WAZUH_TIMEOUT": "30"
      }
    }
  }
}
```

### Multiple Wazuh Environments

Configure multiple Wazuh environments:

```json
{
  "mcpServers": {
    "wazuh-prod": {
      "command": "docker",
      "args": ["exec", "-i", "wazuh-mcp-server-prod", "python3", "wazuh-mcp-server", "--stdio"]
    },
    "wazuh-dev": {
      "command": "docker",
      "args": ["exec", "-i", "wazuh-mcp-server-dev", "python3", "wazuh-mcp-server", "--stdio"]
    }
  }
}
```

### Custom Resource Limits

For Docker deployment with custom resource limits:

```bash
# Modify docker-compose.yml
deploy:
  resources:
    limits:
      memory: 1G
      cpus: '1.0'
```

## 🎯 Configuration Examples by Platform

### Windows with Docker Desktop

```json
{
  "mcpServers": {
    "wazuh": {
      "command": "docker",
      "args": ["exec", "-i", "wazuh-mcp-server", "python3", "wazuh-mcp-server", "--stdio"]
    }
  }
}
```

### Windows Manual Installation

```json
{
  "mcpServers": {
    "wazuh": {
      "command": "python",
      "args": ["C:/Users/YourUsername/Wazuh-MCP-Server/wazuh-mcp-server", "--stdio"]
    }
  }
}
```

### macOS with Docker

```json
{
  "mcpServers": {
    "wazuh": {
      "command": "docker",
      "args": ["exec", "-i", "wazuh-mcp-server", "python3", "wazuh-mcp-server", "--stdio"]
    }
  }
}
```

### macOS Manual Installation

```json
{
  "mcpServers": {
    "wazuh": {
      "command": "python3",
      "args": ["/Users/yourusername/Wazuh-MCP-Server/wazuh-mcp-server", "--stdio"]
    }
  }
}
```

### Linux with Docker

```json
{
  "mcpServers": {
    "wazuh": {
      "command": "docker",
      "args": ["exec", "-i", "wazuh-mcp-server", "python3", "wazuh-mcp-server", "--stdio"]
    }
  }
}
```

### Linux Manual Installation

```json
{
  "mcpServers": {
    "wazuh": {
      "command": "python3",
      "args": ["/home/yourusername/Wazuh-MCP-Server/wazuh-mcp-server", "--stdio"]
    }
  }
}
```

---

## ✅ Verification Checklist

Before asking for help, verify:

- [ ] Configuration file exists at correct location
- [ ] JSON syntax is valid
- [ ] Wazuh MCP Server container/process is running
- [ ] Docker/Python path is correct in configuration
- [ ] Claude Desktop was completely restarted
- [ ] No error messages in logs
- [ ] Test queries return Wazuh data

**Your Wazuh MCP Server should now be fully integrated with Claude Desktop! 🎉**