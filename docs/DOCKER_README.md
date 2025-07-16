# Wazuh MCP Server

![Docker Image Version](https://img.shields.io/docker/v/gensecaihq/wazuh-mcp-server?sort=semver&logo=docker)
![Docker Image Size](https://img.shields.io/docker/image-size/gensecaihq/wazuh-mcp-server/latest?logo=docker)
![Docker Pulls](https://img.shields.io/docker/pulls/gensecaihq/wazuh-mcp-server?logo=docker)
![Security Scan](https://img.shields.io/badge/security-scanned-green?logo=shield)

A Model Context Protocol (MCP) server that provides seamless integration with the Wazuh security platform. This server enables AI assistants and applications to interact with Wazuh for security monitoring, threat detection, and incident response.

## 🚀 Quick Start

### Using Docker Compose (Recommended)

```bash
# Download the latest compose file
curl -O https://raw.githubusercontent.com/gensecaihq/Wazuh-MCP-Server/main/docker-compose.yml

# Create environment file
curl -O https://raw.githubusercontent.com/gensecaihq/Wazuh-MCP-Server/main/.env.example
mv .env.example .env

# Edit configuration
nano .env  # Configure your Wazuh connection details

# Start the services
docker-compose up -d
```

### Using Docker Run

```bash
docker run -d \
  --name wazuh-mcp-server \
  -p 8443:8443 \
  -p 9090:9090 \
  -e WAZUH_API_URL="https://your-wazuh:55000" \
  -e WAZUH_API_USERNAME="your-username" \
  -e WAZUH_API_PASSWORD="your-password" \
  -e JWT_SECRET_KEY="your-secret-key" \
  gensecaihq/wazuh-mcp-server:v3-latest
```

## 🏷️ Available Tags

| Tag | Description | Use Case |
|-----|-------------|----------|
| `latest` | Latest stable release | Production deployments |
| `v3-latest` | Latest v3.x version | Modern features, production |
| `v3.0.0` | Specific version | Version pinning |
| `v3.1.0` | Specific version | Version pinning |

## 🏗️ Multi-Platform Support

This image supports multiple architectures:

- `linux/amd64` - Intel/AMD 64-bit (most common)
- `linux/arm64` - ARM 64-bit (Apple Silicon, ARM servers)

Docker will automatically pull the correct architecture for your platform.

## 🔧 Configuration

### Environment Variables

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `WAZUH_API_URL` | Wazuh Manager API endpoint | ✅ | - |
| `WAZUH_API_USERNAME` | Wazuh API username | ✅ | - |
| `WAZUH_API_PASSWORD` | Wazuh API password | ✅ | - |
| `JWT_SECRET_KEY` | JWT signing secret | ✅ | - |
| `MCP_SERVER_PORT` | Server port | ❌ | `8443` |
| `LOG_LEVEL` | Logging level | ❌ | `INFO` |
| `ENABLE_METRICS` | Enable Prometheus metrics | ❌ | `true` |

### Volume Mounts

```bash
docker run -d \
  -v ./config:/app/config:ro \    # Configuration files
  -v ./logs:/app/logs:rw \        # Log files
  -v ./data:/app/data:rw \        # Application data
  gensecaihq/wazuh-mcp-server:v3-latest
```

## 🔒 Security Features

- ✅ **Non-root user execution** - Container runs as user 1000:1000
- ✅ **Read-only filesystem** - Application directory is read-only
- ✅ **Security scanning** - Images scanned with Trivy and Snyk
- ✅ **SBOM included** - Software Bill of Materials for transparency
- ✅ **Minimal attack surface** - Alpine-based with minimal packages
- ✅ **Security capabilities** - Drops unnecessary Linux capabilities

## 📊 Monitoring

### Health Check

The container includes a built-in health check:

```bash
# Check container health
docker ps  # Look for "healthy" status

# Manual health check
curl -f http://localhost:8443/health
```

### Metrics

Prometheus metrics are available on port 9090:

```bash
# View metrics
curl http://localhost:9090/metrics
```

## 🔧 Development

### Local Development

For local development, you can build from source:

```yaml
# docker-compose.override.yml
services:
  wazuh-mcp-server:
    build:
      context: .
      dockerfile: Dockerfile
    # Comment out the image line in docker-compose.yml
```

### Custom Configuration

```bash
# Create custom config
mkdir -p ./config
echo "custom_setting: value" > ./config/custom.yml

# Mount custom config
docker run -d \
  -v ./config:/app/config:ro \
  gensecaihq/wazuh-mcp-server:v3-latest
```

## 🚨 Troubleshooting

### Common Issues

1. **Connection refused**
   ```bash
   # Check if Wazuh API is accessible
   curl -k https://your-wazuh:55000/
   ```

2. **Authentication failed**
   ```bash
   # Verify credentials
   curl -k -u username:password https://your-wazuh:55000/
   ```

3. **Permission denied**
   ```bash
   # Check volume permissions
   sudo chown -R 1000:1000 ./logs ./data
   ```

### Debug Mode

```bash
# Enable debug logging
docker run -d \
  -e LOG_LEVEL=DEBUG \
  gensecaihq/wazuh-mcp-server:v3-latest

# View logs
docker logs -f wazuh-mcp-server
```

## 📋 Requirements

- Docker 20.10+ or Docker Desktop
- Wazuh Manager 4.0+ with API enabled
- Network connectivity to Wazuh Manager (port 55000)
- Minimum 512MB RAM, 1GB recommended

## 🔗 Links

- **GitHub Repository**: [gensecaihq/Wazuh-MCP-Server](https://github.com/gensecaihq/Wazuh-MCP-Server)
- **Documentation**: [docs/](https://github.com/gensecaihq/Wazuh-MCP-Server/tree/main/docs)
- **Issues**: [GitHub Issues](https://github.com/gensecaihq/Wazuh-MCP-Server/issues)
- **Security**: [SECURITY.md](https://github.com/gensecaihq/Wazuh-MCP-Server/blob/main/SECURITY.md)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](https://github.com/gensecaihq/Wazuh-MCP-Server/blob/main/LICENSE) file for details.

---

**Maintained by**: [GenSecAI](https://github.com/gensecaihq)  
**Docker Hub**: [gensecaihq/wazuh-mcp-server](https://hub.docker.com/r/gensecaihq/wazuh-mcp-server)