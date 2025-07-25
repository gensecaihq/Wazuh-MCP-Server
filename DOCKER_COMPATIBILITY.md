# Docker Compatibility Guide

## Docker Compose Command Compatibility

This project uses the **modern Docker Compose Plugin** syntax (`docker compose`) and the **modern compose file naming** (`compose.yml`) as per the [official Docker documentation](https://docs.docker.com/reference/cli/docker/compose/).

### ✅ **Recommended (Modern - Docker CLI v24.0+)**
```bash
# Use the Docker Compose Plugin (v2) with explicit flags
docker compose up --detach
docker compose ps
docker compose logs --follow

# Modern container commands
docker container run --interactive --tty image_name
docker container exec --interactive container_name command
docker container logs --follow container_name

# Modern build commands
docker buildx build -t image_name .
```

### ⚠️ **Legacy Support (Docker CLI v20.10-v23.x)**
```bash
# If you're using the standalone docker-compose (v1)
docker-compose up -d
docker-compose ps  
docker-compose logs -f

# Legacy container commands (still work)
docker run -it image_name
docker exec -i container_name command
docker logs -f container_name

# Legacy build commands
docker build -t image_name .
```

## Version Requirements

### **Docker Compose Plugin (Recommended)**
- **Docker**: 24.0+ (for latest CLI features)
- **Docker**: 20.10.13+ (minimum for Plugin support)
- **Docker Compose Plugin**: 2.20+ (recommended)
- **Docker Compose Plugin**: 2.0+ (minimum)
- **Command**: `docker compose`

**Check your version:**
```bash
docker --version          # Should show 24.0+ for best experience
docker compose version    # Should show 2.20+
docker buildx version     # Check buildx availability
```

### **Legacy Docker Compose (Deprecated)**
- **Docker**: 19.03+
- **Docker Compose Standalone**: 1.28+
- **Command**: `docker-compose`

**Check your version:**
```bash
docker --version
docker-compose --version
```

## Migration from Legacy

If you're using the legacy `docker-compose` command, you can:

1. **Install Docker Desktop** (includes Compose Plugin automatically)
2. **Install Compose Plugin manually**:
   ```bash
   # On Linux
   sudo apt-get update
   sudo apt-get install docker-compose-plugin
   
   # On macOS (with Homebrew)
   brew install docker-compose
   ```

3. **Update your commands and files**:
   - Replace `docker-compose` with `docker compose`
   - Use `compose.yml` instead of `docker-compose.yml` (both work, but `compose.yml` is preferred)
   - All other syntax remains the same

## Feature Compatibility

Both versions support the same `compose.yml` syntax used in this project:

- ✅ Services configuration
- ✅ Environment variables
- ✅ Health checks
- ✅ Resource limits
- ✅ Networks and volumes
- ✅ Build contexts

## Troubleshooting

### "docker: 'compose' is not a docker command"

**Solution**: You're using legacy Docker. Either:
1. Upgrade to Docker Desktop 4.0+ (includes Compose Plugin)
2. Use `docker-compose` instead of `docker compose`

### "Unknown compose file version"

**Solution**: Update Docker and Docker Compose to latest versions.

### "Service 'wazuh-mcp-server' failed to build"

**Solution**: Ensure Docker version 20.10+ for proper BuildKit support.

## Why Use Docker Compose Plugin?

1. **Official Support**: Docker Compose Plugin is the official way forward
2. **Better Integration**: Tighter integration with Docker CLI
3. **Active Development**: New features and bug fixes
4. **Simpler Installation**: Included with Docker Desktop by default
5. **Consistent Experience**: Same command structure across platforms

For the best experience, we recommend using the Docker Compose Plugin with `docker compose` commands.

---

**Need Help?** See our [DOCKER_USAGE.md](DOCKER_USAGE.md) for detailed usage instructions.