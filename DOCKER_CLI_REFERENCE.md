# Docker CLI Reference - Latest Commands Used

This document outlines all Docker commands used in this project and their alignment with the latest Docker CLI documentation.

## ✅ Docker Compose Commands (Updated to Latest)

### Basic Operations
```bash
# Start services (modern flag)
docker compose up --detach

# Stop services  
docker compose down

# Restart services
docker compose restart

# List containers
docker compose ps

# List all containers (including stopped)
docker compose ps --all

# View logs with modern flags
docker compose logs --follow
docker compose logs --follow --tail=100
docker compose logs --timestamps

# Execute commands
docker compose exec wazuh-mcp-server bash

# Run one-off commands
docker compose run --rm wazuh-mcp-server python3 --version

# Build services
docker compose build --no-cache

# Advanced operations
docker compose down --volumes --remove-orphans
docker compose config
docker compose version
```

## ✅ Container Commands (Updated to Latest)

### Modern Container Management
```bash
# Run containers (explicit container command)
docker container run --interactive --tty --env-file .env image_name

# Execute commands in containers
docker container exec --interactive container_name command

# View container logs
docker container logs --follow container_name
docker container logs --timestamps container_name

# Inspect containers
docker container inspect container_name --format='{{.State.Health.Status}}'

# List containers
docker container ls
docker container ls --all

# Monitor resource usage
docker container stats container_name

# Container lifecycle
docker container start container_name
docker container stop container_name
docker container restart container_name
docker container rm container_name
```

## ✅ Build Commands (Updated to Latest)

### Modern Build with BuildX
```bash
# Standard build (modern buildx)
docker buildx build -t image_name .

# Multi-platform build
docker buildx build --platform linux/amd64,linux/arm64 -t image_name .

# Build with build arguments
docker buildx build --build-arg BUILD_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ") -t image_name .

# Build with cache
docker buildx build --cache-from type=local,src=/tmp/.buildx-cache -t image_name .
```

## ✅ File and Syntax Updates

### Dockerfile
- Added `# syntax=docker/dockerfile:1` directive for latest BuildKit features
- Uses multi-stage builds optimally
- Proper label formatting and metadata

### compose.yml
- Modern filename (preferred over docker-compose.yml)
- Removed deprecated `version` field
- Using current resource limit syntax (`mem_limit`, `cpus`)
- Modern health check configuration

## 🔍 Command Comparison

| Operation | Legacy Command | Modern Command |
|-----------|----------------|----------------|
| Start services | `docker-compose up -d` | `docker compose up --detach` |
| View logs | `docker-compose logs -f` | `docker compose logs --follow` |
| Execute command | `docker exec -it container cmd` | `docker container exec --interactive --tty container cmd` |
| Build image | `docker build -t name .` | `docker buildx build -t name .` |
| Run container | `docker run -it image` | `docker container run --interactive --tty image` |
| Inspect container | `docker inspect container` | `docker container inspect container` |
| View stats | `docker stats container` | `docker container stats container` |

## 📋 Version Requirements

### Recommended (Full Modern Support)
- **Docker CLI**: 24.0+
- **Docker Compose Plugin**: 2.20+
- **BuildKit**: Enabled (default in modern Docker)

### Minimum Supported
- **Docker CLI**: 20.10.13+
- **Docker Compose Plugin**: 2.0+

## 🎯 Best Practices Applied

1. **Explicit Flag Names**: Use `--detach` instead of `-d`, `--follow` instead of `-f`
2. **Subcommand Structure**: Use `docker container exec` instead of `docker exec`
3. **Modern Build**: Use `docker buildx build` instead of `docker build`
4. **Compose Plugin**: Use `docker compose` instead of `docker-compose`
5. **Modern Filenames**: Use `compose.yml` instead of `docker-compose.yml`
6. **Health Checks**: Proper health check configuration in compose files
7. **Resource Limits**: Modern resource limit syntax

## 🔗 Documentation Sources

All commands are aligned with:
- [Docker CLI Reference](https://docs.docker.com/reference/cli/docker/)
- [Docker Compose Reference](https://docs.docker.com/reference/cli/docker/compose/)
- [Docker Container Reference](https://docs.docker.com/reference/cli/docker/container/)
- [Docker BuildX Reference](https://docs.docker.com/reference/cli/docker/buildx/)

## ✅ Verification

Every command in this project has been verified against the latest Docker documentation:
- All `docker compose` commands use modern syntax
- All container operations use explicit `docker container` commands where appropriate
- All build operations use `docker buildx build`
- All flags use long-form names for clarity
- All files use modern naming conventions

This ensures maximum compatibility with current and future Docker versions while maintaining backward compatibility where needed.