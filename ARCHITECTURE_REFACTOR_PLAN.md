# Wazuh MCP Server - Multi-Transport Architecture Refactoring Plan

## Overview
This document outlines the strategy to maintain two transport implementations (STDIO and Remote) with shared core functionality while enabling independent versioning.

## Current State
- **main branch**: FastMCP STDIO transport (v2.1.0)
- **mcp-remote branch**: HTTP/SSE transport (v3.0.0)
- **Shared functionality**: 29 tools, analyzers, API clients

## Target Architecture

### 1. Repository Structure
```
wazuh-mcp-server/
├── packages/
│   ├── core/                    # wazuh-mcp-core (v1.x.x)
│   │   ├── pyproject.toml
│   │   └── src/wazuh_mcp_core/
│   │       ├── api/             # Wazuh API clients
│   │       ├── analyzers/       # Security analyzers
│   │       ├── tools/           # 29 MCP tools (transport-agnostic)
│   │       ├── utils/           # Common utilities
│   │       └── config/          # Configuration management
│   ├── stdio/                   # wazuh-mcp-stdio (v2.x.x)
│   │   ├── pyproject.toml
│   │   └── src/wazuh_mcp_stdio/
│   │       ├── server.py        # FastMCP implementation
│   │       ├── main.py          # CLI entry point
│   │       └── transport/       # STDIO-specific logic
│   └── remote/                  # wazuh-mcp-remote (v3.x.x)
│       ├── pyproject.toml
│       ├── Dockerfile
│       ├── compose.yml
│       └── src/wazuh_mcp_remote/
│           ├── server.py        # FastAPI implementation
│           ├── auth.py          # JWT authentication
│           ├── monitoring.py    # Prometheus metrics
│           └── transport/       # SSE/HTTP-specific logic
├── docs/
│   ├── core/                    # Core library docs
│   ├── stdio/                   # STDIO transport docs
│   └── remote/                  # Remote transport docs
├── .github/
│   └── workflows/
│       ├── core-ci.yml          # Core package CI/CD
│       ├── stdio-ci.yml         # STDIO package CI/CD
│       └── remote-ci.yml        # Remote package CI/CD
└── tools/
    ├── migrate-to-monorepo.sh   # Migration script
    └── version-sync.py          # Version management
```

## 2. Package Dependencies

### Core Package (wazuh-mcp-core)
```toml
[project]
name = "wazuh-mcp-core"
version = "1.2.0"
description = "Shared core library for Wazuh MCP implementations"
dependencies = [
    "aiohttp>=3.12.14",
    "pydantic>=2.11.7", 
    "python-dotenv>=1.1.1"
]
```

### STDIO Package (wazuh-mcp-stdio)  
```toml
[project]
name = "wazuh-mcp-stdio"
version = "2.1.0"
description = "FastMCP STDIO transport for Wazuh"
dependencies = [
    "wazuh-mcp-core>=1.2.0,<2.0.0",
    "fastmcp>=2.10.6"
]
```

### Remote Package (wazuh-mcp-remote)
```toml
[project]
name = "wazuh-mcp-remote" 
version = "3.0.0"
description = "Remote MCP server with HTTP/SSE transport"
dependencies = [
    "wazuh-mcp-core>=1.2.0,<2.0.0",
    "fastapi>=0.115.0",
    "uvicorn[standard]>=0.32.0",
    "prometheus-client>=0.20.0"
]
```

## 3. Tool Abstraction Layer

### Transport-Agnostic Tool Interface
```python
# core/src/wazuh_mcp_core/tools/base.py
class WazuhTool:
    """Base class for transport-agnostic Wazuh tools."""
    
    async def execute(self, **kwargs) -> dict:
        """Execute tool logic - returns dict for any transport."""
        raise NotImplementedError
    
    @property 
    def schema(self) -> dict:
        """Tool schema for MCP registration."""
        raise NotImplementedError

# Example tool implementation
class AlertsTool(WazuhTool):
    async def execute(self, limit=100, **kwargs) -> dict:
        alerts = await self.wazuh_client.get_alerts(limit=limit)
        return {"alerts": alerts, "count": len(alerts)}
```

### Transport-Specific Adapters
```python
# stdio/src/wazuh_mcp_stdio/transport/adapter.py
class STDIOToolAdapter:
    """Adapts core tools for FastMCP STDIO transport."""
    
    def register_tool(self, mcp_app, tool_instance):
        @mcp_app.tool(**tool_instance.schema)
        async def tool_wrapper(**kwargs) -> str:
            result = await tool_instance.execute(**kwargs)
            return json.dumps(result, indent=2)

# remote/src/wazuh_mcp_remote/transport/adapter.py  
class RemoteToolAdapter:
    """Adapts core tools for MCP remote transport."""
    
    def register_tool(self, tool_instance):
        async def tool_handler(params: dict) -> dict:
            return await tool_instance.execute(**params)
        return tool_handler
```

## 4. Migration Strategy

### Phase 1: Create Core Package
1. **Extract shared modules** to `packages/core/`
2. **Maintain API compatibility** during transition
3. **Create core package** with independent versioning

### Phase 2: Refactor Transport Layers
1. **Update main branch** to consume core package
2. **Update mcp-remote branch** to consume core package  
3. **Maintain feature parity** across transports

### Phase 3: Independent Versioning
1. **Set up semantic versioning** for each package
2. **Create release workflows** for coordinated releases
3. **Document migration guide** for users

## 5. Version Management Strategy

### Core Library Versioning
- **v1.x.x**: Stable API for tools and analyzers
- **Breaking changes**: Bump major version (v2.x.x)
- **New tools**: Bump minor version (v1.x.0)
- **Bug fixes**: Bump patch version (v1.x.x)

### Transport Package Versioning
- **STDIO (v2.x.x)**: FastMCP-focused releases
- **Remote (v3.x.x)**: Enterprise server releases
- **Independent release cycles** based on transport needs

### Compatibility Matrix
```
Core v1.2.x ← STDIO v2.1.x
Core v1.2.x ← Remote v3.0.x

Core v1.3.x ← STDIO v2.2.x  
Core v1.3.x ← Remote v3.1.x
```

## 6. CI/CD Pipeline

### Multi-Package Build Matrix
```yaml
# .github/workflows/packages.yml
strategy:
  matrix:
    package: [core, stdio, remote]
    python-version: [3.11, 3.12]

steps:
- name: Test ${{ matrix.package }}
  run: |
    cd packages/${{ matrix.package }}
    python -m pytest tests/
```

### Coordinated Releases
```yaml
# .github/workflows/release.yml  
name: Multi-Package Release
on:
  workflow_dispatch:
    inputs:
      core_version:
        required: true
      stdio_version: 
        required: true
      remote_version:
        required: true

jobs:
  release-core:
    # Release core first
  release-stdio:
    needs: release-core
    # Release stdio with updated core dependency
  release-remote:
    needs: release-core  
    # Release remote with updated core dependency
```

## 7. Migration Commands

### One-Time Migration Script
```bash
#!/bin/bash
# tools/migrate-to-monorepo.sh

echo "🔄 Migrating to monorepo structure..."

# Create package directories
mkdir -p packages/{core,stdio,remote}

# Extract core components
echo "📦 Extracting core components..."
# Move shared modules to packages/core/

# Update import paths
echo "🔧 Updating import paths..."
# Automated refactoring of imports

# Create package configurations  
echo "⚙️ Creating package configurations..."
# Generate pyproject.toml for each package

echo "✅ Migration complete!"
```

## 8. User Migration Guide

### For STDIO Users (v2.1.0 → v2.2.0)
```bash
# Before
pip install wazuh-mcp-server==2.1.0

# After  
pip install wazuh-mcp-stdio==2.2.0
# Core automatically installed as dependency
```

### For Remote Users (v3.0.0 → v3.1.0)
```bash
# Before
git clone -b mcp-remote wazuh-mcp-server

# After
pip install wazuh-mcp-remote==3.1.0
# Or via Docker
docker pull wazuh-mcp-remote:3.1.0
```

## 9. Benefits of This Architecture

### ✅ **Maintainability**
- Single source of truth for business logic
- Reduced code duplication
- Easier bug fixes and feature additions

### ✅ **Independent Evolution**  
- Transport layers can evolve independently
- Different release cycles for different use cases
- Clear separation of concerns

### ✅ **User Experience**
- Simple installation via package managers
- Clear documentation per transport
- Migration paths between transports

### ✅ **Development Efficiency**
- Shared testing infrastructure
- Coordinated but independent CI/CD
- Clear ownership boundaries

## 10. Implementation Timeline

| Phase | Duration | Deliverables |
|-------|----------|-------------|
| **Phase 1** | 2 weeks | Core package extraction |
| **Phase 2** | 2 weeks | Transport refactoring |  
| **Phase 3** | 1 week | CI/CD setup |
| **Phase 4** | 1 week | Documentation & migration |

**Total**: 6 weeks for complete refactoring

## Next Steps

1. **Review and approve** this architecture plan
2. **Create feature branch** for refactoring work
3. **Begin Phase 1** core package extraction
4. **Set up testing** for monorepo structure
5. **Plan user communication** for migration

This architecture ensures both transport implementations can evolve independently while sharing core business logic, enabling sustainable long-term maintenance.