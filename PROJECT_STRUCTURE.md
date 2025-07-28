# 📁 Project Structure

```
Wazuh-MCP-Server/
│
├── 📋 Core Files
│   ├── README.md           # Main documentation
│   ├── LICENSE             # MIT License
│   ├── compose.yml         # Docker Compose configuration
│   ├── Dockerfile          # Container build instructions
│   ├── requirements.txt    # Python dependencies
│   └── pyproject.toml      # Python package configuration
│
├── 📁 src/                 # Source code
│   └── wazuh_mcp_server/
│       ├── __init__.py
│       ├── server.py       # FastMCP server implementation
│       ├── config.py       # Configuration management
│       └── api/
│           ├── __init__.py
│           └── wazuh_client.py  # Wazuh API client
│
├── 📁 config/              # Configuration templates
│   └── wazuh.env.example   # Environment template
│
├── 📁 scripts/             # User-facing scripts
│   ├── configure.sh        # Interactive configuration
│   └── quick-start.sh      # One-command deployment
│
├── 📁 install/             # Installation scripts
│   ├── install-docker-debian.sh
│   ├── install-docker-redhat.sh
│   ├── install-docker-macos.sh
│   ├── install-docker-windows.ps1
│   └── verify-installation.sh
│
├── 📁 tests/               # Test suite
│   └── test_server.py      # Server tests
│
├── 📁 docs/                # Documentation
│   ├── QUICK_START.md      # Getting started guide
│   └── guides/
│       ├── CONFIGURATION.md
│       ├── PRODUCTION_DEPLOYMENT.md
│       └── DOCKER_INSTALLATION_GUIDE.md
│
└── 📁 docker/              # Docker support files
    └── entrypoint.sh       # Container entrypoint
```

## 🎯 Structure Principles

1. **Clarity**: Each directory has a single, clear purpose
2. **Simplicity**: No duplicate functionality across directories
3. **User-Focused**: Scripts are in easily accessible locations
4. **Standards**: Follows Python and Docker best practices
5. **Minimal**: Only essential files included

## 📝 Key Decisions

- **Single compose.yml**: Following Docker Compose V2+ standards
- **config/ directory**: Centralized configuration management
- **scripts/ vs tools/**: Merged into scripts/ for simplicity
- **Flat documentation**: Easy to find guides in docs/guides/
- **No build artifacts**: Clean repository, build in container