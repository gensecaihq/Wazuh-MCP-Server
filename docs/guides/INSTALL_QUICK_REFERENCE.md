# 🚀 Quick Installation Reference

One-command installation for all supported platforms.

## 🐧 Linux

### Debian/Ubuntu/Mint/Pop!_OS/Elementary
```bash
curl -fsSL https://raw.githubusercontent.com/gensecaihq/Wazuh-MCP-Server/main/scripts/install-docker-debian.sh | bash
```

### RHEL/CentOS/Fedora/Rocky/AlmaLinux
```bash
curl -fsSL https://raw.githubusercontent.com/gensecaihq/Wazuh-MCP-Server/main/scripts/install-docker-redhat.sh | bash
```

## 🍎 macOS (Intel & Apple Silicon)
```bash
curl -fsSL https://raw.githubusercontent.com/gensecaihq/Wazuh-MCP-Server/main/scripts/install-docker-macos.sh | bash
```

## 🪟 Windows
**PowerShell (Run as Administrator):**
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
iwr -useb https://raw.githubusercontent.com/gensecaihq/Wazuh-MCP-Server/main/scripts/install-docker-windows.ps1 | iex
```

## ✅ Verification
```bash
# After installation, verify everything is working
./scripts/verify-installation.sh
```

## 🔧 Next Steps
1. **Configure Wazuh connection:** `python3 configure.py`
2. **Deploy server:** `docker compose up -d`
3. **Test functionality:** `python3 test-functionality.py`
4. **Setup Claude Desktop:** See README.md for MCP client integration

## 📚 Full Documentation
- **[README.md](README.md)** - Complete setup guide
- **[DOCKER_INSTALLATION_GUIDE.md](DOCKER_INSTALLATION_GUIDE.md)** - Detailed Docker installation
- **[PRODUCTION_DEPLOYMENT.md](PRODUCTION_DEPLOYMENT.md)** - Production deployment guide

## 🆘 Support
- **Troubleshooting:** [DOCKER_INSTALLATION_GUIDE.md#troubleshooting](DOCKER_INSTALLATION_GUIDE.md#troubleshooting)
- **Issues:** [GitHub Issues](https://github.com/gensecaihq/Wazuh-MCP-Server/issues)