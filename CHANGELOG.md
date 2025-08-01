# Changelog

All notable changes to Wazuh MCP Server will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] - 2024-08-01

### 🎯 Major Repository Restructure & Production Ready Release

#### Added
- **29 FastMCP Tools**: Complete security tool suite for Wazuh integration
- **Dual API Support**: Intelligent routing between Wazuh Server API and Indexer API
- **Comprehensive Health Checks**: Production-grade startup validation with 15+ checks
- **Cross-Platform Installers**: Universal and platform-specific installation scripts
- **Production Documentation**: Complete documentation suite with security guides
- **Security Hardening**: Enterprise-grade security configurations and audit logging

#### Repository Structure
- **New Directory Structure**: Clean, professional organization
  - `bin/` - Executable scripts
  - `docs/` - Comprehensive documentation with proper linking
  - `installers/platform/` - OS-specific installation scripts
  - `examples/configs/` - Configuration examples
  - `tools/` - Development and validation tools
- **Removed Redundancies**: Eliminated 1MB+ of duplicate and obsolete files
- **Consolidated Requirements**: Streamlined dependency management

#### FastMCP Implementation  
- **STDIO Transport Only**: Secure local connection to Claude Desktop
- **Intelligent API Routing**: Automatic selection between Server API and Indexer API
- **Comprehensive Error Handling**: Consistent error patterns across all 29 tools
- **Production Health Checks**: Startup validation for system, dependencies, configuration
- **Graceful Shutdown**: Signal handling for clean server termination

#### Security Enhancements
- **SSL/TLS by Default**: Certificate validation and encryption
- **Input Validation**: Pydantic v2 models for all tool parameters
- **Audit Logging**: Complete security event logging
- **Credential Security**: Environment variable and secrets management
- **File Permissions**: Secure default permissions for configuration files

#### Documentation
- **Complete Documentation Suite**: Installation, configuration, API reference, security
- **Logical Structure**: Organized by user type (new users, security teams, admins, developers)
- **Cross-Referenced**: Proper linking between documentation sections
- **Production Ready**: Real-world examples and troubleshooting guides

#### Performance & Reliability
- **Connection Pooling**: Efficient HTTP connection management
- **Rate Limiting**: Built-in request throttling
- **Caching**: Query result caching for performance
- **Automatic Fallback**: API failover mechanisms
- **Memory Management**: Proper resource cleanup

### Changed
- **Repository Structure**: Complete reorganization for professional deployment
- **Installation Process**: Simplified cross-platform installation
- **Configuration Management**: Streamlined environment variable handling
- **Error Handling**: Consistent error responses across all tools
- **Documentation**: Complete rewrite with focus on usability

### Removed
- **Docker Support**: Removed Docker components for pure STDIO implementation
- **Duplicate Files**: Eliminated redundant installation scripts and configurations
- **Obsolete Code**: Removed unused imports, dead code, and deprecated files
- **Complex Installers**: Simplified installation process

### Fixed
- **Dependency Mismatch**: Critical FastMCP vs MCP package issue resolved
- **Version Inconsistencies**: Synchronized version numbers across all files  
- **Import Errors**: Fixed missing method implementations in client manager
- **Path Issues**: Corrected executable path references after restructure

### Security
- **Production Security**: Enterprise-grade security configuration
- **Vulnerability Mitigation**: Input validation and injection prevention
- **Audit Trail**: Comprehensive security event logging
- **Access Control**: Proper file permissions and credential management

---

## [2.0.0] - 2024-07-15

### Added
- FastMCP framework integration
- Wazuh 4.8.0+ support
- Basic tool implementations

### Changed
- Migrated from legacy MCP to FastMCP
- Updated API client architecture

---

## [1.0.0] - 2024-06-01

### Added
- Initial Wazuh MCP Server implementation
- Basic alert and agent management
- Docker support
- Initial documentation

---

## Migration Notes

### Upgrading from v2.0.x to v2.1.0

**Repository Structure Changes:**
- Main executable moved from root to `bin/wazuh-mcp-server`
- Installation scripts moved to `installers/platform/`
- Documentation restructured in `docs/` with proper organization

**Configuration Changes:**
- No breaking changes to `.env` configuration
- Claude Desktop config needs path update to `bin/wazuh-mcp-server`

**Installation Changes:**
- Use new installer paths: `python3 installers/install.py`
- Platform-specific installers in `installers/platform/`

### Breaking Changes
- **Executable Path**: Update Claude Desktop config to use `bin/wazuh-mcp-server`
- **Installer Paths**: Use new installer locations
- **Docker Removal**: Docker support completely removed in favor of STDIO-only

### Deprecations
- Docker deployment method (removed)
- Root-level installation scripts (moved to `installers/`)

---

## Development

### Contributing
See [Contributing Guide](docs/development/CONTRIBUTING.md) for development setup and contribution guidelines.

### Versioning
This project uses [Semantic Versioning](https://semver.org/):
- **MAJOR**: Incompatible API changes
- **MINOR**: New functionality (backward compatible)
- **PATCH**: Bug fixes (backward compatible)