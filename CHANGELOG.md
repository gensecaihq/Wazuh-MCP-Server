# Changelog

## v3.0.0 - Remote MCP Server & Docker Deployment (July 15, 2025)

### 🚀 Major Features - Remote MCP Capability

#### Remote MCP Server Implementation
- **HTTP/SSE Transport**: Production-grade Server-Sent Events transport for real-time communication
- **OAuth 2.0 Authentication**: Complete OAuth2 server with JWT token management and secure credential handling
- **RESTful API**: Standard HTTP endpoints for MCP operations with comprehensive error handling
- **Claude Code Integration**: Native support for Claude Code remote MCP connections and MCP Connector API

#### Docker Production Deployment
- **Multi-stage Dockerfile**: Optimized production container with minimal attack surface
- **Docker Compose Stack**: Complete deployment with Redis, Prometheus, and Grafana
- **Health Checks**: Comprehensive health monitoring with auto-recovery
- **Security Hardening**: Non-root user, read-only filesystem, capability dropping, and security headers

#### Enterprise Security Features
- **OAuth 2.0 Server**: Full authorization server with client management and scope-based access control
- **JWT Token Management**: Secure token creation, validation, and revocation with key rotation
- **Rate Limiting**: Per-client rate limiting with configurable thresholds and abuse protection
- **SSL/TLS Support**: Full HTTPS support with certificate management and security best practices

#### Monitoring & Observability
- **Prometheus Integration**: Complete metrics collection with custom dashboards
- **Structured Logging**: JSON logs with correlation IDs, security audit trails, and performance metrics
- **Grafana Dashboards**: Pre-configured monitoring dashboards for operational insights
- **Health Endpoints**: Comprehensive health checks and system status reporting

### 🔧 Technical Improvements

#### Transport Architecture
- **Multi-Transport Support**: Seamless switching between stdio, HTTP, and SSE transports
- **Transport Adapter**: Protocol conversion layer for backward compatibility
- **Connection Management**: Advanced connection pooling and lifecycle management
- **Message Framing**: Efficient message serialization and streaming

#### Authentication System
- **Token Manager**: Secure JWT token creation with proper encryption and expiration
- **User Management**: Complete user lifecycle with password hashing and scope management
- **Client Registration**: OAuth2 client management with redirect URI validation
- **Middleware Integration**: Seamless authentication middleware with request context

#### Production Features
- **Configuration Management**: Environment-based configuration with validation
- **Error Standardization**: Consistent error handling across all components
- **Request Validation**: Comprehensive input validation and sanitization
- **Audit Logging**: Security event logging for compliance requirements

### 🐛 Bug Fixes
- Fixed import path inconsistencies in test files (16 files updated)
- Resolved dependency version conflicts in requirements files
- Corrected configuration validation edge cases
- Enhanced error handling in transport layer

### 🔄 Migration & Compatibility
- **Backward Compatibility**: All v2.0.0 tools continue to work unchanged
- **Migration Scripts**: Automated migration from v2.0.0 to v3.0.0
- **Configuration Compatibility**: Existing .env files work without changes
- **Graceful Degradation**: Fallback to stdio mode when remote features unavailable

### 📦 Dependencies
- Added FastAPI 0.104.1 for HTTP server framework
- Added AuthLib 1.2.1 for OAuth2 implementation
- Added SSE-Starlette 1.6.5 for Server-Sent Events
- Added Prometheus-Client 0.19.0 for metrics
- Added OpenTelemetry for distributed tracing
- Pinned all production dependencies for stability

### 🧪 Testing
- **Comprehensive Test Suite**: 95%+ test coverage for all v3.0.0 features
- **Transport Layer Tests**: Complete testing of HTTP/SSE functionality
- **Authentication Tests**: OAuth2 flow and JWT token validation
- **Docker Integration Tests**: Container deployment and health verification
- **Security Tests**: Authentication, authorization, and rate limiting

### 📖 Documentation
- **v3.0.0 README**: Complete setup and deployment guide
- **API Documentation**: Interactive OpenAPI documentation
- **Docker Guide**: Production deployment best practices
- **Migration Guide**: Step-by-step migration from v2.0.0
- **Security Guide**: Authentication and security configuration

## v2.0.0 - Intelligence Enhancement & Factory Architecture (July 14, 2025)

### 🚀 Major Features

#### 12 New Advanced Tools
- **Statistics Tools (4)**: `get_wazuh_alert_summary`, `get_wazuh_weekly_stats`, `get_wazuh_remoted_stats`, `get_wazuh_log_collector_stats`
- **Vulnerability Tools (2)**: `get_wazuh_vulnerability_summary`, `get_wazuh_critical_vulnerabilities`
- **Agent Tools (2)**: `get_wazuh_running_agents`, `get_wazuh_rules_summary`
- **Cluster Tools (4)**: `get_wazuh_cluster_health`, `get_wazuh_cluster_nodes`, `search_wazuh_manager_logs`, `get_wazuh_manager_error_logs`

#### Phase 5 Prompt Enhancement System
- **Context Aggregator**: Intelligent context gathering engine
- **Adaptive Formatting**: Dynamic response formatting based on data quality
- **Intelligent Caching**: LRU cache with TTL for performance optimization (60-90% reduction in API calls)
- **Real-time Updates**: Live monitoring during ongoing incidents
- **Pipeline System**: Specialized context gathering for different analysis types

#### Modern Architecture
- **Factory Pattern**: Modular tool organization for easy extension
- **Full Async Support**: Complete asynchronous operation support
- **Backward Compatibility**: All v1.0.0 tools continue to work unchanged

### 🔧 Technical Improvements
- **Performance**: Intelligent caching and parallel processing
- **Maintainability**: Clean factory-based architecture with clear separation of concerns
- **Extensibility**: Easy to add new tools and enhancement features
- **Production Ready**: Comprehensive error handling and validation

### 📊 Impact
- **Total Tools**: 14 → 26 (+85% increase)
- **API Efficiency**: 60-90% reduction in redundant calls
- **Response Quality**: Enhanced context-aware responses
- **Development Velocity**: Factory pattern enables rapid feature addition

### 🔄 Migration
- **Zero Breaking Changes**: Complete backward compatibility maintained
- **Gradual Adoption**: New features are additive, existing workflows unchanged
- **Enhanced Experience**: Existing tools benefit from Phase 5 enhancements

## v1.0.0 - Unix Systems Consolidation

### Major Changes

#### Platform Consolidation
- **Unified Unix Support**: macOS and Linux now both use the wrapper script approach
- **Simplified Setup**: Single configuration method for Unix-like systems
- **Windows Distinction**: Windows continues to use direct Python execution

#### Documentation Restructuring
- **Consolidated Troubleshooting**: Merged macOS and Linux troubleshooting into unified Unix guide
- **Updated Setup Instructions**: Clear platform-specific configuration examples
- **Enhanced README**: Streamlined setup process with platform-specific sections

#### Security Improvements
- **Credential Security**: Removed exposed production credentials from repository
- **Enhanced .gitignore**: Comprehensive exclusion of sensitive files
- **SSL Configuration**: Clear guidance on production vs development settings

#### API Authentication
- **Dedicated API Users**: Clear instructions for creating Wazuh API users
- **Separation of Concerns**: Distinct Dashboard vs API authentication explained
- **Enhanced Troubleshooting**: Comprehensive authentication troubleshooting guide

### Files Added
- `docs/unix-troubleshooting.md` - Comprehensive Unix systems troubleshooting
- `CHANGELOG.md` - This changelog file

### Files Modified
- `README.md` - Updated with consolidated platform approach
- `WRAPPER_SCRIPT_DOCUMENTATION.md` - Updated to reflect Unix support
- `docs/claude-desktop-setup.md` - Platform-specific configuration examples
- `docs/windows-troubleshooting.md` - Enhanced Windows-specific guidance
- `.env` - Sanitized credentials (placeholder values)

### Files Removed
- `docs/macos-troubleshooting.md` - Merged into unix-troubleshooting.md
- `docs/linux-setup.md` - Merged into main documentation
- `logs/*.log` - Removed log files from repository

### Configuration Changes

#### Unix Systems (macOS/Linux)
```json
{
  "mcpServers": {
    "wazuh": {
      "command": "/path/to/Wazuh-MCP-Server/mcp_wrapper.sh",
      "args": ["--stdio"]
    }
  }
}
```

#### Windows
```json
{
  "mcpServers": {
    "wazuh": {
      "command": "C:/path/to/Wazuh-MCP-Server/venv/Scripts/python.exe",
      "args": ["C:/path/to/Wazuh-MCP-Server/src/wazuh_mcp_server/main.py", "--stdio"]
    }
  }
}
```

### Benefits
- **Simplified Setup**: Users no longer need to distinguish between macOS and Linux
- **Better Error Handling**: Unified troubleshooting approach
- **Enhanced Security**: Proper credential management and SSL configuration
- **Improved Documentation**: Clear, comprehensive guides for all platforms
- **Production Ready**: Cleaned repository ready for deployment

### Migration Guide

#### For Existing macOS Users
- No changes needed - existing configuration continues to work
- Refer to `docs/unix-troubleshooting.md` for any issues

#### For Existing Linux Users
- Update Claude Desktop configuration to use wrapper script
- Change from direct Python execution to wrapper script approach
- Refer to updated documentation for configuration examples

#### For New Users
- Follow platform-specific setup instructions in README.md
- Use appropriate configuration for your operating system
- Refer to platform-specific troubleshooting guides

### Technical Improvements
- **Cross-Platform Compatibility**: Wrapper script tested on both macOS and Linux
- **Environment Handling**: Improved .env file loading and validation
- **Process Management**: Enhanced signal handling and cleanup
- **Logging**: Better log management with temporary directory creation
- **Error Recovery**: Comprehensive error handling and recovery mechanisms

### Future Considerations
- Monitor wrapper script performance across different Linux distributions
- Consider adding automated testing for all supported platforms
- Evaluate potential for Windows wrapper script if needed
- Plan for additional platform support based on user feedback