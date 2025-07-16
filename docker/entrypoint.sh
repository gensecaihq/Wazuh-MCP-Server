#!/bin/bash
# Production-grade Docker entrypoint for Wazuh MCP Server v3.0.0
# ==============================================================

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1" >&2
}

log_debug() {
    if [[ "${LOG_LEVEL:-INFO}" == "DEBUG" ]]; then
        echo -e "${BLUE}[DEBUG]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
    fi
}

# Error handler
error_exit() {
    log_error "$1"
    exit 1
}

# Signal handlers for graceful shutdown
shutdown_handler() {
    log_info "Received shutdown signal, terminating gracefully..."
    if [[ -n "${MCP_PID:-}" ]]; then
        kill -TERM "$MCP_PID" 2>/dev/null || true
        wait "$MCP_PID" 2>/dev/null || true
    fi
    log_info "Shutdown complete"
    exit 0
}

# Set up signal handlers
trap shutdown_handler SIGTERM SIGINT SIGQUIT

# Configuration validation
validate_config() {
    log_info "Validating configuration..."
    
    # Required environment variables
    local required_vars=(
        "WAZUH_API_URL"
        "WAZUH_API_USERNAME" 
        "WAZUH_API_PASSWORD"
    )
    
    for var in "${required_vars[@]}"; do
        if [[ -z "${!var:-}" ]]; then
            error_exit "Required environment variable $var is not set"
        fi
    done
    
    # Validate network settings
    if [[ ! "${MCP_SERVER_PORT:-8443}" =~ ^[0-9]+$ ]] || 
       [[ "${MCP_SERVER_PORT:-8443}" -lt 1 ]] || 
       [[ "${MCP_SERVER_PORT:-8443}" -gt 65535 ]]; then
        error_exit "Invalid MCP_SERVER_PORT: ${MCP_SERVER_PORT:-8443}"
    fi
    
    # Validate transport mode
    case "${MCP_TRANSPORT:-sse}" in
        stdio|http|sse)
            log_debug "Transport mode: ${MCP_TRANSPORT:-sse}"
            ;;
        *)
            error_exit "Invalid MCP_TRANSPORT: ${MCP_TRANSPORT:-sse}. Must be stdio, http, or sse"
            ;;
    esac
    
    log_info "Configuration validation complete"
}

# Initialize directories and permissions
init_directories() {
    log_info "Initializing directories..."
    
    # Create necessary directories
    mkdir -p /app/logs /app/config /app/data
    
    # Set proper permissions
    chmod 750 /app/logs /app/config /app/data
    
    # Create log files if they don't exist
    touch /app/logs/wazuh-mcp-server.log
    touch /app/logs/access.log
    touch /app/logs/error.log
    
    chmod 640 /app/logs/*.log
    
    log_info "Directory initialization complete"
}

# Generate default configuration if needed
generate_config() {
    local config_file="/app/config/server.env"
    
    if [[ ! -f "$config_file" ]]; then
        log_info "Generating default configuration..."
        
        cat > "$config_file" << EOF
# Wazuh MCP Server v3.0.0 Configuration
# Generated on $(date)

# Server settings
MCP_SERVER_HOST=${MCP_SERVER_HOST:-0.0.0.0}
MCP_SERVER_PORT=${MCP_SERVER_PORT:-8443}
MCP_SERVER_MODE=${MCP_SERVER_MODE:-remote}
MCP_TRANSPORT=${MCP_TRANSPORT:-sse}

# Wazuh API settings
WAZUH_API_URL=${WAZUH_API_URL}
WAZUH_API_USERNAME=${WAZUH_API_USERNAME}
WAZUH_API_VERIFY_SSL=${WAZUH_API_VERIFY_SSL:-true}

# Security settings
OAUTH_ENABLED=${OAUTH_ENABLED:-true}
JWT_SECRET_KEY=${JWT_SECRET_KEY:-$(openssl rand -base64 32)}

# Logging settings
LOG_LEVEL=${LOG_LEVEL:-INFO}
LOG_FORMAT=${LOG_FORMAT:-json}

# Monitoring settings
ENABLE_METRICS=${ENABLE_METRICS:-true}
METRICS_PORT=${METRICS_PORT:-9090}

# Performance settings
MAX_CONNECTIONS=${MAX_CONNECTIONS:-1000}
REQUEST_TIMEOUT=${REQUEST_TIMEOUT:-30}
EOF
        
        chmod 600 "$config_file"
        log_info "Default configuration generated at $config_file"
    fi
}

# Health check function
health_check() {
    local max_attempts=30
    local attempt=1
    
    log_info "Waiting for server to be ready..."
    
    while [[ $attempt -le $max_attempts ]]; do
        if curl -f -s -k "https://localhost:${MCP_SERVER_PORT:-8443}/health" >/dev/null 2>&1; then
            log_info "Server is ready and healthy"
            return 0
        fi
        
        log_debug "Health check attempt $attempt/$max_attempts failed, retrying..."
        sleep 2
        ((attempt++))
    done
    
    error_exit "Server failed to become ready within $(($max_attempts * 2)) seconds"
}

# Start monitoring in background
start_monitoring() {
    if [[ "${ENABLE_METRICS:-true}" == "true" ]]; then
        log_info "Starting monitoring services..."
        
        # Background process for metrics collection
        {
            while true; do
                if [[ -n "${MCP_PID:-}" ]] && kill -0 "$MCP_PID" 2>/dev/null; then
                    # Log system metrics
                    echo "$(date '+%Y-%m-%d %H:%M:%S') METRICS: CPU=$(top -bn1 | grep "Cpu(s)" | cut -d',' -f1 | cut -d':' -f2 | trim), MEM=$(free -m | awk 'NR==2{printf "%.1f%%", $3*100/$2}')" >> /app/logs/metrics.log
                else
                    break
                fi
                sleep 60
            done
        } &
        
        MONITORING_PID=$!
        log_debug "Monitoring started with PID: $MONITORING_PID"
    fi
}

# Main execution
main() {
    log_info "Starting Wazuh MCP Server v3.0.0"
    log_info "Platform: $(uname -m), OS: $(uname -s)"
    log_info "Python: $(python --version)"
    
    # Initialize
    validate_config
    init_directories
    generate_config
    
    # Source configuration
    if [[ -f "/app/config/server.env" ]]; then
        source "/app/config/server.env"
    fi
    
    # Start monitoring
    start_monitoring
    
    # Determine startup command based on mode
    case "${MCP_SERVER_MODE:-remote}" in
        "stdio")
            log_info "Starting in stdio mode (local)"
            exec python -m wazuh_mcp_server.main &
            ;;
        "remote"|"http"|"sse")
            log_info "Starting in remote mode with ${MCP_TRANSPORT:-sse} transport"
            exec python -m wazuh_mcp_server.remote_server \
                --host "${MCP_SERVER_HOST:-0.0.0.0}" \
                --port "${MCP_SERVER_PORT:-8443}" \
                --transport "${MCP_TRANSPORT:-sse}" \
                --log-level "${LOG_LEVEL:-INFO}" &
            ;;
        *)
            error_exit "Invalid MCP_SERVER_MODE: ${MCP_SERVER_MODE}"
            ;;
    esac
    
    MCP_PID=$!
    log_info "Server started with PID: $MCP_PID"
    
    # Wait for server to be ready
    sleep 5
    health_check
    
    # Wait for process to complete
    wait $MCP_PID
    exit_code=$?
    
    log_info "Server process exited with code: $exit_code"
    exit $exit_code
}

# Run main function
main "$@"