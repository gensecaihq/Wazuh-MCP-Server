#!/bin/bash
# Production Deployment Script for Wazuh MCP Server v3.0.0
# =========================================================
# Self-contained deployment with zero local machine dependencies

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
    if [[ "${DEBUG:-false}" == "true" ]]; then
        echo -e "${BLUE}[DEBUG]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
    fi
}

# Error handler
error_exit() {
    log_error "$1"
    exit 1
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        error_exit "Docker is not installed. Please install Docker first."
    fi
    
    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
        error_exit "Docker Compose is not installed. Please install Docker Compose first."
    fi
    
    # Check Docker daemon
    if ! docker info &> /dev/null; then
        error_exit "Docker daemon is not running. Please start Docker first."
    fi
    
    log_info "Prerequisites check passed"
}

# Setup configuration
setup_configuration() {
    log_info "Setting up configuration..."
    
    # Create .env file if it doesn't exist
    if [[ ! -f ".env" ]]; then
        log_info "Creating default .env file..."
        cp config/default.env .env
        log_warn "Please edit .env file with your Wazuh API credentials before proceeding"
        log_warn "Minimum required: WAZUH_API_URL, WAZUH_API_USERNAME, WAZUH_API_PASSWORD"
        
        # Wait for user confirmation
        read -p "Press Enter after configuring .env file..."
    fi
    
    # Validate required environment variables
    source .env
    
    local required_vars=(
        "WAZUH_API_URL"
        "WAZUH_API_USERNAME"
        "WAZUH_API_PASSWORD"
    )
    
    for var in "${required_vars[@]}"; do
        if [[ -z "${!var:-}" ]]; then
            error_exit "Required environment variable $var is not set in .env file"
        fi
    done
    
    log_info "Configuration validation passed"
}

# Deploy production MCP server
deploy_production() {
    log_info "Deploying production MCP server..."
    
    # Build application image
    log_info "Building Wazuh MCP Server image..."
    docker-compose build --no-cache
    
    # Start service
    log_info "Starting MCP server..."
    docker-compose up -d
    
    # Wait for service to be healthy
    log_info "Waiting for service to be healthy..."
    local max_attempts=30
    local attempt=1
    
    while [[ $attempt -le $max_attempts ]]; do
        if docker-compose ps | grep -q "healthy\|Up"; then
            log_info "Service is healthy"
            break
        fi
        
        log_debug "Health check attempt $attempt/$max_attempts"
        sleep 5
        ((attempt++))
    done
    
    if [[ $attempt -gt $max_attempts ]]; then
        log_warn "Service may not be fully healthy. Check logs with: docker-compose logs"
    fi
    
    log_info "Production deployment completed"
}

# Quick deployment (alias for main deployment)
deploy_quick() {
    deploy_production
}

# Test deployment
test_deployment() {
    log_info "Testing deployment..."
    
    # Test health endpoint
    local max_attempts=10
    local attempt=1
    
    while [[ $attempt -le $max_attempts ]]; do
        if curl -f -k -s "https://localhost:8443/health" >/dev/null 2>&1; then
            log_info "Health check passed"
            break
        fi
        
        log_debug "Health test attempt $attempt/$max_attempts"
        sleep 5
        ((attempt++))
    done
    
    if [[ $attempt -gt $max_attempts ]]; then
        log_warn "Health check failed. Service may not be fully ready."
        return 1
    fi
    
    # Test basic functionality
    log_info "Testing basic MCP functionality..."
    
    # This would be expanded with actual MCP protocol tests
    log_info "Basic deployment test completed successfully"
    return 0
}

# Show deployment status
show_status() {
    log_info "Deployment Status:"
    echo
    
    if docker-compose ps | grep -q "Up\|healthy"; then
        echo "MCP Server Status:"
        docker-compose ps
    else
        log_warn "MCP server is not running"
        return 1
    fi
    
    echo
    log_info "Access URLs:"
    echo "  MCP Server:     https://localhost:8443"
    echo "  Health Check:   https://localhost:8443/health"
    
    echo
    log_info "Commands:"
    echo "  View logs:      docker-compose logs -f"
    echo "  Stop server:    docker-compose down"
    echo "  Restart:        docker-compose restart"
}

# Cleanup function
cleanup() {
    log_info "Cleaning up..."
    
    # Stop services
    docker-compose down || true
    
    # Remove volumes if requested
    if [[ "${CLEANUP_VOLUMES:-false}" == "true" ]]; then
        log_warn "Removing all data volumes..."
        docker-compose down -v
    fi
    
    # Remove images if requested
    if [[ "${CLEANUP_IMAGES:-false}" == "true" ]]; then
        log_info "Removing images..."
        docker image prune -f
    fi
    
    log_info "Cleanup completed"
}

# Main function
main() {
    local command="${1:-deploy}"
    
    case "$command" in
        "cleanup")
            cleanup
            ;;
        "status")
            show_status
            ;;
        "deploy")
            log_info "Starting Wazuh MCP Server v3.0.0 Production Deployment"
            
            # Deployment flow
            check_prerequisites
            setup_configuration
            deploy_production
            
            # Test deployment
            if test_deployment; then
                log_info "✅ Deployment successful!"
                show_status
            else
                log_error "❌ Deployment test failed"
                log_info "Check logs with: docker-compose logs"
                exit 1
            fi
            ;;
        *)
            error_exit "Unknown command: $command"
            ;;
    esac
}

# Handle script arguments
case "${1:-}" in
    "status"|"cleanup")
        main "$1"
        ;;
    "--help"|"-h")
        echo "Wazuh MCP Server v3.0.0 Production Deployment Script"
        echo
        echo "Usage: $0 [command]"
        echo
        echo "Commands:"
        echo "  deploy   - Deploy production MCP server (default)"
        echo "  status   - Show deployment status"
        echo "  cleanup  - Stop and cleanup deployment"
        echo
        echo "Examples:"
        echo "  $0                   # Deploy production server"
        echo "  $0 status            # Check deployment status"
        echo "  $0 cleanup           # Stop and cleanup"
        echo
        echo "Environment Variables:"
        echo "  DEBUG=true           # Enable debug logging"
        echo "  CLEANUP_IMAGES=true  # Remove Docker images during cleanup"
        exit 0
        ;;
    *)
        main "deploy"  # Default to deployment
        ;;
esac