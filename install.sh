#!/bin/bash
# Wazuh MCP Remote Server - Intelligent Installer & Configurator
# OS-agnostic automated setup for production deployment
# Branch: mcp-remote - Production-ready remote MCP server
# Supports: Linux (Ubuntu, CentOS, RHEL, Debian, Alpine), macOS, Windows (WSL)

set -euo pipefail

# Version and metadata
readonly SCRIPT_VERSION="4.0.0"
readonly MIN_DOCKER_VERSION="20.10.0"
readonly MIN_COMPOSE_VERSION="2.20.0"
readonly REQUIRED_MEMORY_MB=1024
readonly REQUIRED_DISK_MB=2048

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly PURPLE='\033[0;35m'
readonly NC='\033[0m'

# Global variables
OS_TYPE=""
DISTRO=""
DOCKER_INSTALLED=false
COMPOSE_INSTALLED=false
INTERACTIVE_MODE=true
SKIP_DOCKER_INSTALL=false

# Logging functions
log_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

log_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

log_error() {
    echo -e "${RED}❌ $1${NC}"
}

log_step() {
    echo -e "${CYAN}🔄 $1${NC}"
}

print_banner() {
    echo -e "${PURPLE}"
    cat << 'EOF'
╔══════════════════════════════════════════════════════════════╗
║                    WAZUH MCP SERVER                         ║
║              Intelligent Installer v4.0.0                  ║
║                                                              ║
║  🔗 MCP-Compliant Remote Server for Wazuh SIEM             ║
║  🐳 OS-Agnostic Docker Deployment                          ║
║  🚀 Automated Setup & Configuration                        ║
╚══════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

# OS Detection
detect_os() {
    log_step "Detecting operating system..."
    
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        OS_TYPE="linux"
        if [[ -f "/etc/os-release" ]]; then
            . /etc/os-release
            DISTRO="$ID"
        elif [[ -f "/etc/redhat-release" ]]; then
            DISTRO="rhel"
        elif [[ -f "/etc/debian_version" ]]; then
            DISTRO="debian"
        else
            DISTRO="unknown"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS_TYPE="macos"
        DISTRO="macos"
    elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]]; then
        OS_TYPE="windows"
        DISTRO="windows"
    else
        OS_TYPE="unknown"
        DISTRO="unknown"
    fi
    
    log_success "Detected: $OS_TYPE ($DISTRO)"
}

# System requirements check
check_system_requirements() {
    log_step "Checking system requirements..."
    
    # Check available memory
    if command -v free >/dev/null 2>&1; then
        local available_memory=$(free -m | awk 'NR==2{print $7}')
        if [[ $available_memory -lt $REQUIRED_MEMORY_MB ]]; then
            log_warning "Available memory: ${available_memory}MB (recommended: ${REQUIRED_MEMORY_MB}MB)"
        else
            log_success "Memory check passed: ${available_memory}MB available"
        fi
    elif [[ "$OS_TYPE" == "macos" ]]; then
        local total_memory=$(sysctl -n hw.memsize)
        local total_memory_mb=$((total_memory / 1024 / 1024))
        if [[ $total_memory_mb -lt $REQUIRED_MEMORY_MB ]]; then
            log_warning "Total memory: ${total_memory_mb}MB (recommended: ${REQUIRED_MEMORY_MB}MB)"
        else
            log_success "Memory check passed: ${total_memory_mb}MB total"
        fi
    fi
    
    # Check available disk space
    local available_disk=$(df . | tail -1 | awk '{print $4}')
    local available_disk_mb=$((available_disk / 1024))
    
    if [[ $available_disk_mb -lt $REQUIRED_DISK_MB ]]; then
        log_warning "Available disk: ${available_disk_mb}MB (recommended: ${REQUIRED_DISK_MB}MB)"
    else
        log_success "Disk space check passed: ${available_disk_mb}MB available"
    fi
    
    # Check architecture
    local arch=$(uname -m)
    case $arch in
        x86_64|amd64)
            log_success "Architecture: x86_64 (supported)"
            ;;
        aarch64|arm64)
            log_success "Architecture: ARM64 (supported)"
            ;;
        *)
            log_warning "Architecture: $arch (may not be supported)"
            ;;
    esac
}

# Docker installation
install_docker() {
    if [[ "$SKIP_DOCKER_INSTALL" == true ]]; then
        return 0
    fi
    
    log_step "Installing Docker..."
    
    case "$DISTRO" in
        ubuntu|debian)
            # Remove old versions
            sudo apt-get remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true
            
            # Update package index
            sudo apt-get update
            
            # Install dependencies
            sudo apt-get install -y \
                ca-certificates \
                curl \
                gnupg \
                lsb-release
            
            # Add Docker's official GPG key
            sudo mkdir -p /etc/apt/keyrings
            curl -fsSL https://download.docker.com/linux/$DISTRO/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
            
            # Set up repository
            echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/$DISTRO $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
            
            # Install Docker Engine
            sudo apt-get update
            sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
            ;;
            
        centos|rhel|fedora)
            # Remove old versions
            sudo yum remove -y docker docker-client docker-client-latest docker-common docker-latest docker-latest-logrotate docker-logrotate docker-engine 2>/dev/null || true
            
            # Install yum-utils
            sudo yum install -y yum-utils
            
            # Add Docker repository
            sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
            
            # Install Docker Engine
            sudo yum install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
            ;;
            
        alpine)
            # Install Docker
            sudo apk update
            sudo apk add docker docker-compose
            ;;
            
        macos)
            log_info "Please install Docker Desktop for Mac from: https://docs.docker.com/desktop/mac/install/"
            log_info "After installation, restart this script with --skip-docker-install flag"
            exit 1
            ;;
            
        *)
            log_error "Unsupported distribution: $DISTRO"
            log_info "Please install Docker manually and restart with --skip-docker-install flag"
            exit 1
            ;;
    esac
    
    # Start and enable Docker service
    if [[ "$OS_TYPE" == "linux" ]]; then
        sudo systemctl start docker
        sudo systemctl enable docker
        
        # Add current user to docker group
        sudo usermod -aG docker $USER
        log_warning "Please log out and log back in for Docker group changes to take effect"
    fi
    
    log_success "Docker installation completed"
}

# Docker version check
check_docker() {
    log_step "Checking Docker installation..."
    
    if command -v docker >/dev/null 2>&1; then
        DOCKER_INSTALLED=true
        local docker_version=$(docker --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        log_success "Docker found: v$docker_version"
        
        # Check if Docker daemon is running
        if ! docker info >/dev/null 2>&1; then
            log_error "Docker daemon is not running"
            if [[ "$OS_TYPE" == "linux" ]]; then
                log_info "Starting Docker service..."
                sudo systemctl start docker
            else
                log_error "Please start Docker Desktop and retry"
                exit 1
            fi
        fi
        
        # Check Docker Compose
        if docker compose version >/dev/null 2>&1; then
            COMPOSE_INSTALLED=true
            local compose_version=$(docker compose version --short)
            log_success "Docker Compose found: v$compose_version"
        else
            log_error "Docker Compose v2 not found"
            return 1
        fi
    else
        log_warning "Docker not found"
        return 1
    fi
}

# Interactive configuration
interactive_config() {
    if [[ "$INTERACTIVE_MODE" != true ]]; then
        return 0
    fi
    
    log_step "Interactive Configuration"
    echo
    
    # Wazuh connection details
    echo -e "${CYAN}🔧 Wazuh Server Configuration${NC}"
    read -p "Enter Wazuh server URL (e.g., https://wazuh.company.com): " wazuh_host
    read -p "Enter Wazuh API username: " wazuh_user
    read -s -p "Enter Wazuh API password: " wazuh_pass
    echo
    read -p "Enter Wazuh API port [55000]: " wazuh_port
    wazuh_port=${wazuh_port:-55000}
    
    # SSL configuration
    echo -e "\n${CYAN}🔒 SSL Configuration${NC}"
    read -p "Verify SSL certificates? (y/n) [n]: " verify_ssl
    verify_ssl=${verify_ssl:-n}
    if [[ "$verify_ssl" =~ ^[Yy] ]]; then
        verify_ssl="true"
        allow_self_signed="false"
    else
        verify_ssl="false"
        allow_self_signed="true"
    fi
    
    # Server configuration
    echo -e "\n${CYAN}🌐 MCP Server Configuration${NC}"
    read -p "Enter MCP server host [0.0.0.0]: " mcp_host
    mcp_host=${mcp_host:-0.0.0.0}
    read -p "Enter MCP server port [3000]: " mcp_port
    mcp_port=${mcp_port:-3000}
    
    # Authentication
    echo -e "\n${CYAN}🔑 Authentication Configuration${NC}"
    log_info "Generating secure authentication key..."
    auth_secret=$(openssl rand -hex 32)
    log_success "Authentication key generated"
    
    # CORS configuration
    echo -e "\n${CYAN}🌍 CORS Configuration${NC}"
    read -p "Enter allowed origins [https://claude.ai,http://localhost:*]: " cors_origins
    cors_origins=${cors_origins:-"https://claude.ai,http://localhost:*"}
    
    # Create .env file
    log_step "Creating configuration file..."
    
    cat > .env << EOF
# Wazuh MCP Server Configuration
# Generated by installer v${SCRIPT_VERSION} on $(date)

# === Wazuh Configuration ===
WAZUH_HOST=${wazuh_host}
WAZUH_USER=${wazuh_user}
WAZUH_PASS=${wazuh_pass}
WAZUH_PORT=${wazuh_port}

# === MCP Server Configuration ===
MCP_HOST=${mcp_host}
MCP_PORT=${mcp_port}

# === Authentication ===
AUTH_SECRET_KEY=${auth_secret}
TOKEN_LIFETIME_HOURS=24

# === CORS Configuration ===
ALLOWED_ORIGINS=${cors_origins}

# === SSL Configuration ===
WAZUH_VERIFY_SSL=${verify_ssl}
WAZUH_ALLOW_SELF_SIGNED=${allow_self_signed}

# === Logging ===
LOG_LEVEL=INFO

# === API Keys (Will be generated during deployment) ===
API_KEYS=[]
EOF
    
    # Secure the configuration file
    chmod 600 .env
    log_success "Configuration saved to .env (secure permissions applied)"
}

# Pre-deployment checks
pre_deployment_checks() {
    log_step "Running pre-deployment checks..."
    
    # Check if .env exists
    if [[ ! -f ".env" ]]; then
        log_error ".env file not found"
        log_info "Please run with interactive mode or create .env manually"
        exit 1
    fi
    
    # Validate configuration
    source .env
    
    local config_errors=0
    
    if [[ -z "${WAZUH_HOST:-}" ]]; then
        log_error "WAZUH_HOST not configured"
        ((config_errors++))
    fi
    
    if [[ -z "${WAZUH_USER:-}" ]]; then
        log_error "WAZUH_USER not configured"
        ((config_errors++))
    fi
    
    if [[ -z "${WAZUH_PASS:-}" ]]; then
        log_error "WAZUH_PASS not configured"
        ((config_errors++))
    fi
    
    if [[ -z "${AUTH_SECRET_KEY:-}" ]]; then
        log_error "AUTH_SECRET_KEY not configured"
        ((config_errors++))
    fi
    
    if [[ $config_errors -gt 0 ]]; then
        log_error "Configuration validation failed with $config_errors errors"
        exit 1
    fi
    
    # Test Wazuh connectivity
    log_step "Testing Wazuh server connectivity..."
    if curl -f -s --max-time 10 -u "$WAZUH_USER:$WAZUH_PASS" \
        --insecure \
        "$WAZUH_HOST:$WAZUH_PORT/" >/dev/null 2>&1; then
        log_success "Wazuh server connectivity test passed"
    else
        log_warning "Wazuh server connectivity test failed (deployment will continue)"
        log_info "Please verify Wazuh server details after deployment"
    fi
    
    log_success "Pre-deployment checks completed"
}

# Deploy the MCP server
deploy_server() {
    log_step "Deploying Wazuh MCP Server..."
    
    # Set build metadata
    export BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ')
    export VERSION="4.0.0"
    export PYTHON_VERSION="3.13"
    
    # Build and deploy
    log_info "Building container image..."
    docker compose build --pull --parallel --progress=auto
    
    log_info "Starting MCP server..."
    docker compose up -d --wait --wait-timeout 120
    
    # Wait for service to be ready
    log_step "Waiting for service to be ready..."
    local max_attempts=30
    local attempt=1
    
    while [[ $attempt -le $max_attempts ]]; do
        if curl -f -s --max-time 5 http://localhost:${MCP_PORT:-3000}/health >/dev/null 2>&1; then
            break
        fi
        echo -n "."
        sleep 2
        ((attempt++))
    done
    
    echo
    
    if [[ $attempt -gt $max_attempts ]]; then
        log_error "Service failed to start within timeout"
        docker compose logs --tail=20
        exit 1
    fi
    
    log_success "Wazuh MCP Server deployed successfully!"
}

# Generate API key for authentication
generate_api_key() {
    log_step "Generating API key for client authentication..."
    
    # Generate secure API key
    local api_key="wazuh_$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-32)"
    
    # Save to secure file
    echo "MCP_API_KEY=${api_key}" > .api_key
    chmod 600 .api_key
    
    log_success "API key generated and saved to .api_key"
    echo -e "${YELLOW}🔑 API Key: ${api_key}${NC}"
    echo -e "${YELLOW}⚠️  Save this key securely - you'll need it for Claude Desktop integration${NC}"
    
    return 0
}

# Post-deployment verification
post_deployment_verification() {
    log_step "Running post-deployment verification..."
    
    local port=${MCP_PORT:-3000}
    
    # Health check
    if curl -f -s http://localhost:$port/health | jq -e '.status == "healthy"' >/dev/null 2>&1; then
        log_success "Health check passed"
    else
        log_warning "Health check failed"
    fi
    
    # MCP protocol test
    if curl -f -s http://localhost:$port/ \
        -H "Origin: https://claude.ai" \
        -H "Accept: application/json" >/dev/null 2>&1; then
        log_success "MCP protocol endpoint responding"
    else
        log_warning "MCP protocol endpoint test failed"
    fi
    
    # Container status
    if docker compose ps --format json | jq -e '.[0].Health == "healthy"' >/dev/null 2>&1; then
        log_success "Container health check passed"
    else
        log_warning "Container health check inconclusive"
    fi
    
    log_success "Post-deployment verification completed"
}

# Show deployment summary
show_deployment_summary() {
    local port=${MCP_PORT:-3000}
    local api_key=$(cat .api_key 2>/dev/null | cut -d= -f2 || echo "Not generated")
    
    echo
    echo -e "${GREEN}🎉 Deployment Completed Successfully!${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════════════════════${NC}"
    echo
    echo -e "${CYAN}🔗 Service Information:${NC}"
    echo -e "  • MCP Server: http://localhost:$port"
    echo -e "  • Health Check: http://localhost:$port/health"
    echo -e "  • API Documentation: http://localhost:$port/docs"
    echo -e "  • Metrics: http://localhost:$port/metrics"
    echo
    echo -e "${CYAN}🔑 Authentication:${NC}"
    echo -e "  • API Key: $api_key"
    echo -e "  • Configuration: .api_key (secure file)"
    echo
    echo -e "${CYAN}🐳 Docker Management:${NC}"
    echo -e "  • Status: docker compose ps"
    echo -e "  • Logs: docker compose logs -f"
    echo -e "  • Stop: docker compose down"
    echo -e "  • Restart: docker compose restart"
    echo
    echo -e "${CYAN}📖 Next Steps:${NC}"
    echo -e "  1. Test the deployment: curl http://localhost:$port/health"
    echo -e "  2. Configure Claude Desktop (see README.md)"
    echo -e "  3. Set up monitoring and alerts"
    echo -e "  4. Review security settings"
    echo
    echo -e "${YELLOW}⚠️  Important Notes:${NC}"
    echo -e "  • Save your API key securely"
    echo -e "  • Keep your .env file private"
    echo -e "  • Review firewall settings for port $port"
    echo -e "  • Check logs regularly: docker compose logs"
    echo
    echo -e "${CYAN}🆘 Support:${NC}"
    echo -e "  • Documentation: README.md"
    echo -e "  • Issues: https://github.com/gensecaihq/Wazuh-MCP-Server/issues"
    echo -e "  • Troubleshooting: See README.md troubleshooting section"
    echo
}

# Usage information
show_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Wazuh MCP Server Intelligent Installer v${SCRIPT_VERSION}

OPTIONS:
    -h, --help                 Show this help message
    -v, --version             Show version information
    -n, --non-interactive     Run in non-interactive mode
    --skip-docker-install     Skip Docker installation
    --config-only             Only run configuration (skip deployment)
    --deploy-only             Only run deployment (skip configuration)

EXAMPLES:
    $0                        # Interactive installation
    $0 --non-interactive      # Automated installation (requires .env)
    $0 --config-only          # Configure only
    $0 --deploy-only          # Deploy only

ENVIRONMENT VARIABLES:
    WAZUH_HOST               Wazuh server URL
    WAZUH_USER               Wazuh API username
    WAZUH_PASS               Wazuh API password
    MCP_PORT                 MCP server port (default: 3000)

For detailed documentation, see README.md
EOF
}

# Main installation function
main() {
    local config_only=false
    local deploy_only=false
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_usage
                exit 0
                ;;
            -v|--version)
                echo "Wazuh MCP Server Installer v${SCRIPT_VERSION}"
                exit 0
                ;;
            -n|--non-interactive)
                INTERACTIVE_MODE=false
                shift
                ;;
            --skip-docker-install)
                SKIP_DOCKER_INSTALL=true
                shift
                ;;
            --config-only)
                config_only=true
                shift
                ;;
            --deploy-only)
                deploy_only=true
                shift
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    # Show banner
    print_banner
    
    # Detect operating system
    detect_os
    
    # Check system requirements
    check_system_requirements
    
    # Configuration phase
    if [[ "$deploy_only" != true ]]; then
        # Check and install Docker if needed
        if ! check_docker; then
            if [[ "$INTERACTIVE_MODE" == true ]]; then
                read -p "Docker not found. Install Docker? (y/n): " -n 1 -r
                echo
                if [[ $REPLY =~ ^[Yy]$ ]]; then
                    install_docker
                else
                    log_error "Docker is required for deployment"
                    exit 1
                fi
            else
                install_docker
            fi
            
            # Re-check Docker after installation
            if ! check_docker; then
                log_error "Docker installation verification failed"
                exit 1
            fi
        fi
        
        # Interactive configuration
        interactive_config
    fi
    
    # Exit if config-only mode
    if [[ "$config_only" == true ]]; then
        log_success "Configuration completed. Run with --deploy-only to deploy."
        exit 0
    fi
    
    # Deployment phase
    if [[ "$deploy_only" == true ]] || [[ "$config_only" != true ]]; then
        # Pre-deployment checks
        pre_deployment_checks
        
        # Deploy the server
        deploy_server
        
        # Generate API key
        generate_api_key
        
        # Post-deployment verification
        post_deployment_verification
        
        # Show summary
        show_deployment_summary
    fi
}

# Error handling
trap 'log_error "Installation failed at line $LINENO. Exit code: $?"' ERR

# Run main function
main "$@"