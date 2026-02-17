#!/bin/bash
# Production deployment script for Wazuh MCP Remote Server v4.0
# MCP-compliant remote server with Docker Compose v3.9
# OS-agnostic deployment with security hardening and monitoring
# Branch: mcp-remote

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

print_header() {
    echo -e "${CYAN}================================================================${NC}"
    echo -e "${CYAN}   WAZUH MCP REMOTE SERVER - PRODUCTION DEPLOYMENT${NC}"
    echo -e "${CYAN}   Branch: mcp-remote | MCP-Compliant Remote Server${NC}"
    echo -e "${CYAN}================================================================${NC}"
    echo
}

print_step() {
    echo -e "${BLUE}▶ $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

check_prerequisites() {
    print_step "Checking prerequisites..."
    
    # Check Docker
    if ! command -v docker &> /dev/null; then
        print_error "Docker is not installed"
        exit 1
    fi
    
    # Check Docker Compose v2
    if ! docker compose version &> /dev/null; then
        print_error "Docker Compose v2 is not available. Install latest Docker with Compose v2 integrated."
        exit 1
    fi
    
    # Check Docker daemon
    if ! docker info &> /dev/null; then
        print_error "Docker daemon is not running"
        exit 1
    fi
    
    print_success "Prerequisites check passed"
}

setup_environment() {
    print_step "Setting up environment configuration..."

    if [[ ! -f .env ]]; then
        if [[ -f .env.example ]]; then
            cp .env.example .env
            print_success "Copied .env.example to .env"
        else
            print_error ".env file not found and no .env.example template available"
            exit 1
        fi
    fi
    
    # Validate required environment variables
    required_vars=("WAZUH_HOST" "WAZUH_USER" "WAZUH_PASS")
    missing_vars=()
    
    for var in "${required_vars[@]}"; do
        if ! grep -q "^${var}=" .env || grep -q "^${var}=your-" .env; then
            missing_vars+=("$var")
        fi
    done
    
    if [[ ${#missing_vars[@]} -gt 0 ]]; then
        print_error "Please configure the following variables in .env:"
        for var in "${missing_vars[@]}"; do
            echo "  - $var"
        done
        exit 1
    fi
    
    print_success "Environment configuration validated"
}

generate_api_key() {
    print_step "Generating API key for client authentication..."
    
    # Generate a secure API key
    API_KEY="wazuh_$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-32)"
    
    echo
    print_success "Generated API key: ${API_KEY}"
    echo -e "${YELLOW}⚠️  Save this API key securely - it won't be shown again${NC}"
    echo -e "${CYAN}Use this key to authenticate with the MCP server${NC}"
    echo
    
    # Save to a secure file
    echo "API_KEY=${API_KEY}" > .api_key
    chmod 600 .api_key
    
    print_success "API key saved to .api_key (secure permissions)"
}

build_and_deploy() {
    print_step "Building and deploying MCP server..."
    
    # Set build metadata
    export BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ')
    export VERSION=${VERSION:-4.0.6}
    export PYTHON_VERSION=${PYTHON_VERSION:-3.13}
    
    # Build with Docker Compose v2 latest features
    print_step "Building container image..."
    docker compose build --pull --parallel --progress=auto
    
    # Deploy with health check wait
    print_step "Starting MCP server with health checks..."
    docker compose up -d --wait --wait-timeout 120
    
    print_success "MCP server deployed successfully"
}

wait_for_services() {
    print_step "Waiting for services to be ready..."
    
    local max_attempts=30
    local attempt=1
    
    while [[ $attempt -le $max_attempts ]]; do
        if curl -f -s http://localhost:3000/health > /dev/null 2>&1; then
            break
        fi
        
        echo -n "."
        sleep 2
        ((attempt++))
    done
    
    echo
    
    if [[ $attempt -gt $max_attempts ]]; then
        print_error "Services failed to start within timeout"
        docker compose logs --tail=50
        exit 1
    fi
    
    print_success "Services are ready"
}

run_health_checks() {
    print_step "Running health checks..."
    
    # Check main service
    if curl -f -s http://localhost:3000/health | grep -q '"status":"healthy"'; then
        print_success "MCP server is healthy"
    else
        print_error "MCP server health check failed"
        return 1
    fi
    
    
    return 0
}

show_deployment_info() {
    print_step "Deployment complete! Here's your service information:"
    
    echo
    echo -e "${CYAN}🔗 Service URLs:${NC}"
    echo "  • SSE Server: http://localhost:3000"
    echo "  • Health Check: http://localhost:3000/health"
    echo
    
    echo -e "${CYAN}🔑 Authentication:${NC}"
    if [[ -f .api_key ]]; then
        echo "  • API Key: $(cat .api_key | cut -d= -f2)"
    fi
    echo "  • Get Token: curl -X POST http://localhost:3000/auth/token -d '{\"api_key\":\"YOUR_KEY\"}'"
    echo
    
    echo -e "${CYAN}📊 Monitoring:${NC}"
    echo "  • Container Status: docker compose ps"
    echo "  • Logs: docker compose logs -f"
    echo "  • Metrics: http://localhost:3000/metrics"
    echo
    
    echo -e "${CYAN}🔧 Management:${NC}"
    echo "  • Stop: docker compose down"
    echo "  • Restart: docker compose restart"
    echo "  • Update: ./deploy.sh"
    echo
}

cleanup_on_error() {
    print_error "Deployment failed, cleaning up..."
    docker compose down --remove-orphans || true
}

main() {
    print_header
    
    # Set up error handling
    trap cleanup_on_error ERR
    
    # Run deployment steps
    check_prerequisites
    setup_environment
    generate_api_key
    build_and_deploy
    wait_for_services
    
    if run_health_checks; then
        print_success "All health checks passed"
        show_deployment_info
    else
        print_error "Some health checks failed, check logs for details"
        docker compose logs --tail=20
        exit 1
    fi
    
    print_success "Deployment completed successfully!"
}

# Handle script arguments
case "${1:-deploy}" in
    "deploy")
        main
        ;;
    "stop")
        print_step "Stopping services..."
        docker compose down
        print_success "Services stopped"
        ;;
    "restart")
        print_step "Restarting services..."
        docker compose restart
        print_success "Services restarted"
        ;;
    "logs")
        docker compose logs -f
        ;;
    "status")
        echo -e "${CYAN}Service Status:${NC}"
        docker compose ps --format table
        echo -e "\n${CYAN}Container Health:${NC}"
        docker inspect wazuh-mcp-server --format='Health: {{.State.Health.Status}}' 2>/dev/null || echo "Health check not available"
        echo -e "\n${CYAN}Resource Usage:${NC}"
        docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}" wazuh-mcp-server
        ;;
    "cleanup")
        print_step "Cleaning up resources..."
        docker compose down --volumes --remove-orphans --timeout 30
        docker system prune -f --volumes
        print_success "Cleanup completed"
        ;;
    "build")
        print_step "Building container image..."
        export BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ')
        docker compose build --pull --parallel --progress=auto
        print_success "Build completed"
        ;;
    *)
        echo "Usage: $0 {deploy|stop|restart|logs|status|cleanup|build}"
        echo "Commands:"
        echo "  deploy  - Deploy the MCP server (default)"
        echo "  stop    - Stop all services"
        echo "  restart - Restart the MCP server"
        echo "  logs    - Follow service logs"
        echo "  status  - Show service status and resource usage"
        echo "  cleanup - Stop services and clean up resources"
        echo "  build   - Build container image only"
        exit 1
        ;;
esac