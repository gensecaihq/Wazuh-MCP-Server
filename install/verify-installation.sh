#!/bin/bash
set -e

# Wazuh MCP Server - Installation Verification Script
# Cross-platform verification for Docker and Wazuh MCP Server setup

SCRIPT_VERSION="v2.0.0"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Banner
print_banner() {
    echo "=================================================================="
    echo "🔍 Wazuh MCP Server - Installation Verification"
    echo "=================================================================="
    echo "Version: ${SCRIPT_VERSION}"
    echo "Checking Docker installation and Wazuh MCP Server setup"
    echo "=================================================================="
    echo
}

# Detect operating system
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if [[ -f /etc/os-release ]]; then
            . /etc/os-release
            OS_NAME="$PRETTY_NAME"
            OS_TYPE="linux"
        else
            OS_NAME="Linux (Unknown Distribution)"
            OS_TYPE="linux"
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS_NAME="macOS $(sw_vers -productVersion)"
        OS_TYPE="macos"
    elif [[ "$OSTYPE" == "msys" || "$OSTYPE" == "cygwin" ]]; then
        OS_NAME="Windows (Git Bash/Cygwin)"
        OS_TYPE="windows"
    else
        OS_NAME="Unknown OS: $OSTYPE"
        OS_TYPE="unknown"
    fi
    
    log_info "Operating System: $OS_NAME"
}

# Check Docker installation
check_docker() {
    log_info "Checking Docker installation..."
    
    # Check if Docker command exists
    if ! command -v docker &> /dev/null; then
        log_error "Docker command not found"
        log_error "Please install Docker first using the appropriate installation script:"
        case $OS_TYPE in
            "linux")
                log_error "  - Debian/Ubuntu: curl -fsSL https://raw.githubusercontent.com/gensecaihq/Wazuh-MCP-Server/main/scripts/install-docker-debian.sh | bash"
                log_error "  - RHEL/CentOS/Fedora: curl -fsSL https://raw.githubusercontent.com/gensecaihq/Wazuh-MCP-Server/main/scripts/install-docker-redhat.sh | bash"
                ;;
            "macos")
                log_error "  - macOS: curl -fsSL https://raw.githubusercontent.com/gensecaihq/Wazuh-MCP-Server/main/scripts/install-docker-macos.sh | bash"
                ;;
            "windows")
                log_error "  - Windows: Run PowerShell as Administrator and execute:"
                log_error "    iwr -useb https://raw.githubusercontent.com/gensecaihq/Wazuh-MCP-Server/main/scripts/install-docker-windows.ps1 | iex"
                ;;
        esac
        return 1
    fi
    
    # Check Docker version
    DOCKER_VERSION=$(docker --version 2>/dev/null || echo "Unknown")
    log_success "Docker installed: $DOCKER_VERSION"
    
    # Check if Docker daemon is running
    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running"
        case $OS_TYPE in
            "linux")
                log_error "Start Docker with: sudo systemctl start docker"
                ;;
            "macos"|"windows")
                log_error "Start Docker Desktop application"
                ;;
        esac
        return 1
    fi
    
    log_success "Docker daemon is running"
    
    # Check Docker Compose
    if docker compose version &> /dev/null; then
        COMPOSE_VERSION=$(docker compose version --short 2>/dev/null || echo "Unknown")
        log_success "Docker Compose available: $COMPOSE_VERSION"
    elif command -v docker-compose &> /dev/null; then
        COMPOSE_VERSION=$(docker-compose --version 2>/dev/null || echo "Unknown")
        log_success "Docker Compose (standalone) available: $COMPOSE_VERSION"
    else
        log_error "Docker Compose not available"
        return 1
    fi
    
    return 0
}

# Test Docker functionality
test_docker() {
    log_info "Testing Docker functionality..."
    
    # Test with hello-world image
    if docker run --rm hello-world &> /dev/null; then
        log_success "Docker can run containers successfully"
    else
        log_error "Docker cannot run containers"
        log_error "Check Docker daemon status and user permissions"
        return 1
    fi
    
    return 0
}

# Check Wazuh MCP Server project
check_project() {
    log_info "Checking Wazuh MCP Server project..."
    
    # Check if we're in the project directory or find it
    PROJECT_DIRS=(
        "."
        "./Wazuh-MCP-Server"
        "$HOME/wazuh-mcp-server"
        "$HOME/Wazuh-MCP-Server"
    )
    
    PROJECT_DIR=""
    for dir in "${PROJECT_DIRS[@]}"; do
        if [[ -f "$dir/wazuh-mcp-server" && -f "$dir/compose.yml" ]]; then
            PROJECT_DIR="$dir"
            break
        fi
    done
    
    if [[ -z "$PROJECT_DIR" ]]; then
        log_error "Wazuh MCP Server project not found"
        log_error "Clone the repository with:"
        log_error "  git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git"
        return 1
    fi
    
    log_success "Project found at: $(realpath "$PROJECT_DIR")"
    cd "$PROJECT_DIR"
    
    # Check essential files
    REQUIRED_FILES=(
        "wazuh-mcp-server"
        "compose.yml"
        "Dockerfile"
        "requirements.txt"
        "src/wazuh_mcp_server/server.py"
    )
    
    for file in "${REQUIRED_FILES[@]}"; do
        if [[ -f "$file" ]]; then
            log_success "✓ $file"
        else
            log_error "✗ $file (missing)"
            return 1
        fi
    done
    
    return 0
}

# Check configuration
check_configuration() {
    log_info "Checking configuration..."
    
    # Check for .env file
    if [[ -f ".env" ]]; then
        log_success "Configuration file (.env) found"
        
        # Check required variables
        REQUIRED_VARS=("WAZUH_HOST" "WAZUH_USER" "WAZUH_PASS")
        
        for var in "${REQUIRED_VARS[@]}"; do
            if grep -q "^${var}=" .env; then
                log_success "✓ $var configured"
            else
                log_warning "✗ $var not configured"
            fi
        done
    else
        log_warning "No .env file found"
        log_info "Create configuration with: python3 configure.py"
        log_info "Or create .env file manually with required Wazuh settings"
    fi
    
    # Check compose.yml
    if [[ -f "compose.yml" ]]; then
        log_success "Docker Compose configuration found"
    else
        log_error "compose.yml not found"
        return 1
    fi
    
    return 0
}

# Test build capability
test_build() {
    log_info "Testing Docker build capability..."
    
    if docker compose build --quiet &> /dev/null; then
        log_success "Docker image builds successfully"
    else
        log_error "Docker build failed"
        log_error "Check Dockerfile and dependencies"
        return 1
    fi
    
    return 0
}

# Check if container is running
check_running_container() {
    log_info "Checking for running Wazuh MCP Server container..."
    
    if docker compose ps --quiet wazuh-mcp-server | grep -q .; then
        CONTAINER_STATUS=$(docker compose ps wazuh-mcp-server --format "table {{.Status}}" | tail -n +2)
        if echo "$CONTAINER_STATUS" | grep -q "Up"; then
            log_success "Wazuh MCP Server container is running"
            
            # Get container logs (last 10 lines)
            log_info "Recent container logs:"
            docker compose logs --tail=10 wazuh-mcp-server 2>/dev/null | sed 's/^/  /'
        else
            log_warning "Wazuh MCP Server container exists but is not running"
            log_info "Status: $CONTAINER_STATUS"
        fi
    else
        log_info "No Wazuh MCP Server container found (this is normal for fresh installations)"
    fi
}

# Test functionality (if running)
test_functionality() {
    if [[ -f "test-functionality.py" ]]; then
        log_info "Running functionality test..."
        
        if python3 test-functionality.py --quick &> /dev/null; then
            log_success "Functionality test passed"
        else
            log_warning "Functionality test failed (container may not be running or configured)"
        fi
    fi
}

# Check system resources
check_resources() {
    log_info "Checking system resources..."
    
    case $OS_TYPE in
        "linux")
            # Memory check
            MEMORY_GB=$(free -g | awk '/^Mem:/{print $2}')
            if [[ $MEMORY_GB -ge 2 ]]; then
                log_success "Memory: ${MEMORY_GB}GB (adequate)"
            else
                log_warning "Memory: ${MEMORY_GB}GB (low, minimum 2GB recommended)"
            fi
            
            # Disk space check
            DISK_GB=$(df / | awk 'NR==2 {print int($4/1024/1024)}')
            if [[ $DISK_GB -ge 5 ]]; then
                log_success "Disk space: ${DISK_GB}GB available (adequate)"
            else
                log_warning "Disk space: ${DISK_GB}GB available (low, minimum 5GB recommended)"
            fi
            ;;
        "macos")
            # Memory check
            MEMORY_GB=$(( $(sysctl -n hw.memsize) / 1024 / 1024 / 1024 ))
            if [[ $MEMORY_GB -ge 4 ]]; then
                log_success "Memory: ${MEMORY_GB}GB (adequate)"
            else
                log_warning "Memory: ${MEMORY_GB}GB (low, minimum 4GB recommended for Docker Desktop)"
            fi
            
            # Disk space check
            DISK_GB=$(df -g / | awk 'NR==2 {print $4}')
            if [[ $DISK_GB -ge 10 ]]; then
                log_success "Disk space: ${DISK_GB}GB available (adequate)"
            else
                log_warning "Disk space: ${DISK_GB}GB available (low, minimum 10GB recommended)"
            fi
            ;;
    esac
}

# Generate installation report
generate_report() {
    log_info "Generating installation report..."
    
    REPORT_FILE="installation-verification-report.txt"
    
    {
        echo "Wazuh MCP Server - Installation Verification Report"
        echo "Generated: $(date)"
        echo "=================================================="
        echo ""
        echo "System Information:"
        echo "- OS: $OS_NAME"
        echo "- Docker: $DOCKER_VERSION"
        echo "- Docker Compose: $COMPOSE_VERSION"
        echo ""
        echo "Project Status:"
        echo "- Location: $(pwd)"
        echo "- Configuration: $(test -f .env && echo "Present" || echo "Missing")"
        echo "- Container: $(docker compose ps --quiet wazuh-mcp-server | grep -q . && echo "Exists" || echo "Not created")"
        echo ""
        echo "System Resources:"
        case $OS_TYPE in
            "linux")
                echo "- Memory: $(free -g | awk '/^Mem:/{print $2}')GB"
                echo "- Disk: $(df / | awk 'NR==2 {print int($4/1024/1024)}')GB available"
                ;;
            "macos")
                echo "- Memory: $(( $(sysctl -n hw.memsize) / 1024 / 1024 / 1024 ))GB"
                echo "- Disk: $(df -g / | awk 'NR==2 {print $4}')GB available"
                ;;
        esac
        echo ""
        echo "Next Steps:"
        if [[ ! -f .env ]]; then
            echo "1. Create configuration: python3 configure.py"
        fi
        echo "2. Deploy server: docker compose up -d"
        echo "3. Test functionality: python3 test-functionality.py"
        echo "4. Setup Claude Desktop: See README.md for MCP client integration"
    } > "$REPORT_FILE"
    
    log_success "Report saved to: $REPORT_FILE"
}

# Main execution
main() {
    print_banner
    
    # Run checks
    detect_os
    
    local exit_code=0
    
    if ! check_docker; then
        exit_code=1
    fi
    
    if ! test_docker; then
        exit_code=1
    fi
    
    if ! check_project; then
        exit_code=1
    fi
    
    check_configuration
    check_resources
    check_running_container
    
    # Try to build if everything else is OK
    if [[ $exit_code -eq 0 ]]; then
        test_build || exit_code=1
        test_functionality
    fi
    
    generate_report
    
    echo
    echo "=================================================================="
    if [[ $exit_code -eq 0 ]]; then
        log_success "✅ Installation verification completed successfully!"
        echo "Your Wazuh MCP Server is ready for deployment."
        echo ""
        echo "🚀 Quick start:"
        echo "1. Configure: python3 configure.py"
        echo "2. Deploy: docker compose up -d"
        echo "3. Integrate with Claude Desktop (see README.md)"
    else
        log_error "❌ Installation verification found issues."
        echo "Please address the errors above and run this script again."
        echo ""
        echo "📖 For help, see:"
        echo "- README.md"
        echo "- PRODUCTION_DEPLOYMENT.md"
        echo "- GitHub Issues: https://github.com/gensecaihq/Wazuh-MCP-Server/issues"
    fi
    echo "=================================================================="
    
    exit $exit_code
}

# Run main function
main "$@"