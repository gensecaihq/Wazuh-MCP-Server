#!/bin/bash
set -e

# Wazuh MCP Server - Docker Installation Script for Debian/Ubuntu
# Supports: Debian 11+, Ubuntu 20.04+, Linux Mint, Pop!_OS, Elementary OS

SCRIPT_VERSION="v2.0.0"
DOCKER_COMPOSE_VERSION="2.24.0"

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
    echo "🐳 Wazuh MCP Server - Docker Installation (Debian/Ubuntu)"
    echo "=================================================================="
    echo "Version: ${SCRIPT_VERSION}"
    echo "Supported: Debian 11+, Ubuntu 20.04+, derivatives"
    echo "=================================================================="
    echo
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        log_error "This script should not be run as root for security reasons."
        log_info "Please run as a regular user with sudo privileges."
        exit 1
    fi
}

# Check sudo privileges
check_sudo() {
    if ! sudo -n true 2>/dev/null; then
        log_info "This script requires sudo privileges for system package installation."
        log_info "You may be prompted for your password."
        sudo -v || {
            log_error "Failed to obtain sudo privileges."
            exit 1
        }
    fi
}

# Detect OS and version
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
        OS_CODENAME=$VERSION_CODENAME
    else
        log_error "Cannot detect OS. /etc/os-release not found."
        exit 1
    fi
    
    log_info "Detected OS: $PRETTY_NAME"
    
    # Check if supported
    case $OS in
        ubuntu)
            if [[ $(echo "$OS_VERSION >= 20.04" | bc -l) -eq 0 ]]; then
                log_error "Ubuntu 20.04 or higher required. Found: $OS_VERSION"
                exit 1
            fi
            ;;
        debian)
            if [[ $(echo "$OS_VERSION >= 11" | bc -l) -eq 0 ]]; then
                log_error "Debian 11 or higher required. Found: $OS_VERSION"
                exit 1
            fi
            ;;
        linuxmint|pop|elementary)
            log_info "Detected derivative distribution. Proceeding with Ubuntu compatibility mode."
            ;;
        *)
            log_warning "Unsupported OS detected: $OS. Proceeding anyway..."
            ;;
    esac
}

# Check system requirements
check_requirements() {
    log_info "Checking system requirements..."
    
    # Check architecture
    ARCH=$(uname -m)
    case $ARCH in
        x86_64|amd64)
            DOCKER_ARCH="amd64"
            ;;
        aarch64|arm64)
            DOCKER_ARCH="arm64"
            ;;
        *)
            log_error "Unsupported architecture: $ARCH"
            exit 1
            ;;
    esac
    log_success "Architecture: $ARCH ($DOCKER_ARCH)"
    
    # Check memory
    MEMORY_GB=$(free -g | awk '/^Mem:/{print $2}')
    if [[ $MEMORY_GB -lt 2 ]]; then
        log_warning "Low memory detected: ${MEMORY_GB}GB. Minimum 2GB recommended."
    else
        log_success "Memory: ${MEMORY_GB}GB"
    fi
    
    # Check disk space
    DISK_GB=$(df / | awk 'NR==2 {print int($4/1024/1024)}')
    if [[ $DISK_GB -lt 5 ]]; then
        log_warning "Low disk space: ${DISK_GB}GB. Minimum 5GB recommended."
    else
        log_success "Disk space: ${DISK_GB}GB available"
    fi
}

# Install required packages
install_prerequisites() {
    log_info "Installing prerequisites..."
    
    # Update package index
    sudo apt-get update -qq
    
    # Install required packages
    sudo apt-get install -y \
        apt-transport-https \
        ca-certificates \
        curl \
        gnupg \
        lsb-release \
        software-properties-common \
        bc \
        jq \
        wget \
        unzip
    
    log_success "Prerequisites installed"
}

# Remove old Docker installations
remove_old_docker() {
    log_info "Removing old Docker installations..."
    
    # Remove old versions
    sudo apt-get remove -y \
        docker \
        docker-engine \
        docker.io \
        containerd \
        runc \
        docker-compose \
        docker-doc \
        docker-compose-doc \
        podman-docker \
        containerd.io \
        docker-ce \
        docker-ce-cli \
        docker-buildx-plugin \
        docker-compose-plugin 2>/dev/null || true
    
    log_success "Old Docker installations removed"
}

# Install Docker
install_docker() {
    log_info "Installing Docker..."
    
    # Add Docker's official GPG key
    sudo mkdir -p /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/$OS/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    sudo chmod a+r /etc/apt/keyrings/docker.gpg
    
    # Add Docker repository
    echo \
        "deb [arch=$DOCKER_ARCH signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/$OS \
        $(lsb_release -cs) stable" | \
        sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
    
    # Update package index
    sudo apt-get update -qq
    
    # Install Docker Engine
    sudo apt-get install -y \
        docker-ce \
        docker-ce-cli \
        containerd.io \
        docker-buildx-plugin \
        docker-compose-plugin
    
    log_success "Docker installed"
}

# Configure Docker
configure_docker() {
    log_info "Configuring Docker..."
    
    # Add user to docker group
    sudo usermod -aG docker $USER
    
    # Enable and start Docker service
    sudo systemctl enable docker
    sudo systemctl start docker
    
    # Configure Docker daemon
    sudo mkdir -p /etc/docker
    sudo tee /etc/docker/daemon.json > /dev/null <<EOF
{
    "log-driver": "json-file",
    "log-opts": {
        "max-size": "100m",
        "max-file": "3"
    },
    "storage-driver": "overlay2",
    "userland-proxy": false,
    "experimental": false,
    "features": {
        "buildkit": true
    }
}
EOF
    
    # Restart Docker
    sudo systemctl restart docker
    
    log_success "Docker configured"
}

# Verify Docker installation
verify_docker() {
    log_info "Verifying Docker installation..."
    
    # Check Docker version
    if ! command -v docker &> /dev/null; then
        log_error "Docker command not found"
        return 1
    fi
    
    DOCKER_VERSION=$(docker --version | cut -d' ' -f3 | cut -d',' -f1)
    log_success "Docker version: $DOCKER_VERSION"
    
    # Check Docker Compose
    if ! docker compose version &> /dev/null; then
        log_error "Docker Compose not available"
        return 1
    fi
    
    COMPOSE_VERSION=$(docker compose version --short)
    log_success "Docker Compose version: $COMPOSE_VERSION"
    
    # Test Docker with hello-world (as current user in new shell)
    log_info "Testing Docker installation..."
    if newgrp docker <<EONG
docker run --rm hello-world > /dev/null 2>&1
EONG
    then
        log_success "Docker is working correctly"
    else
        log_warning "Docker test failed. You may need to log out and back in."
    fi
}

# Install Docker Compose standalone (fallback)
install_docker_compose_standalone() {
    log_info "Installing Docker Compose standalone..."
    
    # Download and install Docker Compose
    sudo curl -L "https://github.com/docker/compose/releases/download/v${DOCKER_COMPOSE_VERSION}/docker-compose-$(uname -s)-$(uname -m)" \
        -o /usr/local/bin/docker-compose
    
    sudo chmod +x /usr/local/bin/docker-compose
    
    # Create symlink for compatibility
    sudo ln -sf /usr/local/bin/docker-compose /usr/bin/docker-compose
    
    log_success "Docker Compose standalone installed"
}

# Setup Wazuh MCP Server
setup_wazuh_mcp() {
    log_info "Setting up Wazuh MCP Server..."
    
    # Create project directory
    PROJECT_DIR="$HOME/wazuh-mcp-server"
    if [[ ! -d "$PROJECT_DIR" ]]; then
        mkdir -p "$PROJECT_DIR"
        cd "$PROJECT_DIR"
        
        # Download or clone the project
        if command -v git &> /dev/null; then
            log_info "Cloning Wazuh MCP Server repository..."
            git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git . || {
                log_error "Failed to clone repository"
                return 1
            }
        else
            log_info "Git not available. Please download the project manually."
            log_info "Visit: https://github.com/gensecaihq/Wazuh-MCP-Server"
            return 1
        fi
    else
        cd "$PROJECT_DIR"
        log_info "Using existing project directory: $PROJECT_DIR"
    fi
    
    # Make scripts executable
    chmod +x wazuh-mcp-server 2>/dev/null || true
    chmod +x docker/entrypoint.sh 2>/dev/null || true
    
    log_success "Wazuh MCP Server setup complete"
    log_info "Project location: $PROJECT_DIR"
}

# Generate deployment script
generate_deployment_script() {
    log_info "Generating deployment script..."
    
    cat > "$HOME/wazuh-mcp-server/deploy.sh" <<'EOF'
#!/bin/bash
set -e

# Wazuh MCP Server Deployment Script
echo "🚀 Starting Wazuh MCP Server deployment..."

# Check if .env exists
if [[ ! -f .env ]]; then
    echo "❌ .env file not found!"
    echo "Please run: python3 configure.py"
    echo "Or create .env file manually with required settings."
    exit 1
fi

# Source environment variables
set -a
source .env
set +a

# Verify required variables
if [[ -z "$WAZUH_HOST" || -z "$WAZUH_USER" || -z "$WAZUH_PASS" ]]; then
    echo "❌ Missing required environment variables in .env"
    echo "Required: WAZUH_HOST, WAZUH_USER, WAZUH_PASS"
    exit 1
fi

echo "✅ Configuration loaded"
echo "   Wazuh Host: $WAZUH_HOST"
echo "   Transport: ${MCP_TRANSPORT:-stdio}"

# Build and start services
echo "🐳 Building Docker image..."
docker compose build

echo "🚀 Starting services..."
docker compose up -d

echo "🔍 Checking service status..."
docker compose ps

echo "✅ Deployment complete!"
echo ""
echo "Next steps:"
echo "1. Check logs: docker compose logs -f wazuh-mcp-server"
echo "2. Test functionality: python3 test-functionality.py"
echo "3. Verify production readiness: python3 validate-production.py --quick"
EOF
    
    chmod +x "$HOME/wazuh-mcp-server/deploy.sh"
    log_success "Deployment script created: $HOME/wazuh-mcp-server/deploy.sh"
}

# Final instructions
show_final_instructions() {
    echo
    echo "=================================================================="
    echo "🎉 Docker Installation Complete!"
    echo "=================================================================="
    echo
    echo "✅ Docker Engine: Installed and configured"
    echo "✅ Docker Compose: Available"
    echo "✅ Wazuh MCP Server: Ready for deployment"
    echo
    echo "📁 Project location: $HOME/wazuh-mcp-server"
    echo
    echo "🔧 Next steps:"
    echo "1. Configure your Wazuh connection:"
    echo "   cd $HOME/wazuh-mcp-server"
    echo "   python3 configure.py"
    echo
    echo "2. Deploy the server:"
    echo "   ./deploy.sh"
    echo
    echo "3. Or manually:"
    echo "   docker compose up -d"
    echo
    echo "📖 For detailed configuration, see:"
    echo "   - README.md"
    echo "   - PRODUCTION_DEPLOYMENT.md"
    echo
    echo "⚠️  IMPORTANT: You need to log out and back in (or restart)"
    echo "   for Docker group membership to take effect."
    echo
    echo "🔍 Verify installation:"
    echo "   docker --version"
    echo "   docker compose version"
    echo "   docker run hello-world"
    echo "=================================================================="
}

# Error handling
cleanup_on_error() {
    log_error "Installation failed. Cleaning up..."
    # Add cleanup logic here if needed
}

# Main execution
main() {
    print_banner
    
    # Set up error handling
    trap cleanup_on_error ERR
    
    # Run installation steps
    check_root
    check_sudo
    detect_os
    check_requirements
    install_prerequisites
    remove_old_docker
    install_docker
    configure_docker
    
    # Verify installation
    if verify_docker; then
        setup_wazuh_mcp
        generate_deployment_script
        show_final_instructions
    else
        log_error "Docker verification failed"
        exit 1
    fi
}

# Run main function
main "$@"