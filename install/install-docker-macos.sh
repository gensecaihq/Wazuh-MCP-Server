#!/bin/bash
set -e

# Wazuh MCP Server - Docker Installation Script for macOS
# Supports: macOS 10.15+ (Catalina), macOS 11+ (Big Sur), macOS 12+ (Monterey), macOS 13+ (Ventura), macOS 14+ (Sonoma)

SCRIPT_VERSION="v2.0.0"
DOCKER_DESKTOP_VERSION="4.26.1"

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
    echo "🐳 Wazuh MCP Server - Docker Installation (macOS)"
    echo "=================================================================="
    echo "Version: ${SCRIPT_VERSION}"
    echo "Supported: macOS 10.15+ (Intel/Apple Silicon)"
    echo "=================================================================="
    echo
}

# Check macOS version and architecture
check_system() {
    log_info "Checking system compatibility..."
    
    # Check macOS version
    MACOS_VERSION=$(sw_vers -productVersion)
    MACOS_MAJOR=$(echo $MACOS_VERSION | cut -d. -f1)
    MACOS_MINOR=$(echo $MACOS_VERSION | cut -d. -f2)
    
    log_info "macOS version: $MACOS_VERSION"
    
    # Check minimum version (10.15)
    if [[ $MACOS_MAJOR -lt 11 ]] && [[ $MACOS_MAJOR -eq 10 && $MACOS_MINOR -lt 15 ]]; then
        log_error "macOS 10.15 (Catalina) or later required. Current: $MACOS_VERSION"
        exit 1
    fi
    
    # Check architecture
    ARCH=$(uname -m)
    case $ARCH in
        x86_64)
            DOCKER_ARCH="amd64"
            HOMEBREW_PREFIX="/usr/local"
            log_info "Architecture: Intel (x86_64)"
            ;;
        arm64)
            DOCKER_ARCH="arm64"
            HOMEBREW_PREFIX="/opt/homebrew"
            log_info "Architecture: Apple Silicon (arm64)"
            ;;
        *)
            log_error "Unsupported architecture: $ARCH"
            exit 1
            ;;
    esac
    
    # Check available memory
    MEMORY_GB=$(( $(sysctl -n hw.memsize) / 1024 / 1024 / 1024 ))
    if [[ $MEMORY_GB -lt 4 ]]; then
        log_warning "Low memory detected: ${MEMORY_GB}GB. Docker Desktop requires 4GB minimum."
    else
        log_success "Memory: ${MEMORY_GB}GB"
    fi
    
    # Check available disk space
    DISK_GB=$(df -g / | awk 'NR==2 {print $4}')
    if [[ $DISK_GB -lt 10 ]]; then
        log_warning "Low disk space: ${DISK_GB}GB. Docker Desktop requires 10GB minimum."
    else
        log_success "Disk space: ${DISK_GB}GB available"
    fi
}

# Check if Homebrew is installed
check_homebrew() {
    log_info "Checking Homebrew installation..."
    
    if ! command -v brew &> /dev/null; then
        log_info "Homebrew not found. Installing Homebrew..."
        install_homebrew
    else
        BREW_VERSION=$(brew --version | head -n1 | cut -d' ' -f2)
        log_success "Homebrew installed: $BREW_VERSION"
        
        # Update Homebrew
        log_info "Updating Homebrew..."
        brew update
    fi
}

# Install Homebrew
install_homebrew() {
    log_info "Installing Homebrew..."
    
    # Download and install Homebrew
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    
    # Add Homebrew to PATH for current session
    if [[ $ARCH == "arm64" ]]; then
        echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> ~/.zprofile
        eval "$(/opt/homebrew/bin/brew shellenv)"
    else
        echo 'eval "$(/usr/local/bin/brew shellenv)"' >> ~/.bash_profile
        eval "$(/usr/local/bin/brew shellenv)"
    fi
    
    log_success "Homebrew installed"
}

# Check for existing Docker installations
check_existing_docker() {
    log_info "Checking for existing Docker installations..."
    
    # Check for Docker Desktop
    if [[ -d "/Applications/Docker.app" ]]; then
        log_warning "Docker Desktop already installed at /Applications/Docker.app"
        
        # Check if it's running
        if pgrep -f "Docker Desktop" > /dev/null; then
            log_info "Docker Desktop is currently running"
            
            # Get version
            if command -v docker &> /dev/null; then
                DOCKER_VERSION=$(docker --version | cut -d' ' -f3 | cut -d',' -f1)
                log_info "Current Docker version: $DOCKER_VERSION"
            fi
            
            read -p "Do you want to continue with the existing installation? (y/N): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                log_info "Continuing with fresh installation..."
                uninstall_existing_docker
            else
                log_info "Using existing Docker installation"
                return 0
            fi
        else
            log_info "Docker Desktop installed but not running"
        fi
    fi
    
    # Check for other Docker installations
    if command -v docker &> /dev/null; then
        DOCKER_PATH=$(which docker)
        log_warning "Docker CLI found at: $DOCKER_PATH"
        
        if [[ $DOCKER_PATH != "/usr/local/bin/docker" ]] && [[ $DOCKER_PATH != "/opt/homebrew/bin/docker" ]]; then
            log_warning "Non-standard Docker installation detected"
        fi
    fi
}

# Uninstall existing Docker
uninstall_existing_docker() {
    log_info "Uninstalling existing Docker installations..."
    
    # Stop Docker Desktop if running
    if pgrep -f "Docker Desktop" > /dev/null; then
        log_info "Stopping Docker Desktop..."
        osascript -e 'quit app "Docker Desktop"' 2>/dev/null || true
        sleep 5
    fi
    
    # Remove Docker Desktop
    if [[ -d "/Applications/Docker.app" ]]; then
        log_info "Removing Docker Desktop application..."
        sudo rm -rf "/Applications/Docker.app"
    fi
    
    # Remove Docker CLI symlinks
    sudo rm -f /usr/local/bin/docker 2>/dev/null || true
    sudo rm -f /usr/local/bin/docker-compose 2>/dev/null || true
    sudo rm -f /opt/homebrew/bin/docker 2>/dev/null || true
    sudo rm -f /opt/homebrew/bin/docker-compose 2>/dev/null || true
    
    # Remove Homebrew Docker packages
    brew uninstall docker docker-compose docker-buildx 2>/dev/null || true
    
    log_success "Existing Docker installations removed"
}

# Install Docker Desktop
install_docker_desktop() {
    log_info "Installing Docker Desktop..."
    
    # Determine download URL based on architecture
    if [[ $ARCH == "arm64" ]]; then
        DOCKER_DMG_URL="https://desktop.docker.com/mac/main/arm64/Docker.dmg"
    else
        DOCKER_DMG_URL="https://desktop.docker.com/mac/main/amd64/Docker.dmg"
    fi
    
    # Create temporary directory
    TEMP_DIR=$(mktemp -d)
    cd "$TEMP_DIR"
    
    # Download Docker Desktop
    log_info "Downloading Docker Desktop..."
    curl -L -o Docker.dmg "$DOCKER_DMG_URL"
    
    # Mount DMG
    log_info "Mounting Docker Desktop installer..."
    hdiutil attach Docker.dmg -quiet
    
    # Copy Docker.app to Applications
    log_info "Installing Docker Desktop to /Applications..."
    cp -R "/Volumes/Docker/Docker.app" "/Applications/"
    
    # Unmount DMG
    hdiutil detach "/Volumes/Docker" -quiet
    
    # Clean up
    cd - > /dev/null
    rm -rf "$TEMP_DIR"
    
    log_success "Docker Desktop installed"
}

# Install Docker via Homebrew (alternative method)
install_docker_homebrew() {
    log_info "Installing Docker via Homebrew..."
    
    # Install Docker
    brew install --cask docker
    
    log_success "Docker installed via Homebrew"
}

# Configure Docker Desktop
configure_docker_desktop() {
    log_info "Configuring Docker Desktop..."
    
    # Start Docker Desktop
    log_info "Starting Docker Desktop..."
    open -a Docker
    
    # Wait for Docker to start
    log_info "Waiting for Docker to start (this may take a few minutes)..."
    
    local timeout=300  # 5 minutes
    local elapsed=0
    
    while ! docker info &> /dev/null; do
        if [[ $elapsed -ge $timeout ]]; then
            log_error "Docker failed to start within $timeout seconds"
            return 1
        fi
        
        echo -n "."
        sleep 5
        elapsed=$((elapsed + 5))
    done
    
    echo
    log_success "Docker Desktop started successfully"
    
    # Configure Docker settings
    DOCKER_CONFIG_DIR="$HOME/.docker"
    mkdir -p "$DOCKER_CONFIG_DIR"
    
    # Create daemon configuration
    cat > "$DOCKER_CONFIG_DIR/daemon.json" <<EOF
{
    "log-driver": "json-file",
    "log-opts": {
        "max-size": "100m",
        "max-file": "3"
    },
    "experimental": false,
    "features": {
        "buildkit": true
    }
}
EOF
    
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
    
    # Test Docker with hello-world
    log_info "Testing Docker installation..."
    if docker run --rm hello-world > /dev/null 2>&1; then
        log_success "Docker is working correctly"
        return 0
    else
        log_error "Docker test failed"
        return 1
    fi
}

# Install additional tools
install_tools() {
    log_info "Installing additional development tools..."
    
    # Install useful tools via Homebrew
    brew install \
        git \
        curl \
        wget \
        jq \
        python3 \
        tree 2>/dev/null || log_warning "Some tools may already be installed"
    
    log_success "Additional tools installed"
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

# Wazuh MCP Server Deployment Script for macOS
echo "🚀 Starting Wazuh MCP Server deployment..."

# Check if Docker is running
if ! docker info &> /dev/null; then
    echo "❌ Docker is not running!"
    echo "Please start Docker Desktop and try again."
    echo "You can start it from Applications or run: open -a Docker"
    exit 1
fi

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

# Generate Claude Desktop configuration helper
generate_claude_config_helper() {
    log_info "Generating Claude Desktop configuration helper..."
    
    cat > "$HOME/wazuh-mcp-server/setup-claude-desktop.sh" <<'EOF'
#!/bin/bash

# Claude Desktop Configuration Helper for macOS
echo "🤖 Setting up Claude Desktop integration..."

CLAUDE_CONFIG_DIR="$HOME/Library/Application Support/Claude"
CLAUDE_CONFIG_FILE="$CLAUDE_CONFIG_DIR/claude_desktop_config.json"

# Create config directory if it doesn't exist
mkdir -p "$CLAUDE_CONFIG_DIR"

# Check if config file exists
if [[ -f "$CLAUDE_CONFIG_FILE" ]]; then
    echo "📁 Existing Claude Desktop config found"
    cp "$CLAUDE_CONFIG_FILE" "$CLAUDE_CONFIG_FILE.backup.$(date +%Y%m%d_%H%M%S)"
    echo "✅ Backup created: $CLAUDE_CONFIG_FILE.backup.*"
fi

# Generate configuration
cat > "$CLAUDE_CONFIG_FILE" <<EOFF
{
  "mcpServers": {
    "wazuh": {
      "command": "docker",
      "args": ["exec", "-i", "wazuh-mcp-server", "./wazuh-mcp-server", "--stdio"],
      "env": {}
    }
  }
}
EOFF

echo "✅ Claude Desktop configuration created"
echo "📍 Location: $CLAUDE_CONFIG_FILE"
echo ""
echo "🔄 Please restart Claude Desktop for changes to take effect"
echo "📖 Make sure your Wazuh MCP Server container is running: docker compose up -d"
EOF
    
    chmod +x "$HOME/wazuh-mcp-server/setup-claude-desktop.sh"
    log_success "Claude Desktop helper created: $HOME/wazuh-mcp-server/setup-claude-desktop.sh"
}

# Final instructions
show_final_instructions() {
    echo
    echo "=================================================================="
    echo "🎉 Docker Installation Complete!"
    echo "=================================================================="
    echo
    echo "✅ Docker Desktop: Installed and running"
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
    echo "3. Setup Claude Desktop integration:"
    echo "   ./setup-claude-desktop.sh"
    echo
    echo "4. Or manually deploy:"
    echo "   docker compose up -d"
    echo
    echo "📖 For detailed configuration, see:"
    echo "   - README.md"
    echo "   - PRODUCTION_DEPLOYMENT.md"
    echo
    echo "🔍 Verify installation:"
    echo "   docker --version"
    echo "   docker compose version"
    echo "   docker run hello-world"
    echo
    echo "💡 macOS specific notes:"
    echo "   - Docker Desktop will start automatically on boot"
    echo "   - You can manage Docker from the menu bar icon"
    echo "   - Claude Desktop config: ~/Library/Application Support/Claude/"
    echo "=================================================================="
}

# Main installation method selection
select_installation_method() {
    echo "Choose installation method:"
    echo "1) Docker Desktop (Recommended - GUI with easy management)"
    echo "2) Homebrew (Command-line only)"
    echo
    read -p "Enter your choice (1-2): " choice
    
    case $choice in
        1)
            log_info "Selected: Docker Desktop installation"
            return 0
            ;;
        2)
            log_info "Selected: Homebrew installation"
            return 1
            ;;
        *)
            log_error "Invalid choice. Using Docker Desktop (default)"
            return 0
            ;;
    esac
}

# Error handling
cleanup_on_error() {
    log_error "Installation failed. You may need to manually clean up."
    log_info "Common cleanup steps:"
    log_info "- Remove /Applications/Docker.app if partially installed"
    log_info "- Run: brew uninstall --cask docker"
}

# Main execution
main() {
    print_banner
    
    # Set up error handling
    trap cleanup_on_error ERR
    
    # Run system checks
    check_system
    check_homebrew
    check_existing_docker
    
    # Install Docker
    if select_installation_method; then
        # Docker Desktop installation
        install_docker_desktop
        configure_docker_desktop
    else
        # Homebrew installation
        install_docker_homebrew
        log_info "Starting Docker Desktop..."
        open -a Docker
        sleep 10
    fi
    
    # Install additional tools
    install_tools
    
    # Verify installation
    if verify_docker; then
        setup_wazuh_mcp
        generate_deployment_script
        generate_claude_config_helper
        show_final_instructions
    else
        log_error "Docker verification failed"
        exit 1
    fi
}

# Run main function
main "$@"