#!/bin/bash
# =============================================================================
# macOS Installation Script for Wazuh MCP Server
# Supports: macOS 10.15+ (Catalina and later)
# =============================================================================

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Helper functions
print_header() {
    echo -e "${CYAN}======================================================================${NC}"
    echo -e "   ${BOLD}WAZUH MCP SERVER - macOS SETUP${NC}"
    echo -e "   ${BLUE}Secure Integration for Claude Desktop & Wazuh SIEM${NC}"
    echo -e "${CYAN}======================================================================${NC}"
    echo
}

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[⚠]${NC} $1"
}

print_step() {
    echo -e "\n${BOLD}▶▶▶ $1${NC}"
}

# Detect macOS version
detect_macos() {
    print_step "Detecting macOS version"
    
    local macos_version=$(sw_vers -productVersion)
    local macos_name=$(sw_vers -productName)
    local macos_build=$(sw_vers -buildVersion)
    
    print_info "$macos_name $macos_version (Build: $macos_build)"
    
    # Check if macOS version is supported (10.15+)
    local major_version=$(echo $macos_version | cut -d. -f1)
    local minor_version=$(echo $macos_version | cut -d. -f2)
    
    if [ "$major_version" -gt 10 ] || ([ "$major_version" -eq 10 ] && [ "$minor_version" -ge 15 ]); then
        print_success "macOS version supported"
    else
        print_warning "macOS $macos_version may not be fully supported"
        print_info "Recommended: macOS 10.15 (Catalina) or later"
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
    
    # Check architecture
    local arch=$(uname -m)
    print_info "Architecture: $arch"
    
    if [ "$arch" = "arm64" ]; then
        print_info "Apple Silicon (M1/M2) detected"
        ARCH_TYPE="apple_silicon"
    elif [ "$arch" = "x86_64" ]; then
        print_info "Intel Mac detected"
        ARCH_TYPE="intel"
    else
        print_warning "Unsupported architecture: $arch"
        ARCH_TYPE="unknown"
    fi
}

# Check for Xcode Command Line Tools
check_xcode_tools() {
    print_step "Checking Xcode Command Line Tools"
    
    if xcode-select -p >/dev/null 2>&1; then
        print_success "Xcode Command Line Tools are installed"
    else
        print_info "Installing Xcode Command Line Tools..."
        print_warning "This may take several minutes and require your password"
        
        # Trigger installation
        xcode-select --install
        
        # Wait for installation to complete
        print_info "Waiting for Xcode Command Line Tools installation..."
        until xcode-select -p >/dev/null 2>&1; do
            sleep 5
        done
        
        print_success "Xcode Command Line Tools installed"
    fi
}

# Check and install Homebrew
check_homebrew() {
    print_step "Checking Homebrew"
    
    if command -v brew >/dev/null 2>&1; then
        print_success "Homebrew is already installed"
        
        # Update Homebrew
        print_info "Updating Homebrew..."
        brew update || print_warning "Homebrew update failed"
        
    else
        print_info "Installing Homebrew..."
        print_warning "This may take several minutes and require your password"
        
        # Install Homebrew
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        
        # Add Homebrew to PATH for Apple Silicon
        if [ "$ARCH_TYPE" = "apple_silicon" ]; then
            echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> ~/.zprofile
            eval "$(/opt/homebrew/bin/brew shellenv)"
        fi
        
        print_success "Homebrew installed"
    fi
    
    # Verify Homebrew is working
    if brew --version >/dev/null 2>&1; then
        local brew_version=$(brew --version | head -n1)
        print_success "Homebrew is working: $brew_version"
    else
        print_error "Homebrew installation failed or is not in PATH"
        print_info "Please restart your terminal and try again"
        exit 1
    fi
}

# Install system dependencies
install_system_deps() {
    print_step "Installing system dependencies"
    
    local packages=(
        "python@3.11"
        "git"
        "curl"
        "openssl"
        "libffi"
        "readline"
        "sqlite3"
        "xz"
        "zlib"
    )
    
    print_info "Installing packages with Homebrew..."
    
    for package in "${packages[@]}"; do
        if brew list "$package" >/dev/null 2>&1; then
            print_info "$package is already installed"
        else
            print_info "Installing $package..."
            brew install "$package" || print_warning "Failed to install $package"
        fi
    done
    
    print_success "System dependencies installation completed"
}

# Check Python version and setup
check_python() {
    print_step "Checking Python installation"
    
    # Find the best Python 3 version
    local python_cmd=""
    local python_version=""
    
    # Check Homebrew Python first
    for py_ver in python3.12 python3.11 python3.10 python3.9; do
        if command -v "$py_ver" >/dev/null 2>&1; then
            local version=$($py_ver -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
            if python3 -c "import sys; exit(0 if sys.version_info >= (3, 9) else 1)" 2>/dev/null; then
                python_cmd=$py_ver
                python_version=$version
                break
            fi
        fi
    done
    
    # Fallback to system python3
    if [ -z "$python_cmd" ] && command -v python3 >/dev/null 2>&1; then
        if python3 -c "import sys; exit(0 if sys.version_info >= (3, 9) else 1)" 2>/dev/null; then
            python_cmd=python3
            python_version=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
        fi
    fi
    
    if [ -z "$python_cmd" ]; then
        print_error "Python 3.9+ not found"
        print_info "Installing Python 3.11 via Homebrew..."
        brew install python@3.11
        python_cmd=python3.11
        python_version="3.11"
    fi
    
    export PYTHON_CMD=$python_cmd
    print_success "Python $python_version is available (using $python_cmd)"
    
    # Check pip
    if $python_cmd -m pip --version >/dev/null 2>&1; then
        print_success "pip is available"
    else
        print_info "Installing pip..."
        $python_cmd -m ensurepip --upgrade
    fi
}

# Create virtual environment
create_venv() {
    print_step "Setting up virtual environment"
    
    # Check if already in virtual environment
    if [ -n "$VIRTUAL_ENV" ]; then
        print_success "Already running in virtual environment"
        return 0
    fi
    
    if [ -d "venv" ]; then
        print_info "Virtual environment already exists"
    else
        print_info "Creating virtual environment..."
        $PYTHON_CMD -m venv venv
        print_success "Virtual environment created"
    fi
    
    # Activate virtual environment
    print_info "Activating virtual environment..."
    source venv/bin/activate
    
    # Verify activation
    if [ -n "$VIRTUAL_ENV" ]; then
        print_success "Virtual environment activated: $VIRTUAL_ENV"
    else
        print_error "Failed to activate virtual environment"
        exit 1
    fi
    
    # Set environment variables for compilation (macOS specific)
    if [ "$ARCH_TYPE" = "apple_silicon" ]; then
        export LDFLAGS="-L/opt/homebrew/lib"
        export CPPFLAGS="-I/opt/homebrew/include"
        export PKG_CONFIG_PATH="/opt/homebrew/lib/pkgconfig"
    else
        export LDFLAGS="-L/usr/local/lib"
        export CPPFLAGS="-I/usr/local/include"
        export PKG_CONFIG_PATH="/usr/local/lib/pkgconfig"
    fi
}

# Upgrade pip
upgrade_pip() {
    print_step "Upgrading pip"
    
    python -m pip install --upgrade pip setuptools wheel
    if [ $? -eq 0 ]; then
        print_success "Pip upgraded successfully"
    else
        print_warning "Pip upgrade failed, continuing with existing version"
    fi
}

# Install Python dependencies
install_python_deps() {
    print_step "Installing Python dependencies"
    
    if [ ! -f "requirements.txt" ]; then
        print_error "requirements.txt not found"
        exit 1
    fi
    
    print_info "Installing production dependencies..."
    
    # Set compilation flags for macOS
    export MACOSX_DEPLOYMENT_TARGET=$(sw_vers -productVersion | cut -d. -f1-2)
    
    pip install -r requirements.txt
    
    if [ $? -eq 0 ]; then
        print_success "Dependencies installed successfully"
    else
        print_error "Failed to install dependencies"
        print_info "This might be due to missing system packages or compilation issues"
        print_info "Try installing missing dependencies with: brew install <package>"
        exit 1
    fi
    
    # Install development dependencies if available
    if [ -f "requirements-dev.txt" ]; then
        print_info "Installing development dependencies..."
        pip install -r requirements-dev.txt || print_warning "Development dependencies installation failed"
    fi
}

# Install the package
install_package() {
    print_step "Installing Wazuh MCP Server"
    
    pip install -e .
    if [ $? -eq 0 ]; then
        print_success "Wazuh MCP Server installed successfully"
    else
        print_error "Failed to install Wazuh MCP Server"
        exit 1
    fi
}

# Setup configuration
setup_config() {
    print_step "Setting up configuration"
    
    # Create .env file
    if [ ! -f ".env" ]; then
        if [ -f ".env.example" ]; then
            cp .env.example .env
            print_success "Created .env from .env.example"
        else
            # Create default .env
            cat > .env << 'EOF'
# =============================================================================
# WAZUH MCP SERVER - CONFIGURATION (macOS)
# =============================================================================

# Wazuh Manager Configuration
WAZUH_HOST=your-wazuh-server.com
WAZUH_PORT=55000
WAZUH_USER=your-username
WAZUH_PASS=your-password

# Wazuh Indexer Configuration
WAZUH_INDEXER_HOST=your-wazuh-server.com
WAZUH_INDEXER_PORT=9200
WAZUH_INDEXER_USER=your-username
WAZUH_INDEXER_PASS=your-password

# Security Settings (macOS optimized)
VERIFY_SSL=false
WAZUH_ALLOW_SELF_SIGNED=true

# macOS Specific Settings
MACOS_KEYCHAIN_INTEGRATION=false

# Logging
LOG_LEVEL=INFO
EOF
            print_success "Created default .env file"
        fi
        
        # Set secure permissions
        chmod 600 .env
        print_success "Set secure permissions on .env file (600)"
    else
        print_info ".env file already exists"
    fi
    
    # Create logs directory
    if [ ! -d "logs" ]; then
        mkdir -p logs
        chmod 755 logs
        print_success "Created logs directory"
    fi
}

# Test installation
test_installation() {
    print_step "Testing installation"
    
    local tests=(
        "wazuh_mcp_server.main:Main module"
        "wazuh_mcp_server.config:Configuration module"
        "wazuh_mcp_server.api.wazuh_client:API client"
        "wazuh_mcp_server.analyzers.security_analyzer:Security analyzer"
        "wazuh_mcp_server.utils.logging:Utilities"
    )
    
    for test in "${tests[@]}"; do
        local module="${test%%:*}"
        local description="${test##*:}"
        
        if python -c "import $module; print('✓ $description OK')" 2>/dev/null; then
            print_success "$description: OK"
        else
            print_error "$description: FAILED"
            return 1
        fi
    done
    
    print_success "Installation test completed successfully"
}

# Setup Claude Desktop integration
setup_claude_integration() {
    print_step "Setting up Claude Desktop integration"
    
    local claude_config_dir="$HOME/Library/Application Support/Claude"
    local claude_config_file="$claude_config_dir/claude_desktop_config.json"
    local project_path=$(pwd)
    
    # Create Claude config directory if it doesn't exist
    if [ ! -d "$claude_config_dir" ]; then
        mkdir -p "$claude_config_dir"
        print_info "Created Claude Desktop config directory"
    fi
    
    # Generate sample configuration
    local sample_config=$(cat << EOF
{
  "mcpServers": {
    "wazuh": {
      "command": "python",
      "args": ["$project_path/src/wazuh_mcp_server/main.py", "--stdio"],
      "env": {
        "LOG_LEVEL": "INFO"
      }
    }
  }
}
EOF
)
    
    # Save sample configuration
    echo "$sample_config" > "$project_path/claude_desktop_config.json"
    print_success "Created sample Claude Desktop configuration"
    
    print_info "Claude Desktop config file location: $claude_config_file"
}

# Show completion message
show_completion() {
    local project_path=$(pwd)
    local claude_config_file="$HOME/Library/Application Support/Claude/claude_desktop_config.json"
    
    echo
    print_header
    echo -e "${GREEN}   🎉 ${BOLD}SETUP COMPLETE - READY FOR DEPLOYMENT!${NC}"
    echo -e "${GREEN}======================================================================${NC}"
    echo
    
    echo -e "${BOLD}📋 NEXT STEPS:${NC}"
    echo
    
    echo -e "${CYAN}1. Configure Wazuh Connection:${NC}"
    echo "   • Edit .env file with your Wazuh server details:"
    echo -e "     ${YELLOW}nano .env${NC}"
    echo "   • Required fields: WAZUH_HOST, WAZUH_USER, WAZUH_PASS"
    echo
    
    echo -e "${CYAN}2. Test Connection:${NC}"
    echo "   • source venv/bin/activate"
    echo "   • python -m wazuh_mcp_server --stdio"
    echo
    
    echo -e "${CYAN}3. Claude Desktop Integration:${NC}"
    echo "   • Open Claude Desktop"
    echo "   • Go to Settings → Developer → Edit Config"
    echo "   • Copy contents from: claude_desktop_config.json"
    echo "   • Or edit directly: $claude_config_file"
    echo
    
    echo -e "${CYAN}4. macOS Specific Notes:${NC}"
    echo "   • Python installed via Homebrew: $PYTHON_CMD"
    echo "   • Virtual environment: $project_path/venv"
    echo "   • Architecture: $ARCH_TYPE"
    echo "   • Make sure Claude Desktop has necessary permissions"
    echo "   • Check macOS firewall settings for Wazuh connectivity"
    echo
    
    echo -e "${CYAN}5. Security Recommendations:${NC}"
    echo "   • Use dedicated Wazuh service accounts"
    echo "   • Enable SSL verification in production"
    echo "   • Consider using macOS Keychain for credential storage"
    echo "   • Monitor logs regularly"
    echo -e "   • Check permissions: ${YELLOW}ls -la .env${NC}"
    echo
    
    echo -e "${BOLD}🛡️ CAPABILITIES ENABLED:${NC}"
    local capabilities=(
        "Real-time security monitoring and alerting"
        "AI-powered threat analysis and correlation"
        "Comprehensive vulnerability management"
        "Compliance reporting (PCI DSS, GDPR, HIPAA)"
        "Agent management and configuration"
        "macOS native integration and optimization"
    )
    
    for capability in "${capabilities[@]}"; do
        echo "   • $capability"
    done
    echo
    
    echo -e "${BOLD}🔧 SYSTEM CONFIGURATION:${NC}"
    echo "   • macOS: $(sw_vers -productVersion)"
    echo "   • Architecture: $ARCH_TYPE"
    echo "   • Python: $($PYTHON_CMD --version 2>&1)"
    echo "   • Homebrew: $(brew --version | head -n1)"
    echo
    
    echo -e "${BOLD}📞 SUPPORT:${NC}"
    echo "   • Documentation: ./docs/"
    echo "   • Logs: ./logs/"
    echo "   • Issues: https://github.com/gensecaihq/Wazuh-MCP-Server/issues"
    echo "   • macOS troubleshooting: ./docs/macos-setup.md"
    echo
    echo -e "${GREEN}======================================================================${NC}"
}

# Main installation function
main() {
    print_header
    
    # Pre-flight checks
    detect_macos
    check_xcode_tools
    check_homebrew
    
    # Installation steps
    install_system_deps
    check_python
    create_venv
    upgrade_pip
    install_python_deps
    install_package
    setup_config
    test_installation
    setup_claude_integration
    
    # Show completion
    show_completion
}

# Error handling
trap 'print_error "Installation failed at line $LINENO. Check the error messages above."' ERR

# Run main function
main "$@"