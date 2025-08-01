#!/bin/bash
# =============================================================================
# Fedora/RHEL/CentOS Installation Script for Wazuh MCP Server
# Supports: Fedora, RHEL, CentOS, Rocky Linux, AlmaLinux
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
    echo -e "   ${BOLD}WAZUH MCP SERVER - FEDORA/RHEL/CENTOS SETUP${NC}"
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

# Detect distribution
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        VERSION=$VERSION_ID
        DISTRO_NAME=$PRETTY_NAME
        MAJOR_VERSION=${VERSION_ID%%.*}
    else
        print_error "Cannot detect distribution"
        exit 1
    fi
    
    print_info "Detected: $DISTRO_NAME"
    
    case $DISTRO in
        fedora)
            PKG_MGR="dnf"
            print_success "Fedora detected"
            ;;
        rhel|centos|rocky|almalinux)
            # Determine package manager
            if command -v dnf >/dev/null 2>&1; then
                PKG_MGR="dnf"
            elif command -v yum >/dev/null 2>&1; then
                PKG_MGR="yum"
            else
                print_error "Neither dnf nor yum found"
                exit 1
            fi
            print_success "RHEL-compatible distribution detected (using $PKG_MGR)"
            ;;
        *)
            print_warning "Unsupported distribution: $DISTRO"
            print_info "This script is designed for Fedora/RHEL-based distributions"
            read -p "Continue anyway? (y/N): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                exit 1
            fi
            # Default to dnf if available, otherwise yum
            if command -v dnf >/dev/null 2>&1; then
                PKG_MGR="dnf"
            elif command -v yum >/dev/null 2>&1; then
                PKG_MGR="yum"
            else
                print_error "No supported package manager found"
                exit 1
            fi
            ;;
    esac
    
    print_info "Using package manager: $PKG_MGR"
}

# Check if running as root
check_root() {
    if [ "$EUID" -eq 0 ]; then
        print_warning "Running as root - this is not recommended"
        print_info "Consider running as a regular user with sudo access"
        read -p "Continue as root? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

# Enable additional repositories
enable_repos() {
    print_step "Enabling additional repositories"
    
    case $DISTRO in
        fedora)
            # Enable RPM Fusion for additional packages (optional)
            if [ "$EUID" -eq 0 ]; then
                $PKG_MGR install -y https://download1.rpmfusion.org/free/fedora/rpmfusion-free-release-$(rpm -E %fedora).noarch.rpm || print_warning "RPM Fusion installation failed"
            else
                sudo $PKG_MGR install -y https://download1.rpmfusion.org/free/fedora/rpmfusion-free-release-$(rpm -E %fedora).noarch.rpm || print_warning "RPM Fusion installation failed"
            fi
            ;;
        rhel|centos)
            # Enable EPEL repository
            if [ "$MAJOR_VERSION" -ge 8 ]; then
                if [ "$EUID" -eq 0 ]; then
                    $PKG_MGR install -y epel-release || print_warning "EPEL installation failed"
                else
                    sudo $PKG_MGR install -y epel-release || print_warning "EPEL installation failed"
                fi
            elif [ "$MAJOR_VERSION" -eq 7 ]; then
                if [ "$EUID" -eq 0 ]; then
                    yum install -y epel-release || print_warning "EPEL installation failed"
                else
                    sudo yum install -y epel-release || print_warning "EPEL installation failed"
                fi
            fi
            ;;
    esac
    
    print_success "Repository setup completed"
}

# Update packages
update_packages() {
    print_step "Updating package lists"
    
    if [ "$EUID" -eq 0 ]; then
        $PKG_MGR update -y
    else
        sudo $PKG_MGR update -y
    fi
    print_success "Package lists updated"
}

# Install system dependencies
install_system_deps() {
    print_step "Installing system dependencies"
    
    local packages=(
        "python3"
        "python3-pip"
        "python3-devel"
        "gcc"
        "gcc-c++"
        "make"
        "git"
        "curl"
        "ca-certificates"
        "openssl-devel"
        "libffi-devel"
    )
    
    # Add distribution-specific packages
    case $DISTRO in
        fedora)
            packages+=("python3-virtualenv")
            # Try to install python3-pydantic if available
            if $PKG_MGR list python3-pydantic >/dev/null 2>&1; then
                packages+=("python3-pydantic")
            fi
            ;;
        rhel|centos)
            if [ "$MAJOR_VERSION" -ge 8 ]; then
                packages+=("python3-virtualenv")
                packages+=("platform-python-devel")
            else
                # CentOS 7 needs different packages
                packages+=("python36-devel")
            fi
            ;;
    esac
    
    print_info "Installing packages: ${packages[*]}"
    
    if [ "$EUID" -eq 0 ]; then
        $PKG_MGR install -y "${packages[@]}"
    else
        sudo $PKG_MGR install -y "${packages[@]}"
    fi
    
    print_success "System dependencies installed"
}

# Check Python version
check_python() {
    print_step "Checking Python version"
    
    # Try different Python executables
    local python_cmd=""
    for cmd in python3 python3.9 python3.10 python3.11 python3.12; do
        if command -v $cmd >/dev/null 2>&1; then
            local version=$($cmd -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
            if python3 -c "import sys; exit(0 if sys.version_info >= (3, 9) else 1)" 2>/dev/null; then
                python_cmd=$cmd
                break
            fi
        fi
    done
    
    if [ -z "$python_cmd" ]; then
        print_error "Python 3.9+ not found"
        print_info "Available Python versions:"
        for cmd in python3 python3.9 python3.10 python3.11 python3.12; do
            if command -v $cmd >/dev/null 2>&1; then
                local version=$($cmd --version 2>&1)
                print_info "  $cmd: $version"
            fi
        done
        exit 1
    fi
    
    local python_version=$($python_cmd -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    print_success "Python version compatible: $python_version (using $python_cmd)"
    
    # Create symlink if needed
    if [ "$python_cmd" != "python3" ]; then
        export PYTHON_CMD=$python_cmd
    else
        export PYTHON_CMD=python3
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
        
        # Try different methods to create virtual environment
        if command -v virtualenv >/dev/null 2>&1; then
            virtualenv -p $PYTHON_CMD venv
        elif $PYTHON_CMD -m venv --help >/dev/null 2>&1; then
            $PYTHON_CMD -m venv venv
        else
            print_error "Cannot create virtual environment"
            print_info "Please install python3-virtualenv or python3-venv"
            exit 1
        fi
        
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
    pip install -r requirements.txt
    
    if [ $? -eq 0 ]; then
        print_success "Dependencies installed successfully"
    else
        print_error "Failed to install dependencies"
        print_info "This might be due to missing system packages or compilation issues"
        print_info "Try installing development packages: sudo $PKG_MGR groupinstall 'Development Tools'"
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
# WAZUH MCP SERVER - CONFIGURATION
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

# Security Settings (Fedora/RHEL optimized)
VERIFY_SSL=false
WAZUH_ALLOW_SELF_SIGNED=true

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

# Show completion message
show_completion() {
    local project_path=$(pwd)
    
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
    echo "   • Add configuration from documentation"
    echo "   • Config location: ~/.config/Claude/claude_desktop_config.json"
    echo
    
    echo -e "${CYAN}4. Fedora/RHEL Specific Notes:${NC}"
    echo "   • SELinux may affect file access - check with: getenforce"
    echo "   • Firewall rules may need adjustment for Wazuh connectivity"
    echo "   • Consider using system Python packages when available"
    echo -e "   • Check system logs: ${YELLOW}journalctl -f${NC}"
    echo
    
    echo -e "${CYAN}5. Security Recommendations:${NC}"
    echo "   • Use dedicated Wazuh service accounts"
    echo "   • Enable SSL verification in production"
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
        "Fedora/RHEL optimized compatibility layer"
    )
    
    for capability in "${capabilities[@]}"; do
        echo "   • $capability"
    done
    echo
    
    echo -e "${BOLD}🔧 SYSTEM CONFIGURATION:${NC}"
    echo "   • Distribution: $DISTRO_NAME"
    echo "   • Package Manager: $PKG_MGR"
    echo "   • Python: $($PYTHON_CMD --version 2>&1)"
    echo
    
    echo -e "${BOLD}📞 SUPPORT:${NC}"
    echo "   • Documentation: ./docs/"
    echo "   • Logs: ./logs/"
    echo "   • Issues: https://github.com/gensecaihq/Wazuh-MCP-Server/issues"
    echo "   • Fedora/RHEL troubleshooting: ./docs/fedora-rhel-setup.md"
    echo
    echo -e "${GREEN}======================================================================${NC}"
}

# Main installation function
main() {
    print_header
    
    # Pre-flight checks
    detect_distro
    check_root
    
    # Installation steps
    enable_repos
    update_packages
    install_system_deps
    check_python
    create_venv
    upgrade_pip
    install_python_deps
    install_package
    setup_config
    test_installation
    
    # Show completion
    show_completion
}

# Error handling
trap 'print_error "Installation failed at line $LINENO. Check the error messages above."' ERR

# Run main function
main "$@"