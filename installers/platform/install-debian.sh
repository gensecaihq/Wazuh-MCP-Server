#!/bin/bash
# Wazuh MCP Server v2.1.0 - Debian/Ubuntu/Mint Installer
# FastMCP STDIO Edition for Debian-based Linux distributions

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║           Wazuh MCP Server v2.1.0 Installer          ║${NC}"
    echo -e "${CYAN}║          Debian/Ubuntu/Mint Edition (FastMCP)         ║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════╝${NC}"
    echo
}

check_distro() {
    if ! command -v apt &> /dev/null; then
        echo -e "${RED}❌ This installer is for Debian-based distributions (apt required)${NC}"
        exit 1
    fi
    
    # Detect specific distribution
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo -e "${BLUE}🐧 Detected: $PRETTY_NAME${NC}"
    fi
}

check_sudo() {
    if ! command -v sudo &> /dev/null; then
        echo -e "${RED}❌ sudo is required but not installed${NC}"
        echo "Please install sudo or run as root"
        exit 1
    fi
    
    # Test sudo access
    if ! sudo -n true 2>/dev/null; then
        echo -e "${YELLOW}🔐 This installer requires sudo privileges${NC}"
        echo "You may be prompted for your password"
    fi
}

check_python() {
    echo -e "${BLUE}🐍 Checking Python installation...${NC}"
    
    # Check if python3 is available
    if ! command -v python3 &> /dev/null; then
        echo -e "${RED}❌ Python 3 is not installed${NC}"
        return 1
    fi
    
    # Get Python version
    PYTHON_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
    PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)
    
    echo -e "${GREEN}✅ Found Python $PYTHON_VERSION${NC}"
    
    # Check if version meets requirements (3.9+)
    if [ "$PYTHON_MAJOR" -lt 3 ] || [ "$PYTHON_MAJOR" -eq 3 -a "$PYTHON_MINOR" -lt 9 ]; then
        echo -e "${YELLOW}⚠️  Python 3.9+ required for Wazuh MCP Server${NC}"
        echo "Current version: $PYTHON_VERSION"
        echo "Consider upgrading Python for better FastMCP compatibility"
    fi
    
    return 0
}

install_system_deps() {
    echo -e "${BLUE}📦 Installing system dependencies...${NC}"
    
    # Update package index
    echo "Updating package index..."
    sudo apt update
    
    # Install required packages
    echo "Installing Python development packages..."
    sudo apt install -y \
        python3-pip \
        python3-venv \
        python3-dev \
        build-essential \
        libssl-dev \
        libffi-dev \
        curl \
        git
    
    # Install optional but recommended packages
    echo "Installing recommended packages..."
    sudo apt install -y \
        python3-setuptools \
        python3-wheel \
        pkg-config \
        libcurl4-openssl-dev
    
    echo -e "${GREEN}✅ System dependencies installed${NC}"
}

create_venv() {
    echo -e "${BLUE}🐍 Creating Python virtual environment...${NC}"
    
    if [ -d "venv" ]; then
        echo -e "${YELLOW}📁 Virtual environment already exists${NC}"
        read -p "Recreate virtual environment? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            rm -rf venv
        else
            return 0
        fi
    fi
    
    python3 -m venv venv
    echo -e "${GREEN}✅ Virtual environment created${NC}"
}

install_python_deps() {
    echo -e "${BLUE}📚 Installing Python dependencies...${NC}"
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Upgrade pip
    echo "Upgrading pip..."
    python -m pip install --upgrade pip
    
    # Install requirements
    echo "Installing FastMCP and dependencies..."
    pip install -r requirements.txt
    
    echo -e "${GREEN}✅ Python dependencies installed${NC}"
}

create_config() {
    echo -e "${BLUE}⚙️ Creating configuration...${NC}"
    
    if [ -f ".env" ]; then
        echo -e "${YELLOW}📁 Configuration file already exists${NC}"
        return 0
    fi
    
    cat > .env << 'EOF'
# Wazuh MCP Server v2.1.0 Configuration
# FastMCP STDIO Edition - Debian/Ubuntu/Mint

# Wazuh Server Configuration
WAZUH_HOST=localhost
WAZUH_PORT=55000
WAZUH_USER=wazuh
WAZUH_PASS=changeme

# SSL Configuration
VERIFY_SSL=false
ALLOW_SELF_SIGNED=true

# Logging Configuration
LOG_LEVEL=INFO

# FastMCP Configuration
MCP_TRANSPORT=stdio
EOF
    
    echo -e "${GREEN}✅ Configuration file created: .env${NC}"
}

create_claude_config() {
    echo -e "${BLUE}⚙️ Creating Claude Desktop configuration example...${NC}"
    
    CURRENT_DIR=$(pwd)
    PYTHON_PATH="$CURRENT_DIR/venv/bin/python"
    SERVER_PATH="$CURRENT_DIR/wazuh-mcp-server"
    CONFIG_PATH="~/.config/claude/claude_desktop_config.json"
    
    cat > claude-desktop-config-example.json << EOF
{
  "mcpServers": {
    "wazuh": {
      "command": "$PYTHON_PATH",
      "args": ["$SERVER_PATH", "--stdio"]
    }
  }
}
EOF
    
    echo -e "${GREEN}✅ Claude Desktop config example created${NC}"
}

test_installation() {
    echo -e "${BLUE}🧪 Testing installation...${NC}"
    
    # Test Python executable and imports
    if venv/bin/python -c "import sys; sys.path.insert(0, 'src'); from wazuh_mcp_server.server import mcp; print('FastMCP server available')" 2>/dev/null; then
        echo -e "${GREEN}✅ Installation test passed${NC}"
        return 0
    else
        echo -e "${RED}❌ Installation test failed${NC}"
        echo "Please check dependencies and try again"
        return 1
    fi
}

create_launcher() {
    echo -e "${BLUE}🚀 Creating launcher script...${NC}"
    
    cat > start-wazuh-mcp.sh << 'EOF'
#!/bin/bash
# Wazuh MCP Server Launcher for Debian/Ubuntu/Mint

cd "$(dirname "$0")"

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "❌ Virtual environment not found. Please run install-debian.sh first"
    exit 1
fi

# Check if .env exists
if [ ! -f ".env" ]; then
    echo "❌ Configuration file (.env) not found"
    echo "Please create .env with your Wazuh server settings"
    exit 1
fi

# Activate virtual environment and start server
source venv/bin/activate
exec python wazuh-mcp-server --stdio
EOF
    
    chmod +x start-wazuh-mcp.sh
    echo -e "${GREEN}✅ Launcher script created: start-wazuh-mcp.sh${NC}"
}

print_next_steps() {
    echo
    echo -e "${GREEN}🎉 Installation completed successfully!${NC}"
    echo
    echo -e "${CYAN}📝 Next Steps:${NC}"
    echo -e "1. ${YELLOW}Configure Wazuh credentials:${NC}"
    echo "   Edit the .env file with your Wazuh server details:"
    echo "   nano .env"
    echo
    echo -e "2. ${YELLOW}Configure Claude Desktop:${NC}"
    echo "   Add the contents of claude-desktop-config-example.json to:"
    echo "   ~/.config/claude/claude_desktop_config.json"
    echo
    echo -e "3. ${YELLOW}Test the installation:${NC}"
    echo "   ./start-wazuh-mcp.sh"
    echo
    echo -e "4. ${YELLOW}Start using the server:${NC}"
    echo "   Restart Claude Desktop and ask: 'Show me Wazuh alerts'"
    echo
    echo -e "${BLUE}💡 Pro Tips:${NC}"
    echo "• Use the launcher: ./start-wazuh-mcp.sh"
    echo "• Check logs for debugging issues"
    echo "• Ensure Wazuh server is accessible from this machine"
    echo "• For systemd service, see docs/linux-service-setup.md"
}

main() {
    print_header
    
    # Pre-flight checks
    check_distro
    check_sudo
    
    # Check if we're in the right directory
    if [ ! -f "requirements.txt" ]; then
        echo -e "${RED}❌ requirements.txt not found${NC}"
        echo "Please run this script from the Wazuh MCP Server directory"
        exit 1
    fi
    
    # Installation steps
    if ! check_python; then
        echo -e "${YELLOW}Installing Python 3.9...${NC}"
        # Add deadsnakes PPA for newer Python versions on older Ubuntu
        if command -v add-apt-repository &> /dev/null; then
            sudo add-apt-repository ppa:deadsnakes/ppa -y || true
            sudo apt update || true
            sudo apt install python3.9 python3.9-venv python3.9-dev -y || true
        fi
    fi
    
    install_system_deps
    create_venv
    install_python_deps
    create_config
    create_claude_config
    create_launcher
    
    if test_installation; then
        print_next_steps
    else
        echo -e "${YELLOW}⚠️  Installation completed with warnings${NC}"
        echo "Please check the error messages above and fix any issues"
    fi
}

# Handle Ctrl+C gracefully
trap 'echo -e "\n${YELLOW}⚠️  Installation cancelled by user${NC}"; exit 1' INT

# Run main function
main "$@"