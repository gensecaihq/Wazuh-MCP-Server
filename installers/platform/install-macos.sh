#!/bin/bash
# Wazuh MCP Server v2.1.0 - macOS Installer
# FastMCP STDIO Edition for macOS (Intel and Apple Silicon)

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║           Wazuh MCP Server v2.1.0 Installer          ║${NC}"
    echo -e "${CYAN}║              macOS Edition (FastMCP)                  ║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════╝${NC}"
    echo
}

detect_macos() {
    if [[ "$(uname)" != "Darwin" ]]; then
        echo -e "${RED}❌ This installer is for macOS only${NC}"
        exit 1
    fi
    
    # Get macOS version
    MACOS_VERSION=$(sw_vers -productVersion)
    MACOS_BUILD=$(sw_vers -buildVersion)
    ARCH=$(uname -m)
    
    echo -e "${BLUE}🍎 Detected: macOS $MACOS_VERSION ($MACOS_BUILD) on $ARCH${NC}"
    
    # Check for Apple Silicon
    if [[ "$ARCH" == "arm64" ]]; then
        echo -e "${PURPLE}🚀 Apple Silicon (M1/M2/M3) detected${NC}"
        APPLE_SILICON=true
    else
        echo -e "${BLUE}💻 Intel Mac detected${NC}"
        APPLE_SILICON=false
    fi
}

check_xcode() {
    echo -e "${BLUE}🔧 Checking Xcode Command Line Tools...${NC}"
    
    if ! xcode-select -p &> /dev/null; then
        echo -e "${YELLOW}⚠️  Xcode Command Line Tools not installed${NC}"
        echo "Installing Xcode Command Line Tools..."
        xcode-select --install
        
        echo -e "${YELLOW}Please complete the Xcode Command Line Tools installation and run this script again${NC}"
        exit 1
    else
        echo -e "${GREEN}✅ Xcode Command Line Tools installed${NC}"
    fi
}

check_homebrew() {
    echo -e "${BLUE}🍺 Checking Homebrew...${NC}"
    
    if ! command -v brew &> /dev/null; then
        echo -e "${YELLOW}⚠️  Homebrew not installed${NC}"
        echo "Installing Homebrew..."
        
        # Install Homebrew
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
        
        # Add Homebrew to PATH for Apple Silicon
        if [[ "$APPLE_SILICON" == true ]]; then
            echo 'eval "$(/opt/homebrew/bin/brew shellenv)"' >> ~/.zprofile
            eval "$(/opt/homebrew/bin/brew shellenv)"
        else
            echo 'eval "$(/usr/local/bin/brew shellenv)"' >> ~/.zprofile
            eval "$(/usr/local/bin/brew shellenv)"
        fi
        
        echo -e "${GREEN}✅ Homebrew installed${NC}"
    else
        echo -e "${GREEN}✅ Homebrew found${NC}"
        
        # Update Homebrew
        echo "Updating Homebrew..."
        brew update
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
        echo -e "${YELLOW}⚠️  Python 3.9+ recommended for optimal performance${NC}"
        echo "Current version: $PYTHON_VERSION"
        echo "Installing Python 3.9 via Homebrew..."
        return 1
    fi
    
    return 0
}

install_python() {
    echo -e "${BLUE}🐍 Installing Python 3.9 via Homebrew...${NC}"
    
    # Install Python 3.9
    brew install python@3.9
    
    # Create symlinks if needed
    if [[ "$APPLE_SILICON" == true ]]; then
        PYTHON_PATH="/opt/homebrew/bin/python3.9"
    else
        PYTHON_PATH="/usr/local/bin/python3.9"
    fi
    
    if [ -f "$PYTHON_PATH" ]; then
        echo -e "${GREEN}✅ Python 3.9 installed at $PYTHON_PATH${NC}"
        # Use this specific Python version
        ln -sf "$PYTHON_PATH" /usr/local/bin/python3 || true
    fi
}

install_system_deps() {
    echo -e "${BLUE}📦 Installing system dependencies via Homebrew...${NC}"
    
    # Install essential packages
    brew install \
        openssl \
        libffi \
        curl \
        git \
        pkg-config
    
    # Install optional but useful packages
    brew install \
        wget \
        jq \
        tree || echo -e "${YELLOW}⚠️  Some optional packages failed to install${NC}"
    
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
    
    # Use python3 or the specific version we installed
    if [[ "$APPLE_SILICON" == true && -f "/opt/homebrew/bin/python3.9" ]]; then
        /opt/homebrew/bin/python3.9 -m venv venv
    elif [[ -f "/usr/local/bin/python3.9" ]]; then
        /usr/local/bin/python3.9 -m venv venv
    else
        python3 -m venv venv
    fi
    
    echo -e "${GREEN}✅ Virtual environment created${NC}"
}

install_python_deps() {
    echo -e "${BLUE}📚 Installing Python dependencies...${NC}"
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Upgrade pip
    echo "Upgrading pip..."
    python -m pip install --upgrade pip
    
    # Install wheel and setuptools for better compatibility
    pip install wheel setuptools
    
    # Install requirements
    echo "Installing FastMCP and dependencies..."
    
    # Special handling for Apple Silicon if needed
    if [[ "$APPLE_SILICON" == true ]]; then
        # Some packages might need special handling on Apple Silicon
        export ARCHFLAGS="-arch arm64"
    fi
    
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
# FastMCP STDIO Edition - macOS

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
    echo -e "${BLUE}⚙️ Creating Claude Desktop configuration...${NC}"
    
    CURRENT_DIR=$(pwd)
    PYTHON_PATH="$CURRENT_DIR/venv/bin/python"
    SERVER_PATH="$CURRENT_DIR/wazuh-mcp-server"
    CONFIG_DIR="$HOME/Library/Application Support/Claude"
    CONFIG_FILE="$CONFIG_DIR/claude_desktop_config.json"
    
    # Create config directory if it doesn't exist
    mkdir -p "$CONFIG_DIR"
    
    # Create example config
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
    
    # Offer to install directly
    if [ -f "$CONFIG_FILE" ]; then
        echo -e "${YELLOW}⚠️  Claude Desktop config already exists at:${NC}"
        echo "   $CONFIG_FILE"
        read -p "Merge with existing config? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            merge_claude_config "$CONFIG_FILE"
        fi
    else
        read -p "Install Claude Desktop config now? (Y/n): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Nn]$ ]]; then
            cp claude-desktop-config-example.json "$CONFIG_FILE"
            echo -e "${GREEN}✅ Claude Desktop config installed${NC}"
        fi
    fi
}

merge_claude_config() {
    local config_file=$1
    echo -e "${BLUE}📝 Merging Claude Desktop configuration...${NC}"
    
    # Create backup
    cp "$config_file" "$config_file.backup"
    
    # Use jq to merge if available, otherwise manual merge
    if command -v jq &> /dev/null; then
        CURRENT_DIR=$(pwd)
        PYTHON_PATH="$CURRENT_DIR/venv/bin/python"
        SERVER_PATH="$CURRENT_DIR/wazuh-mcp-server"
        
        jq --arg cmd "$PYTHON_PATH" --arg args "$SERVER_PATH --stdio" \
           '.mcpServers.wazuh = {"command": $cmd, "args": [$args]}' \
           "$config_file" > "$config_file.tmp" && mv "$config_file.tmp" "$config_file"
        
        echo -e "${GREEN}✅ Configuration merged successfully${NC}"
    else
        echo -e "${YELLOW}⚠️  jq not available, please merge manually:${NC}"
        echo "   Backup created: $config_file.backup"
        echo "   Example config: claude-desktop-config-example.json"
    fi
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
# Wazuh MCP Server Launcher for macOS

cd "$(dirname "$0")"

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "❌ Virtual environment not found. Please run install-macos.sh first"
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

create_launchd_service() {
    echo -e "${BLUE}🔧 Creating LaunchAgent for auto-start...${NC}"
    
    CURRENT_DIR=$(pwd)
    USER=$(whoami)
    PLIST_PATH="$HOME/Library/LaunchAgents/com.wazuh.mcp-server.plist"
    
    cat > "$PLIST_PATH" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.wazuh.mcp-server</string>
    <key>ProgramArguments</key>
    <array>
        <string>$CURRENT_DIR/venv/bin/python</string>
        <string>$CURRENT_DIR/wazuh-mcp-server</string>
        <string>--stdio</string>
    </array>
    <key>WorkingDirectory</key>
    <string>$CURRENT_DIR</string>
    <key>RunAtLoad</key>
    <false/>
    <key>KeepAlive</key>
    <false/>
    <key>StandardOutPath</key>
    <string>$CURRENT_DIR/logs/wazuh-mcp-server.log</string>
    <key>StandardErrorPath</key>
    <string>$CURRENT_DIR/logs/wazuh-mcp-server-error.log</string>
</dict>
</plist>
EOF
    
    # Create logs directory
    mkdir -p logs
    
    echo -e "${GREEN}✅ LaunchAgent created: $PLIST_PATH${NC}"
    echo -e "${YELLOW}ℹ️  To enable auto-start:${NC}"
    echo "   launchctl load $PLIST_PATH"
    echo "   launchctl start com.wazuh.mcp-server"
    echo
    echo -e "${YELLOW}ℹ️  To disable auto-start:${NC}"
    echo "   launchctl stop com.wazuh.mcp-server"
    echo "   launchctl unload $PLIST_PATH"
}

print_next_steps() {
    echo
    echo -e "${GREEN}🎉 Installation completed successfully!${NC}"
    echo
    echo -e "${CYAN}📝 Next Steps:${NC}"
    echo -e "1. ${YELLOW}Configure Wazuh credentials:${NC}"
    echo "   Edit the .env file with your Wazuh server details:"
    echo "   open -a TextEdit .env"
    echo
    echo -e "2. ${YELLOW}Configure Claude Desktop:${NC}"
    if [ -f "$HOME/Library/Application Support/Claude/claude_desktop_config.json" ]; then
        echo "   ✅ Configuration already installed"
    else
        echo "   Add the contents of claude-desktop-config-example.json to:"
        echo "   ~/Library/Application Support/Claude/claude_desktop_config.json"
    fi
    echo
    echo -e "3. ${YELLOW}Test the installation:${NC}"
    echo "   ./start-wazuh-mcp.sh"
    echo
    echo -e "4. ${YELLOW}Start using the server:${NC}"
    echo "   Restart Claude Desktop and ask: 'Show me Wazuh alerts'"
    echo
    echo -e "${BLUE}💡 macOS Pro Tips:${NC}"
    echo "• Use the launcher: ./start-wazuh-mcp.sh"
    echo "• Enable LaunchAgent for auto-start (see above)"
    echo "• Check Console.app for system logs"
    echo "• Use Activity Monitor to check server status"
    echo "• For Homebrew updates: brew upgrade"
}

main() {
    print_header
    
    # Pre-flight checks
    detect_macos
    check_xcode
    check_homebrew
    
    # Check if we're in the right directory
    if [ ! -f "requirements.txt" ]; then
        echo -e "${RED}❌ requirements.txt not found${NC}"
        echo "Please run this script from the Wazuh MCP Server directory"
        exit 1
    fi
    
    # Installation steps
    if ! check_python; then
        install_python
    fi
    
    install_system_deps
    create_venv
    install_python_deps
    create_config
    create_claude_config
    create_launcher
    create_launchd_service
    
    if test_installation; then
        print_next_steps
    else
        echo -e "${YELLOW}⚠️  Installation completed with warnings${NC}"
        echo "Please check the error messages above and fix any issues"
        echo "Consider checking Homebrew doctor: brew doctor"
    fi
}

# Handle Ctrl+C gracefully
trap 'echo -e "\n${YELLOW}⚠️  Installation cancelled by user${NC}"; exit 1' INT

# Run main function
main "$@"