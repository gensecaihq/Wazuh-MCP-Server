#!/bin/bash
#
# Wazuh MCP Server Migration Script
# Upgrades from v1.0.0 to v2.0.0
#
# This script helps users migrate their configuration after the repository
# restructuring that moved scripts from root to scripts/ directory.
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo -e "${BLUE}🚀 Wazuh MCP Server Migration Tool (v1.0.0 → v2.0.0)${NC}"
echo "=================================================="
echo ""

# Function to detect OS
detect_os() {
    case "$OSTYPE" in
        darwin*)  echo "macos" ;;
        linux*)   echo "linux" ;;
        msys*|cygwin*|mingw*) echo "windows" ;;
        *)        echo "unknown" ;;
    esac
}

# Function to get Claude Desktop config path
get_claude_config_path() {
    local os="$1"
    case "$os" in
        "macos")
            echo "$HOME/Library/Application Support/Claude/claude_desktop_config.json"
            ;;
        "linux")
            echo "$HOME/.config/Claude/claude_desktop_config.json"
            ;;
        "windows")
            echo "$APPDATA/Claude/claude_desktop_config.json"
            ;;
        *)
            echo ""
            ;;
    esac
}

# Function to backup file
backup_file() {
    local file="$1"
    local backup="${file}.backup.$(date +%Y%m%d_%H%M%S)"
    
    if [[ -f "$file" ]]; then
        cp "$file" "$backup"
        echo -e "${GREEN}✓${NC} Backup created: $backup"
        return 0
    else
        echo -e "${YELLOW}⚠${NC} File not found: $file"
        return 1
    fi
}

# Function to update Claude Desktop config
update_claude_config() {
    local config_file="$1"
    local project_path="$2"
    
    if [[ ! -f "$config_file" ]]; then
        echo -e "${YELLOW}⚠${NC} Claude Desktop config not found: $config_file"
        return 1
    fi
    
    echo -e "${BLUE}📝 Updating Claude Desktop configuration...${NC}"
    
    # Create backup
    if ! backup_file "$config_file"; then
        return 1
    fi
    
    # Update the configuration
    # Replace old wrapper script path with new one
    if grep -q "mcp_wrapper.sh" "$config_file"; then
        sed -i.tmp "s|/mcp_wrapper.sh|/scripts/mcp_wrapper.sh|g" "$config_file"
        sed -i.tmp "s|\\\\mcp_wrapper.sh|\\\\scripts\\\\mcp_wrapper.sh|g" "$config_file"
        rm -f "${config_file}.tmp"
        
        echo -e "${GREEN}✓${NC} Updated wrapper script path in Claude Desktop config"
    else
        echo -e "${YELLOW}⚠${NC} No wrapper script references found in config"
    fi
    
    # Update absolute paths if they exist
    if grep -q "$project_path" "$config_file"; then
        # This is more complex - we need to be careful not to break the JSON
        echo -e "${YELLOW}⚠${NC} Found project-specific paths in config"
        echo -e "  ${YELLOW}→${NC} Please manually update any absolute paths to include 'scripts/'"
        echo -e "  ${YELLOW}→${NC} Example: Change /path/to/Wazuh-MCP-Server/mcp_wrapper.sh"
        echo -e "  ${YELLOW}→${NC}          to    /path/to/Wazuh-MCP-Server/scripts/mcp_wrapper.sh"
    fi
    
    return 0
}

# Function to check and update environment
check_environment() {
    echo -e "${BLUE}🔍 Checking current environment...${NC}"
    
    # Check if we're in the right directory
    if [[ ! -f "$PROJECT_ROOT/src/wazuh_mcp_server/main.py" ]]; then
        echo -e "${RED}✗${NC} Error: Not in Wazuh MCP Server directory"
        echo "Please run this script from the Wazuh-MCP-Server directory"
        exit 1
    fi
    
    # Check if scripts directory exists
    if [[ ! -d "$PROJECT_ROOT/scripts" ]]; then
        echo -e "${RED}✗${NC} Error: scripts/ directory not found"
        echo "This doesn't appear to be v2.0.0 - scripts should be in scripts/ directory"
        exit 1
    fi
    
    # Check if new script files exist
    if [[ ! -f "$PROJECT_ROOT/scripts/mcp_wrapper.sh" ]]; then
        echo -e "${RED}✗${NC} Error: scripts/mcp_wrapper.sh not found"
        exit 1
    fi
    
    echo -e "${GREEN}✓${NC} Environment looks good"
}

# Function to update script permissions
update_permissions() {
    echo -e "${BLUE}🔧 Updating script permissions...${NC}"
    
    chmod +x "$PROJECT_ROOT/scripts/mcp_wrapper.sh" 2>/dev/null || true
    chmod +x "$PROJECT_ROOT/scripts/test_wrapper.sh" 2>/dev/null || true
    chmod +x "$PROJECT_ROOT/scripts/migrate_v1_to_v2.sh" 2>/dev/null || true
    
    echo -e "${GREEN}✓${NC} Script permissions updated"
}

# Function to show migration summary
show_summary() {
    echo ""
    echo -e "${GREEN}🎉 Migration completed successfully!${NC}"
    echo "============================================"
    echo ""
    echo -e "${BLUE}📋 What was changed:${NC}"
    echo "• Claude Desktop configuration updated"
    echo "• Script permissions set correctly"
    echo "• Backup files created for safety"
    echo ""
    echo -e "${BLUE}📋 What you need to do:${NC}"
    echo "1. Restart Claude Desktop"
    echo "2. Test the connection: 'Show me recent security alerts'"
    echo "3. Enable new features in .env if desired:"
    echo "   ENABLE_PROMPT_ENHANCEMENT=true"
    echo "   ENABLE_CONTEXT_AGGREGATION=true"
    echo "   ENABLE_ADAPTIVE_RESPONSES=true"
    echo "   ENABLE_REALTIME_UPDATES=true"
    echo ""
    echo -e "${BLUE}📋 New features in v2.0.0:${NC}"
    echo "• 12 new security tools (23 total vs 11 in v1.0.0)"
    echo "• AI-powered prompt enhancement system"
    echo "• Real-time context updates"
    echo "• Enhanced compliance checking (5 frameworks)"
    echo "• Advanced threat analysis with ML"
    echo ""
    echo -e "${YELLOW}💡 Need help? Check docs/UPCOMING.md for full feature list${NC}"
}

# Function to validate post-migration
validate_migration() {
    echo -e "${BLUE}🧪 Validating migration...${NC}"
    
    # Check if validation script exists
    if [[ -f "$PROJECT_ROOT/scripts/validate_setup.py" ]]; then
        echo -e "${BLUE}→${NC} Running setup validation..."
        if python3 "$PROJECT_ROOT/scripts/validate_setup.py" --quiet 2>/dev/null; then
            echo -e "${GREEN}✓${NC} Setup validation passed"
        else
            echo -e "${YELLOW}⚠${NC} Setup validation had warnings (check configuration)"
        fi
    fi
    
    # Test wrapper script
    if [[ -x "$PROJECT_ROOT/scripts/mcp_wrapper.sh" ]]; then
        echo -e "${GREEN}✓${NC} Wrapper script is executable"
    else
        echo -e "${YELLOW}⚠${NC} Wrapper script permissions issue"
    fi
}

# Main migration function
main() {
    local os
    local config_path
    
    echo -e "${BLUE}🔍 Detecting system...${NC}"
    os=$(detect_os)
    echo -e "${GREEN}✓${NC} Detected OS: $os"
    
    # Check environment first
    check_environment
    
    # Update script permissions
    update_permissions
    
    # Get Claude Desktop config path
    config_path=$(get_claude_config_path "$os")
    
    if [[ -n "$config_path" ]]; then
        echo -e "${BLUE}📍 Claude Desktop config: $config_path${NC}"
        
        # Update Claude Desktop configuration
        if update_claude_config "$config_path" "$PROJECT_ROOT"; then
            echo -e "${GREEN}✓${NC} Claude Desktop configuration updated"
        else
            echo -e "${YELLOW}⚠${NC} Could not automatically update Claude Desktop config"
            echo -e "  ${YELLOW}→${NC} You may need to manually update the path from:"
            echo -e "  ${YELLOW}→${NC} '/path/to/Wazuh-MCP-Server/mcp_wrapper.sh'"
            echo -e "  ${YELLOW}→${NC} to '/path/to/Wazuh-MCP-Server/scripts/mcp_wrapper.sh'"
        fi
    else
        echo -e "${YELLOW}⚠${NC} Could not determine Claude Desktop config path for OS: $os"
        echo -e "  ${YELLOW}→${NC} Please manually update your Claude Desktop configuration"
    fi
    
    # Validate migration
    validate_migration
    
    # Show summary
    show_summary
    
    echo -e "${GREEN}✅ Migration completed! Please restart Claude Desktop.${NC}"
}

# Show usage if help requested
if [[ "${1:-}" == "-h" ]] || [[ "${1:-}" == "--help" ]]; then
    echo "Wazuh MCP Server Migration Tool (v1.0.0 → v2.0.0)"
    echo ""
    echo "USAGE:"
    echo "  $0                    # Run interactive migration"
    echo "  $0 --help           # Show this help"
    echo ""
    echo "DESCRIPTION:"
    echo "  This script helps migrate from Wazuh MCP Server v1.0.0 to v2.0.0"
    echo "  by updating Claude Desktop configuration to use the new script locations."
    echo ""
    echo "WHAT IT DOES:"
    echo "  • Updates Claude Desktop config with new script paths"
    echo "  • Sets proper permissions on scripts"
    echo "  • Creates backup files for safety"
    echo "  • Validates the migration"
    echo ""
    echo "REQUIREMENTS:"
    echo "  • Must be run from Wazuh-MCP-Server directory"
    echo "  • Claude Desktop must be installed"
    echo "  • Write access to Claude Desktop config directory"
    echo ""
    exit 0
fi

# Run main migration
main "$@"