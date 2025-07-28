#!/usr/bin/env bash
# Wazuh MCP Server Configuration Helper

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration file paths
CONFIG_DIR="./config"
ENV_EXAMPLE="${CONFIG_DIR}/wazuh.env.example"
ENV_FILE="${CONFIG_DIR}/wazuh.env"

# Create config directory if it doesn't exist
mkdir -p "${CONFIG_DIR}"

echo -e "${BLUE}Wazuh MCP Server Configuration Setup${NC}"
echo -e "${BLUE}=====================================${NC}\n"

# Check if config already exists
if [ -f "${ENV_FILE}" ]; then
    echo -e "${YELLOW}Configuration file already exists at: ${ENV_FILE}${NC}"
    read -p "Do you want to reconfigure? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${GREEN}Using existing configuration.${NC}"
        exit 0
    fi
    # Backup existing config
    cp "${ENV_FILE}" "${ENV_FILE}.backup.$(date +%Y%m%d_%H%M%S)"
    echo -e "${GREEN}Existing configuration backed up.${NC}\n"
fi

# Copy template if it doesn't exist
if [ ! -f "${ENV_EXAMPLE}" ]; then
    echo -e "${RED}Error: Configuration template not found at ${ENV_EXAMPLE}${NC}"
    exit 1
fi

cp "${ENV_EXAMPLE}" "${ENV_FILE}"

echo -e "${GREEN}Step 1: Required Wazuh Manager Settings${NC}"
echo -e "Please provide your Wazuh Manager connection details:\n"

# Get Wazuh host
read -p "Wazuh Manager hostname or IP: " wazuh_host
sed -i.bak "s|WAZUH_HOST=.*|WAZUH_HOST=${wazuh_host}|" "${ENV_FILE}"

# Get Wazuh user
read -p "Wazuh API username: " wazuh_user
sed -i.bak "s|WAZUH_USER=.*|WAZUH_USER=${wazuh_user}|" "${ENV_FILE}"

# Get Wazuh password (hidden input)
echo -n "Wazuh API password: "
read -s wazuh_pass
echo
sed -i.bak "s|WAZUH_PASS=.*|WAZUH_PASS=${wazuh_pass}|" "${ENV_FILE}"

# Clean up backup files
rm -f "${ENV_FILE}.bak"

echo -e "\n${GREEN}Step 2: Optional Settings${NC}"
read -p "Do you want to configure optional settings? (y/N): " -n 1 -r
echo

if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo -e "\n${YELLOW}Wazuh Manager Port (press Enter for default 55000):${NC}"
    read -p "Port: " wazuh_port
    if [ ! -z "$wazuh_port" ]; then
        sed -i.bak "s|# WAZUH_PORT=.*|WAZUH_PORT=${wazuh_port}|" "${ENV_FILE}"
    fi

    echo -e "\n${YELLOW}Do you have Wazuh Indexer installed? (y/N):${NC}"
    read -p "" -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        read -p "Wazuh Indexer hostname or IP: " indexer_host
        sed -i.bak "s|# WAZUH_INDEXER_HOST=.*|WAZUH_INDEXER_HOST=${indexer_host}|" "${ENV_FILE}"
        
        read -p "Wazuh Indexer username (default: admin): " indexer_user
        indexer_user=${indexer_user:-admin}
        sed -i.bak "s|# WAZUH_INDEXER_USER=.*|WAZUH_INDEXER_USER=${indexer_user}|" "${ENV_FILE}"
        
        echo -n "Wazuh Indexer password: "
        read -s indexer_pass
        echo
        sed -i.bak "s|# WAZUH_INDEXER_PASS=.*|WAZUH_INDEXER_PASS=${indexer_pass}|" "${ENV_FILE}"
    fi

    # Clean up backup files
    rm -f "${ENV_FILE}.bak"
fi

echo -e "\n${GREEN}Configuration complete!${NC}"
echo -e "Configuration saved to: ${BLUE}${ENV_FILE}${NC}\n"

# Test configuration
echo -e "${YELLOW}Testing configuration...${NC}"
if docker compose config >/dev/null 2>&1; then
    echo -e "${GREEN}✓ Configuration is valid${NC}\n"
else
    echo -e "${RED}✗ Configuration validation failed${NC}"
    echo -e "Please check your settings in ${ENV_FILE}\n"
    exit 1
fi

echo -e "${GREEN}Next steps:${NC}"
echo -e "1. Start the server: ${BLUE}docker compose up -d${NC}"
echo -e "2. Check logs: ${BLUE}docker compose logs -f${NC}"
echo -e "3. Configure Claude Desktop with the settings from the README\n"