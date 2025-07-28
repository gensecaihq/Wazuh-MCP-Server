#!/usr/bin/env bash
# Wazuh MCP Server Quick Start Script

set -euo pipefail

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}Wazuh MCP Server - Quick Start${NC}"
echo -e "${BLUE}==============================${NC}\n"

# Check Docker
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Error: Docker is not installed${NC}"
    echo -e "Please install Docker first: ${YELLOW}https://docs.docker.com/get-docker/${NC}"
    exit 1
fi

# Check Docker Compose
if ! docker compose version &> /dev/null 2>&1; then
    echo -e "${RED}Error: Docker Compose is not installed${NC}"
    exit 1
fi

# Configuration check
CONFIG_FILE="./config/wazuh.env"
if [ ! -f "${CONFIG_FILE}" ]; then
    echo -e "${YELLOW}No configuration found. Starting configuration setup...${NC}\n"
    ./scripts/configure.sh
    if [ $? -ne 0 ]; then
        echo -e "${RED}Configuration failed. Please try again.${NC}"
        exit 1
    fi
fi

# Build and start
echo -e "\n${YELLOW}Building Wazuh MCP Server...${NC}"
docker compose build

echo -e "\n${YELLOW}Starting Wazuh MCP Server...${NC}"
docker compose up -d

# Wait for container to be healthy
echo -e "\n${YELLOW}Waiting for server to be ready...${NC}"
for i in {1..30}; do
    if docker compose ps | grep -q "healthy"; then
        echo -e "${GREEN}✓ Server is ready!${NC}"
        break
    fi
    echo -n "."
    sleep 2
done

echo -e "\n${GREEN}Wazuh MCP Server is running!${NC}\n"

# Show Claude Desktop configuration
echo -e "${BLUE}Claude Desktop Configuration:${NC}"
echo -e "Add this to your Claude Desktop settings:\n"
cat << EOF
{
  "mcpServers": {
    "wazuh": {
      "command": "docker",
      "args": ["exec", "-i", "wazuh-mcp-server", "./wazuh-mcp-server", "--stdio"]
    }
  }
}
EOF

echo -e "\n${YELLOW}Useful commands:${NC}"
echo -e "View logs:    ${BLUE}docker compose logs -f${NC}"
echo -e "Stop server:  ${BLUE}docker compose down${NC}"
echo -e "Restart:      ${BLUE}docker compose restart${NC}"
echo -e "Check status: ${BLUE}docker compose ps${NC}\n"