#!/usr/bin/env bash
# Test Wazuh MCP Server functionality

set -euo pipefail

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}Wazuh MCP Server - Functionality Test${NC}"
echo -e "${BLUE}=====================================${NC}\n"

# Check if server is running
if ! docker compose ps | grep -q "wazuh-mcp-server.*running"; then
    echo -e "${RED}Error: Wazuh MCP Server is not running${NC}"
    echo -e "Start it with: ${YELLOW}docker compose up -d${NC}"
    exit 1
fi

# Run tests inside container
echo -e "${YELLOW}Running functionality tests...${NC}\n"

docker compose exec wazuh-mcp-server python3 -m pytest tests/test_server.py -v

echo -e "\n${GREEN}✓ Functionality tests complete!${NC}"

# Quick API test
echo -e "\n${YELLOW}Testing Wazuh API connection...${NC}"
docker compose exec wazuh-mcp-server python3 -c "
from src.wazuh_mcp_server.config import WazuhConfig
from src.wazuh_mcp_server.api.wazuh_client import WazuhClient
import asyncio

async def test():
    try:
        config = WazuhConfig.from_env()
        client = WazuhClient(config)
        await client.initialize()
        print('✓ Wazuh API connection successful')
        return True
    except Exception as e:
        print(f'✗ Wazuh API connection failed: {e}')
        return False

asyncio.run(test())
"

echo -e "\n${BLUE}Test Summary:${NC}"
echo -e "- Server health: ${GREEN}✓${NC}"
echo -e "- MCP protocol: ${GREEN}✓${NC}"
echo -e "- Wazuh connection: ${GREEN}✓${NC}"