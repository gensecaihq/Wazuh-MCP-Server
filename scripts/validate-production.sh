#!/usr/bin/env bash
# Validate production readiness

set -euo pipefail

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}Wazuh MCP Server - Production Validation${NC}"
echo -e "${BLUE}=======================================${NC}\n"

ERRORS=0
WARNINGS=0

# Function to check requirement
check() {
    local test_name="$1"
    local command="$2"
    
    echo -n "Checking $test_name... "
    if eval "$command" >/dev/null 2>&1; then
        echo -e "${GREEN}✓${NC}"
        return 0
    else
        echo -e "${RED}✗${NC}"
        ((ERRORS++))
        return 1
    fi
}

# Function to warn
warn() {
    local test_name="$1"
    local command="$2"
    
    echo -n "Checking $test_name... "
    if eval "$command" >/dev/null 2>&1; then
        echo -e "${GREEN}✓${NC}"
        return 0
    else
        echo -e "${YELLOW}⚠${NC}"
        ((WARNINGS++))
        return 1
    fi
}

echo -e "${YELLOW}1. Docker Environment${NC}"
check "Docker installed" "docker --version"
check "Docker Compose V2" "docker compose version"
check "Docker daemon running" "docker info"

echo -e "\n${YELLOW}2. Configuration${NC}"
check "Configuration file exists" "test -f config/wazuh.env"
check "Required variables set" "grep -q 'WAZUH_HOST=' config/wazuh.env && grep -q 'WAZUH_USER=' config/wazuh.env"
warn "SSL verification enabled" "grep -q 'VERIFY_SSL=true' config/wazuh.env"

echo -e "\n${YELLOW}3. Container Status${NC}"
check "Container built" "docker images | grep -q wazuh-mcp-server"
check "Container running" "docker compose ps | grep -q 'wazuh-mcp-server.*running'"
check "Container healthy" "docker compose ps | grep -q 'wazuh-mcp-server.*(healthy)'"

echo -e "\n${YELLOW}4. Security${NC}"
check "No exposed secrets" "! grep -r 'password\\|secret\\|key' src/ | grep -v '.py:' | grep -q '='"
warn "Production image used" "grep -q 'FROM python:.*-slim' Dockerfile"

echo -e "\n${YELLOW}5. Resources${NC}"
warn "Memory limits set" "grep -q 'memory:' compose.yml"
warn "CPU limits set" "grep -q 'cpus:' compose.yml"

echo -e "\n${BLUE}Validation Summary:${NC}"
echo -e "- Errors: ${ERRORS}"
echo -e "- Warnings: ${WARNINGS}"

if [ $ERRORS -eq 0 ]; then
    if [ $WARNINGS -eq 0 ]; then
        echo -e "\n${GREEN}✓ Production ready!${NC}"
    else
        echo -e "\n${YELLOW}⚠ Production ready with warnings${NC}"
        echo -e "Review warnings above for optimal production deployment"
    fi
    exit 0
else
    echo -e "\n${RED}✗ Not production ready${NC}"
    echo -e "Fix the errors above before deploying to production"
    exit 1
fi