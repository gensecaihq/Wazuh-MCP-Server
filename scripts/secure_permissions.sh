#!/bin/bash
# Script to set secure file permissions for production deployment

echo "🔒 Setting secure file permissions for Wazuh MCP Server..."

# Set secure permissions for sensitive configuration files
find . -name ".env*" -type f -exec chmod 600 {} \; 2>/dev/null
find . -name "*.key" -type f -exec chmod 600 {} \; 2>/dev/null
find . -name "*.pem" -type f -exec chmod 600 {} \; 2>/dev/null

# Set secure permissions for scripts
find . -name "*.sh" -type f -exec chmod 755 {} \; 2>/dev/null
find . -name "*.py" -type f -exec chmod 644 {} \; 2>/dev/null

# Make main executable scripts executable
chmod +x wazuh-mcp-server 2>/dev/null
chmod +x docker/entrypoint.sh 2>/dev/null
chmod +x scripts/*.sh 2>/dev/null

# Set secure permissions for directories
find . -type d -exec chmod 755 {} \; 2>/dev/null

# Special permissions for log directory if it exists
if [ -d "logs" ]; then
    chmod 750 logs
    find logs -type f -exec chmod 640 {} \; 2>/dev/null
fi

echo "✅ File permissions secured successfully!"
echo ""
echo "Summary of changes:"
echo "- .env files: 600 (read/write owner only)"
echo "- Key/certificate files: 600 (read/write owner only)"
echo "- Python files: 644 (read all, write owner)"
echo "- Shell scripts: 755 (executable)"
echo "- Directories: 755 (standard)"
echo "- Log files: 640 (read owner/group, write owner)"