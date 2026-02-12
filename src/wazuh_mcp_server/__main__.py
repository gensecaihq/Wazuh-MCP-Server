#!/usr/bin/env python3
"""
Wazuh MCP Server - Main Entry Point
MCP-compliant remote server for Wazuh SIEM integration
"""

import sys
import os
import logging
import uvicorn
from pathlib import Path

# Add the src directory to Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Configure basic logging for startup
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("wazuh_mcp_server.main")


def main():
    """Main entry point for the Wazuh MCP Server."""
    try:
        from wazuh_mcp_server.server import app

        # Get configuration from environment
        host = os.getenv('MCP_HOST', '0.0.0.0')
        port = int(os.getenv('MCP_PORT', '3000'))
        log_level = os.getenv('LOG_LEVEL', 'info').lower()

        logger.info(f"Starting Wazuh MCP Server v4.0.6")
        logger.info(f"Server: http://{host}:{port}")
        logger.info(f"Health: http://{host}:{port}/health")
        logger.info(f"Metrics: http://{host}:{port}/metrics")
        logger.info(f"Docs: http://{host}:{port}/docs")

        # Run the server
        uvicorn.run(
            app,
            host=host,
            port=port,
            log_level=log_level,
            access_log=True,
            server_header=False,
            date_header=False
        )

    except ImportError as e:
        logger.error(f"Import error: {e}")
        logger.error("Make sure all dependencies are installed: pip install -r requirements.txt")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Server error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()