#!/usr/bin/env python3
"""
Wazuh MCP Server - Main Entry Point
MCP-compliant remote server for Wazuh SIEM integration
"""

import logging
import os
import sys
from pathlib import Path

import uvicorn

# Add the src directory to Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Configure logging (LOG_FORMAT=json for structured logs with correlation IDs).
from wazuh_mcp_server.monitoring import configure_logging  # noqa: E402

configure_logging(level=getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper(), logging.INFO))
logger = logging.getLogger("wazuh_mcp_server.main")

# Redact credentials on the root handler immediately, before any module logs — the app
# lifespan re-applies this (idempotently) and also covers uvicorn's own handlers.
from wazuh_mcp_server.security import install_log_sanitizer  # noqa: E402

install_log_sanitizer()


USAGE = """usage: python -m wazuh_mcp_server

Starts the Wazuh MCP Server (Streamable HTTP on MCP_HOST:MCP_PORT, default 127.0.0.1:3000).
All settings come from environment variables; see .env.example and docs/configuration.md.
From a checkout: set -a; . ./.env; set +a; python -m wazuh_mcp_server
"""


def main() -> None:
    """Main entry point for the Wazuh MCP Server."""
    if any(arg in ("-h", "--help") for arg in sys.argv[1:]):
        print(USAGE, end="")
        return
    if len(sys.argv) > 1:
        print(f"unknown argument(s): {' '.join(sys.argv[1:])}\n\n{USAGE}", end="", file=sys.stderr)
        sys.exit(2)
    try:
        from wazuh_mcp_server.server import app

        # Get configuration from environment
        # Loopback unless configured: the server speaks plain HTTP. The image sets 0.0.0.0.
        host = os.getenv("MCP_HOST", "127.0.0.1")
        port = int(os.getenv("MCP_PORT", "3000"))
        # Normalize LOG_LEVEL to a value uvicorn accepts. LOG_LEVEL=WARN (valid for the stdlib
        # logging module and accepted elsewhere in the app) is NOT a valid uvicorn level and would
        # crash startup with a cryptic "Server error"; map it, and fall back to info on anything
        # unrecognized rather than aborting the boot.
        _uvicorn_levels = {"critical", "error", "warning", "info", "debug", "trace"}
        log_level = os.getenv("LOG_LEVEL", "info").strip().lower()
        if log_level == "warn":
            log_level = "warning"
        if log_level not in _uvicorn_levels:
            log_level = "info"

        from wazuh_mcp_server import __version__

        logger.info(f"Starting Wazuh MCP Server v{__version__}")
        logger.info(f"Server: http://{host}:{port}")
        logger.info(f"Health: http://{host}:{port}/health")
        logger.info(f"Metrics: http://{host}:{port}/metrics")
        logger.info(f"Docs: http://{host}:{port}/docs")

        # Run the server
        # Bound shutdown: without a timeout an open SSE stream keeps uvicorn "waiting for
        # connections to close" forever after SIGTERM, lifespan cleanup never runs, and the
        # orchestrator has to SIGKILL.
        uvicorn.run(
            app,
            host=host,
            port=port,
            log_level=log_level,
            access_log=True,
            server_header=False,
            date_header=False,
            timeout_graceful_shutdown=20,
            # Explicit, or uvicorn reads WEB_CONCURRENCY (set by Heroku and other PaaS) itself
            # and refuses to start with an app object. State is per-process; see the startup warning.
            workers=1,
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
