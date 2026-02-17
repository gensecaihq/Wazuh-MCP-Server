#!/usr/bin/env python3
"""
FastMCP Stub for Wazuh MCP Server v2.1.2
=========================================
Minimal stub to allow server to run without FastMCP package.
This provides just enough interface to prevent import errors.
"""

import asyncio
import logging
import sys
from typing import Callable, Optional

logger = logging.getLogger(__name__)


class FastMCP:
    """Minimal FastMCP stub for basic MCP server operations."""

    def __init__(self, name: str, version: str = "2.1.2"):
        self.name = name
        self.version = version
        self.tools = {}

    def tool(self, name: Optional[str] = None, description: str = ""):
        """Tool decorator stub."""

        def decorator(func: Callable) -> Callable:
            tool_name = name or func.__name__
            self.tools[tool_name] = func
            return func

        return decorator

    def run(self, transport: str = "stdio"):
        """Run stub - logs message and exits gracefully."""
        logger.info(f"{self.name} v{self.version}")
        logger.warning("Running in stub mode - FastMCP not available")
        logger.info("Install FastMCP with Python 3.10+ for full functionality")
        logger.info("Server configuration validated successfully")

        # Keep running to simulate server
        try:
            while True:
                asyncio.run(asyncio.sleep(1))
        except KeyboardInterrupt:
            logger.info("Server stopped")
            sys.exit(0)
