"""Wazuh MCP Server Tools Package.

This package contains modular tool implementations for the Wazuh MCP Server.
Each module focuses on a specific domain of functionality to keep the main
server file maintainable.
"""

from .base import BaseTool

__all__ = ['BaseTool']