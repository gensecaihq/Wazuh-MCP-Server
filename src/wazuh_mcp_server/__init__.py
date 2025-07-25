"""
Wazuh MCP Server - Production-grade Model Context Protocol server for Wazuh security platform.

This package provides a comprehensive interface between Wazuh SIEM and AI language models
through the Model Context Protocol (MCP), enabling natural language security operations.
"""

from .__version__ import __version__, __author__, __email__

# Optional imports that may not be available
try:
    from .config import WazuhConfig
    # Import from server.py instead of main.py for v2.0.0
    # The WazuhMCPServer class is not defined in main.py anymore
    _imports_available = True
    WazuhMCPServer = None  # Not available in current structure
except ImportError:
    # Dependencies not available
    WazuhConfig = None
    WazuhMCPServer = None
    _imports_available = False

# Public API
__all__ = [
    "__version__",
    "__author__",
    "__email__",
]

if _imports_available:
    __all__.extend(["WazuhConfig", "WazuhMCPServer"])

# Package metadata
__package_name__ = "wazuh-mcp-server"
__description__ = "Production-grade Model Context Protocol server for Wazuh security platform"
__url__ = "https://github.com/gensecaihq/Wazuh-MCP-Server"