#!/usr/bin/env python3
"""
Wazuh MCP Server - Main Entry Point
===================================
Production-ready entry point for Wazuh MCP Server with comprehensive
error handling, logging, and graceful shutdown capabilities.
"""

import sys
import signal
import asyncio
import logging
import traceback
from typing import NoReturn
from pathlib import Path

# Add the source directory to Python path for development installations
src_path = Path(__file__).parent.parent.parent / "src"
if src_path.exists():
    sys.path.insert(0, str(src_path))

try:
    from wazuh_mcp_server.server import mcp, initialize_server
    from wazuh_mcp_server.utils import setup_logging, get_logger
    from wazuh_mcp_server.__version__ import __version__
except ImportError as e:
    print(f"❌ Failed to import Wazuh MCP Server components: {e}", file=sys.stderr)
    print("Make sure the package is properly installed:", file=sys.stderr)
    print("  pip install wazuh-mcp-server", file=sys.stderr)
    sys.exit(1)

# Global flag for graceful shutdown
shutdown_requested = False

def signal_handler(signum: int, frame) -> None:
    """Handle shutdown signals gracefully."""
    global shutdown_requested
    signal_name = signal.Signals(signum).name
    logger = get_logger(__name__)
    logger.info(f"🛑 Received {signal_name} signal - initiating graceful shutdown...")
    shutdown_requested = True

def setup_signal_handlers() -> None:
    """Setup signal handlers for graceful shutdown."""
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    
    # Windows doesn't have SIGHUP
    if hasattr(signal, 'SIGHUP'):
        signal.signal(signal.SIGHUP, signal_handler)

async def startup_server() -> None:
    """Initialize and start the Wazuh MCP server with health checks."""
    logger = get_logger(__name__)
    
    try:
        logger.info("🚀 Starting Wazuh MCP Server v%s initialization...", __version__)
        
        # Initialize server components with health checks
        await initialize_server()
        
        logger.info("✅ Wazuh MCP Server initialization completed successfully")
        logger.info("🔗 Ready to accept FastMCP STDIO connections")
        
    except Exception as e:
        logger.error("❌ Failed to initialize Wazuh MCP Server: %s", str(e))
        logger.error("Stack trace:\n%s", traceback.format_exc())
        raise

def run_server() -> NoReturn:
    """Run the Wazuh MCP Server with proper error handling and shutdown."""
    # Setup logging first
    setup_logging()
    logger = get_logger(__name__)
    
    logger.info("🎯 Wazuh MCP Server v%s starting up...", __version__)
    
    # Setup signal handlers for graceful shutdown
    setup_signal_handlers()
    
    try:
        # Initialize server components
        logger.info("⚡ Initializing server components...")
        asyncio.run(startup_server())
        
        # Check for shutdown request after initialization
        if shutdown_requested:
            logger.info("🛑 Shutdown requested during initialization - exiting")
            sys.exit(0)
        
        # Start the FastMCP server with STDIO transport
        logger.info("📡 Starting FastMCP STDIO transport...")
        logger.info("🎉 Wazuh MCP Server is now running and ready for connections")
        
        # Run the FastMCP server
        mcp.run(transport="stdio")
        
    except KeyboardInterrupt:
        logger.info("🛑 Received keyboard interrupt - shutting down gracefully")
        sys.exit(0)
        
    except Exception as e:
        logger.error("💥 Fatal error during server execution: %s", str(e))
        logger.error("Stack trace:\n%s", traceback.format_exc())
        
        # Print user-friendly error message
        print("\n" + "="*60, file=sys.stderr)
        print("❌ WAZUH MCP SERVER STARTUP FAILED", file=sys.stderr)
        print("="*60, file=sys.stderr)
        print(f"Error: {str(e)}", file=sys.stderr)
        print("\nTroubleshooting steps:", file=sys.stderr)
        print("1. Check your .env configuration file", file=sys.stderr)
        print("2. Verify Wazuh server connectivity", file=sys.stderr)
        print("3. Ensure all required dependencies are installed", file=sys.stderr)
        print("4. Check the logs for detailed error information", file=sys.stderr)
        print("5. Run: wazuh-mcp-server --help for usage information", file=sys.stderr)
        print("="*60, file=sys.stderr)
        
        sys.exit(1)
    
    finally:
        logger.info("🏁 Wazuh MCP Server shutdown complete")

def main() -> NoReturn:
    """Main entry point for the Wazuh MCP Server."""
    
    # Handle command line arguments
    if len(sys.argv) > 1:
        arg = sys.argv[1].lower()
        if arg in ['--help', '-h', 'help']:
            print_help()
            sys.exit(0)
        elif arg in ['--version', '-v', 'version']:
            print(f"Wazuh MCP Server v{__version__}")
            sys.exit(0)
        elif arg in ['--check', 'check', 'validate']:
            run_connection_check()
            sys.exit(0)
        else:
            print(f"Unknown argument: {arg}", file=sys.stderr)
            print("Run 'wazuh-mcp-server --help' for usage information", file=sys.stderr)
            sys.exit(1)
    
    # Run the server
    run_server()

def print_help() -> None:
    """Print help information."""
    print(f"""
Wazuh MCP Server v{__version__}
===============================

A FastMCP-powered server for Wazuh SIEM integration with Claude Desktop.

USAGE:
    wazuh-mcp-server [COMMAND]

COMMANDS:
    <none>      Start the MCP server (default)
    --help      Show this help message
    --version   Show version information
    --check     Validate Wazuh connection and configuration

CONFIGURATION:
    Configure the server using a .env file in your project directory.
    See the documentation for detailed configuration options.

EXAMPLES:
    # Start the server
    wazuh-mcp-server
    
    # Check configuration and connectivity
    wazuh-mcp-server --check
    
    # Show version
    wazuh-mcp-server --version

DOCUMENTATION:
    https://github.com/gensecaihq/Wazuh-MCP-Server/blob/main/README.md

SUPPORT:
    For issues and support, visit:
    https://github.com/gensecaihq/Wazuh-MCP-Server/issues
""")

def run_connection_check() -> None:
    """Run connection validation check."""
    setup_logging()
    logger = get_logger(__name__)
    
    print("🔍 Validating Wazuh MCP Server configuration and connectivity...")
    
    try:
        # Import and run connection validator
        from wazuh_mcp_server.scripts.connection_validator import validate_connection
        
        async def check():
            result = await validate_connection()
            if result.get('status') == 'success':
                print("✅ Configuration and connectivity check passed!")
                return True
            else:
                print("❌ Configuration or connectivity issues detected:")
                for issue in result.get('issues', []):
                    print(f"  - {issue}")
                return False
        
        success = asyncio.run(check())
        sys.exit(0 if success else 1)
        
    except Exception as e:
        logger.error("Connection check failed: %s", str(e))
        print(f"❌ Connection check failed: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()