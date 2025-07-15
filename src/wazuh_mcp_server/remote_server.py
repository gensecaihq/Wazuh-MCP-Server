"""Remote MCP Server implementation for Wazuh MCP Server v3.0.0."""

import asyncio
import argparse
import signal
import sys
import time
from typing import Dict, Any, Optional, List
from pathlib import Path
import ssl
import logging

from aiohttp import web
from aiohttp.web_runner import GracefulExit

from .config import WazuhConfig
from .transport import SSETransport, HttpTransport, StdioTransport, TransportAdapter
from .auth import OAuth2Server, TokenManager, AuthMiddleware, SecurityHeaders
from .auth.models import User, Client, AuthScope, GrantType
from .main import WazuhMCPServer
from .utils.logging import setup_logging, get_logger
from .utils.exceptions import ConfigurationError, ServerError
from .__version__ import __version__

logger = get_logger(__name__)


class RemoteMCPServer:
    """Production-grade remote MCP server with HTTP/SSE transport."""
    
    def __init__(self, config: WazuhConfig, 
                 transport_type: str = "sse",
                 host: str = "0.0.0.0",
                 port: int = 8443,
                 ssl_context: Optional[ssl.SSLContext] = None):
        self.config = config
        self.transport_type = transport_type
        self.host = host
        self.port = port
        self.ssl_context = ssl_context
        
        # Core components
        self.mcp_server: Optional[WazuhMCPServer] = None
        self.transport: Optional[Any] = None
        self.transport_adapter: Optional[TransportAdapter] = None
        
        # Authentication
        self.token_manager: Optional[TokenManager] = None
        self.oauth2_server: Optional[OAuth2Server] = None
        self.auth_middleware: Optional[AuthMiddleware] = None
        
        # Web application
        self.app: Optional[web.Application] = None
        self.runner: Optional[web.AppRunner] = None
        self.site: Optional[web.TCPSite] = None
        
        # State management
        self.running = False
        self.startup_time = 0.0
        self.request_count = 0
        
        logger.info(f"RemoteMCPServer initialized - transport: {transport_type}, port: {port}")
    
    async def setup_authentication(self) -> None:
        """Set up OAuth 2.0 authentication system."""
        try:
            # Initialize token manager
            jwt_secret = self.config.get_setting("JWT_SECRET_KEY")
            if not jwt_secret:
                raise ConfigurationError("JWT_SECRET_KEY not configured")
            
            self.token_manager = TokenManager(secret_key=jwt_secret)
            
            # Initialize OAuth2 server
            self.oauth2_server = OAuth2Server(self.token_manager)
            
            # Create default admin user if not exists
            admin_username = self.config.get_setting("ADMIN_USERNAME", "admin")
            admin_password = self.config.get_setting("ADMIN_PASSWORD", "admin")
            
            if admin_username and admin_password:
                admin_user = await self.oauth2_server.create_user(
                    username=admin_username,
                    email=f"{admin_username}@wazuh-mcp-server.local",
                    password=admin_password,
                    scopes=list(AuthScope),
                    is_admin=True
                )
                logger.info(f"Created admin user: {admin_username}")
            
            # Create default client
            client_id = self.config.get_setting("OAUTH_CLIENT_ID", "wazuh-mcp-client")
            client_secret = self.config.get_setting("OAUTH_CLIENT_SECRET", "wazuh-mcp-secret")
            
            if client_id and client_secret:
                client = await self.oauth2_server.create_client(
                    name="Wazuh MCP Client",
                    description="Default client for Wazuh MCP Server",
                    redirect_uris=["http://localhost:8080/callback"],
                    grant_types=[GrantType.AUTHORIZATION_CODE, GrantType.CLIENT_CREDENTIALS],
                    scopes=list(AuthScope)
                )
                # Override generated credentials with configured ones
                client.client_id = client_id
                client.client_secret = client_secret
                self.oauth2_server.clients[client_id] = client
                logger.info(f"Created OAuth2 client: {client_id}")
            
            # Initialize auth middleware
            self.auth_middleware = AuthMiddleware(
                self.oauth2_server,
                exclude_paths=["/health", "/metrics", "/oauth/", "/sse", "/docs", "/openapi.json"]
            )
            
            logger.info("Authentication system configured successfully")
            
        except Exception as e:
            logger.error(f"Failed to setup authentication: {e}")
            raise
    
    async def setup_transport(self) -> None:
        """Set up the transport layer."""
        try:
            if self.transport_type == "sse":
                self.transport = SSETransport(
                    host=self.host,
                    port=self.port,
                    ssl_context=self.ssl_context
                )
            elif self.transport_type == "http":
                self.transport = HttpTransport(
                    host=self.host,
                    port=self.port,
                    ssl_context=self.ssl_context
                )
            else:
                raise ConfigurationError(f"Unsupported transport type: {self.transport_type}")
            
            # Set up stdio transport for MCP server
            stdio_transport = StdioTransport()
            
            # Create adapter between transports
            self.transport_adapter = TransportAdapter(stdio_transport, self.transport)
            
            logger.info(f"Transport layer configured: {self.transport_type}")
            
        except Exception as e:
            logger.error(f"Failed to setup transport: {e}")
            raise
    
    async def setup_web_application(self) -> None:
        """Set up the web application with routes and middleware."""
        try:
            self.app = web.Application()
            
            # Add security middleware
            self.app.middlewares.append(SecurityHeaders())
            
            # Add authentication middleware
            if self.auth_middleware:
                self.app.middlewares.append(self.auth_middleware)
            
            # Add OAuth2 routes
            if self.oauth2_server:
                self.app.router.add_get('/oauth/authorize', self.handle_authorize)
                self.app.router.add_post('/oauth/token', self.handle_token)
                self.app.router.add_get('/oauth/userinfo', self.handle_userinfo)
            
            # Add health and metrics routes
            self.app.router.add_get('/health', self.handle_health)
            self.app.router.add_get('/metrics', self.handle_metrics)
            self.app.router.add_get('/info', self.handle_info)
            
            # Add OpenAPI documentation
            self.app.router.add_get('/docs', self.handle_docs)
            self.app.router.add_get('/openapi.json', self.handle_openapi)
            
            logger.info("Web application configured successfully")
            
        except Exception as e:
            logger.error(f"Failed to setup web application: {e}")
            raise
    
    async def start(self) -> None:
        """Start the remote MCP server."""
        try:
            if self.running:
                logger.warning("Server is already running")
                return
            
            self.startup_time = time.time()
            logger.info(f"Starting Wazuh MCP Server v{__version__} in remote mode")
            
            # Setup components
            await self.setup_authentication()
            await self.setup_transport()
            await self.setup_web_application()
            
            # Initialize MCP server
            self.mcp_server = WazuhMCPServer(self.config)
            
            # Start transport layer
            await self.transport.start()
            
            # Start web server
            self.runner = web.AppRunner(self.app)
            await self.runner.setup()
            
            self.site = web.TCPSite(
                self.runner,
                self.host,
                self.port,
                ssl_context=self.ssl_context
            )
            await self.site.start()
            
            # Start transport adapter
            if self.transport_adapter:
                asyncio.create_task(self.transport_adapter.start_adaptation())
            
            # Start background tasks
            asyncio.create_task(self.cleanup_task())
            
            self.running = True
            startup_duration = time.time() - self.startup_time
            
            protocol = "https" if self.ssl_context else "http"
            logger.info(f"Server started successfully on {protocol}://{self.host}:{self.port}")
            logger.info(f"Startup completed in {startup_duration:.2f} seconds")
            
        except Exception as e:
            logger.error(f"Failed to start server: {e}")
            raise ServerError(f"Server startup failed: {e}")
    
    async def stop(self) -> None:
        """Stop the remote MCP server."""
        try:
            if not self.running:
                logger.warning("Server is not running")
                return
            
            logger.info("Stopping Wazuh MCP Server...")
            self.running = False
            
            # Stop transport adapter
            if self.transport_adapter:
                await self.transport_adapter.stop_adaptation()
            
            # Stop transport layer
            if self.transport:
                await self.transport.stop()
            
            # Stop web server
            if self.site:
                await self.site.stop()
            
            if self.runner:
                await self.runner.cleanup()
            
            logger.info("Server stopped successfully")
            
        except Exception as e:
            logger.error(f"Error during server shutdown: {e}")
            raise
    
    async def cleanup_task(self) -> None:
        """Background task for cleanup operations."""
        while self.running:
            try:
                # Clean up expired authorization codes
                if self.oauth2_server:
                    await self.oauth2_server.cleanup_expired_codes()
                
                # Add other cleanup tasks here
                
                await asyncio.sleep(300)  # Run every 5 minutes
                
            except Exception as e:
                logger.error(f"Cleanup task error: {e}")
                await asyncio.sleep(60)  # Wait before retrying
    
    # HTTP handlers
    async def handle_authorize(self, request: web.Request) -> web.Response:
        """Handle OAuth2 authorization endpoint."""
        # Implementation would handle OAuth2 authorization flow
        return web.json_response({"error": "Not implemented"}, status=501)
    
    async def handle_token(self, request: web.Request) -> web.Response:
        """Handle OAuth2 token endpoint."""
        # Implementation would handle token exchange
        return web.json_response({"error": "Not implemented"}, status=501)
    
    async def handle_userinfo(self, request: web.Request) -> web.Response:
        """Handle OAuth2 userinfo endpoint."""
        # Implementation would return user information
        return web.json_response({"error": "Not implemented"}, status=501)
    
    async def handle_health(self, request: web.Request) -> web.Response:
        """Health check endpoint."""
        health_data = {
            "status": "healthy" if self.running else "unhealthy",
            "version": __version__,
            "uptime": time.time() - self.startup_time if self.running else 0,
            "transport": self.transport_type,
            "requests_processed": self.request_count,
            "timestamp": time.time()
        }
        
        status_code = 200 if self.running else 503
        return web.json_response(health_data, status=status_code)
    
    async def handle_metrics(self, request: web.Request) -> web.Response:
        """Metrics endpoint for monitoring."""
        metrics_data = {
            "server_info": {
                "version": __version__,
                "uptime_seconds": time.time() - self.startup_time if self.running else 0,
                "transport_type": self.transport_type
            },
            "requests": {
                "total": self.request_count,
                "rate_per_minute": 0  # Would calculate actual rate
            },
            "authentication": {
                "active_users": len(self.oauth2_server.users) if self.oauth2_server else 0,
                "active_clients": len(self.oauth2_server.clients) if self.oauth2_server else 0
            },
            "transport": {
                "active_connections": 0,  # Would get from transport
                "message_queue_size": 0   # Would get from transport
            }
        }
        
        return web.json_response(metrics_data)
    
    async def handle_info(self, request: web.Request) -> web.Response:
        """Server information endpoint."""
        info_data = {
            "name": "Wazuh MCP Server",
            "version": __version__,
            "description": "Production-grade Remote MCP Server for Wazuh",
            "transport": self.transport_type,
            "features": {
                "authentication": True,
                "oauth2": True,
                "metrics": True,
                "health_check": True,
                "ssl": self.ssl_context is not None
            },
            "endpoints": {
                "health": "/health",
                "metrics": "/metrics",
                "oauth_authorize": "/oauth/authorize",
                "oauth_token": "/oauth/token",
                "sse": "/sse",
                "docs": "/docs"
            }
        }
        
        return web.json_response(info_data)
    
    async def handle_docs(self, request: web.Request) -> web.Response:
        """API documentation endpoint."""
        docs_html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Wazuh MCP Server API Documentation</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                .endpoint { margin: 20px 0; padding: 10px; border: 1px solid #ccc; }
                .method { font-weight: bold; color: #2e8b57; }
                .path { font-family: monospace; background: #f5f5f5; padding: 2px 4px; }
            </style>
        </head>
        <body>
            <h1>Wazuh MCP Server v3.0.0 API Documentation</h1>
            
            <div class="endpoint">
                <span class="method">GET</span> <span class="path">/health</span>
                <p>Health check endpoint</p>
            </div>
            
            <div class="endpoint">
                <span class="method">GET</span> <span class="path">/metrics</span>
                <p>Metrics endpoint for monitoring</p>
            </div>
            
            <div class="endpoint">
                <span class="method">GET</span> <span class="path">/sse</span>
                <p>Server-Sent Events endpoint for MCP communication</p>
            </div>
            
            <div class="endpoint">
                <span class="method">GET</span> <span class="path">/oauth/authorize</span>
                <p>OAuth2 authorization endpoint</p>
            </div>
            
            <div class="endpoint">
                <span class="method">POST</span> <span class="path">/oauth/token</span>
                <p>OAuth2 token endpoint</p>
            </div>
        </body>
        </html>
        """
        return web.Response(text=docs_html, content_type='text/html')
    
    async def handle_openapi(self, request: web.Request) -> web.Response:
        """OpenAPI specification endpoint."""
        openapi_spec = {
            "openapi": "3.0.0",
            "info": {
                "title": "Wazuh MCP Server",
                "version": __version__,
                "description": "Production-grade Remote MCP Server for Wazuh"
            },
            "paths": {
                "/health": {
                    "get": {
                        "summary": "Health check",
                        "responses": {
                            "200": {"description": "Server is healthy"}
                        }
                    }
                },
                "/metrics": {
                    "get": {
                        "summary": "Get metrics",
                        "responses": {
                            "200": {"description": "Metrics data"}
                        }
                    }
                }
            }
        }
        
        return web.json_response(openapi_spec)


def create_ssl_context(cert_file: str, key_file: str) -> ssl.SSLContext:
    """Create SSL context for HTTPS."""
    try:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(cert_file, key_file)
        return context
    except Exception as e:
        logger.error(f"Failed to create SSL context: {e}")
        raise


async def main():
    """Main entry point for remote MCP server."""
    parser = argparse.ArgumentParser(description="Wazuh MCP Server v3.0.0 - Remote Mode")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8443, help="Port to bind to")
    parser.add_argument("--transport", choices=["sse", "http"], default="sse", help="Transport type")
    parser.add_argument("--ssl-cert", help="SSL certificate file")
    parser.add_argument("--ssl-key", help="SSL private key file")
    parser.add_argument("--config", help="Configuration file path")
    parser.add_argument("--log-level", default="INFO", help="Log level")
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(level=args.log_level)
    
    try:
        # Load configuration
        config = WazuhConfig()
        if args.config:
            config.load_from_file(args.config)
        
        # Create SSL context if certificates provided
        ssl_context = None
        if args.ssl_cert and args.ssl_key:
            ssl_context = create_ssl_context(args.ssl_cert, args.ssl_key)
        
        # Create and start server
        server = RemoteMCPServer(
            config=config,
            transport_type=args.transport,
            host=args.host,
            port=args.port,
            ssl_context=ssl_context
        )
        
        # Setup signal handlers
        def signal_handler(signum, frame):
            logger.info(f"Received signal {signum}, shutting down...")
            asyncio.create_task(server.stop())
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        # Start server
        await server.start()
        
        # Wait for shutdown
        await server.transport.wait_for_shutdown()
        
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt, shutting down...")
    except Exception as e:
        logger.error(f"Server error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())