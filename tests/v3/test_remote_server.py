"""Comprehensive tests for v3.0.0 remote server functionality."""

import pytest
import asyncio
import ssl
import time
from unittest.mock import Mock, AsyncMock, patch, MagicMock
from typing import Dict, Any, Optional

from aiohttp import web
from aiohttp.test_utils import AioHTTPTestCase, unittest_run_loop

from wazuh_mcp_server.remote_server import RemoteMCPServer
from wazuh_mcp_server.config import WazuhConfig
from wazuh_mcp_server.auth import OAuth2Server, TokenManager
from wazuh_mcp_server.auth.models import AuthScope, User, Client
from wazuh_mcp_server.transport import SSETransport, HttpTransport
from wazuh_mcp_server.utils.exceptions import ConfigurationError, ServerError
from wazuh_mcp_server.__version__ import __version__


class TestRemoteMCPServer:
    """Test RemoteMCPServer functionality."""
    
    def test_server_initialization(self):
        """Test server initialization with default parameters."""
        config = WazuhConfig()
        server = RemoteMCPServer(config)
        
        assert server.config == config
        assert server.transport_type == "sse"
        assert server.host == "0.0.0.0"
        assert server.port == 8443
        assert server.ssl_context is None
        assert server.running is False
    
    def test_server_initialization_with_custom_params(self):
        """Test server initialization with custom parameters."""
        config = WazuhConfig()
        ssl_context = ssl.create_default_context()
        
        server = RemoteMCPServer(
            config=config,
            transport_type="http",
            host="127.0.0.1",
            port=9000,
            ssl_context=ssl_context
        )
        
        assert server.transport_type == "http"
        assert server.host == "127.0.0.1"
        assert server.port == 9000
        assert server.ssl_context == ssl_context
    
    @pytest.mark.asyncio
    async def test_setup_authentication_success(self):
        """Test successful authentication setup."""
        config = WazuhConfig()
        # Mock configuration values
        config.settings = {
            "JWT_SECRET_KEY": "test_secret_key",
            "ADMIN_USERNAME": "admin",
            "ADMIN_PASSWORD": "admin_password",
            "OAUTH_CLIENT_ID": "test_client",
            "OAUTH_CLIENT_SECRET": "test_secret"
        }
        
        server = RemoteMCPServer(config)
        
        await server.setup_authentication()
        
        assert server.token_manager is not None
        assert server.oauth2_server is not None
        assert server.auth_middleware is not None
        
        # Check that admin user was created
        admin_users = [u for u in server.oauth2_server.users.values() if u.username == "admin"]
        assert len(admin_users) == 1
        assert admin_users[0].is_admin is True
        
        # Check that client was created
        assert "test_client" in server.oauth2_server.clients
    
    @pytest.mark.asyncio
    async def test_setup_authentication_missing_secret(self):
        """Test authentication setup with missing JWT secret."""
        config = WazuhConfig()
        config.settings = {}  # No JWT_SECRET_KEY
        
        server = RemoteMCPServer(config)
        
        with pytest.raises(ConfigurationError, match="JWT_SECRET_KEY not configured"):
            await server.setup_authentication()
    
    @pytest.mark.asyncio
    async def test_setup_transport_sse(self):
        """Test SSE transport setup."""
        config = WazuhConfig()
        server = RemoteMCPServer(config, transport_type="sse")
        
        await server.setup_transport()
        
        assert server.transport is not None
        assert isinstance(server.transport, SSETransport)
        assert server.transport_adapter is not None
    
    @pytest.mark.asyncio
    async def test_setup_transport_http(self):
        """Test HTTP transport setup."""
        config = WazuhConfig()
        server = RemoteMCPServer(config, transport_type="http")
        
        await server.setup_transport()
        
        assert server.transport is not None
        assert isinstance(server.transport, HttpTransport)
        assert server.transport_adapter is not None
    
    @pytest.mark.asyncio
    async def test_setup_transport_invalid_type(self):
        """Test transport setup with invalid type."""
        config = WazuhConfig()
        server = RemoteMCPServer(config, transport_type="invalid")
        
        with pytest.raises(ConfigurationError, match="Unsupported transport type"):
            await server.setup_transport()
    
    @pytest.mark.asyncio
    async def test_setup_web_application(self):
        """Test web application setup."""
        config = WazuhConfig()
        server = RemoteMCPServer(config)
        
        # Setup authentication first
        server.token_manager = TokenManager()
        server.oauth2_server = OAuth2Server(server.token_manager)
        
        await server.setup_web_application()
        
        assert server.app is not None
        assert isinstance(server.app, web.Application)
        
        # Check that routes are configured
        routes = [str(route.resource) for route in server.app.router.routes()]
        expected_routes = ["/health", "/metrics", "/info", "/oauth/authorize", "/oauth/token"]
        
        for expected_route in expected_routes:
            assert any(expected_route in route for route in routes)
    
    @pytest.mark.asyncio
    async def test_server_lifecycle_start_stop(self):
        """Test server start and stop lifecycle."""
        config = WazuhConfig()
        config.settings = {
            "JWT_SECRET_KEY": "test_secret_key",
            "ADMIN_USERNAME": "admin",
            "ADMIN_PASSWORD": "admin_password"
        }
        
        server = RemoteMCPServer(config)
        
        # Mock transport and related components to avoid actual network binding
        with patch.object(server, 'transport', spec=SSETransport) as mock_transport:
            mock_transport.start = AsyncMock()
            mock_transport.stop = AsyncMock()
            
            with patch('aiohttp.web.AppRunner') as mock_runner_class:
                mock_runner = AsyncMock()
                mock_runner_class.return_value = mock_runner
                
                with patch('aiohttp.web.TCPSite') as mock_site_class:
                    mock_site = AsyncMock()
                    mock_site_class.return_value = mock_site
                    
                    # Mock transport adapter
                    with patch.object(server, 'transport_adapter') as mock_adapter:
                        mock_adapter.start_adaptation = AsyncMock()
                        mock_adapter.stop_adaptation = AsyncMock()
                        
                        # Start server
                        await server.start()
                        
                        assert server.running is True
                        assert server.startup_time > 0
                        
                        # Verify components were started
                        mock_transport.start.assert_called_once()
                        mock_runner.setup.assert_called_once()
                        mock_site.start.assert_called_once()
                        
                        # Stop server
                        await server.stop()
                        
                        assert server.running is False
                        
                        # Verify components were stopped
                        mock_transport.stop.assert_called_once()
                        mock_adapter.stop_adaptation.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_cleanup_task(self):
        """Test background cleanup task."""
        config = WazuhConfig()
        server = RemoteMCPServer(config)
        
        # Mock OAuth2 server
        server.oauth2_server = AsyncMock()
        server.oauth2_server.cleanup_expired_codes = AsyncMock()
        server.running = True
        
        # Create cleanup task
        cleanup_task = asyncio.create_task(server.cleanup_task())
        
        # Let it run briefly
        await asyncio.sleep(0.1)
        
        # Stop the server to end the cleanup task
        server.running = False
        
        # Wait for cleanup task to complete
        await asyncio.sleep(0.1)
        cleanup_task.cancel()
        
        try:
            await cleanup_task
        except asyncio.CancelledError:
            pass
        
        # Verify cleanup was called
        server.oauth2_server.cleanup_expired_codes.assert_called()


class TestRemoteMCPServerHTTPHandlers:
    """Test HTTP handler methods."""
    
    def setup_method(self):
        """Setup for each test method."""
        self.config = WazuhConfig()
        self.server = RemoteMCPServer(self.config)
        self.server.startup_time = time.time()
        self.server.running = True
        self.server.request_count = 42
    
    @pytest.mark.asyncio
    async def test_health_handler_healthy(self):
        """Test health check handler when server is healthy."""
        mock_request = Mock()
        
        response = await self.server.handle_health(mock_request)
        
        assert response.status == 200
        
        # Parse response body
        import json
        response_data = json.loads(response.text)
        
        assert response_data["status"] == "healthy"
        assert response_data["version"] == __version__
        assert response_data["transport"] == "sse"
        assert response_data["requests_processed"] == 42
        assert "uptime" in response_data
        assert "timestamp" in response_data
    
    @pytest.mark.asyncio
    async def test_health_handler_unhealthy(self):
        """Test health check handler when server is unhealthy."""
        self.server.running = False
        
        mock_request = Mock()
        response = await self.server.handle_health(mock_request)
        
        assert response.status == 503
        
        import json
        response_data = json.loads(response.text)
        
        assert response_data["status"] == "unhealthy"
        assert response_data["uptime"] == 0
    
    @pytest.mark.asyncio
    async def test_metrics_handler(self):
        """Test metrics handler."""
        # Mock OAuth2 server
        self.server.oauth2_server = Mock()
        self.server.oauth2_server.users = {"user1": Mock(), "user2": Mock()}
        self.server.oauth2_server.clients = {"client1": Mock()}
        
        mock_request = Mock()
        response = await self.server.handle_metrics(mock_request)
        
        assert response.status == 200
        
        import json
        response_data = json.loads(response.text)
        
        assert "server_info" in response_data
        assert "requests" in response_data
        assert "authentication" in response_data
        assert "transport" in response_data
        
        assert response_data["server_info"]["version"] == __version__
        assert response_data["authentication"]["active_users"] == 2
        assert response_data["authentication"]["active_clients"] == 1
    
    @pytest.mark.asyncio
    async def test_info_handler(self):
        """Test info handler."""
        mock_request = Mock()
        response = await self.server.handle_info(mock_request)
        
        assert response.status == 200
        
        import json
        response_data = json.loads(response.text)
        
        assert response_data["name"] == "Wazuh MCP Server"
        assert response_data["version"] == __version__
        assert response_data["transport"] == "sse"
        assert "features" in response_data
        assert "endpoints" in response_data
        
        features = response_data["features"]
        assert features["authentication"] is True
        assert features["oauth2"] is True
        assert features["metrics"] is True
    
    @pytest.mark.asyncio
    async def test_docs_handler(self):
        """Test documentation handler."""
        mock_request = Mock()
        response = await self.server.handle_docs(mock_request)
        
        assert response.status == 200
        assert response.content_type == 'text/html'
        assert "Wazuh MCP Server v3.0.0 API Documentation" in response.text
    
    @pytest.mark.asyncio
    async def test_openapi_handler(self):
        """Test OpenAPI specification handler."""
        mock_request = Mock()
        response = await self.server.handle_openapi(mock_request)
        
        assert response.status == 200
        
        import json
        response_data = json.loads(response.text)
        
        assert response_data["openapi"] == "3.0.0"
        assert response_data["info"]["title"] == "Wazuh MCP Server"
        assert response_data["info"]["version"] == __version__
        assert "paths" in response_data
        assert "/health" in response_data["paths"]
        assert "/metrics" in response_data["paths"]
    
    @pytest.mark.asyncio
    async def test_oauth_handlers_not_implemented(self):
        """Test OAuth handlers return not implemented."""
        mock_request = Mock()
        
        # Test authorize handler
        response = await self.server.handle_authorize(mock_request)
        assert response.status == 501
        
        # Test token handler
        response = await self.server.handle_token(mock_request)
        assert response.status == 501
        
        # Test userinfo handler
        response = await self.server.handle_userinfo(mock_request)
        assert response.status == 501


class TestSSLContextCreation:
    """Test SSL context creation utility."""
    
    def test_create_ssl_context_success(self):
        """Test successful SSL context creation."""
        from wazuh_mcp_server.remote_server import create_ssl_context
        
        # Mock SSL context creation
        with patch('ssl.create_default_context') as mock_create_context:
            mock_context = Mock()
            mock_context.load_cert_chain = Mock()
            mock_create_context.return_value = mock_context
            
            result = create_ssl_context("cert.pem", "key.pem")
            
            assert result == mock_context
            mock_create_context.assert_called_once_with(ssl.Purpose.CLIENT_AUTH)
            mock_context.load_cert_chain.assert_called_once_with("cert.pem", "key.pem")
    
    def test_create_ssl_context_failure(self):
        """Test SSL context creation failure."""
        from wazuh_mcp_server.remote_server import create_ssl_context
        
        with patch('ssl.create_default_context') as mock_create_context:
            mock_create_context.side_effect = Exception("SSL error")
            
            with pytest.raises(Exception, match="SSL error"):
                create_ssl_context("cert.pem", "key.pem")


class TestRemoteMCPServerIntegration:
    """Integration tests for RemoteMCPServer."""
    
    @pytest.mark.asyncio
    async def test_server_authentication_integration(self):
        """Test server with authentication integration."""
        config = WazuhConfig()
        config.settings = {
            "JWT_SECRET_KEY": "integration_test_secret",
            "ADMIN_USERNAME": "admin",
            "ADMIN_PASSWORD": "admin_password",
            "OAUTH_CLIENT_ID": "integration_client",
            "OAUTH_CLIENT_SECRET": "integration_secret"
        }
        
        server = RemoteMCPServer(config)
        
        # Setup authentication
        await server.setup_authentication()
        
        # Verify admin user creation
        admin_users = [u for u in server.oauth2_server.users.values() if u.username == "admin"]
        assert len(admin_users) == 1
        
        admin_user = admin_users[0]
        assert admin_user.is_admin is True
        assert len(admin_user.scopes) == len(list(AuthScope))
        
        # Verify client creation
        client = server.oauth2_server.clients.get("integration_client")
        assert client is not None
        assert client.client_id == "integration_client"
        assert client.client_secret == "integration_secret"
        
        # Test authentication flow
        authenticated_user = await server.oauth2_server.authenticate_user("admin", "admin_password")
        assert authenticated_user is not None
        assert authenticated_user.username == "admin"
        
        # Test token creation
        access_token = server.token_manager.create_access_token(
            admin_user.id, client.client_id, admin_user.scopes
        )
        
        # Verify token
        token_payload = await server.oauth2_server.validate_token(access_token)
        assert token_payload is not None
        assert token_payload["sub"] == admin_user.id
    
    @pytest.mark.asyncio
    async def test_server_transport_integration(self):
        """Test server with transport integration."""
        config = WazuhConfig()
        server = RemoteMCPServer(config, transport_type="sse")
        
        await server.setup_transport()
        
        # Verify transport setup
        assert server.transport is not None
        assert isinstance(server.transport, SSETransport)
        assert server.transport.host == "0.0.0.0"
        assert server.transport.port == 8443
        
        # Verify transport adapter
        assert server.transport_adapter is not None
        assert server.transport_adapter.target_transport == server.transport
    
    @pytest.mark.asyncio
    async def test_server_web_application_integration(self):
        """Test server with web application integration."""
        config = WazuhConfig()
        config.settings = {"JWT_SECRET_KEY": "test_secret"}
        
        server = RemoteMCPServer(config)
        
        # Setup dependencies
        await server.setup_authentication()
        await server.setup_web_application()
        
        # Verify web application setup
        assert server.app is not None
        assert len(server.app.middlewares) >= 2  # Security + Auth middleware
        
        # Verify routes
        route_methods_paths = [(route.method, str(route.resource)) for route in server.app.router.routes()]
        
        expected_routes = [
            ("GET", "/health"),
            ("GET", "/metrics"),
            ("GET", "/info"),
            ("GET", "/docs"),
            ("GET", "/openapi.json"),
            ("GET", "/oauth/authorize"),
            ("POST", "/oauth/token"),
            ("GET", "/oauth/userinfo")
        ]
        
        for method, path in expected_routes:
            assert any(method == route_method and path in route_path 
                      for route_method, route_path in route_methods_paths)


class TestRemoteMCPServerErrorHandling:
    """Test error handling in RemoteMCPServer."""
    
    @pytest.mark.asyncio
    async def test_start_server_authentication_error(self):
        """Test server start with authentication error."""
        config = WazuhConfig()
        # Missing required JWT secret
        config.settings = {}
        
        server = RemoteMCPServer(config)
        
        with pytest.raises(ServerError, match="Server startup failed"):
            await server.start()
    
    @pytest.mark.asyncio
    async def test_start_server_transport_error(self):
        """Test server start with transport error."""
        config = WazuhConfig()
        config.settings = {"JWT_SECRET_KEY": "test_secret"}
        
        server = RemoteMCPServer(config, transport_type="invalid")
        
        with pytest.raises(ServerError, match="Server startup failed"):
            await server.start()
    
    @pytest.mark.asyncio
    async def test_stop_server_when_not_running(self):
        """Test stopping server when not running."""
        config = WazuhConfig()
        server = RemoteMCPServer(config)
        
        # Should not raise exception
        await server.stop()
        
        assert server.running is False
    
    @pytest.mark.asyncio
    async def test_start_server_when_already_running(self):
        """Test starting server when already running."""
        config = WazuhConfig()
        server = RemoteMCPServer(config)
        server.running = True
        
        # Should not raise exception and should return early
        await server.start()
        
        assert server.running is True