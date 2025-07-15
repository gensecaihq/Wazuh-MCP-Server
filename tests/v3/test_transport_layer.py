"""Comprehensive tests for v3.0.0 transport layer."""

import pytest
import asyncio
import json
import time
from unittest.mock import Mock, AsyncMock, patch
from typing import List, Dict, Any

from wazuh_mcp_server.transport import (
    BaseTransport, TransportMessage, StdioTransport, 
    HttpTransport, SSETransport, TransportAdapter
)
from wazuh_mcp_server.transport.base import TransportType


class TestTransportMessage:
    """Test TransportMessage functionality."""
    
    def test_message_creation(self):
        """Test basic message creation."""
        message = TransportMessage(
            type="test_message",
            data={"key": "value"},
            id="msg_123"
        )
        
        assert message.type == "test_message"
        assert message.data == {"key": "value"}
        assert message.id == "msg_123"
        assert message.timestamp is None
    
    def test_message_json_serialization(self):
        """Test JSON serialization/deserialization."""
        original = TransportMessage(
            type="test",
            data={"test": True},
            id="123",
            timestamp=1234567890.0
        )
        
        json_str = original.to_json()
        restored = TransportMessage.from_json(json_str)
        
        assert restored.type == original.type
        assert restored.data == original.data
        assert restored.id == original.id
        assert restored.timestamp == original.timestamp
    
    def test_message_json_without_optional_fields(self):
        """Test JSON handling with missing optional fields."""
        message = TransportMessage(type="test", data={"value": 42})
        json_str = message.to_json()
        restored = TransportMessage.from_json(json_str)
        
        assert restored.type == "test"
        assert restored.data == {"value": 42}
        assert restored.id is None
        assert restored.timestamp is None


class TestBaseTransport:
    """Test BaseTransport abstract functionality."""
    
    def test_transport_initialization(self):
        """Test transport initialization."""
        class TestTransport(BaseTransport):
            async def start(self): pass
            async def stop(self): pass
            async def send_message(self, message): pass
            async def receive_messages(self): pass
        
        transport = TestTransport(TransportType.HTTP)
        assert transport.transport_type == TransportType.HTTP
        assert not transport.is_running
        assert transport._message_handlers == {}
    
    def test_handler_registration(self):
        """Test message handler registration."""
        class TestTransport(BaseTransport):
            async def start(self): pass
            async def stop(self): pass
            async def send_message(self, message): pass
            async def receive_messages(self): pass
        
        transport = TestTransport(TransportType.HTTP)
        handler = Mock()
        
        transport.register_handler("test_type", handler)
        assert "test_type" in transport._message_handlers
        assert transport._message_handlers["test_type"] == handler
    
    @pytest.mark.asyncio
    async def test_message_handling(self):
        """Test message handling with registered handlers."""
        class TestTransport(BaseTransport):
            async def start(self): pass
            async def stop(self): pass
            async def send_message(self, message): pass
            async def receive_messages(self): pass
        
        transport = TestTransport(TransportType.HTTP)
        handler = AsyncMock()
        
        transport.register_handler("test_type", handler)
        
        message = TransportMessage(type="test_type", data={"test": True})
        await transport.handle_message(message)
        
        handler.assert_called_once_with(message)
    
    @pytest.mark.asyncio
    async def test_message_handling_no_handler(self):
        """Test message handling without registered handler."""
        class TestTransport(BaseTransport):
            async def start(self): pass
            async def stop(self): pass
            async def send_message(self, message): pass
            async def receive_messages(self): pass
        
        transport = TestTransport(TransportType.HTTP)
        message = TransportMessage(type="unknown_type", data={})
        
        # Should not raise exception
        await transport.handle_message(message)


@pytest.mark.asyncio
class TestStdioTransport:
    """Test StdioTransport functionality."""
    
    async def test_transport_initialization(self):
        """Test stdio transport initialization."""
        transport = StdioTransport()
        assert transport.transport_type == TransportType.STDIO
        assert not transport.is_running
    
    @patch('sys.stdin')
    @patch('sys.stdout')
    async def test_start_stop_lifecycle(self, mock_stdout, mock_stdin):
        """Test transport start/stop lifecycle."""
        transport = StdioTransport()
        
        # Mock asyncio streams
        with patch('asyncio.get_event_loop') as mock_loop:
            mock_loop.return_value.connect_read_pipe = AsyncMock()
            mock_loop.return_value.connect_write_pipe = AsyncMock(
                return_value=(Mock(), Mock())
            )
            
            await transport.start()
            assert transport.is_running
            
            await transport.stop()
            assert not transport.is_running
    
    async def test_message_creation_with_timestamp(self):
        """Test that messages get timestamps when sent."""
        transport = StdioTransport()
        message = TransportMessage(type="test", data={})
        
        # Mock the writer to avoid actual I/O
        transport._stdout_writer = AsyncMock()
        transport._running = True
        
        await transport.send_message(message)
        
        # Message should have been given a timestamp
        assert message.timestamp is not None
        assert isinstance(message.timestamp, float)


@pytest.mark.asyncio 
class TestHttpTransport:
    """Test HttpTransport functionality."""
    
    async def test_transport_initialization(self):
        """Test HTTP transport initialization."""
        transport = HttpTransport(host="127.0.0.1", port=8080)
        assert transport.transport_type == TransportType.HTTP
        assert transport.host == "127.0.0.1"
        assert transport.port == 8080
        assert not transport.is_running
    
    async def test_routes_setup(self):
        """Test that HTTP routes are properly configured."""
        transport = HttpTransport()
        
        # Check that routes are configured
        routes = [route.resource.canonical for route in transport.app.router.routes()]
        assert '/mcp/message' in routes
        assert '/health' in routes
        assert '/metrics' in routes
    
    async def test_health_endpoint_response(self):
        """Test health check endpoint."""
        transport = HttpTransport()
        
        # Create mock request
        mock_request = Mock()
        
        response = await transport._health_check(mock_request)
        
        assert response.status == 200
        # Response should be JSON with health info
        assert 'transport' in response.text
    
    async def test_metrics_endpoint_response(self):
        """Test metrics endpoint."""
        transport = HttpTransport()
        
        mock_request = Mock()
        response = await transport._metrics(mock_request)
        
        assert response.status == 200


@pytest.mark.asyncio
class TestSSETransport:
    """Test SSETransport functionality."""
    
    async def test_transport_initialization(self):
        """Test SSE transport initialization."""
        transport = SSETransport(host="0.0.0.0", port=8443)
        assert transport.transport_type == TransportType.SSE
        assert transport.host == "0.0.0.0"
        assert transport.port == 8443
        assert not transport.is_running
        assert transport.connections == {}
    
    async def test_routes_setup(self):
        """Test that SSE routes are properly configured."""
        transport = SSETransport()
        
        routes = [route.resource.canonical for route in transport.app.router.routes()]
        assert '/sse' in routes
        assert '/mcp/message' in routes
        assert '/health' in routes
        assert '/metrics' in routes
    
    async def test_cors_middleware(self):
        """Test CORS middleware functionality."""
        transport = SSETransport()
        
        # Mock request and handler
        mock_request = Mock()
        mock_request.method = "GET"
        mock_handler = AsyncMock()
        mock_response = Mock()
        mock_response.headers = {}
        mock_handler.return_value = mock_response
        
        result = await transport._cors_middleware(mock_request, mock_handler)
        
        assert 'Access-Control-Allow-Origin' in result.headers
        assert result.headers['Access-Control-Allow-Origin'] == '*'
    
    async def test_options_request_handling(self):
        """Test OPTIONS request handling in CORS middleware."""
        transport = SSETransport()
        
        mock_request = Mock()
        mock_request.method = "OPTIONS"
        mock_handler = Mock()
        
        result = await transport._cors_middleware(mock_request, mock_handler)
        
        # Should create response without calling handler for OPTIONS
        assert 'Access-Control-Allow-Origin' in result.headers
        mock_handler.assert_not_called()
    
    async def test_health_check_with_connections(self):
        """Test health check endpoint with active connections."""
        transport = SSETransport()
        
        # Add mock connection
        mock_connection = Mock()
        transport.connections["test_conn"] = mock_connection
        
        mock_request = Mock()
        response = await transport._health_check(mock_request)
        
        assert response.status == 200
        # Should include connection count
        assert "active_connections" in response.text


@pytest.mark.asyncio
class TestTransportAdapter:
    """Test TransportAdapter functionality."""
    
    async def test_adapter_initialization(self):
        """Test transport adapter initialization."""
        source_transport = Mock(spec=BaseTransport)
        target_transport = Mock(spec=BaseTransport)
        
        adapter = TransportAdapter(source_transport, target_transport)
        
        assert adapter.source_transport == source_transport
        assert adapter.target_transport == target_transport
        assert not adapter._running
    
    async def test_adapter_lifecycle(self):
        """Test adapter start/stop lifecycle."""
        source_transport = AsyncMock(spec=BaseTransport)
        target_transport = AsyncMock(spec=BaseTransport)
        
        # Mock receive_messages to return empty async generator
        async def empty_generator():
            return
            yield  # This line will never execute
        
        source_transport.receive_messages.return_value = empty_generator()
        target_transport.receive_messages.return_value = empty_generator()
        
        adapter = TransportAdapter(source_transport, target_transport)
        
        # Start adapter (will complete quickly due to empty generators)
        start_task = asyncio.create_task(adapter.start_adaptation())
        
        # Give it a moment to start
        await asyncio.sleep(0.1)
        
        # Stop adapter
        await adapter.stop_adaptation()
        
        # Wait for start task to complete
        try:
            await asyncio.wait_for(start_task, timeout=1.0)
        except asyncio.TimeoutError:
            start_task.cancel()
        
        # Verify transports were started and stopped
        source_transport.start.assert_called_once()
        target_transport.start.assert_called_once()
        source_transport.stop.assert_called_once()
        target_transport.stop.assert_called_once()


class TestTransportIntegration:
    """Integration tests for transport layer."""
    
    @pytest.mark.asyncio
    async def test_message_flow_through_adapter(self):
        """Test message flow through transport adapter."""
        # This would be a more complex integration test
        # For now, we'll test the basic setup
        
        source_transport = AsyncMock(spec=BaseTransport)
        target_transport = AsyncMock(spec=BaseTransport)
        
        # Mock message flow
        test_message = TransportMessage(type="test", data={"value": 123})
        
        async def message_generator():
            yield test_message
        
        source_transport.receive_messages.return_value = message_generator()
        target_transport.receive_messages.return_value = message_generator()
        
        adapter = TransportAdapter(source_transport, target_transport)
        
        # This test would verify message passing in a real scenario
        assert adapter.source_transport == source_transport
        assert adapter.target_transport == target_transport
    
    def test_transport_type_enumeration(self):
        """Test transport type enumeration."""
        assert TransportType.STDIO.value == "stdio"
        assert TransportType.HTTP.value == "http"
        assert TransportType.SSE.value == "sse"
        assert TransportType.WEBSOCKET.value == "websocket"
    
    @pytest.mark.asyncio
    async def test_concurrent_message_handling(self):
        """Test handling multiple messages concurrently."""
        transport = StdioTransport()
        
        # Mock handlers
        handler1 = AsyncMock()
        handler2 = AsyncMock()
        
        transport.register_handler("type1", handler1)
        transport.register_handler("type2", handler2)
        
        # Create test messages
        message1 = TransportMessage(type="type1", data={"id": 1})
        message2 = TransportMessage(type="type2", data={"id": 2})
        
        # Handle messages concurrently
        await asyncio.gather(
            transport.handle_message(message1),
            transport.handle_message(message2)
        )
        
        handler1.assert_called_once_with(message1)
        handler2.assert_called_once_with(message2)