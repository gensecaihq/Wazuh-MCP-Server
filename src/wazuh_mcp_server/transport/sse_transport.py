"""Server-Sent Events (SSE) transport for real-time MCP communication."""

import asyncio
import json
import time
import uuid
from typing import AsyncIterator, Dict, Any, Optional, Set
import logging

from aiohttp import web
from sse_starlette import EventSourceResponse

from .base import BaseTransport, TransportMessage, TransportType

logger = logging.getLogger(__name__)


class SSEConnection:
    """Represents an active SSE connection."""
    
    def __init__(self, connection_id: str, request: web.Request):
        self.connection_id = connection_id
        self.request = request
        self.message_queue = asyncio.Queue()
        self.connected = True
        self.created_at = time.time()
    
    async def send_message(self, message: TransportMessage) -> None:
        """Send a message to this connection."""
        if self.connected:
            await self.message_queue.put(message)
    
    async def get_messages(self) -> AsyncIterator[TransportMessage]:
        """Get messages for this connection."""
        while self.connected:
            try:
                message = await asyncio.wait_for(
                    self.message_queue.get(),
                    timeout=1.0
                )
                yield message
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Error getting message for connection {self.connection_id}: {e}")
                break
    
    def disconnect(self) -> None:
        """Disconnect this connection."""
        self.connected = False


class SSETransport(BaseTransport):
    """Server-Sent Events transport for real-time MCP communication."""
    
    def __init__(self, host: str = "0.0.0.0", port: int = 8080, ssl_context=None):
        super().__init__(TransportType.SSE)
        self.host = host
        self.port = port
        self.ssl_context = ssl_context
        self.app = web.Application()
        self.runner: Optional[web.AppRunner] = None
        self.site: Optional[web.TCPSite] = None
        
        # Connection management
        self.connections: Dict[str, SSEConnection] = {}
        self.connection_lock = asyncio.Lock()
        
        # Message handling
        self._incoming_queue = asyncio.Queue()
        
        self._setup_routes()
    
    def _setup_routes(self) -> None:
        """Setup SSE routes."""
        self.app.router.add_get('/sse', self._handle_sse_connection)
        self.app.router.add_post('/mcp/message', self._handle_message)
        self.app.router.add_get('/health', self._health_check)
        self.app.router.add_get('/metrics', self._metrics)
        
        # CORS middleware
        self.app.middlewares.append(self._cors_middleware)
    
    async def _cors_middleware(self, request: web.Request, handler) -> web.Response:
        """CORS middleware for cross-origin requests."""
        if request.method == "OPTIONS":
            response = web.Response()
        else:
            response = await handler(request)
        
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, Cache-Control'
        response.headers['Access-Control-Expose-Headers'] = 'X-Connection-ID'
        return response
    
    async def start(self) -> None:
        """Start the SSE server."""
        if self._running:
            return
        
        logger.info(f"Starting SSE transport on {self.host}:{self.port}")
        
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        
        self.site = web.TCPSite(
            self.runner,
            self.host,
            self.port,
            ssl_context=self.ssl_context
        )
        await self.site.start()
        
        self._running = True
        logger.info(f"SSE transport started on {'https' if self.ssl_context else 'http'}://{self.host}:{self.port}")
    
    async def stop(self) -> None:
        """Stop the SSE server."""
        if not self._running:
            return
        
        logger.info("Stopping SSE transport")
        self._running = False
        
        # Disconnect all connections
        async with self.connection_lock:
            for connection in self.connections.values():
                connection.disconnect()
            self.connections.clear()
        
        if self.site:
            await self.site.stop()
        
        if self.runner:
            await self.runner.cleanup()
        
        self.signal_shutdown()
        logger.info("SSE transport stopped")
    
    async def send_message(self, message: TransportMessage) -> None:
        """Send a message to all connected clients."""
        if not self._running:
            raise RuntimeError("Transport not running")
        
        async with self.connection_lock:
            if not self.connections:
                logger.warning("No SSE connections available to send message")
                return
            
            # Send to all connections
            for connection in list(self.connections.values()):
                try:
                    await connection.send_message(message)
                except Exception as e:
                    logger.error(f"Failed to send message to connection {connection.connection_id}: {e}")
        
        logger.debug(f"Sent SSE message to {len(self.connections)} connections: {message.type}")
    
    async def receive_messages(self) -> AsyncIterator[TransportMessage]:
        """Receive messages from HTTP posts."""
        while self._running:
            try:
                message = await asyncio.wait_for(
                    self._incoming_queue.get(),
                    timeout=1.0
                )
                yield message
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Error receiving SSE message: {e}")
                break
    
    async def _handle_sse_connection(self, request: web.Request) -> web.Response:
        """Handle new SSE connection."""
        connection_id = str(uuid.uuid4())
        
        async def event_generator():
            # Create connection
            connection = SSEConnection(connection_id, request)
            
            async with self.connection_lock:
                self.connections[connection_id] = connection
            
            logger.info(f"New SSE connection: {connection_id}")
            
            try:
                # Send initial connection message
                init_message = TransportMessage(
                    type="connection_established",
                    data={"connection_id": connection_id},
                    id=str(uuid.uuid4()),
                    timestamp=time.time()
                )
                
                yield {
                    "event": "connection",
                    "data": init_message.to_json(),
                    "id": init_message.id
                }
                
                # Stream messages
                async for message in connection.get_messages():
                    if not connection.connected:
                        break
                    
                    yield {
                        "event": message.type,
                        "data": message.to_json(),
                        "id": message.id or str(uuid.uuid4())
                    }
                    
            except Exception as e:
                logger.error(f"SSE connection {connection_id} error: {e}")
            finally:
                # Clean up connection
                async with self.connection_lock:
                    self.connections.pop(connection_id, None)
                connection.disconnect()
                logger.info(f"SSE connection closed: {connection_id}")
        
        response = EventSourceResponse(event_generator())
        response.headers['X-Connection-ID'] = connection_id
        return response
    
    async def _handle_message(self, request: web.Request) -> web.Response:
        """Handle incoming MCP messages via HTTP POST."""
        try:
            data = await request.json()
            
            message = TransportMessage(
                type=data.get("type", "unknown"),
                data=data.get("data", {}),
                id=data.get("id"),
                timestamp=data.get("timestamp", time.time())
            )
            
            await self._incoming_queue.put(message)
            
            logger.debug(f"Received SSE message: {message.type}")
            
            return web.json_response({
                "status": "success",
                "message_id": message.id
            })
            
        except json.JSONDecodeError:
            return web.json_response(
                {"error": "Invalid JSON"},
                status=400
            )
        except Exception as e:
            logger.error(f"Error handling SSE message: {e}")
            return web.json_response(
                {"error": "Internal server error"},
                status=500
            )
    
    async def _health_check(self, request: web.Request) -> web.Response:
        """Health check endpoint."""
        async with self.connection_lock:
            active_connections = len(self.connections)
        
        return web.json_response({
            "status": "healthy",
            "transport": "sse",
            "active_connections": active_connections,
            "timestamp": time.time()
        })
    
    async def _metrics(self, request: web.Request) -> web.Response:
        """Metrics endpoint."""
        async with self.connection_lock:
            connection_info = [
                {
                    "id": conn.connection_id,
                    "connected_at": conn.created_at,
                    "queue_size": conn.message_queue.qsize()
                }
                for conn in self.connections.values()
            ]
        
        return web.json_response({
            "transport_type": "sse",
            "running": self._running,
            "total_connections": len(connection_info),
            "connections": connection_info,
            "incoming_queue_size": self._incoming_queue.qsize()
        })