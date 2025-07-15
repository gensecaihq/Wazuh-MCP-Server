"""HTTP transport implementation for remote MCP communication."""

import asyncio
import json
import time
from typing import AsyncIterator, Dict, Any, Optional
import logging
from urllib.parse import urlparse

import aiohttp
from aiohttp import web

from .base import BaseTransport, TransportMessage, TransportType

logger = logging.getLogger(__name__)


class HttpTransport(BaseTransport):
    """HTTP transport for remote MCP communication."""
    
    def __init__(self, host: str = "0.0.0.0", port: int = 8080, ssl_context=None):
        super().__init__(TransportType.HTTP)
        self.host = host
        self.port = port
        self.ssl_context = ssl_context
        self.app = web.Application()
        self.runner: Optional[web.AppRunner] = None
        self.site: Optional[web.TCPSite] = None
        self._request_queue = asyncio.Queue()
        self._setup_routes()
    
    def _setup_routes(self) -> None:
        """Setup HTTP routes."""
        self.app.router.add_post('/mcp/message', self._handle_message)
        self.app.router.add_get('/health', self._health_check)
        self.app.router.add_get('/metrics', self._metrics)
        
        # CORS middleware
        self.app.middlewares.append(self._cors_middleware)
    
    async def _cors_middleware(self, request: web.Request, handler) -> web.Response:
        """CORS middleware for cross-origin requests."""
        response = await handler(request)
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        return response
    
    async def start(self) -> None:
        """Start the HTTP server."""
        if self._running:
            return
        
        logger.info(f"Starting HTTP transport on {self.host}:{self.port}")
        
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
        logger.info(f"HTTP transport started on {'https' if self.ssl_context else 'http'}://{self.host}:{self.port}")
    
    async def stop(self) -> None:
        """Stop the HTTP server."""
        if not self._running:
            return
        
        logger.info("Stopping HTTP transport")
        self._running = False
        
        if self.site:
            await self.site.stop()
        
        if self.runner:
            await self.runner.cleanup()
        
        self.signal_shutdown()
        logger.info("HTTP transport stopped")
    
    async def send_message(self, message: TransportMessage) -> None:
        """Send a message via HTTP (for client mode)."""
        # This would be used when acting as an HTTP client
        # For now, we'll store in queue for testing
        await self._request_queue.put(message)
        logger.debug(f"Queued HTTP message: {message.type}")
    
    async def receive_messages(self) -> AsyncIterator[TransportMessage]:
        """Receive messages from HTTP requests."""
        while self._running:
            try:
                message = await asyncio.wait_for(
                    self._request_queue.get(),
                    timeout=1.0
                )
                yield message
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Error receiving HTTP message: {e}")
                break
    
    async def _handle_message(self, request: web.Request) -> web.Response:
        """Handle incoming MCP messages."""
        try:
            # Parse request body
            data = await request.json()
            
            # Create transport message
            message = TransportMessage(
                type=data.get("type", "unknown"),
                data=data.get("data", {}),
                id=data.get("id"),
                timestamp=data.get("timestamp", time.time())
            )
            
            # Queue message for processing
            await self._request_queue.put(message)
            
            logger.debug(f"Received HTTP message: {message.type}")
            
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
            logger.error(f"Error handling HTTP message: {e}")
            return web.json_response(
                {"error": "Internal server error"}, 
                status=500
            )
    
    async def _health_check(self, request: web.Request) -> web.Response:
        """Health check endpoint."""
        return web.json_response({
            "status": "healthy",
            "transport": "http",
            "timestamp": time.time()
        })
    
    async def _metrics(self, request: web.Request) -> web.Response:
        """Metrics endpoint."""
        return web.json_response({
            "transport_type": "http",
            "running": self._running,
            "queue_size": self._request_queue.qsize() if self._request_queue else 0
        })


class HttpClient:
    """HTTP client for sending MCP messages."""
    
    def __init__(self, base_url: str, timeout: int = 30):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def start(self) -> None:
        """Start the HTTP client."""
        if self.session:
            return
        
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        self.session = aiohttp.ClientSession(timeout=timeout)
        logger.info(f"HTTP client started for {self.base_url}")
    
    async def stop(self) -> None:
        """Stop the HTTP client."""
        if self.session:
            await self.session.close()
            self.session = None
        logger.info("HTTP client stopped")
    
    async def send_message(self, message: TransportMessage) -> Dict[str, Any]:
        """Send a message to the HTTP server."""
        if not self.session:
            raise RuntimeError("HTTP client not started")
        
        url = f"{self.base_url}/mcp/message"
        
        try:
            async with self.session.post(url, json={
                "type": message.type,
                "data": message.data,
                "id": message.id,
                "timestamp": message.timestamp
            }) as response:
                response.raise_for_status()
                return await response.json()
                
        except Exception as e:
            logger.error(f"Failed to send HTTP message: {e}")
            raise
    
    async def health_check(self) -> Dict[str, Any]:
        """Check server health."""
        if not self.session:
            raise RuntimeError("HTTP client not started")
        
        url = f"{self.base_url}/health"
        
        try:
            async with self.session.get(url) as response:
                response.raise_for_status()
                return await response.json()
                
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            raise