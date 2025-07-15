"""Base transport interface for MCP communication."""

import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, Optional, AsyncIterator, Callable
from enum import Enum
import json
import logging

logger = logging.getLogger(__name__)


class TransportType(Enum):
    """Transport type enumeration."""
    STDIO = "stdio"
    HTTP = "http"
    SSE = "sse"
    WEBSOCKET = "websocket"


@dataclass
class TransportMessage:
    """Message container for transport communication."""
    type: str
    data: Dict[str, Any]
    id: Optional[str] = None
    timestamp: Optional[float] = None
    
    def to_json(self) -> str:
        """Convert message to JSON string."""
        return json.dumps({
            "type": self.type,
            "data": self.data,
            "id": self.id,
            "timestamp": self.timestamp
        }, separators=(',', ':'))
    
    @classmethod
    def from_json(cls, json_str: str) -> "TransportMessage":
        """Create message from JSON string."""
        data = json.loads(json_str)
        return cls(
            type=data["type"],
            data=data["data"],
            id=data.get("id"),
            timestamp=data.get("timestamp")
        )


class BaseTransport(ABC):
    """Base class for all transport implementations."""
    
    def __init__(self, transport_type: TransportType):
        self.transport_type = transport_type
        self._running = False
        self._message_handlers: Dict[str, Callable] = {}
        self._shutdown_event = asyncio.Event()
    
    @abstractmethod
    async def start(self) -> None:
        """Start the transport."""
        pass
    
    @abstractmethod
    async def stop(self) -> None:
        """Stop the transport."""
        pass
    
    @abstractmethod
    async def send_message(self, message: TransportMessage) -> None:
        """Send a message through the transport."""
        pass
    
    @abstractmethod
    async def receive_messages(self) -> AsyncIterator[TransportMessage]:
        """Receive messages from the transport."""
        pass
    
    def register_handler(self, message_type: str, handler: Callable) -> None:
        """Register a message handler."""
        self._message_handlers[message_type] = handler
        logger.debug(f"Registered handler for message type: {message_type}")
    
    async def handle_message(self, message: TransportMessage) -> None:
        """Handle an incoming message."""
        handler = self._message_handlers.get(message.type)
        if handler:
            try:
                await handler(message)
            except Exception as e:
                logger.error(f"Error handling message {message.type}: {e}")
        else:
            logger.warning(f"No handler registered for message type: {message.type}")
    
    @property
    def is_running(self) -> bool:
        """Check if transport is running."""
        return self._running
    
    async def wait_for_shutdown(self) -> None:
        """Wait for shutdown signal."""
        await self._shutdown_event.wait()
    
    def signal_shutdown(self) -> None:
        """Signal shutdown."""
        self._shutdown_event.set()


class TransportAdapter:
    """Adapter to convert between different transport protocols."""
    
    def __init__(self, source_transport: BaseTransport, target_transport: BaseTransport):
        self.source_transport = source_transport
        self.target_transport = target_transport
        self._running = False
    
    async def start_adaptation(self) -> None:
        """Start adapting messages between transports."""
        self._running = True
        
        # Start both transports
        await self.source_transport.start()
        await self.target_transport.start()
        
        # Create adaptation tasks
        tasks = [
            asyncio.create_task(self._adapt_source_to_target()),
            asyncio.create_task(self._adapt_target_to_source())
        ]
        
        try:
            await asyncio.gather(*tasks)
        except Exception as e:
            logger.error(f"Transport adaptation error: {e}")
        finally:
            await self.stop_adaptation()
    
    async def stop_adaptation(self) -> None:
        """Stop transport adaptation."""
        self._running = False
        await self.source_transport.stop()
        await self.target_transport.stop()
    
    async def _adapt_source_to_target(self) -> None:
        """Adapt messages from source to target."""
        async for message in self.source_transport.receive_messages():
            if not self._running:
                break
            await self.target_transport.send_message(message)
    
    async def _adapt_target_to_source(self) -> None:
        """Adapt messages from target to source."""
        async for message in self.target_transport.receive_messages():
            if not self._running:
                break
            await self.source_transport.send_message(message)