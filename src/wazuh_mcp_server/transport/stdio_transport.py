"""Stdio transport implementation for backward compatibility."""

import asyncio
import sys
import json
import time
from typing import AsyncIterator, Optional
import logging

from .base import BaseTransport, TransportMessage, TransportType

logger = logging.getLogger(__name__)


class StdioTransport(BaseTransport):
    """Standard input/output transport for local MCP communication."""
    
    def __init__(self):
        super().__init__(TransportType.STDIO)
        self._stdin_reader: Optional[asyncio.StreamReader] = None
        self._stdout_writer: Optional[asyncio.StreamWriter] = None
        self._message_queue = asyncio.Queue()
        self._reader_task: Optional[asyncio.Task] = None
    
    async def start(self) -> None:
        """Start the stdio transport."""
        if self._running:
            return
        
        logger.info("Starting stdio transport")
        
        # Set up stdin/stdout streams
        loop = asyncio.get_event_loop()
        self._stdin_reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(self._stdin_reader)
        await loop.connect_read_pipe(lambda: protocol, sys.stdin)
        
        # Set up stdout writer
        transport, protocol = await loop.connect_write_pipe(
            asyncio.streams.FlowControlMixin, sys.stdout
        )
        self._stdout_writer = asyncio.StreamWriter(transport, protocol, None, loop)
        
        # Start reading messages
        self._reader_task = asyncio.create_task(self._read_stdin())
        self._running = True
        
        logger.info("Stdio transport started successfully")
    
    async def stop(self) -> None:
        """Stop the stdio transport."""
        if not self._running:
            return
        
        logger.info("Stopping stdio transport")
        self._running = False
        
        if self._reader_task:
            self._reader_task.cancel()
            try:
                await self._reader_task
            except asyncio.CancelledError:
                pass
        
        if self._stdout_writer:
            self._stdout_writer.close()
            await self._stdout_writer.wait_closed()
        
        self.signal_shutdown()
        logger.info("Stdio transport stopped")
    
    async def send_message(self, message: TransportMessage) -> None:
        """Send a message via stdout."""
        if not self._running or not self._stdout_writer:
            raise RuntimeError("Transport not running")
        
        try:
            # Add timestamp if not present
            if message.timestamp is None:
                message.timestamp = time.time()
            
            json_data = message.to_json()
            self._stdout_writer.write(json_data.encode('utf-8') + b'\n')
            await self._stdout_writer.drain()
            
            logger.debug(f"Sent message via stdio: {message.type}")
            
        except Exception as e:
            logger.error(f"Failed to send message via stdio: {e}")
            raise
    
    async def receive_messages(self) -> AsyncIterator[TransportMessage]:
        """Receive messages from stdin."""
        while self._running:
            try:
                message = await asyncio.wait_for(
                    self._message_queue.get(), 
                    timeout=1.0
                )
                yield message
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Error receiving message: {e}")
                break
    
    async def _read_stdin(self) -> None:
        """Read messages from stdin."""
        try:
            while self._running and self._stdin_reader:
                line = await self._stdin_reader.readline()
                if not line:
                    break
                
                try:
                    line_str = line.decode('utf-8').strip()
                    if not line_str:
                        continue
                    
                    # Parse JSON message
                    data = json.loads(line_str)
                    message = TransportMessage(
                        type=data.get("type", "unknown"),
                        data=data.get("data", {}),
                        id=data.get("id"),
                        timestamp=data.get("timestamp", time.time())
                    )
                    
                    await self._message_queue.put(message)
                    logger.debug(f"Received message via stdio: {message.type}")
                    
                except json.JSONDecodeError as e:
                    logger.error(f"Invalid JSON received: {e}")
                except Exception as e:
                    logger.error(f"Error processing stdin message: {e}")
                    
        except Exception as e:
            logger.error(f"Stdin reader error: {e}")
        finally:
            logger.debug("Stdin reader stopped")