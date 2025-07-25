"""
FastMCP state management system for persistent session handling.
Implements comprehensive state management across requests and user sessions.
"""

from __future__ import annotations
from typing import Dict, List, Any, Optional, Set, Union, Callable
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass, field
import asyncio
import json
import uuid
import pickle
from pathlib import Path
import weakref

from fastmcp import Context, get_context
from ..models.fastmcp_models import SessionState
from ..utils.fastmcp_exceptions import FastMCPError, ErrorCategory


class StateScope(str, Enum):
    """Scope levels for state management."""
    SESSION = "session"          # Per-user session
    REQUEST = "request"          # Single request
    GLOBAL = "global"           # Server-wide
    USER = "user"               # Per-user across sessions
    TOOL = "tool"               # Per-tool instance
    RESOURCE = "resource"       # Per-resource instance


class StatePersistence(str, Enum):
    """State persistence strategies."""
    MEMORY = "memory"           # In-memory only
    DISK = "disk"              # Persistent to disk
    DISTRIBUTED = "distributed" # Distributed cache
    HYBRID = "hybrid"          # Memory + disk backup


@dataclass
class StateEntry:
    """Individual state entry with metadata."""
    key: str
    value: Any
    scope: StateScope
    created_at: datetime
    last_accessed: datetime
    expires_at: Optional[datetime] = None
    access_count: int = 0
    session_id: Optional[str] = None
    user_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def is_expired(self) -> bool:
        """Check if state entry has expired."""
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at
    
    def touch(self) -> None:
        """Update last accessed time and increment access count."""
        self.last_accessed = datetime.utcnow()
        self.access_count += 1


class StateChangeEvent:
    """Event for state changes."""
    
    def __init__(
        self,
        event_type: str,
        key: str,
        old_value: Any = None,
        new_value: Any = None,
        metadata: Dict[str, Any] = None
    ):
        self.event_id = str(uuid.uuid4())
        self.event_type = event_type
        self.key = key
        self.old_value = old_value
        self.new_value = new_value
        self.timestamp = datetime.utcnow()
        self.metadata = metadata or {}


class SessionManager:
    """
    Comprehensive FastMCP state management system.
    
    Features:
    - Multi-scope state management
    - Session persistence
    - Automatic cleanup
    - State change events
    - Context integration
    - Performance optimization
    """
    
    def __init__(
        self,
        persistence: StatePersistence = StatePersistence.HYBRID,
        default_ttl: int = 3600,
        cleanup_interval: int = 300,
        storage_path: Optional[Path] = None
    ):
        """
        Initialize session manager.
        
        Args:
            persistence: State persistence strategy
            default_ttl: Default TTL for state entries in seconds
            cleanup_interval: Cleanup interval in seconds
            storage_path: Path for disk persistence
        """
        self.persistence = persistence
        self.default_ttl = default_ttl
        self.cleanup_interval = cleanup_interval
        self.storage_path = storage_path or Path.home() / ".wazuh-mcp" / "state"
        
        # State storage
        self.state_store: Dict[str, StateEntry] = {}
        self.session_registry: Dict[str, SessionState] = {}
        
        # Event system
        self.event_handlers: Dict[str, List[Callable]] = {}
        self.state_history: List[StateChangeEvent] = []
        
        # Context tracking
        self.active_contexts: weakref.WeakSet = weakref.WeakSet()
        
        # Locks for thread safety
        self._state_lock = asyncio.Lock()
        self._session_lock = asyncio.Lock()
        
        # Background tasks
        self._cleanup_task: Optional[asyncio.Task] = None
        self._persistence_task: Optional[asyncio.Task] = None
        
        # Initialize storage
        if self.persistence in [StatePersistence.DISK, StatePersistence.HYBRID]:
            self._init_disk_storage()
        
        # Start background tasks
        self._start_background_tasks()
    
    def _init_disk_storage(self) -> None:
        """Initialize disk storage directory."""
        self.storage_path.mkdir(parents=True, exist_ok=True)
        
        # Load existing state if available
        state_file = self.storage_path / "state.json"
        if state_file.exists():
            try:
                with open(state_file, 'r') as f:
                    state_data = json.load(f)
                
                for key, entry_data in state_data.items():
                    # Reconstruct state entry
                    entry = StateEntry(
                        key=entry_data['key'],
                        value=entry_data['value'],
                        scope=StateScope(entry_data['scope']),
                        created_at=datetime.fromisoformat(entry_data['created_at']),
                        last_accessed=datetime.fromisoformat(entry_data['last_accessed']),
                        expires_at=datetime.fromisoformat(entry_data['expires_at']) if entry_data.get('expires_at') else None,
                        access_count=entry_data.get('access_count', 0),
                        session_id=entry_data.get('session_id'),
                        user_id=entry_data.get('user_id'),
                        metadata=entry_data.get('metadata', {})
                    )
                    
                    if not entry.is_expired():
                        self.state_store[key] = entry
                        
            except Exception as e:
                # Log error but continue - don't fail initialization
                print(f"Warning: Failed to load persisted state: {e}")
    
    def _start_background_tasks(self) -> None:
        """Start background maintenance tasks."""
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        
        if self.persistence in [StatePersistence.DISK, StatePersistence.HYBRID]:
            self._persistence_task = asyncio.create_task(self._persistence_loop())
    
    async def _cleanup_loop(self) -> None:
        """Background loop for cleaning up expired state."""
        while True:
            try:
                await asyncio.sleep(self.cleanup_interval)
                await self.cleanup_expired_state()
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"Error in cleanup loop: {e}")
    
    async def _persistence_loop(self) -> None:
        """Background loop for persisting state to disk."""
        while True:
            try:
                await asyncio.sleep(60)  # Persist every minute
                await self._persist_to_disk()
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"Error in persistence loop: {e}")
    
    async def _persist_to_disk(self) -> None:
        """Persist current state to disk."""
        if self.persistence not in [StatePersistence.DISK, StatePersistence.HYBRID]:
            return
        
        async with self._state_lock:
            try:
                state_data = {}
                for key, entry in self.state_store.items():
                    if not entry.is_expired():
                        state_data[key] = {
                            'key': entry.key,
                            'value': entry.value,
                            'scope': entry.scope.value,
                            'created_at': entry.created_at.isoformat(),
                            'last_accessed': entry.last_accessed.isoformat(),
                            'expires_at': entry.expires_at.isoformat() if entry.expires_at else None,
                            'access_count': entry.access_count,
                            'session_id': entry.session_id,
                            'user_id': entry.user_id,
                            'metadata': entry.metadata
                        }
                
                state_file = self.storage_path / "state.json"
                with open(state_file, 'w') as f:
                    json.dump(state_data, f, indent=2)
                    
            except Exception as e:
                print(f"Failed to persist state: {e}")
    
    async def create_session(
        self,
        user_id: Optional[str] = None,
        session_data: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Create a new user session.
        
        Args:
            user_id: User identifier
            session_data: Initial session data
        
        Returns:
            Session ID
        """
        session_id = str(uuid.uuid4())
        
        async with self._session_lock:
            session_state = SessionState(
                session_id=session_id,
                created_at=datetime.utcnow(),
                last_activity=datetime.utcnow(),
                user_id=user_id,
                permissions=set(),
                cached_results=session_data or {}
            )
            
            self.session_registry[session_id] = session_state
        
        # Emit session created event
        await self._emit_event("session_created", session_id, new_value=session_state.dict())
        
        return session_id
    
    async def get_session(self, session_id: str) -> Optional[SessionState]:
        """Get session state by ID."""
        async with self._session_lock:
            session = self.session_registry.get(session_id)
            if session:
                session.last_activity = datetime.utcnow()
            return session
    
    async def set_state(
        self,
        key: str,
        value: Any,
        scope: StateScope = StateScope.SESSION,
        ttl: Optional[int] = None,
        session_id: Optional[str] = None,
        user_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        context: Optional[Context] = None
    ) -> None:
        """
        Set state value.
        
        Args:
            key: State key
            value: State value
            scope: State scope
            ttl: Time to live in seconds
            session_id: Session identifier
            user_id: User identifier
            metadata: Additional metadata
            context: FastMCP context
        """
        # Auto-detect context if not provided
        if context is None:
            try:
                context = get_context()
                if context:
                    self.active_contexts.add(context)
            except:
                pass  # No active context
        
        # Generate full key with scope prefix
        full_key = self._generate_key(key, scope, session_id, user_id)
        
        async with self._state_lock:
            old_entry = self.state_store.get(full_key)
            old_value = old_entry.value if old_entry else None
            
            # Calculate expiration
            expires_at = None
            if ttl is not None:
                expires_at = datetime.utcnow() + timedelta(seconds=ttl)
            elif self.default_ttl > 0:
                expires_at = datetime.utcnow() + timedelta(seconds=self.default_ttl)
            
            # Create new state entry
            entry = StateEntry(
                key=full_key,
                value=value,
                scope=scope,
                created_at=datetime.utcnow(),
                last_accessed=datetime.utcnow(),
                expires_at=expires_at,
                session_id=session_id,
                user_id=user_id,
                metadata=metadata or {}
            )
            
            self.state_store[full_key] = entry
        
        # Emit state change event
        await self._emit_event("state_set", full_key, old_value, value, metadata)
        
        # Log to context if available
        if context:
            await context.debug(f"State set: {key} in scope {scope.value}")
    
    async def get_state(
        self,
        key: str,
        scope: StateScope = StateScope.SESSION,
        default: Any = None,
        session_id: Optional[str] = None,
        user_id: Optional[str] = None,
        context: Optional[Context] = None
    ) -> Any:
        """
        Get state value.
        
        Args:
            key: State key
            scope: State scope
            default: Default value if not found
            session_id: Session identifier
            user_id: User identifier
            context: FastMCP context
        
        Returns:
            State value or default
        """
        full_key = self._generate_key(key, scope, session_id, user_id)
        
        async with self._state_lock:
            entry = self.state_store.get(full_key)
            
            if entry is None:
                return default
            
            if entry.is_expired():
                del self.state_store[full_key]
                return default
            
            entry.touch()
            
            # Log to context if available
            if context:
                await context.debug(f"State retrieved: {key} from scope {scope.value}")
            
            return entry.value
    
    async def delete_state(
        self,
        key: str,
        scope: StateScope = StateScope.SESSION,
        session_id: Optional[str] = None,
        user_id: Optional[str] = None,
        context: Optional[Context] = None
    ) -> bool:
        """
        Delete state value.
        
        Args:
            key: State key
            scope: State scope
            session_id: Session identifier
            user_id: User identifier
            context: FastMCP context
        
        Returns:
            True if deleted, False if not found
        """
        full_key = self._generate_key(key, scope, session_id, user_id)
        
        async with self._state_lock:
            entry = self.state_store.get(full_key)
            if entry is None:
                return False
            
            old_value = entry.value
            del self.state_store[full_key]
        
        # Emit state change event
        await self._emit_event("state_deleted", full_key, old_value, None)
        
        # Log to context if available
        if context:
            await context.debug(f"State deleted: {key} from scope {scope.value}")
        
        return True
    
    async def list_state_keys(
        self,
        scope: Optional[StateScope] = None,
        session_id: Optional[str] = None,
        user_id: Optional[str] = None,
        include_expired: bool = False
    ) -> List[str]:
        """
        List state keys matching criteria.
        
        Args:
            scope: Filter by scope
            session_id: Filter by session ID
            user_id: Filter by user ID
            include_expired: Include expired entries
        
        Returns:
            List of matching keys
        """
        async with self._state_lock:
            matching_keys = []
            
            for key, entry in self.state_store.items():
                if not include_expired and entry.is_expired():
                    continue
                
                if scope and entry.scope != scope:
                    continue
                
                if session_id and entry.session_id != session_id:
                    continue
                
                if user_id and entry.user_id != user_id:
                    continue
                
                # Extract original key (remove scope prefix)
                original_key = key.split(':', 2)[-1] if ':' in key else key
                matching_keys.append(original_key)
            
            return matching_keys
    
    async def clear_scope(
        self,
        scope: StateScope,
        session_id: Optional[str] = None,
        user_id: Optional[str] = None
    ) -> int:
        """
        Clear all state in a specific scope.
        
        Args:
            scope: Scope to clear
            session_id: Filter by session ID
            user_id: Filter by user ID
        
        Returns:
            Number of entries cleared
        """
        async with self._state_lock:
            keys_to_delete = []
            
            for key, entry in self.state_store.items():
                if entry.scope != scope:
                    continue
                
                if session_id and entry.session_id != session_id:
                    continue
                
                if user_id and entry.user_id != user_id:
                    continue
                
                keys_to_delete.append(key)
            
            for key in keys_to_delete:
                del self.state_store[key]
        
        # Emit bulk clear event
        await self._emit_event("scope_cleared", f"{scope.value}:{session_id}:{user_id}", 
                              metadata={"cleared_count": len(keys_to_delete)})
        
        return len(keys_to_delete)
    
    async def cleanup_expired_state(self) -> int:
        """Clean up expired state entries."""
        async with self._state_lock:
            expired_keys = [
                key for key, entry in self.state_store.items()
                if entry.is_expired()
            ]
            
            for key in expired_keys:
                del self.state_store[key]
        
        if expired_keys:
            await self._emit_event("expired_cleanup", "system", 
                                  metadata={"cleaned_count": len(expired_keys)})
        
        return len(expired_keys)
    
    async def get_state_stats(self) -> Dict[str, Any]:
        """Get comprehensive state statistics."""
        async with self._state_lock:
            stats = {
                "total_entries": len(self.state_store),
                "scope_breakdown": {},
                "session_count": len(self.session_registry),
                "expired_entries": 0,
                "memory_usage": 0,
                "oldest_entry": None,
                "most_accessed": None
            }
            
            oldest_entry = None
            most_accessed = None
            max_access_count = 0
            
            for entry in self.state_store.values():
                # Scope breakdown
                scope_name = entry.scope.value
                stats["scope_breakdown"][scope_name] = stats["scope_breakdown"].get(scope_name, 0) + 1
                
                # Expired count
                if entry.is_expired():
                    stats["expired_entries"] += 1
                
                # Oldest entry
                if oldest_entry is None or entry.created_at < oldest_entry.created_at:
                    oldest_entry = entry
                
                # Most accessed
                if entry.access_count > max_access_count:
                    max_access_count = entry.access_count
                    most_accessed = entry
            
            if oldest_entry:
                stats["oldest_entry"] = {
                    "key": oldest_entry.key,
                    "created_at": oldest_entry.created_at.isoformat() + 'Z',
                    "age_seconds": (datetime.utcnow() - oldest_entry.created_at).total_seconds()
                }
            
            if most_accessed:
                stats["most_accessed"] = {
                    "key": most_accessed.key,
                    "access_count": most_accessed.access_count,
                    "last_accessed": most_accessed.last_accessed.isoformat() + 'Z'
                }
            
            return stats
    
    def _generate_key(
        self,
        key: str,
        scope: StateScope,
        session_id: Optional[str] = None,
        user_id: Optional[str] = None
    ) -> str:
        """Generate full key with scope and identifiers."""
        parts = [scope.value]
        
        if scope == StateScope.SESSION and session_id:
            parts.append(session_id)
        elif scope == StateScope.USER and user_id:
            parts.append(user_id)
        
        parts.append(key)
        return ':'.join(parts)
    
    async def _emit_event(
        self,
        event_type: str,
        key: str,
        old_value: Any = None,
        new_value: Any = None,
        metadata: Dict[str, Any] = None
    ) -> None:
        """Emit state change event."""
        event = StateChangeEvent(event_type, key, old_value, new_value, metadata)
        self.state_history.append(event)
        
        # Keep history size manageable
        if len(self.state_history) > 1000:
            self.state_history = self.state_history[-500:]  # Keep last 500 events
        
        # Notify event handlers
        handlers = self.event_handlers.get(event_type, [])
        for handler in handlers:
            try:
                if asyncio.iscoroutinefunction(handler):
                    await handler(event)
                else:
                    handler(event)
            except Exception as e:
                print(f"Error in event handler: {e}")
    
    def add_event_handler(self, event_type: str, handler: Callable) -> None:
        """Add event handler for state changes."""
        if event_type not in self.event_handlers:
            self.event_handlers[event_type] = []
        self.event_handlers[event_type].append(handler)
    
    def remove_event_handler(self, event_type: str, handler: Callable) -> None:
        """Remove event handler."""
        if event_type in self.event_handlers:
            try:
                self.event_handlers[event_type].remove(handler)
            except ValueError:
                pass
    
    async def shutdown(self) -> None:
        """Shutdown session manager and cleanup resources."""
        # Cancel background tasks
        if self._cleanup_task:
            self._cleanup_task.cancel()
        if self._persistence_task:
            self._persistence_task.cancel()
        
        # Final persistence
        if self.persistence in [StatePersistence.DISK, StatePersistence.HYBRID]:
            await self._persist_to_disk()
        
        # Clear state
        async with self._state_lock:
            self.state_store.clear()
        
        async with self._session_lock:
            self.session_registry.clear()


# ============================================================================
# GLOBAL SESSION MANAGER INSTANCE
# ============================================================================

# Global session manager instance
session_manager: Optional[SessionManager] = None


def get_session_manager() -> SessionManager:
    """Get or create global session manager instance."""
    global session_manager
    if session_manager is None:
        session_manager = SessionManager()
    return session_manager


# ============================================================================
# FASTMCP CONTEXT INTEGRATION
# ============================================================================

async def set_context_state(key: str, value: Any, **kwargs) -> None:
    """Set state using current FastMCP context."""
    try:
        context = get_context()
        sm = get_session_manager()
        await sm.set_state(key, value, context=context, **kwargs)
    except Exception as e:
        raise FastMCPError(
            message=f"Failed to set context state: {str(e)}",
            category=ErrorCategory.INTERNAL_ERROR
        )


async def get_context_state(key: str, default: Any = None, **kwargs) -> Any:
    """Get state using current FastMCP context."""
    try:
        context = get_context()
        sm = get_session_manager()
        return await sm.get_state(key, default=default, context=context, **kwargs)
    except Exception as e:
        raise FastMCPError(
            message=f"Failed to get context state: {str(e)}",
            category=ErrorCategory.INTERNAL_ERROR
        )