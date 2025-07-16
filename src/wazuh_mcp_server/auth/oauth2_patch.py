"""
Minimal patch to add persistent storage to OAuth2Server
This provides a non-breaking enhancement to enable persistence
"""

import os
import logging
from .storage_wrapper import OAuth2StorageManager

logger = logging.getLogger(__name__)


def patch_oauth2_server(oauth2_server):
    """
    Patch existing OAuth2Server instance to use persistent storage.
    This is a non-breaking enhancement that maintains full compatibility.
    """
    # Check if persistence is enabled
    enable_persistence = os.getenv("OAUTH2_ENABLE_PERSISTENCE", "true").lower() == "true"
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
    
    if not enable_persistence:
        logger.info("OAuth2 persistence disabled via OAUTH2_ENABLE_PERSISTENCE=false")
        return oauth2_server
    
    try:
        # Create storage manager
        storage_manager = OAuth2StorageManager(redis_url, enable_persistence)
        
        # Replace in-memory dicts with persistent ones
        original_users = oauth2_server.users
        original_clients = oauth2_server.clients
        original_codes = oauth2_server.authorization_codes
        original_tokens = oauth2_server.active_tokens
        
        # Initialize storage
        async def initialize_storage():
            success = await storage_manager.initialize()
            if success:
                # Copy existing data to persistent storage
                for user_id, user in original_users.items():
                    storage_manager.users[user_id] = user
                
                for client_id, client in original_clients.items():
                    storage_manager.clients[client_id] = client
                
                for code, auth_code in original_codes.items():
                    storage_manager.authorization_codes[code] = auth_code
                
                for token, token_obj in original_tokens.items():
                    storage_manager.active_tokens[token] = token_obj
                
                # Replace the dictionaries
                oauth2_server.users = storage_manager.users
                oauth2_server.clients = storage_manager.clients
                oauth2_server.authorization_codes = storage_manager.authorization_codes
                oauth2_server.active_tokens = storage_manager.active_tokens
                
                # Add storage manager to server for health checks
                oauth2_server._storage_manager = storage_manager
                
                logger.info("OAuth2Server enhanced with persistent storage")
            else:
                logger.warning("Failed to enable OAuth2 persistence, continuing with in-memory storage")
        
        # Initialize storage asynchronously
        import asyncio
        asyncio.create_task(initialize_storage())
        
    except Exception as e:
        logger.error(f"Failed to patch OAuth2Server with persistence: {e}")
        logger.warning("Continuing with in-memory storage")
    
    return oauth2_server


def get_oauth2_storage_health(oauth2_server) -> dict:
    """Get storage health information from patched OAuth2Server."""
    if hasattr(oauth2_server, '_storage_manager'):
        storage_manager = oauth2_server._storage_manager
        return {
            "persistent_storage_enabled": True,
            "storage_healthy": asyncio.create_task(storage_manager.health_check()),
            "stats": storage_manager.get_stats()
        }
    else:
        return {
            "persistent_storage_enabled": False,
            "storage_healthy": True,
            "stats": {
                "users_count": len(oauth2_server.users),
                "clients_count": len(oauth2_server.clients),
                "active_codes": len(oauth2_server.authorization_codes),
                "active_tokens": len(oauth2_server.active_tokens),
                "storage_type": "memory"
            }
        }