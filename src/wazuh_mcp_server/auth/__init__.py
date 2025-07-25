"""Authentication module for Wazuh MCP Server."""

from .secure_auth import (
    SecureAuthManager,
    AuthToken,
    get_auth_manager
)

__all__ = [
    'SecureAuthManager',
    'AuthToken',
    'get_auth_manager'
]