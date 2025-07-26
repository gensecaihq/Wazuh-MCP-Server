"""Configuration management for Wazuh MCP Server."""

import os
from dataclasses import dataclass
from typing import Optional


class ConfigurationError(Exception):
    """Raised when configuration is invalid."""
    pass


@dataclass
class WazuhConfig:
    """Wazuh configuration settings."""
    
    # Required settings
    wazuh_host: str
    wazuh_port: int = 55000
    wazuh_user: str = ""
    wazuh_pass: str = ""
    
    # Optional settings
    wazuh_indexer_host: Optional[str] = None
    wazuh_indexer_port: int = 9200
    wazuh_indexer_user: Optional[str] = None
    wazuh_indexer_pass: Optional[str] = None
    
    # Security
    verify_ssl: bool = True
    request_timeout_seconds: int = 30
    
    # Performance
    max_alerts_per_query: int = 1000
    max_connections: int = 10
    
    @classmethod
    def from_env(cls) -> 'WazuhConfig':
        """Create configuration from environment variables."""
        host = os.getenv("WAZUH_HOST")
        user = os.getenv("WAZUH_USER")
        password = os.getenv("WAZUH_PASS")
        
        if not all([host, user, password]):
            raise ConfigurationError("Missing required environment variables: WAZUH_HOST, WAZUH_USER, WAZUH_PASS")
        
        # Helper function for safe integer conversion
        def safe_int_env(key: str, default: str, min_val: int = 1, max_val: int = None) -> int:
            try:
                value = int(os.getenv(key, default))
                if value < min_val:
                    raise ValueError(f"{key} must be >= {min_val}")
                if max_val and value > max_val:
                    raise ValueError(f"{key} must be <= {max_val}")
                return value
            except ValueError as e:
                raise ConfigurationError(f"Invalid {key} value '{os.getenv(key)}': {e}")
        
        return cls(
            wazuh_host=host,
            wazuh_port=safe_int_env("WAZUH_PORT", "55000", 1, 65535),
            wazuh_user=user,
            wazuh_pass=password,
            wazuh_indexer_host=os.getenv("WAZUH_INDEXER_HOST"),
            wazuh_indexer_port=safe_int_env("WAZUH_INDEXER_PORT", "9200", 1, 65535),
            wazuh_indexer_user=os.getenv("WAZUH_INDEXER_USER"),
            wazuh_indexer_pass=os.getenv("WAZUH_INDEXER_PASS"),
            verify_ssl=os.getenv("VERIFY_SSL", "true").lower() == "true",
            request_timeout_seconds=safe_int_env("REQUEST_TIMEOUT_SECONDS", "30", 1, 300),
            max_alerts_per_query=safe_int_env("MAX_ALERTS_PER_QUERY", "1000", 1, 10000),
            max_connections=safe_int_env("MAX_CONNECTIONS", "10", 1, 100)
        )
    
    @property
    def base_url(self) -> str:
        """Get the base URL for Wazuh API."""
        return f"https://{self.wazuh_host}:{self.wazuh_port}"