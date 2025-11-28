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
    wazuh_user: str
    wazuh_pass: str
    
    # Optional settings with sensible defaults
    wazuh_port: int = 55000
    verify_ssl: bool = True
    
    # Indexer settings (optional)
    wazuh_indexer_host: Optional[str] = None
    wazuh_indexer_port: int = 9200
    wazuh_indexer_user: Optional[str] = None
    wazuh_indexer_pass: Optional[str] = None
    
    # Transport settings
    mcp_transport: str = "http"  # Default to HTTP/SSE mode
    mcp_host: str = "0.0.0.0"
    mcp_port: int = 3000
    
    # Advanced settings (rarely need to change)
    request_timeout_seconds: int = 30
    max_alerts_per_query: int = 1000
    max_connections: int = 10
    
    @classmethod
    def from_env(cls) -> 'WazuhConfig':
        """Create configuration from environment variables."""
        # Load from config file if exists
        config_file = "./config/wazuh.env"
        if os.path.exists(config_file):
            from dotenv import load_dotenv
            load_dotenv(config_file)
        
        # Required settings
        host = os.getenv("WAZUH_HOST")
        user = os.getenv("WAZUH_USER")
        password = os.getenv("WAZUH_PASS")
        
        if not all([host, user, password]):
            raise ConfigurationError(
                "Missing required Wazuh settings.\n"
                "Please run: ./scripts/configure.sh\n"
                "Or set: WAZUH_HOST, WAZUH_USER, WAZUH_PASS"
            )
        
        # Helper function for safe integer conversion
        def safe_int_env(key: str, default: str, min_val: int = 1, max_val: int = None) -> int:
            try:
                env_value = os.getenv(key, default)
                value = int(env_value)
                if value < min_val:
                    raise ValueError(f"{key} must be >= {min_val}")
                if max_val and value > max_val:
                    raise ValueError(f"{key} must be <= {max_val}")
                return value
            except (ValueError, TypeError) as e:
                raise ConfigurationError(f"Invalid {key} value '{os.getenv(key)}': {e}")
        
        # Parse optional settings with simpler approach
        port = int(os.getenv("WAZUH_PORT", "55000"))
        verify_ssl = os.getenv("VERIFY_SSL", "true").lower() == "true"
        
        # Create config with defaults for most settings
        config = cls(
            wazuh_host=host,
            wazuh_user=user,
            wazuh_pass=password,
            wazuh_port=port,
            verify_ssl=verify_ssl,
            wazuh_indexer_host=os.getenv("WAZUH_INDEXER_HOST"),
            wazuh_indexer_port=int(os.getenv("WAZUH_INDEXER_PORT", "9200")),
            wazuh_indexer_user=os.getenv("WAZUH_INDEXER_USER"),
            wazuh_indexer_pass=os.getenv("WAZUH_INDEXER_PASS"),
            mcp_transport=os.getenv("MCP_TRANSPORT", "http"),  # Default to HTTP/SSE
            mcp_host=os.getenv("MCP_HOST", "0.0.0.0"),
            mcp_port=int(os.getenv("MCP_PORT", "3000")),
            request_timeout_seconds=int(os.getenv("REQUEST_TIMEOUT_SECONDS", "30")),
            max_alerts_per_query=int(os.getenv("MAX_ALERTS_PER_QUERY", "1000")),
            max_connections=int(os.getenv("MAX_CONNECTIONS", "10"))
        )
        
        return config
    
    @property
    def base_url(self) -> str:
        """Get the base URL for Wazuh API."""
        return f"https://{self.wazuh_host}:{self.wazuh_port}"


@dataclass
class ServerConfig:
    """Server configuration for MCP Server."""
    # MCP Server settings
    MCP_HOST: str = "0.0.0.0"
    MCP_PORT: int = 3000

    # Authentication settings
    AUTH_SECRET_KEY: str = ""
    TOKEN_LIFETIME_HOURS: int = 24

    # Authentication mode: "bearer" (default), "oauth", or "none" (authless)
    AUTH_MODE: str = "bearer"

    # OAuth settings (when AUTH_MODE=oauth)
    OAUTH_ISSUER_URL: str = ""  # Will be auto-set to server URL if not provided
    OAUTH_ENABLE_DCR: bool = True  # Dynamic Client Registration
    OAUTH_ACCESS_TOKEN_TTL: int = 3600  # 1 hour
    OAUTH_REFRESH_TOKEN_TTL: int = 86400  # 24 hours
    OAUTH_AUTHORIZATION_CODE_TTL: int = 600  # 10 minutes

    # CORS settings
    ALLOWED_ORIGINS: str = "https://claude.ai,http://localhost:*"

    # Wazuh connection settings
    WAZUH_HOST: str = ""
    WAZUH_USER: str = ""
    WAZUH_PASS: str = ""
    WAZUH_PORT: int = 55000
    WAZUH_VERIFY_SSL: bool = False
    WAZUH_ALLOW_SELF_SIGNED: bool = True

    # Logging
    LOG_LEVEL: str = "INFO"

    @classmethod
    def from_env(cls) -> 'ServerConfig':
        """Create configuration from environment variables."""
        import secrets

        # Generate secure secret key if not provided
        auth_secret = os.getenv("AUTH_SECRET_KEY", "")
        if not auth_secret:
            auth_secret = secrets.token_hex(32)

        # Validate auth mode
        auth_mode = os.getenv("AUTH_MODE", "bearer").lower()
        if auth_mode not in ("bearer", "oauth", "none"):
            auth_mode = "bearer"

        return cls(
            MCP_HOST=os.getenv("MCP_HOST", "0.0.0.0"),
            MCP_PORT=int(os.getenv("MCP_PORT", "3000")),
            AUTH_SECRET_KEY=auth_secret,
            TOKEN_LIFETIME_HOURS=int(os.getenv("TOKEN_LIFETIME_HOURS", "24")),
            AUTH_MODE=auth_mode,
            OAUTH_ISSUER_URL=os.getenv("OAUTH_ISSUER_URL", ""),
            OAUTH_ENABLE_DCR=os.getenv("OAUTH_ENABLE_DCR", "true").lower() == "true",
            OAUTH_ACCESS_TOKEN_TTL=int(os.getenv("OAUTH_ACCESS_TOKEN_TTL", "3600")),
            OAUTH_REFRESH_TOKEN_TTL=int(os.getenv("OAUTH_REFRESH_TOKEN_TTL", "86400")),
            OAUTH_AUTHORIZATION_CODE_TTL=int(os.getenv("OAUTH_AUTHORIZATION_CODE_TTL", "600")),
            ALLOWED_ORIGINS=os.getenv("ALLOWED_ORIGINS", "https://claude.ai,http://localhost:*"),
            WAZUH_HOST=os.getenv("WAZUH_HOST", ""),
            WAZUH_USER=os.getenv("WAZUH_USER", ""),
            WAZUH_PASS=os.getenv("WAZUH_PASS", ""),
            WAZUH_PORT=int(os.getenv("WAZUH_PORT", "55000")),
            WAZUH_VERIFY_SSL=os.getenv("WAZUH_VERIFY_SSL", "false").lower() == "true",
            WAZUH_ALLOW_SELF_SIGNED=os.getenv("WAZUH_ALLOW_SELF_SIGNED", "true").lower() == "true",
            LOG_LEVEL=os.getenv("LOG_LEVEL", "INFO").upper()
        )

    @property
    def is_authless(self) -> bool:
        """Check if server is running in authless mode."""
        return self.AUTH_MODE == "none"

    @property
    def is_oauth(self) -> bool:
        """Check if server is using OAuth authentication."""
        return self.AUTH_MODE == "oauth"

    @property
    def is_bearer(self) -> bool:
        """Check if server is using Bearer token authentication."""
        return self.AUTH_MODE == "bearer"


# Global configuration instance
_config: Optional[ServerConfig] = None


def get_config() -> ServerConfig:
    """Get or create server configuration."""
    global _config
    if _config is None:
        _config = ServerConfig.from_env()
    return _config