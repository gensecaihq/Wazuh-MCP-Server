"""Configuration management for Wazuh MCP Server."""

import os
from dataclasses import dataclass
from typing import Optional


class ConfigurationError(Exception):
    """Raised when configuration is invalid."""

    pass


def validate_port(value: str, name: str) -> int:
    """Validate port number is within valid range."""
    try:
        port = int(value)
        if not (1 <= port <= 65535):
            raise ConfigurationError(f"{name} must be between 1 and 65535, got {port}")
        return port
    except ValueError:
        raise ConfigurationError(f"{name} must be a valid integer, got '{value}'")


def validate_positive_int(value: str, name: str, max_val: Optional[int] = None) -> int:
    """Validate positive integer with optional maximum."""
    try:
        num = int(value)
        if num < 1:
            raise ConfigurationError(f"{name} must be positive, got {num}")
        if max_val and num > max_val:
            raise ConfigurationError(f"{name} must be <= {max_val}, got {num}")
        return num
    except ValueError:
        raise ConfigurationError(f"{name} must be a valid integer, got '{value}'")


def normalize_host(host: str) -> str:
    """
    Normalize hostname by stripping protocol prefix if present.

    Handles common user mistakes like including https:// in WAZUH_HOST.
    Examples:
        'https://192.168.1.100' -> '192.168.1.100'
        'http://wazuh.local' -> 'wazuh.local'
        '192.168.1.100' -> '192.168.1.100'
    """
    if not host:
        return host
    # Strip protocol prefixes
    for prefix in ("https://", "http://"):
        if host.lower().startswith(prefix):
            host = host[len(prefix) :]
            break
    # Strip trailing slashes
    return host.rstrip("/")


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
    def from_env(cls) -> "WazuhConfig":
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

        # Parse optional settings with validation
        port = safe_int_env("WAZUH_PORT", "55000", min_val=1, max_val=65535)
        verify_ssl = os.getenv("VERIFY_SSL", "true").lower() == "true"

        # Normalize host values (strip protocol if user included it)
        normalized_host = normalize_host(host)
        indexer_host = os.getenv("WAZUH_INDEXER_HOST")
        normalized_indexer_host = normalize_host(indexer_host) if indexer_host else None

        # Create config with defaults for most settings
        config = cls(
            wazuh_host=normalized_host,
            wazuh_user=user,
            wazuh_pass=password,
            wazuh_port=port,
            verify_ssl=verify_ssl,
            wazuh_indexer_host=normalized_indexer_host,
            wazuh_indexer_port=safe_int_env("WAZUH_INDEXER_PORT", "9200", min_val=1, max_val=65535),
            wazuh_indexer_user=os.getenv("WAZUH_INDEXER_USER"),
            wazuh_indexer_pass=os.getenv("WAZUH_INDEXER_PASS"),
            mcp_transport=os.getenv("MCP_TRANSPORT", "http"),  # Default to HTTP/SSE
            mcp_host=os.getenv("MCP_HOST", "0.0.0.0"),
            mcp_port=safe_int_env("MCP_PORT", "3000", min_val=1, max_val=65535),
            request_timeout_seconds=safe_int_env("REQUEST_TIMEOUT_SECONDS", "30", min_val=1, max_val=300),
            max_alerts_per_query=safe_int_env("MAX_ALERTS_PER_QUERY", "1000", min_val=1, max_val=10000),
            max_connections=safe_int_env("MAX_CONNECTIONS", "10", min_val=1, max_val=100),
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
    WAZUH_VERIFY_SSL: bool = True
    WAZUH_ALLOW_SELF_SIGNED: bool = True

    # Wazuh Indexer settings (Required for Wazuh 4.8.0+ vulnerability tools)
    WAZUH_INDEXER_HOST: str = ""
    WAZUH_INDEXER_PORT: int = 9200
    WAZUH_INDEXER_USER: str = ""
    WAZUH_INDEXER_PASS: str = ""
    WAZUH_INDEXER_VERIFY_SSL: bool = True

    # Logging
    LOG_LEVEL: str = "INFO"

    @classmethod
    def from_env(cls) -> "ServerConfig":
        """Create configuration from environment variables with validation."""
        import secrets

        # Generate secure secret key if not provided
        auth_secret = os.getenv("AUTH_SECRET_KEY", "")
        if not auth_secret:
            auth_secret = secrets.token_hex(32)

        # Validate auth mode
        auth_mode = os.getenv("AUTH_MODE", "bearer").lower()
        if auth_mode not in ("bearer", "oauth", "none"):
            auth_mode = "bearer"

        # Validate log level
        log_level = os.getenv("LOG_LEVEL", "INFO").upper()
        if log_level not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
            log_level = "INFO"

        return cls(
            MCP_HOST=os.getenv("MCP_HOST", "0.0.0.0"),
            MCP_PORT=validate_port(os.getenv("MCP_PORT", "3000"), "MCP_PORT"),
            AUTH_SECRET_KEY=auth_secret,
            TOKEN_LIFETIME_HOURS=validate_positive_int(
                os.getenv("TOKEN_LIFETIME_HOURS", "24"), "TOKEN_LIFETIME_HOURS", max_val=8760
            ),
            AUTH_MODE=auth_mode,
            OAUTH_ISSUER_URL=os.getenv("OAUTH_ISSUER_URL", ""),
            OAUTH_ENABLE_DCR=os.getenv("OAUTH_ENABLE_DCR", "true").lower() == "true",
            OAUTH_ACCESS_TOKEN_TTL=validate_positive_int(
                os.getenv("OAUTH_ACCESS_TOKEN_TTL", "3600"), "OAUTH_ACCESS_TOKEN_TTL"
            ),
            OAUTH_REFRESH_TOKEN_TTL=validate_positive_int(
                os.getenv("OAUTH_REFRESH_TOKEN_TTL", "86400"), "OAUTH_REFRESH_TOKEN_TTL"
            ),
            OAUTH_AUTHORIZATION_CODE_TTL=validate_positive_int(
                os.getenv("OAUTH_AUTHORIZATION_CODE_TTL", "600"), "OAUTH_AUTHORIZATION_CODE_TTL"
            ),
            ALLOWED_ORIGINS=os.getenv("ALLOWED_ORIGINS", "https://claude.ai,http://localhost:*"),
            WAZUH_HOST=normalize_host(os.getenv("WAZUH_HOST", "")),
            WAZUH_USER=os.getenv("WAZUH_USER", ""),
            WAZUH_PASS=os.getenv("WAZUH_PASS", ""),
            WAZUH_PORT=validate_port(os.getenv("WAZUH_PORT", "55000"), "WAZUH_PORT"),
            WAZUH_VERIFY_SSL=os.getenv("WAZUH_VERIFY_SSL", "true").lower() == "true",
            WAZUH_ALLOW_SELF_SIGNED=os.getenv("WAZUH_ALLOW_SELF_SIGNED", "true").lower() == "true",
            # Wazuh Indexer settings (for vulnerability tools in Wazuh 4.8.0+)
            WAZUH_INDEXER_HOST=normalize_host(os.getenv("WAZUH_INDEXER_HOST", "")),
            WAZUH_INDEXER_PORT=validate_port(os.getenv("WAZUH_INDEXER_PORT", "9200"), "WAZUH_INDEXER_PORT"),
            WAZUH_INDEXER_USER=os.getenv("WAZUH_INDEXER_USER", ""),
            WAZUH_INDEXER_PASS=os.getenv("WAZUH_INDEXER_PASS", ""),
            WAZUH_INDEXER_VERIFY_SSL=os.getenv("WAZUH_INDEXER_VERIFY_SSL", "true").lower() == "true",
            LOG_LEVEL=log_level,
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
