"""Configuration management for Wazuh MCP Server."""

import ipaddress
import json
import logging
import os
import ssl
from dataclasses import dataclass
from typing import FrozenSet, Optional, Union

from wazuh_mcp_server.toolsets import ALL_TOOLS, resolve_enabled_tools


class ConfigurationError(Exception):
    """Raised when configuration is invalid."""

    pass


_TRUE_TOKENS = frozenset({"1", "true", "yes", "y", "on"})
_FALSE_TOKENS = frozenset({"0", "false", "no", "n", "off", ""})


def tls_verify(value: Union[bool, str]) -> Union[bool, ssl.SSLContext]:
    """httpx `verify` for a config value: a CA-bundle path becomes an SSLContext (passing the
    path string itself is deprecated in httpx 0.28); booleans pass through."""
    if isinstance(value, str) and value:
        return ssl.create_default_context(cafile=value)
    return bool(value)


TLS_FAILURE_HINT = (
    "The stock Wazuh API certificate (<WAZUH_PATH>/api/configuration/ssl/server.crt) is self-signed "
    "for CN=wazuh.com with no subjectAltName, so it cannot be verified for your host. Reissue it with "
    "a subjectAltName matching WAZUH_HOST and set WAZUH_CA_BUNDLE to the CA that signed it, or set "
    "WAZUH_ALLOW_SELF_SIGNED=true to connect without verification."
)


def env_unquoted(name: str, default: str = "") -> str:
    """A space- or JSON-bearing variable with one pair of matching surrounding quotes removed.

    `.env` files need quotes around such values for Compose and the shell, but
    `docker run --env-file` passes them through literally: MCP_API_KEY_SCOPES="wazuh:read
    wazuh:write" then silently became read-only and a quoted JSON map failed to parse.
    """
    value = os.getenv(name, default).strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        value = value[1:-1].strip()
    return value


def env_bool(name: str, default: bool) -> bool:
    """Parse a boolean environment variable, accepting the common truthy/falsy spellings.

    A plain ``== "true"`` check silently treats ``WAZUH_VERIFY_SSL=1`` / ``=yes`` as False,
    which would disable TLS verification (or send Indexer credentials over plain HTTP) for an
    operator who meant to enable it. Accept 1/true/yes/y/on and 0/false/no/n/off; raise on
    anything else so a typo fails loudly instead of defaulting to the insecure branch.
    """
    raw = os.getenv(name)
    if raw is None:
        return default
    token = raw.strip().lower()
    if token in _TRUE_TOKENS:
        return True
    if token in _FALSE_TOKENS:
        return False
    raise ConfigurationError(f"{name} must be a boolean (true/false/1/0/yes/no/on/off), got '{raw}'")


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
        if max_val is not None and num > max_val:
            raise ConfigurationError(f"{name} must be <= {max_val}, got {num}")
        return num
    except ValueError:
        raise ConfigurationError(f"{name} must be a valid integer, got '{value}'")


_ENVIRONMENTS = {"development": "development", "dev": "development", "production": "production", "prod": "production"}


def normalize_environment(raw: Optional[str]) -> str:
    """ENVIRONMENT -> "development" | "production". Unknown values fail rather than silently
    running without the production-only safety checks (e.g. "prod" used to mean development)."""
    value = (raw or "development").strip().lower()
    if value not in _ENVIRONMENTS:
        raise ConfigurationError(f"ENVIRONMENT must be 'development' or 'production', got '{raw}'")
    return _ENVIRONMENTS[value]


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
    host = host.strip().rstrip("/")
    # A port or path here used to pass startup and then fail every call
    # ("Invalid port '47102:55000'"), so refuse it now. The port has its own setting.
    if "/" in host:
        raise ConfigurationError(f"Host '{host}' must be a host name or IP address, without a path")
    try:
        if ipaddress.ip_address(host).version == 6:
            return f"[{host}]"  # a bare IPv6 address needs brackets in a URL
    except ValueError:
        pass
    if host.startswith("[") and host.endswith("]"):
        return host
    if ":" in host:
        raise ConfigurationError(
            f"Host '{host}' includes a port; set it in WAZUH_PORT / WAZUH_INDEXER_PORT (or the cluster's port field)"
        )
    return host


@dataclass
class WazuhConfig:
    """Wazuh configuration settings."""

    # Required settings
    wazuh_host: str
    wazuh_user: str
    wazuh_pass: str

    # Optional settings with sensible defaults
    wazuh_port: int = 55000
    verify_ssl: Union[bool, str] = True  # httpx `verify`: bool or path to a CA bundle

    # Indexer settings (optional)
    wazuh_indexer_host: Optional[str] = None
    wazuh_indexer_port: int = 9200
    wazuh_indexer_user: Optional[str] = None
    wazuh_indexer_pass: Optional[str] = None
    wazuh_indexer_ssl: bool = True  # Use HTTPS for the indexer (set False for plain-HTTP OpenSearch nodes)
    wazuh_indexer_verify_ssl: Union[bool, str] = True  # Verify the indexer's TLS certificate (bool or CA path)

    # Transport settings
    mcp_transport: str = "http"  # Default to HTTP/SSE mode
    mcp_host: str = "127.0.0.1"
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
                if max_val is not None and value > max_val:
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
            mcp_host=os.getenv("MCP_HOST", "127.0.0.1"),
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
    MCP_HOST: str = "127.0.0.1"
    MCP_PORT: int = 3000

    # Authentication settings
    AUTH_SECRET_KEY: str = ""
    TOKEN_LIFETIME_HOURS: int = 24

    # Authentication mode: "bearer" (default), "oauth", or "none" (authless)
    AUTH_MODE: str = "bearer"

    # OAuth settings (when AUTH_MODE=oauth)
    OAUTH_ISSUER_URL: str = ""  # Will be auto-set to server URL if not provided
    OAUTH_ENABLE_DCR: bool = False  # Dynamic Client Registration (off by default; unauthenticated)
    OAUTH_ACCESS_TOKEN_TTL: int = 3600  # 1 hour
    OAUTH_REFRESH_TOKEN_TTL: int = 86400  # 24 hours
    OAUTH_AUTHORIZATION_CODE_TTL: int = 600  # 10 minutes

    # External OpenID Connect identity provider for AUTH_MODE=oauth. When set, users
    # authenticate at the IdP (Microsoft Entra ID, Google Workspace, Okta, ...) before an
    # authorization code is issued; without it /oauth/authorize auto-approves.
    OAUTH_IDP_ISSUER: str = ""  # e.g. https://login.microsoftonline.com/<tenant-id>/v2.0
    OAUTH_IDP_CLIENT_ID: str = ""
    OAUTH_IDP_CLIENT_SECRET: str = ""  # optional (public client + PKCE if empty)
    OAUTH_IDP_SCOPES: str = "openid email profile"
    OAUTH_IDP_ALLOWED_DOMAINS: str = ""  # comma-separated; Google `hd` or e-mail domain
    OAUTH_IDP_ALLOWED_TENANTS: str = ""  # comma-separated Entra tenant IDs (`tid` claim)
    OAUTH_IDP_ALLOWED_USERS: str = ""  # comma-separated subjects/e-mails (optional allow-list)
    OAUTH_IDP_GROUP_CLAIM: str = "groups"  # `groups` (Entra/Okta), `roles` (Entra app roles), ...
    OAUTH_IDP_GROUP_SCOPE_MAP: str = ""  # JSON: {"<group>": "wazuh:read wazuh:write", ...}
    OAUTH_IDP_DEFAULT_SCOPE: str = "wazuh:read"  # for users in no mapped group; "" denies them
    OAUTH_IDP_SUBJECT_CLAIM: str = "email"  # claim used as the audited identity
    OAUTH_IDP_LOGIN_TTL: int = 600  # seconds a parked /authorize request waits for the IdP

    # CORS settings
    ALLOWED_ORIGINS: str = "https://claude.ai,http://localhost:3000"

    # Wazuh connection settings
    WAZUH_HOST: str = ""
    WAZUH_USER: str = ""
    WAZUH_PASS: str = ""
    WAZUH_PORT: int = 55000
    WAZUH_VERIFY_SSL: bool = True
    # Accepting a self-signed certificate == not verifying at all (httpx has no middle
    # ground), so this is OFF by default. To trust a private CA or a self-signed
    # certificate *safely*, point WAZUH_CA_BUNDLE at its PEM file instead.
    WAZUH_ALLOW_SELF_SIGNED: bool = False
    WAZUH_CA_BUNDLE: str = ""  # PEM file used to verify the Manager (and Indexer) certificate

    # Wazuh Indexer settings (Required for Wazuh 4.8.0+ vulnerability tools)
    WAZUH_INDEXER_HOST: str = ""
    WAZUH_INDEXER_PORT: int = 9200
    WAZUH_INDEXER_USER: str = ""
    WAZUH_INDEXER_PASS: str = ""
    WAZUH_INDEXER_SSL: bool = True
    WAZUH_INDEXER_VERIFY_SSL: bool = True

    # Wazuh client tuning (applied to the WazuhClient built in server.py)
    REQUEST_TIMEOUT_SECONDS: int = 30
    MAX_CONNECTIONS: int = 10
    MAX_ALERTS_PER_QUERY: int = 1000

    # Session store bounds (see server._enforce_session_bounds)
    MAX_SESSIONS: int = 1000
    MAX_SESSIONS_PER_PRINCIPAL: int = 100  # "principal" = API key / OAuth client, not a person
    # Tool exposure (see toolsets.py): which tools tools/list advertises and tools/call accepts
    ENABLED_TOOLS: FrozenSet[str] = ALL_TOOLS

    # Logging
    LOG_LEVEL: str = "INFO"

    # Deployment environment: "development" | "production"
    ENVIRONMENT: str = "development"

    @classmethod
    def from_env(cls) -> "ServerConfig":
        """Create configuration from environment variables with validation."""
        import secrets

        environment = normalize_environment(os.getenv("ENVIRONMENT"))

        # Validate auth mode
        auth_mode = os.getenv("AUTH_MODE", "bearer").strip().lower()
        if auth_mode not in ("bearer", "oauth", "none"):
            # A typo used to fall back to bearer silently — the operator thinks OAuth is on
            raise ConfigurationError(f"AUTH_MODE must be one of bearer, oauth, none; got '{auth_mode}'")

        # Signing secret. In production with auth enabled it MUST be provided — a random
        # per-process key invalidates all tokens on restart and breaks multi-instance
        # deployments. Auto-generate only outside production (developer convenience).
        auth_secret = os.getenv("AUTH_SECRET_KEY", "").strip()
        auth_required = environment == "production" and auth_mode != "none"
        if not auth_secret:
            if auth_required:
                raise ConfigurationError(
                    "AUTH_SECRET_KEY is required when ENVIRONMENT=production and AUTH_MODE is not 'none'.\n"
                    "Generate one with: openssl rand -hex 32\n"
                    "Set it identically across all instances so tokens survive restarts and load balancing."
                )
            auth_secret = secrets.token_hex(32)
        elif auth_required:
            # A key was provided in production. Reject the shipped placeholder and any obvious
            # stand-in, and require real entropy — otherwise `cp .env.example .env` yields a
            # production server signing every token with a value published in the public repo.
            lowered = auth_secret.lower()
            looks_placeholder = (
                "change_me" in lowered
                or "changeme" in lowered
                or lowered.startswith("<")
                or "your-secret" in lowered
                or "example" in lowered
            )
            if looks_placeholder or len(auth_secret) < 32:
                raise ConfigurationError(
                    "AUTH_SECRET_KEY is set to a placeholder or is too weak for production "
                    f"(need a random value of at least 32 characters; got {len(auth_secret)}).\n"
                    "Generate one with: openssl rand -hex 32"
                )

        # A configured key that can't be loaded used to log a warning and fall back to a
        # generated key nobody knows: every client then got 401 with no obvious cause.
        mcp_api_key = os.getenv("MCP_API_KEY", "").strip()
        if mcp_api_key and not (mcp_api_key.startswith("wazuh_") and len(mcp_api_key) == 49):
            raise ConfigurationError(
                "MCP_API_KEY is not a valid key (expected wazuh_ followed by 43 characters). Generate one with: "
                "python -c \"import secrets; print('wazuh_' + secrets.token_urlsafe(32))\""
            )
        api_keys_json = env_unquoted("API_KEYS")
        if api_keys_json and not mcp_api_key:
            try:
                parsed_keys = json.loads(api_keys_json)
            except json.JSONDecodeError as exc:
                raise ConfigurationError(f"API_KEYS is not valid JSON: {exc}") from exc
            if (
                not isinstance(parsed_keys, list)
                or not parsed_keys
                or not all(isinstance(k, dict) for k in parsed_keys)
            ):
                # An empty array loaded zero keys and skipped the generated default: no usable key at all
                raise ConfigurationError("API_KEYS must be a non-empty JSON array of key objects")

        # Optional CA bundle for the Wazuh Manager / Indexer certificates. Fail fast on a
        # bad path: silently falling back would either break every request or, worse,
        # tempt operators into WAZUH_ALLOW_SELF_SIGNED=true.
        ca_bundle = os.getenv("WAZUH_CA_BUNDLE", "").strip()
        if ca_bundle and not os.path.isfile(ca_bundle):
            raise ConfigurationError(f"WAZUH_CA_BUNDLE points to a file that does not exist: {ca_bundle}")
        if ca_bundle:
            # Load it now: an unreadable or non-PEM file used to pass startup and then fail
            # every call with "NO_CERTIFICATE_OR_CRL_FOUND"
            try:
                tls_verify(ca_bundle)
            except (ssl.SSLError, OSError) as exc:
                raise ConfigurationError(f"WAZUH_CA_BUNDLE could not be loaded as PEM certificates: {exc}") from exc
        if ca_bundle and (not env_bool("WAZUH_VERIFY_SSL", True) or env_bool("WAZUH_ALLOW_SELF_SIGNED", False)):
            logging.getLogger(__name__).warning(
                "WAZUH_CA_BUNDLE is set but Manager certificate verification is disabled "
                "(WAZUH_VERIFY_SSL=false or WAZUH_ALLOW_SELF_SIGNED=true): the bundle only applies to the Indexer."
            )

        # Validate log level
        log_level = os.getenv("LOG_LEVEL", "INFO").upper()
        if log_level not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
            log_level = "INFO"

        # Indexer scheme: honor an explicit WAZUH_INDEXER_SSL, otherwise infer from the
        # host prefix (http:// -> plain HTTP). Defaults to HTTPS when no scheme is given.
        indexer_host_raw = os.getenv("WAZUH_INDEXER_HOST", "")
        if os.getenv("WAZUH_INDEXER_SSL") is not None:
            indexer_ssl = env_bool("WAZUH_INDEXER_SSL", True)
        else:
            indexer_ssl = not indexer_host_raw.strip().lower().startswith("http://")

        # Active-response switches are read per call, but a typo must fail here, at startup,
        # not on every write-tool call
        for switch in ("WAZUH_REQUIRE_ACTION_CONFIRMATION", "WAZUH_ALLOW_FLEET_AR", "WAZUH_ALLOW_MANAGER_AR"):
            if os.getenv(switch, "").strip():
                env_bool(switch, False)

        try:
            enabled_tools = resolve_enabled_tools(os.getenv("WAZUH_TOOLSETS"), os.getenv("WAZUH_DISABLED_TOOLS"))
        except ValueError as e:
            raise ConfigurationError(str(e)) from e

        config = cls(
            MCP_HOST=os.getenv("MCP_HOST", "127.0.0.1"),
            MCP_PORT=validate_port(os.getenv("MCP_PORT", "3000"), "MCP_PORT"),
            AUTH_SECRET_KEY=auth_secret,
            TOKEN_LIFETIME_HOURS=validate_positive_int(
                os.getenv("TOKEN_LIFETIME_HOURS", "24"), "TOKEN_LIFETIME_HOURS", max_val=8760
            ),
            AUTH_MODE=auth_mode,
            OAUTH_ISSUER_URL=os.getenv("OAUTH_ISSUER_URL", ""),
            OAUTH_ENABLE_DCR=env_bool("OAUTH_ENABLE_DCR", False),
            OAUTH_ACCESS_TOKEN_TTL=validate_positive_int(
                os.getenv("OAUTH_ACCESS_TOKEN_TTL", "3600"), "OAUTH_ACCESS_TOKEN_TTL"
            ),
            OAUTH_REFRESH_TOKEN_TTL=validate_positive_int(
                os.getenv("OAUTH_REFRESH_TOKEN_TTL", "86400"), "OAUTH_REFRESH_TOKEN_TTL"
            ),
            OAUTH_AUTHORIZATION_CODE_TTL=validate_positive_int(
                os.getenv("OAUTH_AUTHORIZATION_CODE_TTL", "600"), "OAUTH_AUTHORIZATION_CODE_TTL"
            ),
            OAUTH_IDP_ISSUER=os.getenv("OAUTH_IDP_ISSUER", "").strip().rstrip("/"),
            OAUTH_IDP_CLIENT_ID=os.getenv("OAUTH_IDP_CLIENT_ID", "").strip(),
            OAUTH_IDP_CLIENT_SECRET=os.getenv("OAUTH_IDP_CLIENT_SECRET", ""),
            OAUTH_IDP_SCOPES=env_unquoted("OAUTH_IDP_SCOPES", "openid email profile"),
            OAUTH_IDP_ALLOWED_DOMAINS=env_unquoted("OAUTH_IDP_ALLOWED_DOMAINS", ""),
            OAUTH_IDP_ALLOWED_TENANTS=env_unquoted("OAUTH_IDP_ALLOWED_TENANTS", ""),
            OAUTH_IDP_ALLOWED_USERS=env_unquoted("OAUTH_IDP_ALLOWED_USERS", ""),
            OAUTH_IDP_GROUP_CLAIM=os.getenv("OAUTH_IDP_GROUP_CLAIM", "groups").strip() or "groups",
            OAUTH_IDP_GROUP_SCOPE_MAP=env_unquoted("OAUTH_IDP_GROUP_SCOPE_MAP", ""),
            OAUTH_IDP_DEFAULT_SCOPE=env_unquoted("OAUTH_IDP_DEFAULT_SCOPE", "wazuh:read"),
            OAUTH_IDP_SUBJECT_CLAIM=os.getenv("OAUTH_IDP_SUBJECT_CLAIM", "email").strip() or "email",
            OAUTH_IDP_LOGIN_TTL=validate_positive_int(
                os.getenv("OAUTH_IDP_LOGIN_TTL", "600"), "OAUTH_IDP_LOGIN_TTL", max_val=3600
            ),
            ALLOWED_ORIGINS=os.getenv("ALLOWED_ORIGINS", "https://claude.ai,http://localhost:3000"),
            WAZUH_HOST=normalize_host(os.getenv("WAZUH_HOST", "")),
            WAZUH_USER=os.getenv("WAZUH_USER", ""),
            WAZUH_PASS=os.getenv("WAZUH_PASS", ""),
            WAZUH_PORT=validate_port(os.getenv("WAZUH_PORT", "55000"), "WAZUH_PORT"),
            WAZUH_VERIFY_SSL=env_bool("WAZUH_VERIFY_SSL", True),
            WAZUH_ALLOW_SELF_SIGNED=env_bool("WAZUH_ALLOW_SELF_SIGNED", False),
            WAZUH_CA_BUNDLE=ca_bundle,
            # Wazuh Indexer settings (for vulnerability tools in Wazuh 4.8.0+)
            WAZUH_INDEXER_HOST=normalize_host(indexer_host_raw),
            WAZUH_INDEXER_PORT=validate_port(os.getenv("WAZUH_INDEXER_PORT", "9200"), "WAZUH_INDEXER_PORT"),
            WAZUH_INDEXER_USER=os.getenv("WAZUH_INDEXER_USER", ""),
            WAZUH_INDEXER_PASS=os.getenv("WAZUH_INDEXER_PASS", ""),
            WAZUH_INDEXER_SSL=indexer_ssl,
            WAZUH_INDEXER_VERIFY_SSL=env_bool("WAZUH_INDEXER_VERIFY_SSL", True),
            REQUEST_TIMEOUT_SECONDS=validate_positive_int(
                os.getenv("REQUEST_TIMEOUT_SECONDS", "30"), "REQUEST_TIMEOUT_SECONDS", max_val=300
            ),
            MAX_CONNECTIONS=validate_positive_int(os.getenv("MAX_CONNECTIONS", "10"), "MAX_CONNECTIONS", max_val=100),
            MAX_ALERTS_PER_QUERY=validate_positive_int(
                os.getenv("MAX_ALERTS_PER_QUERY", "1000"), "MAX_ALERTS_PER_QUERY", max_val=10000
            ),
            MAX_SESSIONS=validate_positive_int(os.getenv("MAX_SESSIONS", "1000"), "MAX_SESSIONS", max_val=100000),
            MAX_SESSIONS_PER_PRINCIPAL=validate_positive_int(
                os.getenv("MAX_SESSIONS_PER_PRINCIPAL", "100"), "MAX_SESSIONS_PER_PRINCIPAL", max_val=100000
            ),
            ENABLED_TOOLS=enabled_tools,
            LOG_LEVEL=log_level,
            ENVIRONMENT=environment,
        )

        # External identity provider (AUTH_MODE=oauth): fail fast on an unusable setup
        # instead of serving 401s with the OAuth router never mounted.
        if config.OAUTH_IDP_ISSUER:
            from wazuh_mcp_server.oidc import validate_idp_settings

            try:
                validate_idp_settings(config)
            except ValueError as exc:
                raise ConfigurationError(str(exc)) from exc
            if config.AUTH_MODE != "oauth":
                logging.getLogger(__name__).warning(
                    "OAUTH_IDP_* is configured but AUTH_MODE=%s; the identity provider is only used "
                    "when AUTH_MODE=oauth",
                    config.AUTH_MODE,
                )
        return config

    @property
    def wazuh_tls_verify(self) -> Union[bool, str]:
        """Effective httpx ``verify`` value for the Wazuh Manager connection.

        ``False`` disables certificate verification entirely (WAZUH_VERIFY_SSL=false or
        WAZUH_ALLOW_SELF_SIGNED=true); a path means "verify against this CA bundle";
        ``True`` means the system trust store.
        """
        if not self.WAZUH_VERIFY_SSL or self.WAZUH_ALLOW_SELF_SIGNED:
            return False
        return self.WAZUH_CA_BUNDLE or True

    @property
    def wazuh_indexer_tls_verify(self) -> Union[bool, str]:
        """Effective httpx ``verify`` value for the Wazuh Indexer connection."""
        if not self.WAZUH_INDEXER_VERIFY_SSL:
            return False
        return self.WAZUH_CA_BUNDLE or True

    @property
    def wazuh_tls_verification_disabled(self) -> bool:
        """True when certificate verification is off for the Manager."""
        return self.wazuh_tls_verify is False

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
