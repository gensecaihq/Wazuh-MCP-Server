"""Configuration management with validation and security best practices."""

import os
import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional
from pathlib import Path
from .utils.pydantic_compat import BaseModel, Field, validator
from dotenv import load_dotenv

# Import cross-platform utilities
try:
    from .utils.platform_utils import get_environment_variable, normalize_path, get_config_dir
except ImportError:
    # Fallback if platform_utils not available
    def get_environment_variable(var_name: str, default: Optional[str] = None) -> Optional[str]:
        return os.getenv(var_name, default)
    
    def normalize_path(path: str) -> Path:
        return Path(path)
    
    def get_config_dir(app_name: str = "WazuhMCP") -> Path:
        return Path.home() / ".wazuh-mcp"

# Find .env file - cross-platform approach
current_dir = Path(__file__).resolve().parent
env_file = None

# Search for .env file in current and parent directories
search_paths = [
    current_dir,
    current_dir.parent, 
    current_dir.parent.parent,
    Path.cwd(),  # Current working directory
    get_config_dir()  # Platform-specific config directory
]

for search_path in search_paths:
    potential_env = search_path / '.env'
    if potential_env.exists():
        env_file = potential_env
        break

# Load environment variables from .env file if found with encoding handling
if env_file:
    try:
        # Try to load with explicit encoding handling for Windows
        load_dotenv(dotenv_path=env_file, encoding='utf-8')
        logging.info(f"Loaded .env file from: {env_file}")
    except UnicodeDecodeError:
        try:
            # Fallback to UTF-8 with BOM
            load_dotenv(dotenv_path=env_file, encoding='utf-8-sig')
            logging.info(f"Loaded .env file from: {env_file} (with BOM)")
        except UnicodeDecodeError:
            # Final fallback to system default with error handling
            import platform
            default_encoding = 'cp1252' if platform.system() == 'Windows' else 'utf-8'
            load_dotenv(dotenv_path=env_file, encoding=default_encoding)
            logging.warning(f"Loaded .env file with {default_encoding} encoding (some characters may be replaced)")
else:
    # Try loading from current working directory as fallback
    load_dotenv()
    logging.debug("No .env file found in search paths, trying current working directory")


class AlertSeverity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ComplianceFramework(Enum):
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"
    GDPR = "gdpr"
    NIST = "nist"
    ISO27001 = "iso27001"


class ThreatCategory(Enum):
    MALWARE = "malware"
    INTRUSION = "intrusion"
    VULNERABILITY = "vulnerability"
    COMPLIANCE = "compliance"
    AUTHENTICATION = "authentication"
    DOS = "denial_of_service"
    DATA_LEAK = "data_leak"
    PRIVILEGE_ESCALATION = "privilege_escalation"


class ConfigurationError(Exception):
    """Raised when configuration is invalid or missing required values."""
    pass


class WazuhConfig(BaseModel):
    """Validated Wazuh configuration with security best practices."""
    
    # Required Wazuh Server API settings
    host: str = Field(..., description="Wazuh server hostname or IP address")
    port: int = Field(default=55000, ge=1, le=65535, description="Wazuh API port")
    username: str = Field(..., min_length=1, description="Wazuh API username")
    password: str = Field(..., min_length=1, description="Wazuh API password")
    verify_ssl: bool = Field(default=True, description="Enable SSL certificate verification (secure by default)")
    ca_bundle_path: Optional[str] = Field(default=None, description="Custom CA bundle path")
    client_cert_path: Optional[str] = Field(default=None, description="Client certificate path")
    client_key_path: Optional[str] = Field(default=None, description="Client private key path")
    allow_self_signed: bool = Field(default=True, description="Allow self-signed certificates (enabled by default)")
    ssl_timeout: int = Field(default=30, ge=1, le=300, description="SSL connection timeout")
    auto_detect_ssl_issues: bool = Field(default=True, description="Automatically handle SSL certificate issues")
    api_version: str = Field(default="v4", description="Wazuh API version")
    
    # Wazuh Indexer API settings (for 4.8.0+)
    indexer_host: Optional[str] = Field(default=None, description="Wazuh Indexer hostname or IP")
    indexer_port: int = Field(default=9200, ge=1, le=65535, description="Wazuh Indexer port")
    indexer_username: Optional[str] = Field(default=None, description="Wazuh Indexer username")
    indexer_password: Optional[str] = Field(default=None, description="Wazuh Indexer password")
    indexer_verify_ssl: Optional[bool] = Field(default=None, description="Indexer SSL verification (inherits from verify_ssl if None)")
    indexer_ca_bundle_path: Optional[str] = Field(default=None, description="Indexer custom CA bundle path")
    indexer_client_cert_path: Optional[str] = Field(default=None, description="Indexer client certificate path")
    indexer_client_key_path: Optional[str] = Field(default=None, description="Indexer client private key path")
    indexer_allow_self_signed: bool = Field(default=True, description="Allow self-signed certificates for Indexer (enabled by default)")
    indexer_auto_detect_ssl_issues: bool = Field(default=True, description="Automatically handle Indexer SSL certificate issues")
    
    # Wazuh version compatibility
    wazuh_version: Optional[str] = Field(default=None, description="Wazuh version (auto-detected if None)")
    use_indexer_for_alerts: bool = Field(default=True, description="Use Indexer API for alerts (4.8.0+)")
    use_indexer_for_vulnerabilities: bool = Field(default=True, description="Use Indexer API for vulnerabilities (4.8.0+)")
    
    # Optional external API keys
    virustotal_api_key: Optional[str] = Field(default=None, description="VirusTotal API key")
    shodan_api_key: Optional[str] = Field(default=None, description="Shodan API key")
    abuseipdb_api_key: Optional[str] = Field(default=None, description="AbuseIPDB API key")
    
    # Performance settings
    max_alerts_per_query: int = Field(default=1000, ge=1, le=10000)
    max_agents_per_scan: int = Field(default=10, ge=1, le=100)
    cache_ttl_seconds: int = Field(default=300, ge=0)
    request_timeout_seconds: int = Field(default=30, ge=1, le=300)
    max_connections: int = Field(default=10, ge=1, le=100)
    pool_size: int = Field(default=5, ge=1, le=50)
    
    # Feature flags
    enable_external_intel: bool = Field(default=True)
    enable_ml_analysis: bool = Field(default=True)
    enable_compliance_checking: bool = Field(default=True)
    enable_experimental: bool = Field(default=False)
    

    # Logging configuration
    debug: bool = Field(default=False)
    log_level: str = Field(default="INFO")
    
    class Config:
        """Pydantic configuration."""
        env_prefix = ""
        case_sensitive = False
    
    @validator('host')
    def validate_host(cls, v):
        """Validate host is not empty and not default insecure values."""
        if not v or v.strip() == "":
            raise ValueError("WAZUH_HOST must be provided")
        return v.strip()
    
    @validator('username')
    def validate_username(cls, v):
        """Validate username is provided."""
        if not v or v.strip() == "":
            raise ValueError("WAZUH_USER must be provided")
        if v.strip().lower() in ["admin", "wazuh", "user", "test"]:
            logging.warning("Using default username '%s' is not recommended for production", v)
        return v.strip()
    
    @validator('password')
    def validate_password(cls, v):
        """Validate password meets minimum security requirements."""
        if not v or v.strip() == "":
            raise ValueError("WAZUH_PASS must be provided")
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        if v.lower() in ["admin", "password", "123456", "wazuh"]:
            raise ValueError("Password is too weak. Use a strong, unique password.")
        return v
    
    @validator('log_level')
    def validate_log_level(cls, v):
        """Validate log level is valid."""
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if v.upper() not in valid_levels:
            raise ValueError(f"LOG_LEVEL must be one of {valid_levels}")
        return v.upper()
    
    @property
    def base_url(self) -> str:
        """Get the base URL for Wazuh API."""
        return f"https://{self.host}:{self.port}"
    
    @staticmethod
    def _parse_bool(value: Optional[str]) -> bool:
        """Parse boolean from string with consistent handling."""
        if value is None:
            return False
        return value.lower() in ("true", "yes", "1", "on")
    
    @classmethod
    def from_env(cls) -> 'WazuhConfig':
        """Create configuration from environment variables."""
        try:
            # Indexer settings with fallback to server settings
            indexer_host = os.getenv("WAZUH_INDEXER_HOST") or os.getenv("WAZUH_HOST")
            indexer_username = os.getenv("WAZUH_INDEXER_USER") or os.getenv("WAZUH_USER")
            indexer_password = os.getenv("WAZUH_INDEXER_PASS") or os.getenv("WAZUH_PASS")
            indexer_verify_ssl = os.getenv("WAZUH_INDEXER_VERIFY_SSL")
            if indexer_verify_ssl is None:
                indexer_verify_ssl = cls._parse_bool(os.getenv("VERIFY_SSL", "false"))
            else:
                indexer_verify_ssl = cls._parse_bool(indexer_verify_ssl)
            
            return cls(
                # Server API settings
                host=os.getenv("WAZUH_HOST"),
                port=int(os.getenv("WAZUH_PORT", "55000")),
                username=os.getenv("WAZUH_USER"),
                password=os.getenv("WAZUH_PASS"),
                verify_ssl=cls._parse_bool(os.getenv("VERIFY_SSL", "true")),
                api_version=os.getenv("WAZUH_API_VERSION", "v4"),
                
                # Indexer API settings
                indexer_host=indexer_host,
                indexer_port=int(os.getenv("WAZUH_INDEXER_PORT", "9200")),
                indexer_username=indexer_username,
                indexer_password=indexer_password,
                indexer_verify_ssl=indexer_verify_ssl,
                
                # Version and feature flags
                wazuh_version=os.getenv("WAZUH_VERSION"),
                use_indexer_for_alerts=cls._parse_bool(os.getenv("USE_INDEXER_FOR_ALERTS", "true")),
                use_indexer_for_vulnerabilities=cls._parse_bool(os.getenv("USE_INDEXER_FOR_VULNERABILITIES", "true")),
                
                # External APIs
                virustotal_api_key=os.getenv("VIRUSTOTAL_API_KEY"),
                shodan_api_key=os.getenv("SHODAN_API_KEY"),
                abuseipdb_api_key=os.getenv("ABUSEIPDB_API_KEY"),
                
                # Performance settings
                max_alerts_per_query=int(os.getenv("MAX_ALERTS_PER_QUERY", "1000")),
                max_agents_per_scan=int(os.getenv("MAX_AGENTS_PER_SCAN", "10")),
                cache_ttl_seconds=int(os.getenv("CACHE_TTL_SECONDS", "300")),
                request_timeout_seconds=int(os.getenv("REQUEST_TIMEOUT_SECONDS", "30")),
                max_connections=int(os.getenv("MAX_CONNECTIONS", "10")),
                pool_size=int(os.getenv("POOL_SIZE", "5")),
                
                # Feature flags
                enable_external_intel=cls._parse_bool(os.getenv("ENABLE_EXTERNAL_INTEL", "true")),
                enable_ml_analysis=cls._parse_bool(os.getenv("ENABLE_ML_ANALYSIS", "true")),
                enable_compliance_checking=cls._parse_bool(os.getenv("ENABLE_COMPLIANCE_CHECKING", "true")),
                enable_experimental=os.getenv("ENABLE_EXPERIMENTAL", "false").lower() == "true",
                

                # Logging
                debug=os.getenv("DEBUG", "false").lower() == "true",
                log_level=os.getenv("LOG_LEVEL", "INFO"),
            )
        except Exception as e:
            raise ConfigurationError(f"Configuration validation failed: {str(e)}") from e
