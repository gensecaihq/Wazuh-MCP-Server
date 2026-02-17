#!/usr/bin/env python3
"""
Production configuration validation and secrets management
Implements comprehensive environment validation and secure secrets handling
"""

import hashlib
import logging
import os
import secrets
from dataclasses import dataclass
from typing import Dict, List, Optional
from urllib.parse import urlparse

import httpx
from cryptography.fernet import Fernet
from pydantic import BaseModel, Field, ValidationError, validator

logger = logging.getLogger(__name__)


@dataclass
class ValidationResult:
    """Configuration validation result."""

    is_valid: bool
    errors: List[str]
    warnings: List[str]
    recommendations: List[str]


class WazuhConfig(BaseModel):
    """Validated Wazuh configuration."""

    host: str = Field(..., description="Wazuh server URL")
    port: int = Field(default=55000, ge=1, le=65535)
    user: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=8)
    verify_ssl: bool = Field(default=False)
    timeout: int = Field(default=30, ge=1, le=300)

    @validator("host")
    def validate_host(cls, v):
        """Validate Wazuh host URL."""
        if not v.startswith(("http://", "https://")):
            v = f"https://{v}"

        parsed = urlparse(v)
        if not parsed.netloc:
            raise ValueError("Invalid host URL")

        # Security check: prevent private IP access in production
        if os.getenv("ENVIRONMENT") == "production":
            if any(private in parsed.netloc for private in ["localhost", "127.0.0.1", "::1"]):
                raise ValueError("Localhost not allowed in production")

        return v

    @validator("password")
    def validate_password(cls, v):
        """Validate password strength."""
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")

        # Check for common weak passwords
        weak_passwords = ["password", "12345678", "admin123", "wazuh123"]
        if v.lower() in weak_passwords:
            raise ValueError("Password is too weak")

        return v


class ServerConfig(BaseModel):
    """Validated server configuration."""

    host: str = Field(default="0.0.0.0")
    port: int = Field(default=3000, ge=1, le=65535)
    log_level: str = Field(default="INFO")
    max_connections: int = Field(default=100, ge=1, le=10000)
    session_timeout: int = Field(default=1800, ge=60, le=86400)  # 30 minutes to 24 hours

    @validator("log_level")
    def validate_log_level(cls, v):
        """Validate log level."""
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if v.upper() not in valid_levels:
            raise ValueError(f"Log level must be one of: {valid_levels}")
        return v.upper()


class SecurityConfig(BaseModel):
    """Validated security configuration."""

    secret_key: str = Field(..., min_length=32)
    allowed_origins: List[str] = Field(default_factory=list)
    rate_limit_requests: int = Field(default=100, ge=1, le=10000)
    rate_limit_window: int = Field(default=60, ge=1, le=3600)
    token_lifetime: int = Field(default=86400, ge=300, le=604800)  # 5 minutes to 7 days

    @validator("secret_key")
    def validate_secret_key(cls, v):
        """Validate secret key strength."""
        if len(v) < 32:
            raise ValueError("Secret key must be at least 32 characters")

        # Check entropy
        if len(set(v)) < 16:
            raise ValueError("Secret key has insufficient entropy")

        return v

    @validator("allowed_origins")
    def validate_origins(cls, v):
        """Validate CORS origins."""
        for origin in v:
            if origin != "*":
                parsed = urlparse(origin)
                if not parsed.scheme or not parsed.netloc:
                    raise ValueError(f"Invalid origin URL: {origin}")
        return v


class SecretsManager:
    """Secure secrets management."""

    def __init__(self, master_key: Optional[str] = None):
        if master_key:
            self.cipher = Fernet(master_key.encode())
        else:
            # Generate master key from environment or create new
            key = os.getenv("MASTER_KEY")
            if not key:
                key = Fernet.generate_key().decode()
                logger.warning("Generated new master key - save MASTER_KEY environment variable")
            self.cipher = Fernet(key.encode())

    def encrypt_secret(self, secret: str) -> str:
        """Encrypt a secret."""
        return self.cipher.encrypt(secret.encode()).decode()

    def decrypt_secret(self, encrypted_secret: str) -> str:
        """Decrypt a secret."""
        return self.cipher.decrypt(encrypted_secret.encode()).decode()

    def hash_secret(self, secret: str) -> str:
        """Create hash of secret for comparison."""
        return hashlib.sha256(secret.encode()).hexdigest()


class ConfigValidator:
    """Comprehensive configuration validator."""

    def __init__(self):
        self.secrets_manager = SecretsManager()
        self.required_vars = {
            "WAZUH_HOST": "Wazuh server URL",
            "WAZUH_USER": "Wazuh API username",
            "WAZUH_PASS": "Wazuh API password",
        }
        self.optional_vars = {
            "SSE_HOST": "Server bind address",
            "SSE_PORT": "Server port",
            "LOG_LEVEL": "Logging level",
            "AUTH_SECRET_KEY": "Authentication secret key",
            "ALLOWED_ORIGINS": "CORS allowed origins",
            "REDIS_URL": "Redis connection URL",
            "SSL_KEYFILE": "SSL private key file",
            "SSL_CERTFILE": "SSL certificate file",
        }

    def validate_environment(self) -> ValidationResult:
        """Validate environment configuration."""
        errors = []
        warnings = []
        recommendations = []

        # Check required variables
        for var, description in self.required_vars.items():
            value = os.getenv(var)
            if not value:
                errors.append(f"Missing required environment variable: {var} ({description})")
            elif var == "WAZUH_PASS" and len(value) < 8:
                warnings.append(f"Weak password for {var}")

        # Validate configurations
        try:
            WazuhConfig(
                host=os.getenv("WAZUH_HOST", ""),
                port=int(os.getenv("WAZUH_PORT", "55000")),
                user=os.getenv("WAZUH_USER", ""),
                password=os.getenv("WAZUH_PASS", ""),
                verify_ssl=os.getenv("WAZUH_VERIFY_SSL", "false").lower() == "true",
            )
        except ValidationError as e:
            for error in e.errors():
                errors.append(f"Wazuh config error: {error['msg']}")

        try:
            ServerConfig(
                host=os.getenv("SSE_HOST", "0.0.0.0"),
                port=int(os.getenv("SSE_PORT", "3000")),
                log_level=os.getenv("LOG_LEVEL", "INFO"),
            )
        except ValidationError as e:
            for error in e.errors():
                errors.append(f"Server config error: {error['msg']}")

        # Security checks
        secret_key = os.getenv("AUTH_SECRET_KEY")
        if not secret_key:
            warnings.append("AUTH_SECRET_KEY not set - will generate random key")
            recommendations.append("Set AUTH_SECRET_KEY for consistent authentication")
        elif len(secret_key) < 32:
            errors.append("AUTH_SECRET_KEY must be at least 32 characters")

        # SSL configuration
        ssl_key = os.getenv("SSL_KEYFILE")
        ssl_cert = os.getenv("SSL_CERTFILE")
        if ssl_key and not ssl_cert:
            errors.append("SSL_KEYFILE set but SSL_CERTFILE missing")
        elif ssl_cert and not ssl_key:
            errors.append("SSL_CERTFILE set but SSL_KEYFILE missing")
        elif not ssl_key and not ssl_cert:
            recommendations.append("Consider enabling SSL/TLS for production deployment")

        # Environment-specific checks
        environment = os.getenv("ENVIRONMENT", "development")
        if environment == "production":
            if os.getenv("LOG_LEVEL", "INFO") == "DEBUG":
                warnings.append("DEBUG logging enabled in production")

            if os.getenv("WAZUH_VERIFY_SSL", "false").lower() == "false":
                warnings.append("SSL verification disabled in production")

        return ValidationResult(
            is_valid=len(errors) == 0, errors=errors, warnings=warnings, recommendations=recommendations
        )

    async def validate_connectivity(self) -> ValidationResult:
        """Validate external service connectivity."""
        errors = []
        warnings = []
        recommendations = []

        # Test Wazuh connectivity
        try:
            wazuh_host = os.getenv("WAZUH_HOST")
            if wazuh_host:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    response = await client.get(f"{wazuh_host}/", verify=False)
                    if response.status_code >= 400:
                        warnings.append(f"Wazuh server returned HTTP {response.status_code}")
        except httpx.RequestError as e:
            errors.append(f"Cannot connect to Wazuh server: {e}")
        except Exception as e:
            warnings.append(f"Wazuh connectivity check failed: {e}")

        # Test Redis connectivity if configured
        redis_url = os.getenv("REDIS_URL")
        if redis_url:
            try:
                import redis.asyncio as redis

                client = redis.from_url(redis_url)
                await client.ping()
                await client.close()
            except ImportError:
                warnings.append("Redis URL configured but redis library not available")
            except Exception as e:
                errors.append(f"Cannot connect to Redis: {e}")

        return ValidationResult(
            is_valid=len(errors) == 0, errors=errors, warnings=warnings, recommendations=recommendations
        )

    def generate_secure_config(self) -> Dict[str, str]:
        """Generate secure configuration values."""
        return {
            "AUTH_SECRET_KEY": secrets.token_urlsafe(32),
            "REDIS_PASSWORD": secrets.token_urlsafe(16),
            "MASTER_KEY": Fernet.generate_key().decode(),
            "SESSION_SECRET": secrets.token_hex(32),
        }

    def validate_file_permissions(self) -> ValidationResult:
        """Validate file permissions for security."""
        errors = []
        warnings = []
        recommendations = []

        # Check .env file permissions
        env_files = [".env", ".env.production", ".env.local"]
        for env_file in env_files:
            if os.path.exists(env_file):
                stat = os.stat(env_file)
                mode = stat.st_mode & 0o777

                if mode & 0o044:  # Readable by group or others
                    warnings.append(f"{env_file} is readable by group/others (mode: {oct(mode)})")
                    recommendations.append(f"Run: chmod 600 {env_file}")

        # Check SSL files if configured
        ssl_files = [os.getenv("SSL_KEYFILE"), os.getenv("SSL_CERTFILE")]
        for ssl_file in ssl_files:
            if ssl_file and os.path.exists(ssl_file):
                stat = os.stat(ssl_file)
                mode = stat.st_mode & 0o777

                if ssl_file.endswith("key.pem") and mode & 0o044:
                    errors.append(f"SSL private key {ssl_file} is readable by group/others")
                    recommendations.append(f"Run: chmod 600 {ssl_file}")

        return ValidationResult(
            is_valid=len(errors) == 0, errors=errors, warnings=warnings, recommendations=recommendations
        )


class EnvironmentDetector:
    """Detect deployment environment and apply appropriate settings."""

    @staticmethod
    def detect_environment() -> str:
        """Detect current environment."""
        # Check explicit environment variable
        env = os.getenv("ENVIRONMENT")
        if env:
            return env.lower()

        # Detect based on other indicators
        if os.getenv("KUBERNETES_SERVICE_HOST"):
            return "kubernetes"
        elif os.getenv("DOCKER_CONTAINER"):
            return "docker"
        elif os.getenv("CI"):
            return "ci"
        elif os.getenv("DEBUG", "").lower() == "true":
            return "development"
        else:
            return "production"

    @staticmethod
    def apply_environment_defaults():
        """Apply environment-specific defaults."""
        env = EnvironmentDetector.detect_environment()

        defaults = {
            "development": {"LOG_LEVEL": "DEBUG", "WAZUH_VERIFY_SSL": "false", "RATE_LIMIT_REQUESTS": "1000"},
            "production": {"LOG_LEVEL": "INFO", "WAZUH_VERIFY_SSL": "true", "RATE_LIMIT_REQUESTS": "100"},
            "docker": {"SSE_HOST": "0.0.0.0", "LOG_LEVEL": "INFO"},
            "kubernetes": {"SSE_HOST": "0.0.0.0", "LOG_LEVEL": "INFO", "HEALTH_CHECK_ENABLED": "true"},
        }

        env_defaults = defaults.get(env, {})
        for key, value in env_defaults.items():
            if not os.getenv(key):
                os.environ[key] = value


# Global validator instance
config_validator = ConfigValidator()


async def validate_production_config() -> bool:
    """Comprehensive production configuration validation."""
    logger.info("Starting production configuration validation...")

    # Detect and apply environment defaults
    EnvironmentDetector.apply_environment_defaults()

    # Validate environment variables
    env_result = config_validator.validate_environment()
    if not env_result.is_valid:
        logger.error("Environment validation failed:")
        for error in env_result.errors:
            logger.error(f"  ❌ {error}")
        return False

    # Log warnings and recommendations
    for warning in env_result.warnings:
        logger.warning(f"  ⚠️  {warning}")

    for rec in env_result.recommendations:
        logger.info(f"  💡 {rec}")

    # Validate connectivity
    conn_result = await config_validator.validate_connectivity()
    if not conn_result.is_valid:
        logger.error("Connectivity validation failed:")
        for error in conn_result.errors:
            logger.error(f"  ❌ {error}")
        return False

    # Validate file permissions
    perm_result = config_validator.validate_file_permissions()
    for warning in perm_result.warnings:
        logger.warning(f"  ⚠️  {warning}")

    logger.info("✅ Production configuration validation passed")
    return True
