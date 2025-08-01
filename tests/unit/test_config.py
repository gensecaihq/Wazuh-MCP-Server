"""Tests for configuration module."""

import os
import pytest
from unittest.mock import patch
try:
    from pydantic import ValidationError
except ImportError:
    # Fallback for compatibility
    class ValidationError(Exception):
        pass

from wazuh_mcp_server.config import WazuhConfig, ConfigurationError


class TestWazuhConfig:
    """Test cases for WazuhConfig."""
    
    def test_config_creation_with_valid_data(self):
        """Test configuration creation with valid data."""
        config = WazuhConfig(
            host="test.example.com",
            username="testuser",
            password="testpassword123"
        )
        assert config.host == "test.example.com"
        assert config.username == "testuser"
        assert config.password == "testpassword123"
        assert config.port == 55000  # default
        assert config.verify_ssl is True  # default
    
    def test_config_from_env_valid(self):
        """Test configuration from environment variables."""
        env_vars = {
            "WAZUH_HOST": "env.example.com",
            "WAZUH_USER": "envuser",
            "WAZUH_PASS": "envpassword123",
            "WAZUH_PORT": "55001",
            "VERIFY_SSL": "false"
        }
        
        with patch.dict(os.environ, env_vars, clear=False):
            config = WazuhConfig.from_env()
            assert config.host == "env.example.com"
            assert config.username == "envuser"
            assert config.password == "envpassword123"
            assert config.port == 55001
            assert config.verify_ssl is False
    
    def test_config_validation_missing_host(self):
        """Test validation error when host is missing."""
        with pytest.raises(ValidationError, match="WAZUH_HOST must be provided"):
            WazuhConfig(
                host="",
                username="testuser",
                password="testpassword123"
            )
    
    def test_config_validation_missing_username(self):
        """Test validation error when username is missing."""
        with pytest.raises(ValidationError, match="WAZUH_USER must be provided"):
            WazuhConfig(
                host="test.example.com",
                username="",
                password="testpassword123"
            )
    
    def test_config_validation_missing_password(self):
        """Test validation error when password is missing."""
        with pytest.raises(ValidationError, match="WAZUH_PASS must be provided"):
            WazuhConfig(
                host="test.example.com",
                username="testuser",
                password=""
            )
    
    def test_config_validation_weak_password(self):
        """Test validation error for weak passwords."""
        with pytest.raises(ValidationError, match="Password is too weak"):
            WazuhConfig(
                host="test.example.com",
                username="testuser",
                password="admin"
            )
    
    def test_config_validation_short_password(self):
        """Test validation error for short passwords."""
        with pytest.raises(ValidationError, match="Password must be at least 8 characters"):
            WazuhConfig(
                host="test.example.com",
                username="testuser",
                password="short"
            )
    
    def test_config_validation_invalid_port(self):
        """Test validation error for invalid port."""
        with pytest.raises(ValidationError):
            WazuhConfig(
                host="test.example.com",
                username="testuser",
                password="testpassword123",
                port=70000  # Invalid port
            )
    
    def test_config_validation_invalid_log_level(self):
        """Test validation error for invalid log level."""
        with pytest.raises(ValidationError, match="LOG_LEVEL must be one of"):
            WazuhConfig(
                host="test.example.com",
                username="testuser",
                password="testpassword123",
                log_level="INVALID"
            )
    
    def test_base_url_property(self):
        """Test base_url property."""
        config = WazuhConfig(
            host="test.example.com",
            port=55001,
            username="testuser",
            password="testpassword123"
        )
        assert config.base_url == "https://test.example.com:55001"
    
    def test_config_from_env_missing_required(self):
        """Test configuration error when required env vars are missing."""
        # Clear environment
        env_vars = {
            "WAZUH_HOST": "",
            "WAZUH_USER": "",
            "WAZUH_PASS": ""
        }
        
        with patch.dict(os.environ, env_vars, clear=False):
            with pytest.raises(ConfigurationError):
                WazuhConfig.from_env()
    
    def test_config_performance_settings(self):
        """Test performance settings validation."""
        config = WazuhConfig(
            host="test.example.com",
            username="testuser",
            password="testpassword123",
            max_alerts_per_query=5000,
            max_agents_per_scan=50
        )
        assert config.max_alerts_per_query == 5000
        assert config.max_agents_per_scan == 50
    
    def test_config_feature_flags(self):
        """Test feature flags."""
        config = WazuhConfig(
            host="test.example.com",
            username="testuser",
            password="testpassword123",
            enable_external_intel=False,
            enable_ml_analysis=False
        )
        assert config.enable_external_intel is False
        assert config.enable_ml_analysis is False
    
    def test_config_api_keys_optional(self):
        """Test that API keys are optional."""
        config = WazuhConfig(
            host="test.example.com",
            username="testuser",
            password="testpassword123"
        )
        assert config.virustotal_api_key is None
        assert config.shodan_api_key is None
        assert config.abuseipdb_api_key is None