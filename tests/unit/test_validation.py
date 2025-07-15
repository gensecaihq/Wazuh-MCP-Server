"""Tests for validation utilities."""

import pytest
from wazuh_mcp_server.utils.validation import (
    ValidationError,
    AlertQuery,
    AgentQuery,
    ThreatAnalysisQuery,
    IPAddress,
    FileHash,
    validate_alert_query,
    validate_agent_query,
    validate_threat_analysis,
    validate_ip_address,
    validate_file_hash,
    sanitize_string,
    validate_json_payload
)


class TestAlertQuery:
    """Test cases for AlertQuery validation."""
    
    def test_valid_alert_query(self):
        """Test valid alert query parameters."""
        query = AlertQuery(limit=100, offset=0, level=5, sort="-timestamp")
        assert query.limit == 100
        assert query.offset == 0
        assert query.level == 5
        assert query.sort == "-timestamp"
    
    def test_alert_query_defaults(self):
        """Test alert query with default values."""
        query = AlertQuery()
        assert query.limit == 100
        assert query.offset == 0
        assert query.level is None
        assert query.sort == "-timestamp"
    
    def test_alert_query_invalid_limit(self):
        """Test validation error for invalid limit."""
        with pytest.raises(ValueError):
            AlertQuery(limit=0)
        
        with pytest.raises(ValueError):
            AlertQuery(limit=20000)
    
    def test_alert_query_invalid_level(self):
        """Test validation error for invalid level."""
        with pytest.raises(ValueError):
            AlertQuery(level=0)
        
        with pytest.raises(ValueError):
            AlertQuery(level=16)
    
    def test_alert_query_invalid_sort(self):
        """Test validation error for invalid sort."""
        with pytest.raises(ValueError):
            AlertQuery(sort="invalid_sort")


class TestAgentQuery:
    """Test cases for AgentQuery validation."""
    
    def test_valid_agent_query(self):
        """Test valid agent query parameters."""
        query = AgentQuery(agent_id="001", status="active")
        assert query.agent_id == "001"
        assert query.status == "active"
    
    def test_agent_query_invalid_id(self):
        """Test validation error for invalid agent ID."""
        with pytest.raises(ValueError):
            AgentQuery(agent_id="invalid_id_format")
    
    def test_agent_query_invalid_status(self):
        """Test validation error for invalid status."""
        with pytest.raises(ValueError):
            AgentQuery(status="invalid_status")


class TestThreatAnalysisQuery:
    """Test cases for ThreatAnalysisQuery validation."""
    
    def test_valid_threat_analysis_query(self):
        """Test valid threat analysis parameters."""
        query = ThreatAnalysisQuery(
            category="malware",
            time_range=7200,
            confidence_threshold=0.8
        )
        assert query.category == "malware"
        assert query.time_range == 7200
        assert query.confidence_threshold == 0.8
    
    def test_threat_analysis_query_defaults(self):
        """Test threat analysis query with defaults."""
        query = ThreatAnalysisQuery()
        assert query.category == "all"
        assert query.time_range == 3600
        assert query.confidence_threshold == 0.5
    
    def test_threat_analysis_query_invalid_category(self):
        """Test validation error for invalid category."""
        with pytest.raises(ValueError):
            ThreatAnalysisQuery(category="invalid_category")
    
    def test_threat_analysis_query_invalid_time_range(self):
        """Test validation error for invalid time range."""
        with pytest.raises(ValueError):
            ThreatAnalysisQuery(time_range=100)  # Too short
        
        with pytest.raises(ValueError):
            ThreatAnalysisQuery(time_range=100000)  # Too long


class TestIPAddress:
    """Test cases for IP address validation."""
    
    def test_valid_ipv4_address(self):
        """Test valid IPv4 address."""
        ip = IPAddress(ip="8.8.8.8")
        assert ip.ip == "8.8.8.8"
    
    def test_invalid_ip_address(self):
        """Test validation error for invalid IP."""
        with pytest.raises(ValueError):
            IPAddress(ip="invalid_ip")
        
        with pytest.raises(ValueError):
            IPAddress(ip="999.999.999.999")
    
    def test_private_ip_address(self):
        """Test validation error for private IP addresses."""
        with pytest.raises(ValueError):
            IPAddress(ip="192.168.1.1")
        
        with pytest.raises(ValueError):
            IPAddress(ip="127.0.0.1")
        
        with pytest.raises(ValueError):
            IPAddress(ip="10.0.0.1")


class TestFileHash:
    """Test cases for file hash validation."""
    
    def test_valid_md5_hash(self):
        """Test valid MD5 hash."""
        hash_obj = FileHash(hash_value="5d41402abc4b2a76b9719d911017c592")
        assert hash_obj.hash_value == "5d41402abc4b2a76b9719d911017c592"
        assert hash_obj.hash_type == "md5"
    
    def test_valid_sha1_hash(self):
        """Test valid SHA1 hash."""
        hash_obj = FileHash(hash_value="aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d")
        assert hash_obj.hash_value == "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
        assert hash_obj.hash_type == "sha1"
    
    def test_valid_sha256_hash(self):
        """Test valid SHA256 hash."""
        hash_obj = FileHash(
            hash_value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )
        assert hash_obj.hash_value == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert hash_obj.hash_type == "sha256"
    
    def test_invalid_hash_characters(self):
        """Test validation error for invalid characters."""
        with pytest.raises(ValueError):
            FileHash(hash_value="invalid_hash_with_special_chars!")
    
    def test_invalid_hash_length(self):
        """Test validation error for invalid hash length."""
        with pytest.raises(ValueError):
            FileHash(hash_value="too_short")
        
        with pytest.raises(ValueError):
            FileHash(hash_value="way_too_long_to_be_any_valid_hash_format")


class TestValidationFunctions:
    """Test cases for validation utility functions."""
    
    def test_validate_alert_query_success(self):
        """Test successful alert query validation."""
        params = {"limit": 50, "level": 10}
        result = validate_alert_query(params)
        assert isinstance(result, AlertQuery)
        assert result.limit == 50
        assert result.level == 10
    
    def test_validate_alert_query_error(self):
        """Test validation error for alert query."""
        params = {"limit": 0}  # Invalid limit
        with pytest.raises(ValidationError):
            validate_alert_query(params)
    
    def test_validate_agent_query_success(self):
        """Test successful agent query validation."""
        params = {"agent_id": "001", "status": "active"}
        result = validate_agent_query(params)
        assert isinstance(result, AgentQuery)
        assert result.agent_id == "001"
        assert result.status == "active"
    
    def test_validate_threat_analysis_success(self):
        """Test successful threat analysis validation."""
        params = {"category": "malware", "time_range": 3600}
        result = validate_threat_analysis(params)
        assert isinstance(result, ThreatAnalysisQuery)
        assert result.category == "malware"
        assert result.time_range == 3600
    
    def test_validate_ip_address_success(self):
        """Test successful IP address validation."""
        result = validate_ip_address("8.8.8.8")
        assert isinstance(result, IPAddress)
        assert result.ip == "8.8.8.8"
    
    def test_validate_file_hash_success(self):
        """Test successful file hash validation."""
        result = validate_file_hash("5d41402abc4b2a76b9719d911017c592")
        assert isinstance(result, FileHash)
        assert result.hash_value == "5d41402abc4b2a76b9719d911017c592"
    
    def test_sanitize_string_basic(self):
        """Test basic string sanitization."""
        result = sanitize_string("  test string  ")
        assert result == "test string"
    
    def test_sanitize_string_remove_control_chars(self):
        """Test removal of control characters."""
        result = sanitize_string("test\x00\x01string")
        assert result == "teststring"
    
    def test_sanitize_string_length_limit(self):
        """Test string length limiting."""
        long_string = "a" * 2000
        result = sanitize_string(long_string, max_length=100)
        assert len(result) == 100
    
    def test_validate_json_payload_success(self):
        """Test successful JSON payload validation."""
        payload = {"key": "value", "number": 123}
        result = validate_json_payload(payload)
        assert result == payload
    
    def test_validate_json_payload_not_dict(self):
        """Test validation error for non-dict payload."""
        with pytest.raises(ValidationError):
            validate_json_payload("not a dict")
    
    def test_validate_json_payload_too_large(self):
        """Test validation error for large payload."""
        large_payload = {"key": "x" * 20000}
        with pytest.raises(ValidationError):
            validate_json_payload(large_payload, max_size=1000)