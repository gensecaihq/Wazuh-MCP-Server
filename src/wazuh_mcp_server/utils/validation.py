"""Input validation utilities for secure API operations."""

import re
import ipaddress
import hashlib
import json
from typing import Any, Dict, List, Optional, Union

# Use Fedora-compatible layer instead of direct pydantic import
from .pydantic_compat import BaseModel, Field, validator


class ValidationError(Exception):
    """Raised when input validation fails."""
    pass


class AlertQuery(BaseModel):
    """Validated alert query parameters."""
    
    limit: int = Field(default=100, ge=1, le=10000, description="Maximum number of alerts")
    offset: int = Field(default=0, ge=0, description="Query offset")
    level: Optional[int] = Field(default=None, ge=1, le=15, description="Minimum alert level")
    sort: str = Field(default="-timestamp", description="Sort order")
    
    @validator('sort')
    def validate_sort(cls, v):
        """Validate sort parameter."""
        allowed_sorts = [
            "timestamp", "-timestamp", "level", "-level", 
            "rule.id", "-rule.id", "agent.name", "-agent.name"
        ]
        if v not in allowed_sorts:
            raise ValueError(f"Sort must be one of {allowed_sorts}")
        return v


class AgentQuery(BaseModel):
    """Validated agent query parameters."""
    
    agent_id: Optional[str] = Field(default=None, description="Specific agent ID")
    status: Optional[str] = Field(default=None, description="Agent status filter")
    
    @validator('agent_id')
    def validate_agent_id(cls, v):
        """Validate agent ID format."""
        if v is not None:
            if not re.match(r'^[0-9a-fA-F]{3,8}$', v):
                raise ValueError("Agent ID must be 3-8 character alphanumeric")
        return v
    
    @validator('status')
    def validate_status(cls, v):
        """Validate agent status."""
        if v is not None:
            allowed_statuses = ["active", "disconnected", "never_connected", "pending"]
            if v not in allowed_statuses:
                raise ValueError(f"Status must be one of {allowed_statuses}")
        return v


class ThreatAnalysisQuery(BaseModel):
    """Validated threat analysis parameters."""
    
    category: str = Field(default="all", description="Threat category")
    time_range: int = Field(default=3600, ge=300, le=86400, description="Time range in seconds")
    confidence_threshold: float = Field(default=0.5, ge=0.0, le=1.0, description="Confidence threshold")
    
    @validator('category')
    def validate_category(cls, v):
        """Validate threat category."""
        allowed_categories = [
            "all", "intrusion", "malware", "vulnerability", 
            "compliance", "authentication", "dos", "data_leak"
        ]
        if v not in allowed_categories:
            raise ValueError(f"Category must be one of {allowed_categories}")
        return v


class IPAddress(BaseModel):
    """Validated IP address."""
    
    ip: str = Field(..., description="IP address to validate")
    
    @validator('ip')
    def validate_ip(cls, v):
        """Validate IP address format."""
        try:
            ipaddress.ip_address(v)
            # Check for private/local IPs that shouldn't be queried externally
            ip_obj = ipaddress.ip_address(v)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast:
                raise ValueError("Cannot query reputation for private/local IP addresses")
            return v
        except ipaddress.AddressValueError:
            raise ValueError("Invalid IP address format")


class FileHash(BaseModel):
    """Validated file hash."""
    
    hash_value: str = Field(..., description="File hash to validate")
    hash_type: Optional[str] = Field(default=None, description="Hash type (md5, sha1, sha256)")
    
    @validator('hash_value')
    def validate_hash(cls, v):
        """Validate hash format."""
        # Remove any whitespace
        v = v.strip().lower()
        
        # Check for valid hex characters
        if not re.match(r'^[a-f0-9]+$', v):
            raise ValueError("Hash must contain only hexadecimal characters")
        
        # Validate length and determine hash type
        hash_length = len(v)
        if hash_length not in [32, 40, 64]:
            raise ValueError("Hash length must be 32 (MD5), 40 (SHA1), or 64 (SHA256) characters")
        
        return v
    
    def __init__(self, **data):
        """Initialize with hash type detection."""
        super().__init__(**data)
        if not self.hash_type and self.hash_value:
            # Set hash type based on length
            length = len(self.hash_value)
            if length == 32:
                self.hash_type = "md5"
            elif length == 40:
                self.hash_type = "sha1"
            elif length == 64:
                self.hash_type = "sha256"


def validate_alert_query(params: Dict[str, Any]) -> AlertQuery:
    """Validate and sanitize alert query parameters with security checks."""
    try:
        # Sanitize input parameters
        sanitized_params = {}
        for key, value in params.items():
            if isinstance(value, str):
                sanitized_params[key] = sanitize_string(value, max_length=100)
            else:
                sanitized_params[key] = value
        
        return AlertQuery(**sanitized_params)
    except ValueError as e:
        raise ValidationError(f"Invalid alert query parameters: {str(e)}") from e
    except Exception as e:
        raise ValidationError(f"Unexpected error validating alert query: {str(e)}") from e


def validate_agent_query(params: Dict[str, Any]) -> AgentQuery:
    """Validate and sanitize agent query parameters."""
    try:
        # Sanitize input parameters
        sanitized_params = {}
        for key, value in params.items():
            if isinstance(value, str):
                sanitized_params[key] = sanitize_string(value, max_length=100)
            else:
                sanitized_params[key] = value
                
        return AgentQuery(**sanitized_params)
    except ValueError as e:
        raise ValidationError(f"Invalid agent query parameters: {str(e)}") from e
    except Exception as e:
        raise ValidationError(f"Unexpected error validating agent query: {str(e)}") from e


def validate_threat_analysis(params: Dict[str, Any]) -> ThreatAnalysisQuery:
    """Validate and sanitize threat analysis parameters."""
    try:
        # Sanitize input parameters
        sanitized_params = {}
        for key, value in params.items():
            if isinstance(value, str):
                sanitized_params[key] = sanitize_string(value, max_length=100)
            else:
                sanitized_params[key] = value
                
        return ThreatAnalysisQuery(**sanitized_params)
    except ValueError as e:
        raise ValidationError(f"Invalid threat analysis parameters: {str(e)}") from e
    except Exception as e:
        raise ValidationError(f"Unexpected error validating threat analysis: {str(e)}") from e


def validate_ip_address(ip: str) -> IPAddress:
    """Validate IP address."""
    try:
        # Sanitize input
        sanitized_ip = sanitize_string(ip, max_length=45)  # Max IPv6 length
        return IPAddress(ip=sanitized_ip)
    except ValueError as e:
        raise ValidationError(f"Invalid IP address: {str(e)}") from e
    except Exception as e:
        raise ValidationError(f"Unexpected error validating IP address: {str(e)}") from e


def validate_file_hash(hash_value: str) -> FileHash:
    """Validate file hash."""
    try:
        # Sanitize input
        sanitized_hash = sanitize_string(hash_value, max_length=64)  # Max SHA256 length
        return FileHash(hash_value=sanitized_hash)
    except ValueError as e:
        raise ValidationError(f"Invalid file hash: {str(e)}") from e
    except Exception as e:
        raise ValidationError(f"Unexpected error validating file hash: {str(e)}") from e


def sanitize_string(input_str: str, max_length: int = 1000) -> str:
    """Sanitize string input to prevent injection attacks."""
    if not input_str:
        return ""
    
    # Convert to string if not already
    if not isinstance(input_str, str):
        input_str = str(input_str)
    
    # Remove null bytes and control characters
    sanitized = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', input_str)
    
    # Remove potentially dangerous characters for command injection
    sanitized = re.sub(r'[;&|`$<>]', '', sanitized)
    
    # Escape single and double quotes
    sanitized = sanitized.replace("'", "\\'").replace('"', '\\"')
    
    # Limit length
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length]
    
    return sanitized.strip()


def validate_json_payload(payload: Any, max_size: int = 10000) -> Dict[str, Any]:
    """Validate JSON payload size and structure."""
    if payload is None:
        raise ValidationError("Payload cannot be None")
        
    if not isinstance(payload, dict):
        raise ValidationError("Payload must be a JSON object")
    
    try:
        # Check payload size (approximate)
        payload_str = json.dumps(payload)
        if len(payload_str) > max_size:
            raise ValidationError(f"Payload too large (max {max_size} bytes)")
    except (TypeError, ValueError) as e:
        raise ValidationError(f"Invalid JSON payload: {str(e)}") from e
    
    # Sanitize string values in payload
    sanitized_payload = {}
    for key, value in payload.items():
        if isinstance(value, str):
            sanitized_payload[key] = sanitize_string(value)
        elif isinstance(value, dict):
            sanitized_payload[key] = validate_json_payload(value, max_size=max_size//10)
        elif isinstance(value, list):
            sanitized_payload[key] = [
                sanitize_string(item) if isinstance(item, str) else item 
                for item in value
            ]
        else:
            sanitized_payload[key] = value
    
    return sanitized_payload