#!/usr/bin/env python3
"""
Production security hardening and edge case handling for Wazuh MCP Server
Implements comprehensive security measures and error handling
"""

import ipaddress
import logging
import os
import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

import httpx
from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)


# =============================================================================
# TOOL PARAMETER VALIDATION
# =============================================================================


class ToolValidationError(ValueError):
    """Raised when tool parameter validation fails."""

    def __init__(self, param_name: str, message: str, suggestion: str = None):
        self.param_name = param_name
        self.suggestion = suggestion
        full_message = f"Invalid parameter '{param_name}': {message}"
        if suggestion:
            full_message += f". {suggestion}"
        super().__init__(full_message)


# Valid enum values for tool parameters
VALID_TIME_RANGES = {"1h", "6h", "12h", "24h", "7d", "1d", "30d"}
VALID_SEVERITIES = {"low", "medium", "high", "critical"}
VALID_AGENT_STATUSES = {"active", "disconnected", "never_connected", "pending"}
VALID_INDICATOR_TYPES = {"ip", "hash", "domain", "url"}
VALID_REPORT_TYPES = {"daily", "weekly", "monthly", "incident"}
VALID_COMPLIANCE_FRAMEWORKS = {"PCI-DSS", "HIPAA", "SOX", "GDPR", "NIST", "ISO27001"}

# ISO 27001:2022 Annex A — valid control IDs and domain prefixes
VALID_ISO27001_DOMAINS = {"A.5", "A.6", "A.7", "A.8"}
VALID_ISO27001_CONTROLS = {
    "A.5",
    "A.5.26",
    "A.6",
    "A.6.3",
    "A.7",
    "A.8",
    "A.8.1",
    "A.8.2",
    "A.8.4",
    "A.8.5",
    "A.8.7",
    "A.8.8",
    "A.8.9",
    "A.8.12",
    "A.8.15",
    "A.8.16",
    "A.8.20",
    "A.8.22",
}

# Regex patterns for parameter validation
AGENT_ID_PATTERN = re.compile(r"^[0-9]{1,5}$")  # Wazuh agent IDs: 0 (manager) through 99999
RULE_ID_PATTERN = re.compile(r"^[0-9]{1,6}$")  # Rule IDs are numeric
ISO_TIMESTAMP_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?)?$")
# OpenSearch/Elasticsearch date math, e.g. "now", "now-24h", "now-7d/d", "now-1h-30m".
# These pass straight through to the indexer range query, which evaluates them natively.
DATE_MATH_PATTERN = re.compile(r"^now([+-]\d+[yMwdhHms])*(/[yMwdhHms])?$")
# Use ipaddress module for proper validation instead of regex
IP_ADDRESS_PATTERN = None  # Replaced by _is_valid_ip() function
HASH_PATTERN = re.compile(r"^[a-fA-F0-9]{32,128}$")  # MD5 to SHA-512
DOMAIN_PATTERN = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$")


def validate_limit(
    value: Any, min_val: int = 1, max_val: int = 1000, default: int = 100, param_name: str = "limit"
) -> int:
    """Validate and convert limit parameter."""
    if value is None:
        # Clamp the default to the allowed range to prevent crashes
        return max(min_val, min(default, max_val))

    try:
        limit = int(value)
    except (ValueError, TypeError):
        raise ToolValidationError(
            param_name,
            f"must be an integer, got {type(value).__name__}",
            f"Use a number between {min_val} and {max_val}",
        )

    if limit < min_val or limit > max_val:
        raise ToolValidationError(
            param_name,
            f"must be between {min_val} and {max_val}, got {limit}",
            f"Use a value in range [{min_val}, {max_val}]",
        )

    return limit


def validate_agent_id(value: Any, required: bool = False, param_name: str = "agent_id") -> Optional[str]:
    """Validate Wazuh agent ID format."""
    if value is None:
        if required:
            raise ToolValidationError(param_name, "is required", "Provide a valid agent ID (e.g., '001')")
        return None

    agent_id = str(value).strip()

    if not agent_id:
        if required:
            raise ToolValidationError(param_name, "cannot be empty", "Provide a valid agent ID (e.g., '001')")
        return None

    # Agent ID should be numeric (Wazuh format)
    if not AGENT_ID_PATTERN.match(agent_id):
        raise ToolValidationError(
            param_name, f"invalid format '{agent_id}'", "Agent ID should be a 3-5 digit number (e.g., '001', '1234')"
        )

    # Wazuh zero-pads agent IDs to at least 3 digits ("1" -> "001"). The Manager API
    # requires the padded form and the Indexer stores agent.id padded, so an exact-match
    # term on "1" would silently return nothing. Normalize here.
    return agent_id.zfill(3)


def validate_rule_id(value: Any, required: bool = False, param_name: str = "rule_id") -> Optional[str]:
    """Validate Wazuh rule ID format."""
    if value is None:
        if required:
            raise ToolValidationError(param_name, "is required", "Provide a valid rule ID (e.g., '5402')")
        return None

    rule_id = str(value).strip()

    if not rule_id:
        if required:
            raise ToolValidationError(param_name, "cannot be empty")
        return None

    if not RULE_ID_PATTERN.match(rule_id):
        raise ToolValidationError(
            param_name, f"invalid format '{rule_id}'", "Rule ID should be a 1-6 digit number (e.g., '5402', '100002')"
        )

    return rule_id


POLICY_ID_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


def validate_policy_id(value: Any, required: bool = True, param_name: str = "policy_id") -> Optional[str]:
    """Validate a Wazuh SCA policy ID (e.g. 'cis_debian10', 'cis_apple_macOS_12.0')."""
    if value is None or str(value).strip() == "":
        if required:
            raise ToolValidationError(param_name, "is required", "Provide a valid SCA policy ID (e.g., 'cis_debian10')")
        return None

    policy_id = str(value).strip()
    if not POLICY_ID_PATTERN.match(policy_id):
        raise ToolValidationError(
            param_name,
            f"invalid format '{policy_id}'",
            "Policy ID may contain letters, digits, dot, underscore, and hyphen (max 64 chars)",
        )
    return policy_id


def validate_time_range(value: Any, param_name: str = "time_range") -> str:
    """Validate time range enum value."""
    if value is None:
        return "24h"  # Default

    time_range = str(value).strip().lower()

    if time_range not in VALID_TIME_RANGES:
        raise ToolValidationError(
            param_name, f"invalid value '{value}'", f"Use one of: {', '.join(sorted(VALID_TIME_RANGES))}"
        )

    return time_range


def validate_severity(value: Any, required: bool = False, param_name: str = "severity") -> Optional[str]:
    """Validate severity enum value."""
    if value is None:
        if required:
            raise ToolValidationError(param_name, "is required")
        return None

    severity = str(value).strip().lower()

    if severity not in VALID_SEVERITIES:
        raise ToolValidationError(
            param_name, f"invalid value '{value}'", f"Use one of: {', '.join(sorted(VALID_SEVERITIES))}"
        )

    return severity


def validate_agent_status(value: Any, param_name: str = "status") -> Optional[str]:
    """Validate agent status enum value."""
    if value is None:
        return None

    status = str(value).strip().lower()

    if status not in VALID_AGENT_STATUSES:
        raise ToolValidationError(
            param_name, f"invalid value '{value}'", f"Use one of: {', '.join(sorted(VALID_AGENT_STATUSES))}"
        )

    return status


def validate_timestamp(value: Any, required: bool = False, param_name: str = "timestamp") -> Optional[str]:
    """Validate an ISO 8601 timestamp or OpenSearch relative date math (e.g. 'now-24h').

    Relative expressions are common from LLM clients and are passed straight through to
    the indexer range query, which evaluates date math natively.
    """
    if value is None:
        if required:
            raise ToolValidationError(param_name, "is required")
        return None

    timestamp = str(value).strip()

    if not timestamp:
        if required:
            raise ToolValidationError(param_name, "cannot be empty")
        return None

    # Accept OpenSearch date math (e.g. now-24h). Normalize the leading "now" keyword to
    # lowercase since the indexer requires it; unit case (h/H, m/M) is preserved as-is.
    normalized = ("now" + timestamp[3:]) if timestamp[:3].lower() == "now" else timestamp
    if DATE_MATH_PATTERN.match(normalized):
        return normalized

    if ISO_TIMESTAMP_PATTERN.match(timestamp):
        return timestamp

    raise ToolValidationError(
        param_name,
        f"invalid timestamp '{timestamp}'",
        "Use ISO 8601 (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ) or relative date math (e.g. now-24h, now-7d/d)",
    )


def validate_indicator(value: Any, indicator_type: str, param_name: str = "indicator") -> str:
    """Validate threat indicator based on type."""
    if value is None or str(value).strip() == "":
        raise ToolValidationError(param_name, "is required", "Provide a valid indicator value")

    indicator = str(value).strip()

    if indicator_type == "ip":
        try:
            ipaddress.ip_address(indicator)
        except ValueError:
            raise ToolValidationError(
                param_name, f"invalid IP address '{indicator}'", "Use valid IPv4 (e.g., '192.168.1.1') or IPv6 address"
            )
    elif indicator_type == "hash":
        if not HASH_PATTERN.match(indicator):
            raise ToolValidationError(
                param_name, f"invalid hash '{indicator}'", "Use valid MD5, SHA-1, SHA-256, or SHA-512 hash"
            )
    elif indicator_type == "domain":
        if not DOMAIN_PATTERN.match(indicator):
            raise ToolValidationError(
                param_name, f"invalid domain '{indicator}'", "Use valid domain format (e.g., 'example.com')"
            )
    elif indicator_type == "url":
        if not indicator.startswith(("http://", "https://")):
            raise ToolValidationError(
                param_name, f"invalid URL '{indicator}'", "URL must start with http:// or https://"
            )

    return indicator


def validate_indicator_type(value: Any, param_name: str = "indicator_type") -> str:
    """Validate indicator type enum."""
    if value is None:
        return "ip"  # Default

    ind_type = str(value).strip().lower()

    if ind_type not in VALID_INDICATOR_TYPES:
        raise ToolValidationError(
            param_name, f"invalid value '{value}'", f"Use one of: {', '.join(sorted(VALID_INDICATOR_TYPES))}"
        )

    return ind_type


def validate_report_type(value: Any, param_name: str = "report_type") -> str:
    """Validate report type enum."""
    if value is None:
        return "daily"  # Default

    report_type = str(value).strip().lower()

    if report_type not in VALID_REPORT_TYPES:
        raise ToolValidationError(
            param_name, f"invalid value '{value}'", f"Use one of: {', '.join(sorted(VALID_REPORT_TYPES))}"
        )

    return report_type


def validate_compliance_framework(value: Any, param_name: str = "framework") -> str:
    """Validate compliance framework enum."""
    if value is None:
        return "PCI-DSS"  # Default

    framework = str(value).strip().upper()

    # Normalize common variations
    if framework == "PCI" or framework == "PCIDSS":
        framework = "PCI-DSS"

    if framework not in VALID_COMPLIANCE_FRAMEWORKS:
        raise ToolValidationError(
            param_name, f"invalid value '{value}'", f"Use one of: {', '.join(sorted(VALID_COMPLIANCE_FRAMEWORKS))}"
        )

    return framework


def validate_iso27001_control(value: Any, required: bool = False, param_name: str = "control_id") -> Optional[str]:
    """Validate an ISO 27001:2022 Annex A control ID or domain (e.g. 'A.8.8', 'A.8')."""
    if value is None or str(value).strip() == "":
        if required:
            raise ToolValidationError(param_name, "is required", "Provide a control ID like 'A.8.8' or domain 'A.8'")
        return None

    control = str(value).strip().upper()
    # Normalize lowercase input: a.8.8 → A.8.8
    if control.startswith("A.") is False and control.startswith("A"):
        control = "A." + control[1:].lstrip(".")

    if control not in VALID_ISO27001_CONTROLS:
        raise ToolValidationError(
            param_name,
            f"invalid control '{value}'",
            f"Use a domain (A.5/A.6/A.7/A.8) or specific control like A.8.8. "
            f"Supported: {', '.join(sorted(VALID_ISO27001_CONTROLS))}",
        )
    return control


def validate_query(value: Any, required: bool = True, param_name: str = "query") -> str:
    """Validate search query parameter."""
    if value is None or str(value).strip() == "":
        if required:
            raise ToolValidationError(param_name, "is required", "Provide a search query string")
        return ""

    query = str(value).strip()

    # Check for dangerous patterns
    dangerous = ["<script", "javascript:", "; drop", "; delete", "--"]
    query_lower = query.lower()
    for pattern in dangerous:
        if pattern in query_lower:
            raise ToolValidationError(
                param_name, "contains disallowed pattern", "Remove special characters and try again"
            )

    if len(query) > 500:
        raise ToolValidationError(param_name, f"too long ({len(query)} chars)", "Query must be 500 characters or less")

    return query


RULE_GROUP_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


def validate_rule_groups(value: Any, param_name: str = "rule_groups") -> Optional[List[str]]:
    """Validate an optional list of Wazuh rule group names (e.g. authentication_failed, firewall)."""
    if value is None:
        return None
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        raise ToolValidationError(
            param_name, "must be a list of rule group names", 'Provide e.g. ["authentication_failed", "firewall"]'
        )
    groups: List[str] = []
    for item in value:
        group = str(item).strip()
        if not RULE_GROUP_PATTERN.match(group):
            raise ToolValidationError(
                param_name,
                f"invalid group name '{group}'",
                "Group names may contain letters, digits, dot, underscore, and hyphen (max 64 chars)",
            )
        groups.append(group)
    if len(groups) > 20:
        raise ToolValidationError(param_name, f"too many groups ({len(groups)})", "Provide at most 20 rule groups")
    return groups or None


def validate_boolean(value: Any, default: bool = True, param_name: str = "flag") -> bool:
    """Validate boolean parameter."""
    if value is None:
        return default

    if isinstance(value, bool):
        return value

    if isinstance(value, str):
        if value.lower() in ("true", "1", "yes", "on"):
            return True
        if value.lower() in ("false", "0", "no", "off"):
            return False

    raise ToolValidationError(param_name, f"must be a boolean, got '{value}'", "Use true/false")


# Regex patterns for action tool parameter validation
USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9._@-]{1,128}$")
# Wazuh active-response command names may carry a leading "!" (the stateful-execution
# marker, e.g. "!firewall-drop"). Accept it optionally so both "firewall-drop" and
# "!firewall-drop" validate; run_active_response normalizes to the "!" form.
AR_COMMAND_PATTERN = re.compile(r"^!?[a-zA-Z0-9_-]{1,64}$")


def validate_ip_address(value: Any, required: bool = False, param_name: str = "ip_address") -> Optional[str]:
    """Validate IPv4 or IPv6 address."""
    if value is None or str(value).strip() == "":
        if required:
            raise ToolValidationError(param_name, "is required", "Provide a valid IP address (e.g., '192.168.1.1')")
        return None

    ip_str = str(value).strip()

    try:
        ipaddress.ip_address(ip_str)
    except ValueError:
        raise ToolValidationError(
            param_name, f"invalid IP address '{ip_str}'", "Use valid IPv4 (e.g., '192.168.1.1') or IPv6 address"
        )

    return ip_str


def validate_file_path(value: Any, required: bool = False, param_name: str = "file_path") -> Optional[str]:
    """Validate file path — no null bytes, no traversal, max 500 chars."""
    if value is None or str(value).strip() == "":
        if required:
            raise ToolValidationError(param_name, "is required", "Provide a valid file path")
        return None

    file_path = str(value).strip()

    if "\x00" in file_path:
        raise ToolValidationError(param_name, "contains null byte", "Remove null bytes from file path")

    if ".." in file_path:
        raise ToolValidationError(param_name, "contains path traversal", "Path must not contain '..'")

    if len(file_path) > 500:
        raise ToolValidationError(
            param_name, f"too long ({len(file_path)} chars)", "Path must be 500 characters or less"
        )

    return file_path


def validate_username(value: Any, required: bool = False, param_name: str = "username") -> Optional[str]:
    """Validate username — alphanumeric + ._-@, 1-128 chars."""
    if value is None or str(value).strip() == "":
        if required:
            raise ToolValidationError(param_name, "is required", "Provide a valid username")
        return None

    username = str(value).strip()

    if not USERNAME_PATTERN.match(username):
        raise ToolValidationError(
            param_name,
            f"invalid username '{username}'",
            "Username must be 1-128 alphanumeric characters (plus . _ - @)",
        )

    return username


def validate_active_response_command(value: Any, required: bool = False, param_name: str = "command") -> Optional[str]:
    """Validate active response command name — alphanumeric + -_, 1-64 chars, no shell metacharacters."""
    if value is None or str(value).strip() == "":
        if required:
            raise ToolValidationError(param_name, "is required", "Provide a valid active response command name")
        return None

    command = str(value).strip()

    if not AR_COMMAND_PATTERN.match(command):
        raise ToolValidationError(
            param_name,
            f"invalid command '{command}'",
            "Command must be 1-64 alphanumeric characters (plus - _)",
        )

    return command


def validate_input(value: str, max_length: int = 1000, allowed_chars: Optional[str] = None) -> bool:
    """
    Validate user input for security.

    Args:
        value: Input string to validate
        max_length: Maximum allowed length
        allowed_chars: Optional regex pattern for allowed characters

    Returns:
        True if valid

    Raises:
        ValueError: If validation fails
    """
    if not value:
        raise ValueError("Input cannot be empty")

    if len(value) > max_length:
        raise ValueError(f"Input exceeds maximum length of {max_length}")

    # Check for common injection patterns
    dangerous_patterns = ["<script", "javascript:", "onerror=", "onclick=", "../", "..\\\\"]
    value_lower = value.lower()
    for pattern in dangerous_patterns:
        if pattern in value_lower:
            raise ValueError(f"Input contains disallowed pattern: {pattern}")

    return True


def validate_batch_items(items: List[Any], max_batch_size: int = 100) -> List[Dict[str, Any]]:
    """
    Validate batch request items for security.

    Args:
        items: List of batch request items
        max_batch_size: Maximum allowed batch size

    Returns:
        List of validated items

    Raises:
        ValueError: If validation fails
    """
    if not isinstance(items, list):
        raise ValueError("Batch items must be a list")

    if len(items) > max_batch_size:
        raise ValueError(f"Batch size {len(items)} exceeds maximum of {max_batch_size}")

    validated = []
    for idx, item in enumerate(items):
        if not isinstance(item, dict):
            raise ValueError(f"Batch item at index {idx} must be a dictionary")

        # Validate required fields
        if "jsonrpc" not in item:
            raise ValueError(f"Batch item at index {idx} missing 'jsonrpc' field")

        if "method" not in item:
            raise ValueError(f"Batch item at index {idx} missing 'method' field")

        # Validate method name
        method = item.get("method", "")
        if not isinstance(method, str) or len(method) > 256:
            raise ValueError(f"Invalid method name at index {idx}")

        # Check for suspicious patterns in method
        if any(p in method.lower() for p in ["<", ">", '"', "'", ";", "|", "&"]):
            raise ValueError(f"Invalid characters in method name at index {idx}")

        validated.append(item)

    return validated


# Sensitive data patterns for log sanitization
# Order matters: URL credentials and `bearer <token>` are redacted before the
# label-based rules so the token after an `Authorization:` label is caught by the
# bearer rule instead of being left behind when the label rule stops at whitespace.
SENSITIVE_PATTERNS = [
    # user:pass@ embedded in a URL (e.g. https://admin:s3cret@indexer:9200)
    (r"([a-zA-Z][a-zA-Z0-9+.-]*://)[^\s:/@]+:[^\s@/]+@", r"\1[REDACTED]@"),
    (r"(bearer\s+)[a-zA-Z0-9._~+/=-]+", r"\1[REDACTED]"),
    # `Basic <base64(user:pass)>` — how the Wazuh Manager client authenticates, so the
    # single most likely credential to appear in a header/exception dump. Redact before the
    # label rule below (which would otherwise stop at whitespace and leave the base64).
    (r"(basic\s+)[a-zA-Z0-9+/=]+", r"\1[REDACTED]"),
    (r'(password["\']?\s*[:=]\s*["\']?)[^"\'\s,}]+', r"\1[REDACTED]"),
    (r'(token["\']?\s*[:=]\s*["\']?)[^"\'\s,}]+', r"\1[REDACTED]"),
    (r'(api[_-]?key["\']?\s*[:=]\s*["\']?)[^"\'\s,}]+', r"\1[REDACTED]"),
    (r'(secret["\']?\s*[:=]\s*["\']?)[^"\'\s,}]+', r"\1[REDACTED]"),
    (r'(authorization["\']?\s*[:=]\s*["\']?)[^"\'\s,}]+', r"\1[REDACTED]"),
    (r"wst_[a-zA-Z0-9_-]+", "wst_[REDACTED]"),
    (r"wazuh_[a-zA-Z0-9_-]{40,}", "wazuh_[REDACTED]"),
]


def sanitize_log_message(message: str) -> str:
    """
    Sanitize log messages to remove sensitive data.

    Args:
        message: The log message to sanitize

    Returns:
        Sanitized message with sensitive data redacted
    """
    import re

    result = message
    for pattern, replacement in SENSITIVE_PATTERNS:
        result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)
    return result


class SanitizingLogFilter(logging.Filter):
    """Log filter that sanitizes sensitive data."""

    def filter(self, record: logging.LogRecord) -> bool:
        """Filter and sanitize log record."""
        if hasattr(record, "msg") and isinstance(record.msg, str):
            record.msg = sanitize_log_message(record.msg)
        if hasattr(record, "args") and record.args:
            # record.args can be a tuple, dict, or single value
            if isinstance(record.args, dict):
                record.args = {k: sanitize_log_message(v) if isinstance(v, str) else v for k, v in record.args.items()}
            elif isinstance(record.args, (tuple, list)):
                sanitized_args = []
                for arg in record.args:
                    if isinstance(arg, str):
                        sanitized_args.append(sanitize_log_message(arg))
                    elif isinstance(arg, BaseException):
                        # `logger.error("failed: %s", exc)` formats the exception via str();
                        # httpx errors embed the request URL, which can carry user:pass@host.
                        # Pre-sanitize its string form (str-formatted anyway) so creds don't leak.
                        sanitized_args.append(sanitize_log_message(str(arg)))
                    else:
                        sanitized_args.append(arg)
                record.args = tuple(sanitized_args)
        return True


MAX_JSON_DEPTH = 64


def parse_json_body_safe(raw: bytes, max_depth: int = MAX_JSON_DEPTH):
    """Parse a JSON body, rejecting excessive nesting before it can exhaust the stack.

    ``json.loads`` raises ``RecursionError`` (not ``JSONDecodeError``) on deeply nested
    input, which would escape a handler that only catches decode errors and burn CPU per
    request. Pre-scan the raw bytes for nesting depth (string-aware) and cap it, then
    parse. Raises ``ValueError`` on malformed or over-nested input.
    """
    import json as _json

    depth = 0
    in_string = False
    escaped = False
    for byte in raw:
        char = chr(byte) if byte < 128 else ""
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char in "[{":
            depth += 1
            if depth > max_depth:
                raise ValueError(f"JSON nesting too deep (>{max_depth})")
        elif char in "]}":
            depth = max(0, depth - 1)
    try:
        return _json.loads(raw)
    except RecursionError:
        raise ValueError("JSON nesting too deep")


def install_log_sanitizer(extra_logger_names=("uvicorn", "uvicorn.error", "uvicorn.access")):
    """Attach ``SanitizingLogFilter`` to the handlers that actually emit records.

    A filter attached to a *logger* runs only for records logged directly to that
    logger. Records that propagate up from child loggers (``wazuh_mcp_server.*``,
    ``auth``, the API clients) reach the root logger's *handlers* without consulting
    any ancestor logger's filters — so credential redaction attached to
    ``logging.getLogger()`` never runs for them. The redaction must therefore live on
    the handlers.

    Attaches to the root handlers (creating a ``StreamHandler`` if none exist) and to
    any non-propagating framework loggers that carry their own handlers. Idempotent —
    safe to call from both ``__main__`` startup and the app lifespan.
    """
    sanitizer = SanitizingLogFilter()

    def _attach(target_logger: logging.Logger) -> None:
        for handler in target_logger.handlers:
            if not any(isinstance(f, SanitizingLogFilter) for f in handler.filters):
                handler.addFilter(sanitizer)

    root = logging.getLogger()
    if not root.handlers:
        root.addHandler(logging.StreamHandler())
    _attach(root)

    # uvicorn configures its own non-propagating loggers; the access log in particular
    # can carry credentials in request lines, so redact there too when present.
    for name in extra_logger_names:
        logger_obj = logging.getLogger(name)
        if logger_obj.handlers:
            _attach(logger_obj)

    return sanitizer


@dataclass
class SecurityMetrics:
    """Track security-related metrics."""

    failed_authentications: int = 0
    rate_limit_violations: int = 0
    suspicious_requests: int = 0
    blocked_ips: Set[str] = None
    last_reset: datetime = None

    def __post_init__(self):
        if self.blocked_ips is None:
            self.blocked_ips = set()
        if self.last_reset is None:
            self.last_reset = datetime.now(timezone.utc)


class RateLimiter:
    """Advanced rate limiting with sliding window and bounded memory."""

    MAX_TRACKED_CLIENTS = 10000  # Prevent unbounded memory growth

    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: Dict[str, deque] = defaultdict(deque)
        self.blocked_until: Dict[str, datetime] = {}

    def is_allowed(self, identifier: str) -> tuple[bool, Optional[int]]:
        """Check if request is allowed. Returns (allowed, retry_after_seconds)."""
        now = time.time()

        # Check if currently blocked
        if identifier in self.blocked_until:
            if datetime.now(timezone.utc) < self.blocked_until[identifier]:
                retry_after = int((self.blocked_until[identifier] - datetime.now(timezone.utc)).total_seconds())
                return False, retry_after
            else:
                del self.blocked_until[identifier]

        # Clean old requests
        window_start = now - self.window_seconds
        request_times = self.requests[identifier]
        while request_times and request_times[0] < window_start:
            request_times.popleft()

        # Check rate limit
        if len(request_times) >= self.max_requests:
            # Sliding window: allow again as soon as the oldest request leaves the window,
            # rather than imposing a fixed escalating multi-minute block. A single burst
            # at the ceiling should cost seconds of backoff, not 5 minutes.
            oldest = request_times[0]
            retry_after = max(1, int(self.window_seconds - (now - oldest)) + 1)
            return False, retry_after

        # Allow request
        request_times.append(now)

        # Periodic cleanup to bound memory
        if len(self.requests) > self.MAX_TRACKED_CLIENTS:
            self.cleanup()

        return True, None

    def cleanup(self):
        """Remove stale entries to bound memory usage."""
        now = time.time()
        window_start = now - self.window_seconds
        # Remove clients with no recent requests
        stale = [k for k, v in self.requests.items() if not v or v[-1] < window_start]
        for k in stale:
            del self.requests[k]
        # Remove expired blocks
        now_dt = datetime.now(timezone.utc)
        expired = [k for k, v in self.blocked_until.items() if v < now_dt]
        for k in expired:
            del self.blocked_until[k]


class SecurityValidator:
    """Validate requests for security threats."""

    # Pre-compiled regex patterns for performance (class-level constants)
    MAX_PAYLOAD_SIZE = 1024 * 1024  # 1MB

    def __init__(self):
        import re

        # Pre-compile patterns at initialization for O(1) matching per pattern
        # Patterns require SQL/command context to avoid false positives on
        # legitimate MCP tool names and JSON-RPC content
        self._compiled_patterns = [
            # SQL Injection patterns (require SQL context around keywords)
            re.compile(
                r"(?i)\b(union\s+select|insert\s+into|delete\s+from|drop\s+(table|database)"
                r"|alter\s+table|exec\s*\(|execute\s+|;\s*select\s+|;\s*drop\s+)"
            ),
            # XSS patterns
            re.compile(r"(?i)(<script|javascript:|onload=|onerror=)"),
            # Path traversal
            re.compile(r"(\.\./|\.\.\\|%2e%2e)"),
            # Command injection (require shell context, not bare chars)
            re.compile(r"(;\s*\w+\s|`[^`]+`|\$\([^)]+\)|\$\{[^}]+\})"),
        ]
        self.max_payload_size = self.MAX_PAYLOAD_SIZE

    def validate_request(self, request: Request, body: Optional[str] = None) -> tuple[bool, Optional[str]]:
        """Validate request for security threats. Returns (is_safe, reason)."""

        # Check payload size
        if body and len(body) > self.max_payload_size:
            return False, "Payload too large"

        # Check for suspicious patterns in user-controlled headers only
        # Skip standard framework/transport headers that legitimately contain semicolons, $, etc.
        _skip_headers = {
            "accept",
            "accept-encoding",
            "accept-language",
            "authorization",
            "content-type",
            "content-length",
            "connection",
            "host",
            "origin",
            "referer",
            "user-agent",
            "cookie",
            "cache-control",
            "pragma",
            "if-none-match",
            "if-modified-since",
            "x-forwarded-for",
            "x-real-ip",
            "x-forwarded-proto",
            "x-request-id",
            "mcp-session-id",
            "mcp-protocol-version",
            "last-event-id",
            "sec-websocket-key",
            "sec-websocket-version",
            "upgrade",
        }
        for header_name, header_value in request.headers.items():
            if header_name.lower() in _skip_headers:
                continue
            if self._contains_suspicious_pattern(header_value):
                return False, f"Suspicious pattern in header {header_name}"

        # Check query parameters
        for key, value in request.query_params.items():
            if self._contains_suspicious_pattern(value):
                return False, f"Suspicious pattern in query parameter {key}"

        # Check body content
        if body and self._contains_suspicious_pattern(body):
            return False, "Suspicious pattern in request body"

        return True, None

    def _contains_suspicious_pattern(self, text: str) -> bool:
        """Check if text contains suspicious patterns using pre-compiled regex."""
        for pattern in self._compiled_patterns:
            if pattern.search(text):
                return True
        return False


# Unauthenticated liveness/readiness/metrics probes — never rate-limited by the
# coarse middleware limiter (an orchestrator health-checking must not get 429'd).
RATE_LIMIT_EXEMPT_PATHS = frozenset({"/health", "/healthz", "/ready", "/readyz", "/live", "/livez", "/metrics"})

# Endpoints that run their own principal-keyed rate limiter inside the handler.
# Applying the middleware's raw-IP limiter on top would defeat the principal keying.
RATE_LIMIT_SELF_LIMITED_PATHS = frozenset({"/", "/mcp", "/sse", "/messages"})

# JSON-RPC endpoints whose body must NOT be subjected to the coarse injection-pattern
# body scan. This is a security *tool*: legitimate tool arguments routinely contain the
# very strings the WAF heuristic flags (path-traversal indicators like ../, shell
# metacharacters, SQL fragments) because analysts search for attack indicators. Every
# JSON-RPC parameter is already strictly validated per-tool by the typed validators
# (validate_ip, validate_query's restricted simple_query_string, enum whitelists, etc.),
# so the body scan adds only false positives here. Size limits and header/query-param
# scanning still apply.
JSONRPC_BODY_SCAN_EXEMPT_PATHS = frozenset({"/mcp", "/messages"})


class SecurityManager:
    """Centralized security management."""

    def __init__(self):
        self.metrics = SecurityMetrics()
        try:
            max_req = int(os.getenv("RATE_LIMIT_REQUESTS", "100"))
        except (ValueError, TypeError):
            max_req = 100
        try:
            window = int(os.getenv("RATE_LIMIT_WINDOW", "60"))
        except (ValueError, TypeError):
            window = 60
        self.rate_limiter = RateLimiter(max_requests=max_req, window_seconds=window)
        self.validator = SecurityValidator()
        self.trusted_proxies = {p.strip() for p in os.getenv("TRUSTED_PROXIES", "").split(",") if p.strip()}

    def get_client_ip(self, request: Request) -> str:
        """Get real client IP accounting for proxies.

        Uses the rightmost untrusted IP from X-Forwarded-For to prevent
        IP spoofing via attacker-controlled header entries.
        """
        if not request.client:
            return "unknown"

        direct_ip = request.client.host

        # Only trust proxy headers if the direct connection is from a trusted proxy
        if not self._is_trusted_proxy(direct_ip):
            return direct_ip

        # Check X-Forwarded-For: use rightmost non-trusted IP
        if "x-forwarded-for" in request.headers:
            forwarded_ips = [ip.strip() for ip in request.headers["x-forwarded-for"].split(",")]
            # Walk from right to left, find the first non-trusted IP
            for ip in reversed(forwarded_ips):
                if ip and not self._is_trusted_proxy(ip):
                    return ip
            # All IPs are trusted proxies, use the leftmost
            if forwarded_ips and forwarded_ips[0]:
                return forwarded_ips[0]

        # Check X-Real-IP header
        if "x-real-ip" in request.headers:
            return request.headers["x-real-ip"].strip()

        # Fall back to direct connection
        return direct_ip

    def _is_trusted_proxy(self, ip: str) -> bool:
        """Check if IP is a trusted proxy."""
        return ip in self.trusted_proxies or ip in ["127.0.0.1", "::1"]

    async def validate_request(self, request: Request) -> None:
        """Comprehensive request validation."""
        client_ip = self.get_client_ip(request)
        path = request.url.path

        # Rate limiting. Skip endpoints that run their own principal-keyed limiter
        # (so a proxy that isn't in TRUSTED_PROXIES doesn't collapse every tenant
        # into one raw-IP bucket) and unauthenticated liveness/readiness probes.
        if path not in RATE_LIMIT_EXEMPT_PATHS and path not in RATE_LIMIT_SELF_LIMITED_PATHS:
            allowed, retry_after = self.rate_limiter.is_allowed(client_ip)
            if not allowed:
                self.metrics.rate_limit_violations += 1
                raise HTTPException(
                    status_code=429,
                    detail="Rate limit exceeded",
                    headers={"Retry-After": str(retry_after)} if retry_after else {},
                )

        # Content-Length precheck: reject an oversized body BEFORE buffering it, so
        # an unauthenticated client can't OOM the process with a multi-GB upload.
        max_size = self.validator.max_payload_size
        if request.method in ("POST", "PUT", "PATCH"):
            content_length = request.headers.get("content-length")
            if content_length is not None:
                try:
                    if int(content_length) > max_size:
                        raise HTTPException(status_code=413, detail="Payload too large")
                except ValueError:
                    pass  # malformed header; the post-read length check still applies

        # Read request body for validation (cached by Starlette for the endpoint).
        body = None
        if request.method == "POST":
            try:
                raw = await request.body()
                if len(raw) > max_size:
                    raise HTTPException(status_code=413, detail="Payload too large")
                body = raw.decode("utf-8") if raw else None
            except (UnicodeDecodeError, RuntimeError) as e:
                logger.debug(f"Failed to read request body: {e}")
                body = None

        # Validate for security threats. For JSON-RPC tool endpoints, skip the coarse body
        # pattern-scan (per-parameter typed validation already covers these, and analysts
        # legitimately submit attack-indicator strings) — but keep header/query scanning and
        # the size limits enforced above.
        body_for_scan = None if path in JSONRPC_BODY_SCAN_EXEMPT_PATHS else body
        is_safe, reason = self.validator.validate_request(request, body_for_scan)
        if not is_safe:
            self.metrics.suspicious_requests += 1
            logger.warning(f"Suspicious request from {client_ip}: {reason}")
            raise HTTPException(status_code=400, detail="Invalid request")


class ConnectionPoolManager:
    """Manage HTTP connection pools for external services."""

    def __init__(self):
        self.pools: Dict[str, httpx.AsyncClient] = {}
        self.pool_configs = {
            "wazuh": {
                "timeout": httpx.Timeout(10.0, connect=5.0),
                "limits": httpx.Limits(max_connections=20, max_keepalive_connections=5),
                "retries": 3,
            }
        }

    async def get_client(self, service: str) -> httpx.AsyncClient:
        """Get or create HTTP client for service."""
        if service not in self.pools:
            config = self.pool_configs.get(service, self.pool_configs["wazuh"])
            self.pools[service] = httpx.AsyncClient(timeout=config["timeout"], limits=config["limits"])
        return self.pools[service]

    async def close_all(self):
        """Close all connection pools."""
        for client in self.pools.values():
            await client.aclose()
        self.pools.clear()


class MemoryManager:
    """Monitor and manage memory usage."""

    def __init__(self, max_memory_mb: int = None):
        if max_memory_mb is None:
            # Honor MAX_MEMORY_MB (same knob monitoring.py reads) so the kill-switch and the
            # metrics threshold agree; fall back to 512 only when unset/invalid.
            try:
                max_memory_mb = int(os.getenv("MAX_MEMORY_MB", "512"))
            except (TypeError, ValueError):
                max_memory_mb = 512
        self.max_memory_bytes = max_memory_mb * 1024 * 1024
        self.last_check = time.time()
        self.check_interval = 30  # seconds

    def check_memory_usage(self) -> bool:
        """Check if memory usage is within limits."""
        now = time.time()
        if now - self.last_check < self.check_interval:
            return True

        try:
            import psutil

            process = psutil.Process()
            memory_usage = process.memory_info().rss

            if memory_usage > self.max_memory_bytes:
                logger.warning(f"Memory usage {memory_usage / 1024 / 1024:.1f}MB exceeds limit")
                return False

            self.last_check = now
            return True
        except ImportError:
            # psutil not available, skip check
            return True
        except Exception as e:
            logger.error(f"Memory check failed: {e}")
            return True


# Global security manager instance
security_manager = SecurityManager()
connection_pool_manager = ConnectionPoolManager()
memory_manager = MemoryManager()


async def security_middleware(request: Request, call_next):
    """Security middleware for FastAPI."""
    try:
        # Memory check — but NEVER for liveness/readiness/metrics probes. Those must answer even
        # under memory pressure; 503-ing /health here would fail the container healthcheck and
        # trigger a restart loop, defeating the deliberate liveness-only design of the route.
        if request.url.path not in RATE_LIMIT_EXEMPT_PATHS:
            if not memory_manager.check_memory_usage():
                raise HTTPException(status_code=503, detail="Server overloaded")

        # Security validation
        await security_manager.validate_request(request)

        # Process request
        response = await call_next(request)

        # Add security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Content-Security-Policy"] = "default-src 'self'"

        return response

    except HTTPException as exc:
        # A BaseHTTPMiddleware runs OUTSIDE FastAPI's ExceptionMiddleware, so an
        # HTTPException raised here would escape to ServerErrorMiddleware and become a
        # 500 instead of its intended status (413/429/503). Convert it to a response.
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail},
            headers=getattr(exc, "headers", None) or None,
        )
    except Exception as e:
        logger.error(f"Security middleware error: {e}")
        return JSONResponse(status_code=500, content={"detail": "Internal server error"})
