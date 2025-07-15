"""
Security audit logging module for Wazuh MCP Server.
Provides comprehensive security event logging and monitoring.
"""

import json
import time
import uuid
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from enum import Enum
import hashlib
import hmac
from ipaddress import ip_address, ip_network

from .logging import get_logger

logger = get_logger(__name__)


class AuditEventType(Enum):
    """Types of security audit events."""
    AUTHENTICATION_SUCCESS = "authentication_success"
    AUTHENTICATION_FAILURE = "authentication_failure"
    AUTHORIZATION_SUCCESS = "authorization_success"
    AUTHORIZATION_FAILURE = "authorization_failure"
    TOKEN_CREATED = "token_created"
    TOKEN_REVOKED = "token_revoked"
    TOKEN_EXPIRED = "token_expired"
    PASSWORD_CHANGED = "password_changed"
    ACCOUNT_LOCKED = "account_locked"
    ACCOUNT_UNLOCKED = "account_unlocked"
    ADMIN_ACTION = "admin_action"
    CONFIGURATION_CHANGE = "configuration_change"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    SECURITY_VIOLATION = "security_violation"
    SESSION_CREATED = "session_created"
    SESSION_TERMINATED = "session_terminated"
    DATA_ACCESS = "data_access"
    SYSTEM_ERROR = "system_error"


class AuditSeverity(Enum):
    """Severity levels for audit events."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class AuditEvent:
    """Security audit event structure."""
    event_id: str
    event_type: AuditEventType
    severity: AuditSeverity
    timestamp: str
    user_id: Optional[str] = None
    username: Optional[str] = None
    client_id: Optional[str] = None
    client_ip: Optional[str] = None
    user_agent: Optional[str] = None
    resource: Optional[str] = None
    action: Optional[str] = None
    outcome: str = "success"
    details: Dict[str, Any] = None
    correlation_id: Optional[str] = None
    session_id: Optional[str] = None
    request_id: Optional[str] = None
    
    def __post_init__(self):
        if self.details is None:
            self.details = {}
        
        # Generate event ID if not provided
        if not self.event_id:
            self.event_id = str(uuid.uuid4())
        
        # Generate timestamp if not provided
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary for serialization."""
        data = asdict(self)
        data['event_type'] = self.event_type.value
        data['severity'] = self.severity.value
        return data
    
    def to_json(self) -> str:
        """Convert event to JSON string."""
        return json.dumps(self.to_dict(), ensure_ascii=False)


class SecurityAuditor:
    """Security audit logging manager."""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.enabled = self.config.get("enabled", True)
        self.log_level = self.config.get("log_level", "INFO")
        self.retention_days = self.config.get("retention_days", 90)
        self.max_events_per_minute = self.config.get("max_events_per_minute", 1000)
        
        # Initialize audit logger
        self.audit_logger = logging.getLogger("security_audit")
        self.audit_logger.setLevel(getattr(logging, self.log_level.upper()))
        
        # Add file handler for audit logs
        if not self.audit_logger.handlers:
            handler = logging.FileHandler("logs/security_audit.log")
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            self.audit_logger.addHandler(handler)
        
        # Rate limiting
        self._event_counts = {}
        self._last_reset = time.time()
        
        # Threat detection
        self._failed_login_attempts = {}
        self._suspicious_ips = set()
        self._known_good_ips = set()
        
        # Load IP whitelist/blacklist
        self._load_ip_lists()
        
        logger.info("Security auditor initialized")
    
    def _load_ip_lists(self):
        """Load IP whitelist and blacklist."""
        # Load from configuration or files
        whitelist = self.config.get("ip_whitelist", [])
        blacklist = self.config.get("ip_blacklist", [])
        
        for ip in whitelist:
            try:
                self._known_good_ips.add(ip_network(ip))
            except ValueError as e:
                logger.warning(f"Invalid IP in whitelist: {ip} - {e}")
        
        for ip in blacklist:
            try:
                self._suspicious_ips.add(ip_network(ip))
            except ValueError as e:
                logger.warning(f"Invalid IP in blacklist: {ip} - {e}")
    
    def _is_rate_limited(self) -> bool:
        """Check if event logging is rate limited."""
        current_time = time.time()
        
        # Reset counter every minute
        if current_time - self._last_reset > 60:
            self._event_counts = {}
            self._last_reset = current_time
        
        # Check current rate
        current_count = sum(self._event_counts.values())
        return current_count >= self.max_events_per_minute
    
    def _increment_event_count(self, event_type: AuditEventType):
        """Increment event count for rate limiting."""
        key = event_type.value
        self._event_counts[key] = self._event_counts.get(key, 0) + 1
    
    def _detect_threats(self, event: AuditEvent):
        """Detect potential security threats."""
        if not event.client_ip:
            return
        
        client_ip = ip_address(event.client_ip)
        
        # Check against blacklist
        for network in self._suspicious_ips:
            if client_ip in network:
                self._log_security_violation(
                    event.client_ip,
                    "IP address in blacklist",
                    event.correlation_id
                )
                return
        
        # Track failed login attempts
        if event.event_type == AuditEventType.AUTHENTICATION_FAILURE:
            key = f"{event.client_ip}:{event.username}"
            self._failed_login_attempts[key] = self._failed_login_attempts.get(key, 0) + 1
            
            if self._failed_login_attempts[key] >= 5:
                self._log_security_violation(
                    event.client_ip,
                    f"Multiple failed login attempts for user {event.username}",
                    event.correlation_id
                )
        
        # Reset failed attempts on successful login
        elif event.event_type == AuditEventType.AUTHENTICATION_SUCCESS:
            key = f"{event.client_ip}:{event.username}"
            self._failed_login_attempts.pop(key, None)
    
    def _log_security_violation(self, client_ip: str, description: str, correlation_id: Optional[str] = None):
        """Log a security violation."""
        violation_event = AuditEvent(
            event_id=str(uuid.uuid4()),
            event_type=AuditEventType.SECURITY_VIOLATION,
            severity=AuditSeverity.HIGH,
            timestamp=datetime.now(timezone.utc).isoformat(),
            client_ip=client_ip,
            outcome="failure",
            details={
                "description": description,
                "automated_detection": True
            },
            correlation_id=correlation_id
        )
        
        self._write_audit_log(violation_event)
    
    def _write_audit_log(self, event: AuditEvent):
        """Write audit event to log."""
        if not self.enabled:
            return
        
        # Check rate limiting
        if self._is_rate_limited():
            logger.warning("Security audit logging rate limited")
            return
        
        # Increment event count
        self._increment_event_count(event.event_type)
        
        # Write to audit log
        audit_message = event.to_json()
        
        if event.severity == AuditSeverity.CRITICAL:
            self.audit_logger.critical(audit_message)
        elif event.severity == AuditSeverity.HIGH:
            self.audit_logger.error(audit_message)
        elif event.severity == AuditSeverity.MEDIUM:
            self.audit_logger.warning(audit_message)
        else:
            self.audit_logger.info(audit_message)
        
        # Detect threats
        self._detect_threats(event)
    
    def log_authentication_success(self, user_id: str, username: str, client_ip: str = None,
                                 user_agent: str = None, correlation_id: str = None):
        """Log successful authentication."""
        event = AuditEvent(
            event_id=str(uuid.uuid4()),
            event_type=AuditEventType.AUTHENTICATION_SUCCESS,
            severity=AuditSeverity.LOW,
            timestamp=datetime.now(timezone.utc).isoformat(),
            user_id=user_id,
            username=username,
            client_ip=client_ip,
            user_agent=user_agent,
            outcome="success",
            correlation_id=correlation_id
        )
        
        self._write_audit_log(event)
    
    def log_authentication_failure(self, username: str, client_ip: str = None,
                                 user_agent: str = None, reason: str = None,
                                 correlation_id: str = None):
        """Log failed authentication attempt."""
        event = AuditEvent(
            event_id=str(uuid.uuid4()),
            event_type=AuditEventType.AUTHENTICATION_FAILURE,
            severity=AuditSeverity.MEDIUM,
            timestamp=datetime.now(timezone.utc).isoformat(),
            username=username,
            client_ip=client_ip,
            user_agent=user_agent,
            outcome="failure",
            details={"reason": reason} if reason else {},
            correlation_id=correlation_id
        )
        
        self._write_audit_log(event)
    
    def log_authorization_failure(self, user_id: str, username: str, resource: str,
                                action: str, client_ip: str = None,
                                correlation_id: str = None):
        """Log authorization failure."""
        event = AuditEvent(
            event_id=str(uuid.uuid4()),
            event_type=AuditEventType.AUTHORIZATION_FAILURE,
            severity=AuditSeverity.MEDIUM,
            timestamp=datetime.now(timezone.utc).isoformat(),
            user_id=user_id,
            username=username,
            client_ip=client_ip,
            resource=resource,
            action=action,
            outcome="failure",
            correlation_id=correlation_id
        )
        
        self._write_audit_log(event)
    
    def log_token_created(self, user_id: str, username: str, client_id: str,
                         token_type: str, expires_in: int, correlation_id: str = None):
        """Log token creation."""
        event = AuditEvent(
            event_id=str(uuid.uuid4()),
            event_type=AuditEventType.TOKEN_CREATED,
            severity=AuditSeverity.LOW,
            timestamp=datetime.now(timezone.utc).isoformat(),
            user_id=user_id,
            username=username,
            client_id=client_id,
            outcome="success",
            details={
                "token_type": token_type,
                "expires_in": expires_in
            },
            correlation_id=correlation_id
        )
        
        self._write_audit_log(event)
    
    def log_token_revoked(self, user_id: str, username: str, token_id: str,
                         reason: str = None, correlation_id: str = None):
        """Log token revocation."""
        event = AuditEvent(
            event_id=str(uuid.uuid4()),
            event_type=AuditEventType.TOKEN_REVOKED,
            severity=AuditSeverity.MEDIUM,
            timestamp=datetime.now(timezone.utc).isoformat(),
            user_id=user_id,
            username=username,
            outcome="success",
            details={
                "token_id": token_id,
                "reason": reason
            },
            correlation_id=correlation_id
        )
        
        self._write_audit_log(event)
    
    def log_password_changed(self, user_id: str, username: str, client_ip: str = None,
                           forced: bool = False, correlation_id: str = None):
        """Log password change."""
        event = AuditEvent(
            event_id=str(uuid.uuid4()),
            event_type=AuditEventType.PASSWORD_CHANGED,
            severity=AuditSeverity.MEDIUM,
            timestamp=datetime.now(timezone.utc).isoformat(),
            user_id=user_id,
            username=username,
            client_ip=client_ip,
            outcome="success",
            details={"forced": forced},
            correlation_id=correlation_id
        )
        
        self._write_audit_log(event)
    
    def log_account_locked(self, user_id: str, username: str, client_ip: str = None,
                          reason: str = None, correlation_id: str = None):
        """Log account lockout."""
        event = AuditEvent(
            event_id=str(uuid.uuid4()),
            event_type=AuditEventType.ACCOUNT_LOCKED,
            severity=AuditSeverity.HIGH,
            timestamp=datetime.now(timezone.utc).isoformat(),
            user_id=user_id,
            username=username,
            client_ip=client_ip,
            outcome="success",
            details={"reason": reason},
            correlation_id=correlation_id
        )
        
        self._write_audit_log(event)
    
    def log_admin_action(self, user_id: str, username: str, action: str,
                        target: str = None, client_ip: str = None,
                        correlation_id: str = None):
        """Log administrative action."""
        event = AuditEvent(
            event_id=str(uuid.uuid4()),
            event_type=AuditEventType.ADMIN_ACTION,
            severity=AuditSeverity.HIGH,
            timestamp=datetime.now(timezone.utc).isoformat(),
            user_id=user_id,
            username=username,
            client_ip=client_ip,
            action=action,
            outcome="success",
            details={"target": target},
            correlation_id=correlation_id
        )
        
        self._write_audit_log(event)
    
    def log_configuration_change(self, user_id: str, username: str, setting: str,
                               old_value: str = None, new_value: str = None,
                               client_ip: str = None, correlation_id: str = None):
        """Log configuration change."""
        event = AuditEvent(
            event_id=str(uuid.uuid4()),
            event_type=AuditEventType.CONFIGURATION_CHANGE,
            severity=AuditSeverity.HIGH,
            timestamp=datetime.now(timezone.utc).isoformat(),
            user_id=user_id,
            username=username,
            client_ip=client_ip,
            action="configuration_change",
            outcome="success",
            details={
                "setting": setting,
                "old_value": old_value,
                "new_value": new_value
            },
            correlation_id=correlation_id
        )
        
        self._write_audit_log(event)
    
    def log_suspicious_activity(self, description: str, client_ip: str = None,
                               user_id: str = None, username: str = None,
                               severity: AuditSeverity = AuditSeverity.MEDIUM,
                               correlation_id: str = None):
        """Log suspicious activity."""
        event = AuditEvent(
            event_id=str(uuid.uuid4()),
            event_type=AuditEventType.SUSPICIOUS_ACTIVITY,
            severity=severity,
            timestamp=datetime.now(timezone.utc).isoformat(),
            user_id=user_id,
            username=username,
            client_ip=client_ip,
            outcome="detected",
            details={"description": description},
            correlation_id=correlation_id
        )
        
        self._write_audit_log(event)
    
    def log_rate_limit_exceeded(self, client_ip: str, endpoint: str = None,
                               user_id: str = None, correlation_id: str = None):
        """Log rate limit exceeded."""
        event = AuditEvent(
            event_id=str(uuid.uuid4()),
            event_type=AuditEventType.RATE_LIMIT_EXCEEDED,
            severity=AuditSeverity.MEDIUM,
            timestamp=datetime.now(timezone.utc).isoformat(),
            user_id=user_id,
            client_ip=client_ip,
            resource=endpoint,
            outcome="blocked",
            correlation_id=correlation_id
        )
        
        self._write_audit_log(event)
    
    def log_data_access(self, user_id: str, username: str, resource: str,
                       action: str, client_ip: str = None,
                       correlation_id: str = None):
        """Log data access."""
        event = AuditEvent(
            event_id=str(uuid.uuid4()),
            event_type=AuditEventType.DATA_ACCESS,
            severity=AuditSeverity.LOW,
            timestamp=datetime.now(timezone.utc).isoformat(),
            user_id=user_id,
            username=username,
            client_ip=client_ip,
            resource=resource,
            action=action,
            outcome="success",
            correlation_id=correlation_id
        )
        
        self._write_audit_log(event)
    
    def log_system_error(self, error_type: str, description: str,
                        user_id: str = None, client_ip: str = None,
                        correlation_id: str = None):
        """Log system error."""
        event = AuditEvent(
            event_id=str(uuid.uuid4()),
            event_type=AuditEventType.SYSTEM_ERROR,
            severity=AuditSeverity.HIGH,
            timestamp=datetime.now(timezone.utc).isoformat(),
            user_id=user_id,
            client_ip=client_ip,
            outcome="error",
            details={
                "error_type": error_type,
                "description": description
            },
            correlation_id=correlation_id
        )
        
        self._write_audit_log(event)
    
    def get_audit_statistics(self) -> Dict[str, Any]:
        """Get audit logging statistics."""
        return {
            "enabled": self.enabled,
            "events_logged_this_minute": sum(self._event_counts.values()),
            "rate_limit": self.max_events_per_minute,
            "failed_login_attempts": len(self._failed_login_attempts),
            "suspicious_ips": len(self._suspicious_ips),
            "known_good_ips": len(self._known_good_ips)
        }


# Global auditor instance
_auditor = None


def get_auditor() -> SecurityAuditor:
    """Get the global security auditor instance."""
    global _auditor
    if _auditor is None:
        _auditor = SecurityAuditor()
    return _auditor


def configure_auditor(config: Dict[str, Any]):
    """Configure the global security auditor."""
    global _auditor
    _auditor = SecurityAuditor(config)


# Convenience functions for common audit events
def audit_authentication_success(user_id: str, username: str, client_ip: str = None,
                               user_agent: str = None, correlation_id: str = None):
    """Log successful authentication."""
    get_auditor().log_authentication_success(user_id, username, client_ip, user_agent, correlation_id)


def audit_authentication_failure(username: str, client_ip: str = None,
                               user_agent: str = None, reason: str = None,
                               correlation_id: str = None):
    """Log failed authentication attempt."""
    get_auditor().log_authentication_failure(username, client_ip, user_agent, reason, correlation_id)


def audit_authorization_failure(user_id: str, username: str, resource: str,
                              action: str, client_ip: str = None,
                              correlation_id: str = None):
    """Log authorization failure."""
    get_auditor().log_authorization_failure(user_id, username, resource, action, client_ip, correlation_id)


def audit_admin_action(user_id: str, username: str, action: str,
                      target: str = None, client_ip: str = None,
                      correlation_id: str = None):
    """Log administrative action."""
    get_auditor().log_admin_action(user_id, username, action, target, client_ip, correlation_id)


def audit_suspicious_activity(description: str, client_ip: str = None,
                             user_id: str = None, username: str = None,
                             severity: AuditSeverity = AuditSeverity.MEDIUM,
                             correlation_id: str = None):
    """Log suspicious activity."""
    get_auditor().log_suspicious_activity(description, client_ip, user_id, username, severity, correlation_id)