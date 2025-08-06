"""Enhanced logging configuration with production-grade monitoring and security features."""

import os
import sys
import json
import asyncio
import logging
import logging.handlers
import threading
import uuid
from datetime import datetime
from typing import Dict, Any, Optional
from pathlib import Path
from contextvars import ContextVar

# Context variables for request tracking
request_id_var: ContextVar[str] = ContextVar('request_id', default='')
user_id_var: ContextVar[str] = ContextVar('user_id', default='')
session_id_var: ContextVar[str] = ContextVar('session_id', default='')


class SecurityAuditFilter(logging.Filter):
    """Filter to identify security-relevant log entries."""
    
    def filter(self, record):
        """Add security context to log records."""
        security_keywords = [
            'authentication', 'authorization', 'login', 'logout', 
            'credential', 'token', 'api_key', 'permission', 'access_denied',
            'rate_limit', 'validation_error', 'injection', 'suspicious'
        ]
        
        record.is_security_relevant = any(
            keyword in record.getMessage().lower() 
            for keyword in security_keywords
        )
        
        return True


class StructuredFormatter(logging.Formatter):
    """JSON formatter for structured logging."""
    
    def format(self, record):
        """Format log record as structured JSON."""
        log_entry = {
            'timestamp': datetime.now(datetime.timezone.utc).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno,
        }
        
        # Add exception info if present
        if record.exc_info:
            log_entry['exception'] = self.formatException(record.exc_info)
        
        # Add extra fields
        if hasattr(record, 'details'):
            log_entry['details'] = record.details
        
        if hasattr(record, 'is_security_relevant') and record.is_security_relevant:
            log_entry['security_relevant'] = True
        
        # Add request context if available
        if hasattr(record, 'request_id'):
            log_entry['request_id'] = record.request_id
        
        if hasattr(record, 'user_id'):
            log_entry['user_id'] = record.user_id
        
        if hasattr(record, 'ip_address'):
            log_entry['ip_address'] = record.ip_address
        
        return json.dumps(log_entry, ensure_ascii=False)


def setup_logging(
    log_level: str = "INFO",
    log_dir: Optional[str] = None,
    enable_structured: bool = True,
    enable_rotation: bool = True,
    max_bytes: int = 10 * 1024 * 1024,  # 10MB
    backup_count: int = 5
) -> logging.Logger:
    """Set up comprehensive logging configuration."""
    
    # Create log directory if specified
    if log_dir:
        Path(log_dir).mkdir(parents=True, exist_ok=True)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level.upper()))
    
    # Clear existing handlers
    root_logger.handlers.clear()
    
    # Console handler with color support
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(getattr(logging, log_level.upper()))
    
    if enable_structured:
        console_formatter = StructuredFormatter()
    else:
        console_formatter = logging.Formatter(
            '%(asctime)s [%(levelname)s] %(name)s: %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
    
    console_handler.setFormatter(console_formatter)
    console_handler.addFilter(SecurityAuditFilter())
    root_logger.addHandler(console_handler)
    
    # File handlers if log directory is specified
    if log_dir:
        # Main application log
        if enable_rotation:
            file_handler = logging.handlers.RotatingFileHandler(
                os.path.join(log_dir, 'wazuh-mcp.log'),
                maxBytes=max_bytes,
                backupCount=backup_count
            )
        else:
            file_handler = logging.FileHandler(os.path.join(log_dir, 'wazuh-mcp.log'))
        
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(StructuredFormatter() if enable_structured else console_formatter)
        file_handler.addFilter(SecurityAuditFilter())
        root_logger.addHandler(file_handler)
        
        # Security audit log (security-relevant events only)
        security_handler = logging.handlers.RotatingFileHandler(
            os.path.join(log_dir, 'security-audit.log'),
            maxBytes=max_bytes,
            backupCount=backup_count
        )
        security_handler.setLevel(logging.INFO)
        security_handler.setFormatter(StructuredFormatter())
        
        # Filter for security-relevant events only
        class SecurityOnlyFilter(logging.Filter):
            def filter(self, record):
                return getattr(record, 'is_security_relevant', False)
        
        security_handler.addFilter(SecurityOnlyFilter())
        root_logger.addHandler(security_handler)
        
        # Error log (errors and above only)
        error_handler = logging.handlers.RotatingFileHandler(
            os.path.join(log_dir, 'errors.log'),
            maxBytes=max_bytes,
            backupCount=backup_count
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(StructuredFormatter() if enable_structured else console_formatter)
        root_logger.addHandler(error_handler)
    
    return root_logger


def get_logger(name: str) -> logging.Logger:
    """Get a logger instance with consistent configuration."""
    return logging.getLogger(name)


class LogContext:
    """Context manager for adding request context to logs."""
    
    def __init__(self, request_id: str, user_id: Optional[str] = None, ip_address: Optional[str] = None):
        self.request_id = request_id
        self.user_id = user_id
        self.ip_address = ip_address
        self.old_factory = None
    
    def __enter__(self):
        """Set up log context."""
        self.old_factory = logging.getLogRecordFactory()
        
        def context_factory(*args, **kwargs):
            record = self.old_factory(*args, **kwargs)
            record.request_id = self.request_id
            if self.user_id:
                record.user_id = self.user_id
            if self.ip_address:
                record.ip_address = self.ip_address
            return record
        
        logging.setLogRecordFactory(context_factory)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Restore original log factory."""
        logging.setLogRecordFactory(self.old_factory)


def log_performance(func):
    """Decorator to log function performance."""
    import time
    import functools
    
    @functools.wraps(func)
    async def async_wrapper(*args, **kwargs):
        logger = get_logger(func.__module__)
        start_time = time.time()
        try:
            result = await func(*args, **kwargs)
            duration = time.time() - start_time
            logger.info(f"Function {func.__name__} completed in {duration:.3f}s")
            return result
        except Exception as e:
            duration = time.time() - start_time
            logger.error(f"Function {func.__name__} failed after {duration:.3f}s: {str(e)}")
            raise
    
    @functools.wraps(func)
    def sync_wrapper(*args, **kwargs):
        logger = get_logger(func.__module__)
        start_time = time.time()
        try:
            result = func(*args, **kwargs)
            duration = time.time() - start_time
            logger.info(f"Function {func.__name__} completed in {duration:.3f}s")
            return result
        except Exception as e:
            duration = time.time() - start_time
            logger.error(f"Function {func.__name__} failed after {duration:.3f}s: {str(e)}")
            raise
    
    return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper


def sanitize_log_data(data: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize log data to remove sensitive information."""
    sensitive_keys = {
        'password', 'pass', 'pwd', 'secret', 'token', 'key', 'auth',
        'credential', 'api_key', 'private_key', 'access_token'
    }
    
    def sanitize_value(key: str, value: Any) -> Any:
        if isinstance(key, str) and any(sensitive in key.lower() for sensitive in sensitive_keys):
            return "***REDACTED***"
        elif isinstance(value, dict):
            return {k: sanitize_value(k, v) for k, v in value.items()}
        elif isinstance(value, list):
            return [sanitize_value("", item) for item in value]
        else:
            return value
    
    return {k: sanitize_value(k, v) for k, v in data.items()}