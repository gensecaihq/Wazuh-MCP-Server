"""
FastMCP-compliant exception handling with comprehensive error categorization.
Implements production-grade error handling following FastMCP best practices.
"""

from __future__ import annotations
from typing import Dict, Any, Optional, List, Union
from datetime import datetime
from enum import Enum
import traceback
import uuid

from fastmcp import Context


class ErrorCategory(str, Enum):
    """Categorization of errors for better handling and logging."""
    
    # Tool execution errors
    TOOL_EXECUTION = "tool_execution"
    TOOL_VALIDATION = "tool_validation"
    TOOL_TIMEOUT = "tool_timeout"
    
    # Resource errors
    RESOURCE_NOT_FOUND = "resource_not_found"
    RESOURCE_ACCESS = "resource_access"
    RESOURCE_GENERATION = "resource_generation"
    
    # Authentication and authorization
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    PERMISSION_DENIED = "permission_denied"
    
    # External API errors
    WAZUH_API = "wazuh_api"
    EXTERNAL_SERVICE = "external_service"
    NETWORK_ERROR = "network_error"
    
    # Data processing errors
    DATA_VALIDATION = "data_validation"
    DATA_PARSING = "data_parsing"
    DATA_CORRUPTION = "data_corruption"
    
    # System errors
    CONFIGURATION = "configuration"
    SYSTEM_RESOURCE = "system_resource"
    INTERNAL_ERROR = "internal_error"
    
    # User interaction errors
    USER_INPUT = "user_input"
    ELICITATION_FAILED = "elicitation_failed"
    OPERATION_CANCELLED = "operation_cancelled"


class ErrorSeverity(str, Enum):
    """Error severity levels for prioritization and alerting."""
    
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RecoveryAction(str, Enum):
    """Suggested recovery actions for different error types."""
    
    RETRY = "retry"
    RETRY_WITH_BACKOFF = "retry_with_backoff"
    REFRESH_CONFIG = "refresh_config"
    RECONNECT = "reconnect"
    USER_INTERVENTION = "user_intervention"
    RESTART_SERVICE = "restart_service"
    ESCALATE = "escalate"
    NONE = "none"


class FastMCPError(Exception):
    """
    Base FastMCP-compliant exception with comprehensive error context.
    
    This exception class provides:
    - Structured error information
    - Context logging integration
    - Recovery suggestions
    - Error tracking and correlation
    """
    
    def __init__(
        self,
        message: str,
        category: ErrorCategory = ErrorCategory.INTERNAL_ERROR,
        severity: ErrorSeverity = ErrorSeverity.MEDIUM,
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        recovery_action: RecoveryAction = RecoveryAction.NONE,
        user_message: Optional[str] = None,
        correlation_id: Optional[str] = None,
        context: Optional[Context] = None
    ):
        super().__init__(message)
        
        self.message = message
        self.category = category
        self.severity = severity
        self.error_code = error_code or self._generate_error_code()
        self.details = details or {}
        self.recovery_action = recovery_action
        self.user_message = user_message or self._generate_user_message()
        self.correlation_id = correlation_id or str(uuid.uuid4())
        self.timestamp = datetime.utcnow()
        self.context = context
        
        # Capture stack trace for debugging
        self.stack_trace = traceback.format_exc()
        
        # Log to context if available
        if self.context:
            self._log_to_context()
    
    def _generate_error_code(self) -> str:
        """Generate a standardized error code."""
        return f"{self.category.value.upper()}_{self.__class__.__name__.upper()}"
    
    def _generate_user_message(self) -> str:
        """Generate a user-friendly error message."""
        if self.severity == ErrorSeverity.CRITICAL:
            return "A critical system error occurred. Please contact support immediately."
        elif self.severity == ErrorSeverity.HIGH:
            return "A significant error occurred. The operation could not be completed."
        elif self.severity == ErrorSeverity.MEDIUM:
            return "An error occurred while processing your request. Please try again."
        else:
            return "A minor issue was encountered. The system will attempt to recover automatically."
    
    async def _log_to_context(self) -> None:
        """Log error to FastMCP context."""
        if not self.context:
            return
        
        error_info = {
            "error_code": self.error_code,
            "category": self.category.value,
            "severity": self.severity.value,
            "correlation_id": self.correlation_id,
            "details": self.details,
            "recovery_action": self.recovery_action.value
        }
        
        if self.severity == ErrorSeverity.CRITICAL:
            await self.context.error(f"CRITICAL ERROR [{self.error_code}]: {self.message}", extra=error_info)
        elif self.severity == ErrorSeverity.HIGH:
            await self.context.error(f"ERROR [{self.error_code}]: {self.message}", extra=error_info)
        elif self.severity == ErrorSeverity.MEDIUM:
            await self.context.warning(f"WARNING [{self.error_code}]: {self.message}", extra=error_info)
        else:
            await self.context.info(f"INFO [{self.error_code}]: {self.message}", extra=error_info)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert exception to dictionary for JSON serialization."""
        return {
            "error_code": self.error_code,
            "message": self.message,
            "user_message": self.user_message,
            "category": self.category.value,
            "severity": self.severity.value,
            "correlation_id": self.correlation_id,
            "timestamp": self.timestamp.isoformat() + 'Z',
            "details": self.details,
            "recovery_action": self.recovery_action.value,
            "stack_trace": self.stack_trace if self.severity in [ErrorSeverity.HIGH, ErrorSeverity.CRITICAL] else None
        }


class WazuhAPIError(FastMCPError):
    """Wazuh API specific errors with enhanced context."""
    
    def __init__(
        self,
        message: str,
        status_code: Optional[int] = None,
        response_data: Optional[Dict[str, Any]] = None,
        endpoint: Optional[str] = None,
        **kwargs
    ):
        details = kwargs.get('details', {})
        details.update({
            "status_code": status_code,
            "response_data": response_data,
            "endpoint": endpoint
        })
        
        super().__init__(
            message=message,
            category=ErrorCategory.WAZUH_API,
            severity=self._determine_severity(status_code),
            recovery_action=self._determine_recovery_action(status_code),
            details=details,
            **kwargs
        )
        
        self.status_code = status_code
        self.response_data = response_data
        self.endpoint = endpoint
    
    def _determine_severity(self, status_code: Optional[int]) -> ErrorSeverity:
        """Determine error severity based on HTTP status code."""
        if not status_code:
            return ErrorSeverity.MEDIUM
        
        if status_code >= 500:
            return ErrorSeverity.HIGH
        elif status_code in [401, 403]:
            return ErrorSeverity.HIGH
        elif status_code == 429:
            return ErrorSeverity.MEDIUM
        else:
            return ErrorSeverity.LOW
    
    def _determine_recovery_action(self, status_code: Optional[int]) -> RecoveryAction:
        """Determine recovery action based on HTTP status code."""
        if not status_code:
            return RecoveryAction.RETRY
        
        if status_code in [500, 502, 503, 504]:
            return RecoveryAction.RETRY_WITH_BACKOFF
        elif status_code == 401:
            return RecoveryAction.REFRESH_CONFIG
        elif status_code == 403:
            return RecoveryAction.USER_INTERVENTION
        elif status_code == 429:
            return RecoveryAction.RETRY_WITH_BACKOFF
        else:
            return RecoveryAction.RETRY


class ValidationError(FastMCPError):
    """Data validation errors with field-specific context."""
    
    def __init__(
        self,
        message: str,
        field_errors: Optional[List[Dict[str, Any]]] = None,
        invalid_value: Optional[Any] = None,
        **kwargs
    ):
        details = kwargs.get('details', {})
        details.update({
            "field_errors": field_errors or [],
            "invalid_value": str(invalid_value) if invalid_value is not None else None
        })
        
        super().__init__(
            message=message,
            category=ErrorCategory.DATA_VALIDATION,
            severity=ErrorSeverity.LOW,
            recovery_action=RecoveryAction.USER_INTERVENTION,
            details=details,
            **kwargs
        )
        
        self.field_errors = field_errors or []
        self.invalid_value = invalid_value


class ElicitationError(FastMCPError):
    """User elicitation specific errors."""
    
    def __init__(
        self,
        message: str,
        elicitation_type: Optional[str] = None,
        user_response: Optional[str] = None,
        **kwargs
    ):
        details = kwargs.get('details', {})
        details.update({
            "elicitation_type": elicitation_type,
            "user_response": user_response
        })
        
        super().__init__(
            message=message,
            category=ErrorCategory.ELICITATION_FAILED,
            severity=ErrorSeverity.LOW,
            recovery_action=RecoveryAction.USER_INTERVENTION,
            details=details,
            **kwargs
        )


class ResourceError(FastMCPError):
    """FastMCP resource specific errors."""
    
    def __init__(
        self,
        message: str,
        resource_uri: Optional[str] = None,
        resource_type: Optional[str] = None,
        **kwargs
    ):
        details = kwargs.get('details', {})
        details.update({
            "resource_uri": resource_uri,
            "resource_type": resource_type
        })
        
        super().__init__(
            message=message,
            category=ErrorCategory.RESOURCE_ACCESS,
            severity=ErrorSeverity.MEDIUM,
            recovery_action=RecoveryAction.RETRY,
            details=details,
            **kwargs
        )


class AuthenticationError(FastMCPError):
    """Authentication specific errors."""
    
    def __init__(self, message: str, **kwargs):
        super().__init__(
            message=message,
            category=ErrorCategory.AUTHENTICATION,
            severity=ErrorSeverity.HIGH,
            recovery_action=RecoveryAction.REFRESH_CONFIG,
            user_message="Authentication failed. Please check your credentials.",
            **kwargs
        )


class AuthorizationError(FastMCPError):
    """Authorization specific errors."""
    
    def __init__(
        self,
        message: str,
        required_permission: Optional[str] = None,
        **kwargs
    ):
        details = kwargs.get('details', {})
        details.update({
            "required_permission": required_permission
        })
        
        super().__init__(
            message=message,
            category=ErrorCategory.AUTHORIZATION,
            severity=ErrorSeverity.HIGH,
            recovery_action=RecoveryAction.USER_INTERVENTION,
            user_message="Access denied. You don't have the required permissions.",
            details=details,
            **kwargs
        )


class ConfigurationError(FastMCPError):
    """Configuration specific errors."""
    
    def __init__(
        self,
        message: str,
        config_key: Optional[str] = None,
        **kwargs
    ):
        details = kwargs.get('details', {})
        details.update({
            "config_key": config_key
        })
        
        super().__init__(
            message=message,
            category=ErrorCategory.CONFIGURATION,
            severity=ErrorSeverity.HIGH,
            recovery_action=RecoveryAction.REFRESH_CONFIG,
            details=details,
            **kwargs
        )


class TimeoutError(FastMCPError):
    """Operation timeout errors."""
    
    def __init__(
        self,
        message: str,
        timeout_seconds: Optional[float] = None,
        operation_type: Optional[str] = None,
        **kwargs
    ):
        details = kwargs.get('details', {})
        details.update({
            "timeout_seconds": timeout_seconds,
            "operation_type": operation_type
        })
        
        super().__init__(
            message=message,
            category=ErrorCategory.TOOL_TIMEOUT,
            severity=ErrorSeverity.MEDIUM,
            recovery_action=RecoveryAction.RETRY,
            details=details,
            **kwargs
        )


# ============================================================================
# ERROR HANDLING UTILITIES
# ============================================================================

class ErrorHandler:
    """Centralized error handling with FastMCP context integration."""
    
    @staticmethod
    async def handle_exception(
        error: Exception,
        context: Optional[Context] = None,
        operation: Optional[str] = None
    ) -> FastMCPError:
        """
        Convert generic exceptions to FastMCP errors with proper context.
        
        Args:
            error: The original exception
            context: FastMCP context for logging
            operation: Operation being performed when error occurred
        
        Returns:
            FastMCPError instance with proper categorization
        """
        correlation_id = str(uuid.uuid4())
        
        # Convert known exception types
        if isinstance(error, FastMCPError):
            if context and not error.context:
                error.context = context
                await error._log_to_context()
            return error
        
        # HTTP/API related errors
        if "timeout" in str(error).lower():
            return TimeoutError(
                message=f"Operation timeout: {str(error)}",
                operation_type=operation,
                context=context,
                correlation_id=correlation_id
            )
        
        if "connection" in str(error).lower():
            return WazuhAPIError(
                message=f"Connection error: {str(error)}",
                endpoint=operation,
                context=context,
                correlation_id=correlation_id
            )
        
        if "permission" in str(error).lower() or "access" in str(error).lower():
            return AuthorizationError(
                message=f"Access denied: {str(error)}",
                context=context,
                correlation_id=correlation_id
            )
        
        # Generic error handling
        return FastMCPError(
            message=f"Unexpected error in {operation or 'operation'}: {str(error)}",
            category=ErrorCategory.INTERNAL_ERROR,
            severity=ErrorSeverity.HIGH,
            details={"original_error": str(error), "error_type": type(error).__name__},
            context=context,
            correlation_id=correlation_id
        )
    
    @staticmethod
    async def handle_api_response(
        response_status: int,
        response_data: Optional[Dict[str, Any]] = None,
        endpoint: Optional[str] = None,
        context: Optional[Context] = None
    ) -> None:
        """Handle API response errors and raise appropriate FastMCP exceptions."""
        if 200 <= response_status < 300:
            return  # Success, no error
        
        error_message = "Unknown API error"
        if response_data:
            error_message = response_data.get("message", str(response_data))
        
        if response_status == 400:
            raise ValidationError(
                message=f"Bad request: {error_message}",
                details={"response_data": response_data},
                context=context
            )
        elif response_status == 401:
            raise AuthenticationError(
                message=f"Authentication failed: {error_message}",
                details={"endpoint": endpoint, "response_data": response_data},
                context=context
            )
        elif response_status == 403:
            raise AuthorizationError(
                message=f"Access denied: {error_message}",
                details={"endpoint": endpoint, "response_data": response_data},
                context=context
            )
        elif response_status == 404:
            raise ResourceError(
                message=f"Resource not found: {error_message}",
                resource_uri=endpoint,
                context=context
            )
        elif response_status == 429:
            retry_after = None
            if response_data:
                retry_after = response_data.get("retry_after")
            
            raise WazuhAPIError(
                message=f"Rate limit exceeded: {error_message}",
                status_code=response_status,
                response_data=response_data,
                endpoint=endpoint,
                details={"retry_after": retry_after},
                context=context
            )
        else:
            raise WazuhAPIError(
                message=f"API error: {error_message}",
                status_code=response_status,
                response_data=response_data,
                endpoint=endpoint,
                context=context
            )


# ============================================================================
# DECORATOR FOR ERROR HANDLING
# ============================================================================

def fastmcp_error_handler(operation_name: Optional[str] = None):
    """
    Decorator for automatic FastMCP error handling in tools and resources.
    
    Args:
        operation_name: Name of the operation for error context
    """
    def decorator(func):
        async def wrapper(*args, **kwargs):
            context = None
            
            # Try to extract context from arguments
            for arg in args:
                if isinstance(arg, Context):
                    context = arg
                    break
            
            # Try to extract context from keyword arguments
            if not context and 'ctx' in kwargs:
                context = kwargs['ctx']
            
            operation = operation_name or func.__name__
            
            try:
                return await func(*args, **kwargs)
            except FastMCPError:
                # Re-raise FastMCP errors as-is
                raise
            except Exception as e:
                # Convert to FastMCP error
                fastmcp_error = await ErrorHandler.handle_exception(e, context, operation)
                raise fastmcp_error
        
        return wrapper
    return decorator