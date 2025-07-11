"""
Comprehensive Pydantic V1/V2 compatibility for v1.0.0.
Specifically designed for Fedora compatibility while maintaining macOS/Ubuntu functionality.
"""

import sys
import warnings
from typing import Any, Callable, Dict, Optional, Type, Union

from .platform_compat import PLATFORM_INFO, log_platform_info

# Log platform info for debugging
log_platform_info()

try:
    import pydantic
    pydantic_available = True
    
    # Check version and create compatibility layer
    if hasattr(pydantic, '__version__'):
        version = pydantic.__version__
    elif hasattr(pydantic, 'VERSION'):
        version = pydantic.VERSION
    else:
        version = "unknown"
    
    PYDANTIC_V2 = version.startswith('2')
    
    if PYDANTIC_V2:
        # Pydantic V2 - Create V1 compatibility
        from pydantic import BaseModel as V2BaseModel, Field
        try:
            from pydantic import field_validator, ValidationInfo
        except ImportError:
            # Fallback for older V2 versions
            from pydantic import validator as field_validator
            ValidationInfo = None
        
        # V1-compatible validator decorator for V2
        def validator(
            field_name: str,
            *fields: str,
            pre: bool = False,
            each_item: bool = False,
            always: bool = False,
            check_fields: bool = True
        ):
            """V1-compatible validator decorator that works with V2."""
            def decorator(func: Callable) -> Callable:
                if ValidationInfo is not None:
                    # Full V2 with ValidationInfo
                    @field_validator(field_name, *fields)
                    @classmethod
                    def wrapper(cls, v: Any, info: ValidationInfo) -> Any:
                        return func(cls, v)
                else:
                    # Older V2 or fallback
                    @field_validator(field_name, *fields)
                    @classmethod  
                    def wrapper(cls, v: Any) -> Any:
                        return func(cls, v)
                
                return wrapper
            return decorator
        
        # V1-compatible BaseModel
        class BaseModel(V2BaseModel):
            """V1-compatible BaseModel for V2."""
            pass
            
        # Fedora-specific warning
        if PLATFORM_INFO['is_fedora']:
            warnings.warn(
                "Fedora with Pydantic V2 detected. Using compatibility mode. "
                "For better performance, consider using Pydantic V1: "
                "pip install 'pydantic>=1.10.0,<2.0.0'",
                UserWarning
            )
    
    else:
        # Pydantic V1 - Use directly  
        from pydantic import BaseModel, Field, validator
        ValidationInfo = None
        
        # Log success for non-Fedora systems
        if not PLATFORM_INFO['is_fedora']:
            import logging
            logging.info(f"Pydantic V1 detected on {PLATFORM_INFO['system']} - using native mode")

except ImportError as e:
    # Pydantic not available
    pydantic_available = False
    PYDANTIC_V2 = False
    
    # Create minimal fallback classes
    class BaseModel:
        def __init__(self, **kwargs):
            for key, value in kwargs.items():
                setattr(self, key, value)
    
    def Field(*args, **kwargs):
        return None
        
    def validator(*args, **kwargs):
        def decorator(func):
            return func
        return decorator
    
    ValidationInfo = None
    
    # Error message with platform-specific guidance
    error_msg = f"Pydantic is required but not installed on {PLATFORM_INFO['system']}"
    if PLATFORM_INFO['is_fedora']:
        error_msg += "\nFor Fedora, install with: sudo dnf install python3-pydantic or pip install pydantic"
    elif PLATFORM_INFO['is_ubuntu']:
        error_msg += "\nFor Ubuntu, install with: sudo apt install python3-pydantic or pip install pydantic"
    elif PLATFORM_INFO['is_macos']:
        error_msg += "\nFor macOS, install with: pip install pydantic"
    else:
        error_msg += "\nInstall with: pip install pydantic"
    
    raise ImportError(error_msg)

# Export unified interface
__all__ = [
    'BaseModel',
    'Field',
    'validator', 
    'ValidationInfo',
    'PYDANTIC_V2',
    'pydantic_available'
]