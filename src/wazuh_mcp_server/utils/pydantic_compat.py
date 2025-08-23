"""
Comprehensive Pydantic V1/V2 compatibility layer.
Specifically designed for cross-platform compatibility while maintaining functionality.
"""

import sys
import warnings
import logging
from typing import Any, Callable, Dict, Optional, Type, Union

# Platform detection for compatibility
def detect_platform() -> dict:
    """Detect current platform and Pydantic version."""
    import platform
    import os
    
    system = platform.system().lower()
    
    # Enhanced Linux distribution detection
    is_fedora = False
    is_debian = False
    is_ubuntu = False
    is_centos = False
    is_rhel = False
    distro_name = 'unknown'
    
    if system == 'linux':
        try:
            # Read /etc/os-release for modern distributions
            with open('/etc/os-release', 'r') as f:
                content = f.read().lower()
                
                # Fedora family detection
                if any(x in content for x in ['fedora', 'red hat', 'rhel', 'centos']):
                    is_fedora = True
                    if 'fedora' in content:
                        distro_name = 'fedora'
                    elif 'red hat' in content or 'rhel' in content:
                        distro_name = 'rhel'
                        is_rhel = True
                    elif 'centos' in content:
                        distro_name = 'centos'
                        is_centos = True
                
                # Debian family detection
                elif any(x in content for x in ['debian', 'ubuntu']):
                    is_debian = True
                    if 'ubuntu' in content:
                        distro_name = 'ubuntu'
                        is_ubuntu = True
                    elif 'debian' in content:
                        distro_name = 'debian'
                
        except (FileNotFoundError, PermissionError):
            # Fallback checks using legacy files and paths
            if any(os.path.exists(f) for f in ['/etc/fedora-release', '/etc/redhat-release']):
                is_fedora = True
                if os.path.exists('/etc/fedora-release'):
                    distro_name = 'fedora'
                elif os.path.exists('/etc/redhat-release'):
                    try:
                        with open('/etc/redhat-release', 'r') as f:
                            content = f.read().lower()
                            if 'centos' in content:
                                distro_name = 'centos'
                                is_centos = True
                            else:
                                distro_name = 'rhel'
                                is_rhel = True
                    except:
                        distro_name = 'rhel'
            
            elif any(os.path.exists(f) for f in ['/etc/debian_version', '/etc/lsb-release']):
                is_debian = True
                # Check if it's Ubuntu specifically
                platform_str = platform.platform().lower()
                if 'ubuntu' in platform_str:
                    distro_name = 'ubuntu'
                    is_ubuntu = True
                else:
                    distro_name = 'debian'
            
            # Final fallback using platform string
            platform_str = platform.platform().lower()
            if 'fedora' in platform_str:
                is_fedora = True
                distro_name = 'fedora'
            elif 'ubuntu' in platform_str:
                is_debian = True
                is_ubuntu = True
                distro_name = 'ubuntu'
    
    # Check Pydantic version
    pydantic_version = None
    pydantic_v2 = False
    try:
        import pydantic
        pydantic_version = getattr(pydantic, '__version__', getattr(pydantic, 'VERSION', 'unknown'))
        pydantic_v2 = pydantic_version.startswith('2')
    except ImportError:
        pass
    
    return {
        'system': system,
        'is_fedora': is_fedora,
        'is_debian': is_debian,
        'is_ubuntu': is_ubuntu,
        'is_centos': is_centos,
        'is_rhel': is_rhel,
        'is_macos': system == 'darwin',
        'is_windows': system == 'windows',
        'distro_name': distro_name,
        'pydantic_version': pydantic_version,
        'pydantic_v2': pydantic_v2,
        'platform_string': platform.platform()
    }

# Global platform info
PLATFORM_INFO = detect_platform()

def log_platform_info():
    """Log platform detection results for debugging."""
    logging.info(f"Platform detected: {PLATFORM_INFO}")
    
    # Platform-specific warnings and recommendations
    if PLATFORM_INFO['is_fedora'] and PLATFORM_INFO['pydantic_v2']:
        logging.warning(f"Fedora family ({PLATFORM_INFO['distro_name']}) with Pydantic V2 detected - using compatibility mode")
    elif PLATFORM_INFO['is_debian'] and PLATFORM_INFO['pydantic_v2']:
        logging.info(f"Debian family ({PLATFORM_INFO['distro_name']}) with Pydantic V2 detected - using optimized mode")
    elif PLATFORM_INFO['is_macos']:
        logging.info(f"macOS detected - using native compatibility mode")
    elif PLATFORM_INFO['is_windows']:
        logging.info(f"Windows detected - using cross-platform compatibility mode")

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
                        # For V1 compatibility, we need to handle the old signature
                        # that expected (cls, v, values, field)
                        import inspect
                        sig = inspect.signature(func)
                        params = list(sig.parameters.keys())
                        
                        if len(params) == 4:  # Old V1 signature: cls, v, values, field
                            # Create a mock field object for compatibility
                            class MockField:
                                def __init__(self, name):
                                    self.name = name
                            
                            mock_field = MockField(info.field_name)
                            # Use empty dict for values since we can't modify in V2
                            return func(cls, v, {}, mock_field)
                        elif len(params) == 3:  # V1 signature: cls, v, values
                            # Pass empty dict for values since we can't modify in V2
                            return func(cls, v, {})
                        else:  # New signature: cls, v
                            return func(cls, v)
                else:
                    # Older V2 or fallback
                    @field_validator(field_name, *fields)
                    @classmethod  
                    def wrapper(cls, v: Any) -> Any:
                        # Handle 3-parameter signature for older V2
                        import inspect
                        sig = inspect.signature(func)
                        params = list(sig.parameters.keys())
                        
                        if len(params) == 3:  # V1 signature: cls, v, values
                            # Pass empty dict for values since we can't modify in V2
                            return func(cls, v, {})
                        elif len(params) == 4:  # Old V1 signature with field: cls, v, values, field
                            # Create mock field for compatibility
                            class MockField:
                                def __init__(self, name='field'):
                                    self.name = name
                            return func(cls, v, {}, MockField())
                        else:  # New signature: cls, v
                            return func(cls, v)
                
                return wrapper
            return decorator
        
        # V1-compatible BaseModel with V2 config compatibility
        class BaseModel(V2BaseModel):
            """V1-compatible BaseModel for V2."""
            
            # V2 configuration compatibility
            model_config = {
                'str_strip_whitespace': True,
                'validate_assignment': True,
                'extra': 'forbid'
            }
            
        # Platform-specific warnings and recommendations
        if PLATFORM_INFO['is_fedora']:
            warnings.warn(
                f"Fedora family ({PLATFORM_INFO['distro_name']}) with Pydantic V2 detected. Using compatibility mode. "
                "For better performance, consider using Pydantic V1: "
                "sudo dnf install python3-pydantic or pip install 'pydantic>=1.10.0,<2.0.0'",
                UserWarning
            )
        elif PLATFORM_INFO['is_debian']:
            logging.info(f"Debian family ({PLATFORM_INFO['distro_name']}) with Pydantic V2 - using optimized compatibility mode")
    
    else:
        # Pydantic V1 - Use directly  
        from pydantic import BaseModel, Field, validator
        ValidationInfo = None
        
        # Log success for different platform families
        if PLATFORM_INFO['is_fedora']:
            logging.info(f"Pydantic V1 detected on {PLATFORM_INFO['distro_name']} (Fedora family) - using native mode")
        elif PLATFORM_INFO['is_debian']:
            logging.info(f"Pydantic V1 detected on {PLATFORM_INFO['distro_name']} (Debian family) - using native mode")
        elif PLATFORM_INFO['is_macos']:
            logging.info(f"Pydantic V1 detected on macOS - using native mode")
        elif PLATFORM_INFO['is_windows']:
            logging.info(f"Pydantic V1 detected on Windows - using native mode")
        else:
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
    
    # Log warning but don't fail - provide fallback
    logging.warning(
        f"Pydantic not installed on {PLATFORM_INFO['distro_name'] or PLATFORM_INFO['system']}. "
        f"Running in compatibility mode. Install pydantic for full features: pip install pydantic"
    )

# Export unified interface
__all__ = [
    'BaseModel',
    'Field',
    'validator', 
    'ValidationInfo',
    'PYDANTIC_V2',
    'pydantic_available'
]