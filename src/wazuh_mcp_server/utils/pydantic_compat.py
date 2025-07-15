"""
Pydantic V1/V2 Compatibility Layer

This module provides compatibility between Pydantic V1 and V2 for cross-platform support,
especially on Fedora systems where package management may install different versions.
"""

try:
    # Try Pydantic V2 imports first
    from pydantic import BaseModel, Field, ConfigDict
    from pydantic import field_validator as validator
    from pydantic import ValidationError
    
    PYDANTIC_V2 = True
    
    def create_model_config(**kwargs):
        """Create model configuration for Pydantic V2."""
        return ConfigDict(**kwargs)
    
except ImportError:
    try:
        # Fallback to Pydantic V1 imports
        from pydantic import BaseModel, Field, validator
        from pydantic import ValidationError
        
        PYDANTIC_V2 = False
        
        def create_model_config(**kwargs):
            """Create model configuration for Pydantic V1."""
            class Config:
                pass
            
            for key, value in kwargs.items():
                setattr(Config, key, value)
            
            return Config
        
    except ImportError as e:
        raise ImportError(
            "Neither Pydantic V1 nor V2 could be imported. "
            "Please install pydantic: pip install 'pydantic>=1.10.0,<3.0.0'"
        ) from e

# Export commonly used components
__all__ = [
    'BaseModel',
    'Field', 
    'validator',
    'ValidationError',
    'PYDANTIC_V2',
    'create_model_config'
]