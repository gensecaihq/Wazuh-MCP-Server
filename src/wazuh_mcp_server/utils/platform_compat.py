"""
Platform-specific compatibility handling for Pydantic V1/V2.
Addresses Fedora-specific issues while maintaining macOS/Ubuntu compatibility.
"""

import os
import platform
import sys
import warnings
import logging
from typing import Any, Callable, Optional


def detect_platform() -> dict:
    """Detect current platform and Pydantic version."""
    system = platform.system().lower()
    
    # Detect if we're on Fedora
    is_fedora = False
    if system == 'linux':
        try:
            with open('/etc/os-release', 'r') as f:
                content = f.read().lower()
                is_fedora = 'fedora' in content or 'red hat' in content
        except (FileNotFoundError, PermissionError):
            # Fallback check for Fedora-specific paths
            is_fedora = any([
                os.path.exists('/etc/fedora-release'),
                os.path.exists('/etc/redhat-release'),
                'fedora' in platform.platform().lower()
            ])
    
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
        'is_macos': system == 'darwin',
        'is_ubuntu': 'ubuntu' in platform.platform().lower(),
        'pydantic_version': pydantic_version,
        'pydantic_v2': pydantic_v2,
        'platform_string': platform.platform()
    }


# Global platform info
PLATFORM_INFO = detect_platform()


def log_platform_info():
    """Log platform detection results for debugging."""
    logging.info(f"Platform detected: {PLATFORM_INFO}")
    if PLATFORM_INFO['is_fedora'] and PLATFORM_INFO['pydantic_v2']:
        logging.warning("Fedora with Pydantic V2 detected - using compatibility mode")