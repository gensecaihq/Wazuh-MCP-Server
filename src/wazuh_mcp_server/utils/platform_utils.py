"""Cross-platform utility functions for Wazuh MCP Server.

This module provides platform-specific utilities to ensure consistent behavior
across Linux, macOS, and Windows operating systems.
"""

import os
import platform
from pathlib import Path
from typing import Dict, Any, Optional
import tempfile


def get_platform_info() -> Dict[str, Any]:
    """Get comprehensive platform information.
    
    Returns:
        Dictionary containing platform details including OS type, version,
        architecture, and Python version information.
    """
    system = platform.system()
    
    # Detect Linux distribution
    linux_distro = None
    is_fedora = False
    is_ubuntu = False
    
    if system == "Linux":
        try:
            # Try to read /etc/os-release for distribution info
            if os.path.exists("/etc/os-release"):
                with open("/etc/os-release", "r") as f:
                    os_release = f.read().lower()
                    if "fedora" in os_release:
                        is_fedora = True
                        linux_distro = "fedora"
                    elif "ubuntu" in os_release:
                        is_ubuntu = True
                        linux_distro = "ubuntu"
                    elif "debian" in os_release:
                        linux_distro = "debian"
                    elif "centos" in os_release:
                        linux_distro = "centos"
                    elif "rhel" in os_release or "red hat" in os_release:
                        linux_distro = "rhel"
        except Exception:
            # Fallback detection methods
            try:
                import distro
                linux_distro = distro.id()
                is_fedora = linux_distro == "fedora"
                is_ubuntu = linux_distro == "ubuntu"
            except ImportError:
                pass
    
    return {
        "system": system,
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "is_windows": system == "Windows",
        "is_linux": system == "Linux", 
        "is_macos": system == "Darwin",
        "is_unix": system in ("Linux", "Darwin"),
        "is_fedora": is_fedora,
        "is_ubuntu": is_ubuntu,
        "linux_distro": linux_distro,
        "path_separator": os.sep,
        "line_separator": os.linesep,
        "env_path_separator": os.pathsep
    }


def get_config_dir(app_name: str = "WazuhMCP") -> Path:
    """Get platform-appropriate configuration directory.
    
    Args:
        app_name: Application name for directory naming
        
    Returns:
        Path object pointing to the configuration directory
    """
    system = platform.system()
    
    if system == "Windows":
        # Windows: %APPDATA%\AppName
        appdata = os.environ.get("APPDATA")
        if appdata:
            return Path(appdata) / app_name
        return Path.home() / "AppData" / "Roaming" / app_name
        
    elif system == "Darwin":  # macOS
        # macOS: ~/Library/Application Support/AppName
        return Path.home() / "Library" / "Application Support" / app_name
        
    else:  # Linux and other Unix-like systems
        # Linux: $XDG_CONFIG_HOME/app_name or ~/.config/app_name
        xdg_config = os.environ.get("XDG_CONFIG_HOME")
        if xdg_config:
            return Path(xdg_config) / app_name.lower().replace(" ", "-")
        return Path.home() / ".config" / app_name.lower().replace(" ", "-")


def get_data_dir(app_name: str = "WazuhMCP") -> Path:
    """Get platform-appropriate data directory.
    
    Args:
        app_name: Application name for directory naming
        
    Returns:
        Path object pointing to the data directory
    """
    system = platform.system()
    
    if system == "Windows":
        # Windows: %LOCALAPPDATA%\AppName
        localappdata = os.environ.get("LOCALAPPDATA")
        if localappdata:
            return Path(localappdata) / app_name
        return Path.home() / "AppData" / "Local" / app_name
        
    elif system == "Darwin":  # macOS
        # macOS: ~/Library/Application Support/AppName
        return Path.home() / "Library" / "Application Support" / app_name
        
    else:  # Linux and other Unix-like systems
        # Linux: $XDG_DATA_HOME/app_name or ~/.local/share/app_name
        xdg_data = os.environ.get("XDG_DATA_HOME")
        if xdg_data:
            return Path(xdg_data) / app_name.lower().replace(" ", "-")
        return Path.home() / ".local" / "share" / app_name.lower().replace(" ", "-")


def get_log_dir(app_name: str = "WazuhMCP") -> Path:
    """Get platform-appropriate log directory.
    
    Args:
        app_name: Application name for directory naming
        
    Returns:
        Path object pointing to the log directory
    """
    system = platform.system()
    
    if system == "Windows":
        # Windows: %LOCALAPPDATA%\AppName\logs
        return get_data_dir(app_name) / "logs"
        
    elif system == "Darwin":  # macOS
        # macOS: ~/Library/Logs/AppName
        return Path.home() / "Library" / "Logs" / app_name
        
    else:  # Linux and other Unix-like systems
        # Linux: Try system log dir first, fall back to user dir
        system_log_dir = Path("/var/log") / app_name.lower().replace(" ", "-")
        if os.access("/var/log", os.W_OK):
            return system_log_dir
        # Fall back to user data directory
        return get_data_dir(app_name) / "logs"


def get_cache_dir(app_name: str = "WazuhMCP") -> Path:
    """Get platform-appropriate cache directory.
    
    Args:
        app_name: Application name for directory naming
        
    Returns:
        Path object pointing to the cache directory
    """
    system = platform.system()
    
    if system == "Windows":
        # Windows: %LOCALAPPDATA%\AppName\cache
        return get_data_dir(app_name) / "cache"
        
    elif system == "Darwin":  # macOS
        # macOS: ~/Library/Caches/AppName
        return Path.home() / "Library" / "Caches" / app_name
        
    else:  # Linux and other Unix-like systems
        # Linux: $XDG_CACHE_HOME/app_name or ~/.cache/app_name
        xdg_cache = os.environ.get("XDG_CACHE_HOME")
        if xdg_cache:
            return Path(xdg_cache) / app_name.lower().replace(" ", "-")
        return Path.home() / ".cache" / app_name.lower().replace(" ", "-")


def get_temp_dir() -> Path:
    """Get platform-appropriate temporary directory.
    
    Returns:
        Path object pointing to the system temporary directory
    """
    return Path(tempfile.gettempdir())


def ensure_directory_exists(directory: Path, mode: int = 0o755) -> bool:
    """Ensure a directory exists with proper permissions.
    
    Args:
        directory: Path to the directory
        mode: Permission mode (Unix-like systems only)
        
    Returns:
        True if directory exists or was created successfully
    """
    try:
        directory.mkdir(parents=True, exist_ok=True)
        
        # Set permissions on Unix-like systems
        if platform.system() != "Windows" and mode != 0o755:
            os.chmod(directory, mode)
            
        return True
    except (OSError, PermissionError):
        return False


def set_secure_file_permissions(file_path: Path) -> bool:
    """Set secure file permissions cross-platform.
    
    Args:
        file_path: Path to the file
        
    Returns:
        True if permissions were set successfully
    """
    try:
        if platform.system() != "Windows":
            # Unix-like systems: Owner read/write only
            os.chmod(file_path, 0o600)
        else:
            # Windows: Rely on NTFS permissions
            # Could implement Windows ACL handling here if needed
            pass
        return True
    except (OSError, PermissionError):
        return False


def get_executable_extension() -> str:
    """Get the executable file extension for the current platform.
    
    Returns:
        File extension including dot ('.exe' on Windows, '' on Unix)
    """
    return ".exe" if platform.system() == "Windows" else ""


def get_script_extension() -> str:
    """Get the script file extension for the current platform.
    
    Returns:
        Preferred script extension ('.bat' on Windows, '.sh' on Unix)
    """
    return ".bat" if platform.system() == "Windows" else ".sh"


def normalize_path(path: str) -> Path:
    """Normalize a path string to a Path object with proper separators.
    
    Args:
        path: Path string that may contain forward or back slashes
        
    Returns:
        Normalized Path object
    """
    # Replace any path separators with the OS-appropriate one
    normalized = path.replace("/", os.sep).replace("\\", os.sep)
    return Path(normalized)


def get_wazuh_paths() -> Dict[str, Path]:
    """Get platform-appropriate Wazuh installation paths.
    
    Returns:
        Dictionary mapping path types to Path objects for the current platform
    """
    system = platform.system()
    
    if system == "Windows":
        # Windows Wazuh installation paths
        base_path = Path("C:/Program Files (x86)/ossec-agent")
        if not base_path.exists():
            # Alternative path for newer installations
            base_path = Path("C:/Program Files/Wazuh Agent")
        if not base_path.exists():
            # Fallback generic path
            base_path = Path("C:/ossec")
            
        return {
            "base": base_path,
            "logs": base_path / "logs",
            "bin": base_path / "bin", 
            "etc": base_path / "etc",
            "ossec_log": base_path / "logs" / "ossec.log",
            "api_log": base_path / "logs" / "api.log",
            "cluster_log": base_path / "logs" / "cluster.log",
            "modulesd_log": base_path / "logs" / "wazuh-modulesd.log",
            "authd_log": base_path / "logs" / "wazuh-authd.log",
            "monitord_log": base_path / "logs" / "wazuh-monitord.log",
            "remoted_log": base_path / "logs" / "wazuh-remoted.log"
        }
    else:
        # Unix-like systems (Linux, macOS)
        base_path = Path("/var/ossec")
        
        return {
            "base": base_path,
            "logs": base_path / "logs",
            "bin": base_path / "bin",
            "etc": base_path / "etc", 
            "ossec_log": base_path / "logs" / "ossec.log",
            "api_log": base_path / "logs" / "api.log",
            "cluster_log": base_path / "logs" / "cluster.log",
            "modulesd_log": base_path / "logs" / "wazuh-modulesd.log",
            "authd_log": base_path / "logs" / "wazuh-authd.log",
            "monitord_log": base_path / "logs" / "wazuh-monitord.log",
            "remoted_log": base_path / "logs" / "wazuh-remoted.log"
        }


def get_wazuh_log_path(log_type: str) -> Path:
    """Get the path for a specific Wazuh log file.
    
    Args:
        log_type: Type of log file (e.g., 'ossec', 'api', 'cluster', etc.)
        
    Returns:
        Path object for the specified log file
    """
    paths = get_wazuh_paths()
    log_key = f"{log_type}_log"
    
    if log_key in paths:
        return paths[log_key]
    else:
        # Fallback: construct path from log type
        return paths["logs"] / f"{log_type}.log"


def get_suspicious_paths() -> list:
    """Get list of suspicious file paths for different platforms.
    
    Returns:
        List of path patterns that might indicate malicious activity
    """
    system = platform.system()
    
    common_suspicious = [
        # Temporary directories
        "temp/", "tmp/", "temporary/",
        # Downloads directories  
        "downloads/", "download/",
        # Common malware locations
        "windows/temp/", "windows/system32/",
    ]
    
    if system == "Windows":
        return common_suspicious + [
            "\\temp\\", "\\tmp\\", "\\temporary\\",
            "\\downloads\\", "\\download\\",
            "\\windows\\temp\\", "\\windows\\system32\\",
            "\\users\\public\\", "\\programdata\\",
            "\\appdata\\local\\temp\\", "\\appdata\\roaming\\",
            "%temp%", "%tmp%", "%appdata%", "%programdata%"
        ]
    else:
        return common_suspicious + [
            "/tmp/", "/var/tmp/", "/dev/shm/",
            "/home/*/downloads/", "/home/*/Downloads/",
            "/usr/tmp/", "/var/spool/",
            "~/.cache/", "~/.local/", "~/.config/"
        ]


def is_admin() -> bool:
    """Check if the current process is running with administrator privileges.
    
    Returns:
        True if running as administrator/root, False otherwise
    """
    try:
        if platform.system() == "Windows":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            # Unix-like systems
            return os.geteuid() == 0
    except (ImportError, AttributeError, OSError):
        return False


def get_environment_variable(var_name: str, default: Optional[str] = None) -> Optional[str]:
    """Get environment variable with cross-platform fallbacks.
    
    Args:
        var_name: Name of the environment variable
        default: Default value if variable is not found
        
    Returns:
        Environment variable value or default
    """
    # Try direct lookup first
    value = os.getenv(var_name, default)
    
    # If not found and on Windows, try common variations
    if value == default and platform.system() == "Windows":
        # Try with common Windows prefixes
        for prefix in ["WAZUH_", "MCP_", ""]:
            alt_name = f"{prefix}{var_name}" if prefix else var_name
            value = os.getenv(alt_name.upper())
            if value:
                break
                
        # Try lowercase version
        if not value:
            value = os.getenv(var_name.lower(), default)
    
    return value


def get_system_encoding() -> str:
    """Get the system's default encoding.
    
    Returns:
        String representing the system's preferred encoding
    """
    return platform.system() == "Windows" and "cp1252" or "utf-8"


def supports_color_output() -> bool:
    """Check if the current terminal supports colored output.
    
    Returns:
        True if color output is supported
    """
    # Check for common environment variables that indicate color support
    if os.getenv("NO_COLOR"):
        return False
        
    if os.getenv("FORCE_COLOR") or os.getenv("CLICOLOR_FORCE"):
        return True
        
    # Check if we're in a terminal
    if not hasattr(os, "isatty") or not os.isatty(1):
        return False
        
    # Windows-specific checks
    if platform.system() == "Windows":
        # Windows 10 version 1511 and later support ANSI escape sequences
        try:
            import subprocess
            # Use shell=False and provide command as list for security
            result = subprocess.run(
                ["cmd", "/c", "ver"], capture_output=True, text=True, shell=False
            )
            if "10." in result.stdout or "11." in result.stdout:
                return True
        except (subprocess.SubprocessError, FileNotFoundError):
            pass
        return False
    
    # Unix-like systems: check TERM environment variable
    term = os.getenv("TERM", "").lower()
    return "color" in term or term in ("xterm", "xterm-256color", "screen")