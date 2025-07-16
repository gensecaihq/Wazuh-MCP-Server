"""
Configuration Encryption Utilities
Provides encryption at rest for sensitive configuration data
"""

import os
import base64
import logging
from typing import Dict, Any, Optional, Union
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import json

logger = logging.getLogger(__name__)


class ConfigEncryption:
    """Handles encryption/decryption of sensitive configuration values."""
    
    def __init__(self, master_key: Optional[str] = None):
        """Initialize with master key or generate one."""
        self.master_key = master_key or self._get_or_generate_master_key()
        self.fernet = self._create_fernet_instance()
        
        # Define which config keys should be encrypted
        self.sensitive_keys = {
            'WAZUH_API_PASSWORD',
            'JWT_SECRET_KEY', 
            'REDIS_PASSWORD',
            'ADMIN_PASSWORD',
            'GRAFANA_PASSWORD',
            'GRAFANA_ADMIN_PASSWORD',
            'SNYK_TOKEN',
            'SLACK_WEBHOOK_URL',
            'VIRUSTOTAL_API_KEY',
            'SHODAN_API_KEY',
            'ABUSEIPDB_API_KEY',
            'SMTP_PASSWORD',
            'WAZUH_API_PASSWORD',
            'WAZUH_INDEXER_PASS'
        }
    
    def _get_or_generate_master_key(self) -> str:
        """Get master key from environment or generate a new one."""
        # Try to get from environment first
        master_key = os.getenv('CONFIG_MASTER_KEY')
        if master_key:
            logger.info("Using master key from environment")
            return master_key
        
        # Try to get from secure file
        key_file = os.path.join(os.path.expanduser('~'), '.wazuh_mcp_key')
        if os.path.exists(key_file):
            try:
                with open(key_file, 'r') as f:
                    master_key = f.read().strip()
                logger.info("Using master key from secure file")
                return master_key
            except Exception as e:
                logger.warning(f"Failed to read key file: {e}")
        
        # Generate new key
        key = Fernet.generate_key().decode()
        
        # Save to secure file
        try:
            with open(key_file, 'w') as f:
                f.write(key)
            os.chmod(key_file, 0o600)  # Read-write for owner only
            logger.warning(f"Generated new master key and saved to {key_file}")
            logger.warning("Please backup this key securely!")
        except Exception as e:
            logger.error(f"Failed to save master key: {e}")
        
        return key
    
    def _create_fernet_instance(self) -> Fernet:
        """Create Fernet instance from master key."""
        try:
            # If master key is already a Fernet key, use it directly
            if len(self.master_key) == 44 and self.master_key.endswith('='):
                return Fernet(self.master_key.encode())
            
            # Otherwise, derive a key from the master key
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'wazuh_mcp_salt',  # Static salt for consistent keys
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(self.master_key.encode()))
            return Fernet(key)
            
        except Exception as e:
            logger.error(f"Failed to create encryption instance: {e}")
            raise
    
    def encrypt_value(self, value: str) -> str:
        """Encrypt a configuration value."""
        try:
            if not value:
                return value
            
            encrypted_data = self.fernet.encrypt(value.encode())
            # Prefix with marker to identify encrypted values
            return f"ENC:{base64.urlsafe_b64encode(encrypted_data).decode()}"
            
        except Exception as e:
            logger.error(f"Failed to encrypt value: {e}")
            return value  # Return original on error
    
    def decrypt_value(self, value: str) -> str:
        """Decrypt a configuration value."""
        try:
            if not value or not value.startswith('ENC:'):
                return value  # Not encrypted
            
            # Remove prefix and decode
            encrypted_data = base64.urlsafe_b64decode(value[4:].encode())
            decrypted_data = self.fernet.decrypt(encrypted_data)
            return decrypted_data.decode()
            
        except Exception as e:
            logger.error(f"Failed to decrypt value: {e}")
            return value  # Return original on error
    
    def is_encrypted(self, value: str) -> bool:
        """Check if a value is encrypted."""
        return isinstance(value, str) and value.startswith('ENC:')
    
    def encrypt_config_dict(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Encrypt sensitive values in a configuration dictionary."""
        encrypted_config = config.copy()
        
        for key, value in config.items():
            if key in self.sensitive_keys and isinstance(value, str) and value:
                if not self.is_encrypted(value):
                    encrypted_config[key] = self.encrypt_value(value)
                    logger.debug(f"Encrypted configuration value: {key}")
        
        return encrypted_config
    
    def decrypt_config_dict(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Decrypt sensitive values in a configuration dictionary."""
        decrypted_config = config.copy()
        
        for key, value in config.items():
            if key in self.sensitive_keys and isinstance(value, str):
                if self.is_encrypted(value):
                    decrypted_config[key] = self.decrypt_value(value)
                    logger.debug(f"Decrypted configuration value: {key}")
        
        return decrypted_config
    
    def encrypt_env_file(self, env_file_path: str, output_path: Optional[str] = None) -> str:
        """Encrypt sensitive values in an environment file."""
        output_path = output_path or f"{env_file_path}.encrypted"
        
        try:
            with open(env_file_path, 'r') as f:
                lines = f.readlines()
            
            encrypted_lines = []
            changes_made = False
            
            for line in lines:
                line = line.strip()
                if '=' in line and not line.startswith('#'):
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip().strip('"\'')  # Remove quotes
                    
                    if key in self.sensitive_keys and value and not self.is_encrypted(value):
                        encrypted_value = self.encrypt_value(value)
                        encrypted_lines.append(f"{key}={encrypted_value}\n")
                        changes_made = True
                        logger.info(f"Encrypted {key} in environment file")
                    else:
                        encrypted_lines.append(line + '\n' if line else '\n')
                else:
                    encrypted_lines.append(line + '\n' if line else '\n')
            
            if changes_made:
                with open(output_path, 'w') as f:
                    f.writelines(encrypted_lines)
                os.chmod(output_path, 0o600)  # Secure permissions
                logger.info(f"Encrypted environment file saved to: {output_path}")
            else:
                logger.info("No sensitive values found to encrypt")
            
            return output_path
            
        except Exception as e:
            logger.error(f"Failed to encrypt environment file: {e}")
            raise
    
    def decrypt_env_file(self, env_file_path: str, output_path: Optional[str] = None) -> str:
        """Decrypt sensitive values in an environment file."""
        output_path = output_path or f"{env_file_path}.decrypted"
        
        try:
            with open(env_file_path, 'r') as f:
                lines = f.readlines()
            
            decrypted_lines = []
            changes_made = False
            
            for line in lines:
                line = line.strip()
                if '=' in line and not line.startswith('#'):
                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip()
                    
                    if key in self.sensitive_keys and self.is_encrypted(value):
                        decrypted_value = self.decrypt_value(value)
                        decrypted_lines.append(f"{key}={decrypted_value}\n")
                        changes_made = True
                        logger.info(f"Decrypted {key} in environment file")
                    else:
                        decrypted_lines.append(line + '\n' if line else '\n')
                else:
                    decrypted_lines.append(line + '\n' if line else '\n')
            
            if changes_made:
                with open(output_path, 'w') as f:
                    f.writelines(decrypted_lines)
                os.chmod(output_path, 0o600)  # Secure permissions
                logger.info(f"Decrypted environment file saved to: {output_path}")
            else:
                logger.info("No encrypted values found to decrypt")
            
            return output_path
            
        except Exception as e:
            logger.error(f"Failed to decrypt environment file: {e}")
            raise


class SecureConfigManager:
    """Enhanced configuration manager with encryption support."""
    
    def __init__(self, master_key: Optional[str] = None):
        self.encryption = ConfigEncryption(master_key)
        self._config_cache: Dict[str, Any] = {}
    
    def get_secure_value(self, key: str, default: Any = None) -> Any:
        """Get a configuration value, decrypting if necessary."""
        # Try cache first
        if key in self._config_cache:
            return self._config_cache[key]
        
        # Get from environment
        value = os.getenv(key, default)
        
        # Decrypt if necessary
        if isinstance(value, str) and self.encryption.is_encrypted(value):
            value = self.encryption.decrypt_value(value)
        
        # Cache the decrypted value
        self._config_cache[key] = value
        return value
    
    def set_secure_value(self, key: str, value: str, encrypt: bool = None) -> None:
        """Set a configuration value, encrypting if it's sensitive."""
        if encrypt is None:
            encrypt = key in self.encryption.sensitive_keys
        
        if encrypt and isinstance(value, str) and value:
            encrypted_value = self.encryption.encrypt_value(value)
            os.environ[key] = encrypted_value
        else:
            os.environ[key] = value
        
        # Update cache with decrypted value
        self._config_cache[key] = value
    
    def clear_cache(self):
        """Clear the configuration cache."""
        self._config_cache.clear()
    
    def get_encryption_status(self) -> Dict[str, Any]:
        """Get status of configuration encryption."""
        status = {
            "encryption_enabled": True,
            "master_key_source": "environment" if os.getenv('CONFIG_MASTER_KEY') else "file",
            "sensitive_keys_count": len(self.encryption.sensitive_keys),
            "encrypted_values": []
        }
        
        # Check which environment variables are encrypted
        for key in self.encryption.sensitive_keys:
            value = os.getenv(key)
            if value and self.encryption.is_encrypted(value):
                status["encrypted_values"].append(key)
        
        return status


# Global instance for easy access
_global_config_manager: Optional[SecureConfigManager] = None


def get_secure_config_manager() -> SecureConfigManager:
    """Get the global secure configuration manager."""
    global _global_config_manager
    if _global_config_manager is None:
        _global_config_manager = SecureConfigManager()
    return _global_config_manager


def encrypt_config_file(file_path: str, output_path: Optional[str] = None) -> str:
    """Utility function to encrypt a configuration file."""
    encryption = ConfigEncryption()
    return encryption.encrypt_env_file(file_path, output_path)


def decrypt_config_file(file_path: str, output_path: Optional[str] = None) -> str:
    """Utility function to decrypt a configuration file."""
    encryption = ConfigEncryption()
    return encryption.decrypt_env_file(file_path, output_path)