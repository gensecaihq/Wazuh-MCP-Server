#!/usr/bin/env python3
"""
Configuration Encryption Utility
Encrypts sensitive values in environment files
"""

import sys
import os
import argparse
from pathlib import Path

# Add the source directory to the path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

try:
    from wazuh_mcp_server.utils.config_encryption import ConfigEncryption, encrypt_config_file
except ImportError as e:
    print(f"Error: Failed to import encryption modules: {e}")
    print("Please ensure the project dependencies are installed.")
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Encrypt sensitive values in Wazuh MCP Server configuration files"
    )
    parser.add_argument(
        "input_file",
        help="Input environment file to encrypt (.env, .env.example, etc.)"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output file path (default: input_file.encrypted)"
    )
    parser.add_argument(
        "--master-key",
        help="Master encryption key (if not provided, will be generated/loaded)"
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite output file if it exists"
    )
    parser.add_argument(
        "--decrypt",
        action="store_true",
        help="Decrypt instead of encrypt"
    )
    parser.add_argument(
        "--list-sensitive",
        action="store_true",
        help="List sensitive configuration keys that will be encrypted"
    )
    
    args = parser.parse_args()
    
    if args.list_sensitive:
        encryption = ConfigEncryption()
        print("Sensitive configuration keys that will be encrypted:")
        for key in sorted(encryption.sensitive_keys):
            print(f"  - {key}")
        return
    
    input_file = Path(args.input_file)
    if not input_file.exists():
        print(f"Error: Input file '{input_file}' does not exist")
        sys.exit(1)
    
    output_file = Path(args.output) if args.output else input_file.with_suffix(
        input_file.suffix + ('.decrypted' if args.decrypt else '.encrypted')
    )
    
    if output_file.exists() and not args.force:
        print(f"Error: Output file '{output_file}' already exists. Use --force to overwrite.")
        sys.exit(1)
    
    try:
        encryption = ConfigEncryption(args.master_key)
        
        if args.decrypt:
            print(f"Decrypting '{input_file}' to '{output_file}'...")
            result_file = encryption.decrypt_env_file(str(input_file), str(output_file))
        else:
            print(f"Encrypting '{input_file}' to '{output_file}'...")
            result_file = encryption.encrypt_env_file(str(input_file), str(output_file))
        
        print(f"✅ Successfully {'decrypted' if args.decrypt else 'encrypted'} configuration file")
        print(f"📄 Output saved to: {result_file}")
        
        if not args.decrypt:
            print("\n⚠️  Important Security Notes:")
            print("1. Keep your master encryption key secure!")
            print("2. The master key is required to decrypt the configuration")
            print("3. Backup your master key in a secure location")
            print("4. Consider using environment variable CONFIG_MASTER_KEY in production")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()