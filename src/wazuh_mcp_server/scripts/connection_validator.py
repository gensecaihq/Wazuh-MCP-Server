#!/usr/bin/env python3
"""Intelligent connection validator for Wazuh MCP Server.

This module provides comprehensive connection testing with automatic protocol
detection, SSL validation, and configuration recommendations.
"""

import asyncio
import socket
import ssl
import aiohttp
import json
import platform
from typing import Dict, List, Optional, Tuple
from pathlib import Path
import sys
import os

# Add src to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from wazuh_mcp_server.config import WazuhConfig
from wazuh_mcp_server.utils.logging import get_logger

logger = get_logger(__name__)

# Windows console compatibility
def _supports_unicode():
    """Check if the terminal supports Unicode characters."""
    try:
        "✅".encode(sys.stdout.encoding or 'utf-8')
        return True
    except (UnicodeEncodeError, LookupError):
        return False

def _safe_print(text):
    """Print text with Windows console compatibility."""
    try:
        print(text)
    except UnicodeEncodeError:
        # Replace Unicode characters with ASCII equivalents
        replacements = {
            '✅': '[OK]',
            '❌': '[FAIL]', 
            '🔍': '[SEARCH]',
            '📊': '[CHART]',
            '📡': '[SIGNAL]',
            '📋': '[INFO]',
            '🔒': '[SECURE]',
            '🔓': '[UNSECURE]',
            '⚠️': '[WARN]',
            '🎉': '[SUCCESS]',
            '💡': '[TIP]'
        }
        safe_text = text
        for unicode_char, ascii_replacement in replacements.items():
            safe_text = safe_text.replace(unicode_char, ascii_replacement)
        print(safe_text.encode('ascii', errors='replace').decode('ascii'))


class ConnectionValidator:
    """Intelligent connection validator with protocol detection."""
    
    def __init__(self, config: WazuhConfig):
        self.config = config
        self.results = {
            'manager': {'reachable': False, 'protocol': None, 'ssl_valid': False},
            'indexer': {'reachable': False, 'protocol': None, 'ssl_valid': False},
            'recommendations': []
        }
    
    async def validate_all_connections(self) -> Dict:
        """Validate all configured connections."""
        _safe_print("🔍 Starting comprehensive connection validation...")
        _safe_print("")
        
        # Test Wazuh Manager
        if self.config.host:
            _safe_print(f"📡 Testing Wazuh Manager: {self.config.host}:{self.config.port}")
            manager_result = await self.test_manager_connection()
            self.results['manager'] = manager_result
            self._print_connection_result("Manager", manager_result)
        
        # Test Wazuh Indexer
        if hasattr(self.config, 'indexer_host') and self.config.indexer_host:
            _safe_print(f"📊 Testing Wazuh Indexer: {self.config.indexer_host}:{self.config.indexer_port}")
            indexer_result = await self.test_indexer_connection()
            self.results['indexer'] = indexer_result
            self._print_connection_result("Indexer", indexer_result)
        
        # Generate recommendations
        self._generate_recommendations()
        
        return self.results
    
    async def test_manager_connection(self) -> Dict:
        """Test Wazuh Manager connection with protocol detection."""
        result = {
            'reachable': False,
            'protocol': None,
            'ssl_valid': False,
            'self_signed': False,
            'auth_success': False,
            'api_version': None,
            'error': None
        }
        
        # Test HTTPS first
        https_result = await self._test_https_connection(
            self.config.host, self.config.port
        )
        
        if https_result['success']:
            result.update(https_result)
            result['protocol'] = 'https'
            
            # Test API authentication
            auth_result = await self._test_api_authentication()
            result['auth_success'] = auth_result.get('success', False)
            result['api_version'] = auth_result.get('version')
            if not auth_result.get('success'):
                result['error'] = auth_result.get('error')
        
        return result
    
    async def test_indexer_connection(self) -> Dict:
        """Test Wazuh Indexer connection."""
        result = {
            'reachable': False,
            'protocol': None,
            'ssl_valid': False,
            'self_signed': False,
            'cluster_status': None,
            'error': None
        }
        
        # Test HTTPS connection
        https_result = await self._test_https_connection(
            self.config.indexer_host, self.config.indexer_port
        )
        
        if https_result['success']:
            result.update(https_result)
            result['protocol'] = 'https'
            
            # Test Indexer API
            cluster_result = await self._test_indexer_api()
            result['cluster_status'] = cluster_result.get('status')
            if not cluster_result.get('success'):
                result['error'] = cluster_result.get('error')
        
        return result
    
    async def _test_https_connection(self, host: str, port: int) -> Dict:
        """Test HTTPS connection with SSL validation."""
        result = {
            'success': False,
            'ssl_valid': False,
            'self_signed': False,
            'error': None
        }
        
        # Test with SSL verification
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    result['success'] = True
                    result['ssl_valid'] = True
                    return result
        except ssl.SSLCertVerificationError:
            result['self_signed'] = True
        except Exception:
            result['error'] = str(e)
        
        # Test with disabled SSL verification
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    result['success'] = True
                    result['ssl_valid'] = False
                    return result
        except Exception:
            result['error'] = str(e)
        
        return result
    
    async def _test_api_authentication(self) -> Dict:
        """Test Wazuh API authentication."""
        result = {'success': False, 'error': None, 'version': None}
        
        # Create SSL context based on configuration
        ssl_context = ssl.create_default_context()
        if not self.config.verify_ssl:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
        
        connector = aiohttp.TCPConnector(ssl=ssl_context)
        
        try:
            async with aiohttp.ClientSession(connector=connector) as session:
                # Test authentication endpoint
                auth_url = f"{self.config.base_url}/security/user/authenticate"
                auth = aiohttp.BasicAuth(self.config.username, self.config.password)
                
                async with session.post(auth_url, auth=auth) as response:
                    if response.status == 200:
                        result['success'] = True
                        # Get API version
                        version_url = f"{self.config.base_url}/"
                        async with session.get(version_url, headers={'Authorization': f'Bearer {(await response.json()).get("token", "")}'}) as version_response:
                            if version_response.status == 200:
                                version_data = await version_response.json()
                                result['version'] = version_data.get('data', {}).get('api_version')
                    else:
                        result['error'] = f"Authentication failed: HTTP {response.status}"
        
        except Exception:
            result['error'] = str(e)
        
        return result
    
    async def _test_indexer_api(self) -> Dict:
        """Test Wazuh Indexer API."""
        result = {'success': False, 'error': None, 'status': None}
        
        # Create SSL context
        ssl_context = ssl.create_default_context()
        if not self.config.verify_ssl:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
        
        connector = aiohttp.TCPConnector(ssl=ssl_context)
        
        try:
            async with aiohttp.ClientSession(connector=connector) as session:
                indexer_url = f"https://{self.config.indexer_host}:{self.config.indexer_port}"
                auth = aiohttp.BasicAuth(
                    getattr(self.config, 'indexer_username', self.config.username),
                    getattr(self.config, 'indexer_password', self.config.password)
                )
                
                # Test cluster health
                health_url = f"{indexer_url}/_cluster/health"
                async with session.get(health_url, auth=auth) as response:
                    if response.status == 200:
                        result['success'] = True
                        health_data = await response.json()
                        result['status'] = health_data.get('status', 'unknown')
                    else:
                        result['error'] = f"Cluster health check failed: HTTP {response.status}"
        
        except Exception:
            result['error'] = str(e)
        
        return result
    
    def _print_connection_result(self, service: str, result: Dict):
        """Print formatted connection result."""
        if result['reachable']:
            if _supports_unicode():
                status = "✅ CONNECTED"
            else:
                status = "[CONNECTED]"
            if result.get('auth_success') or result.get('cluster_status'):
                status += " & AUTHENTICATED"
        else:
            if _supports_unicode():
                status = "❌ FAILED" 
            else:
                status = "[FAILED]"
        
        _safe_print(f"   {status}")
        
        if result['reachable']:
            if result.get('ssl_valid'):
                _safe_print("   🔒 SSL: Valid certificate")
            elif result.get('self_signed'):
                _safe_print("   🔓 SSL: Self-signed certificate")
            else:
                _safe_print("   ⚠️  SSL: Verification disabled")
            
            if result.get('api_version'):
                _safe_print(f"   📋 API Version: {result['api_version']}")
            
            if result.get('cluster_status'):
                _safe_print(f"   📊 Cluster Status: {result['cluster_status']}")
        
        if result.get('error'):
            _safe_print(f"   ❗ Error: {result['error']}")
        
        _safe_print("")
    
    def _generate_recommendations(self):
        """Generate configuration recommendations."""
        recommendations = []
        
        # SSL/TLS recommendations
        if self.results['manager']['reachable']:
            if self.results['manager']['ssl_valid']:
                recommendations.append(
                    "🔒 Manager has valid SSL - set VERIFY_SSL=true for production"
                )
            elif self.results['manager']['self_signed']:
                recommendations.append(
                    "🔓 Manager uses self-signed certificate - current VERIFY_SSL=false is correct"
                )
        
        if self.results['indexer']['reachable']:
            if self.results['indexer']['ssl_valid']:
                recommendations.append(
                    "🔒 Indexer has valid SSL - enable SSL verification"
                )
            elif self.results['indexer']['self_signed']:
                recommendations.append(
                    "🔓 Indexer uses self-signed certificate - SSL verification disabled is appropriate"
                )
        
        # Authentication recommendations
        if not self.results['manager'].get('auth_success'):
            recommendations.append(
                "🔑 Authentication failed - verify WAZUH_USER and WAZUH_PASS credentials"
            )
        
        # Performance recommendations
        if self.results['manager']['reachable'] and self.results['indexer']['reachable']:
            recommendations.append(
                "🚀 Both services reachable - full functionality available"
            )
        elif self.results['manager']['reachable']:
            recommendations.append(
                "⚠️  Only Manager reachable - limited to basic operations"
            )
        
        self.results['recommendations'] = recommendations
        
        if recommendations:
            _safe_print("💡 RECOMMENDATIONS:")
            for rec in recommendations:
                _safe_print(f"   {rec}")
            _safe_print("")


async def main():
    """Main function for connection validation."""
    try:
        # Load configuration
        config = WazuhConfig.from_env()
        
        # Create validator
        validator = ConnectionValidator(config)
        
        # Run validation
        results = await validator.validate_all_connections()
        
        # Print summary
        _safe_print("📋 VALIDATION SUMMARY:")
        if _supports_unicode():
            manager_icon = '✅' if results['manager']['reachable'] else '❌'
            indexer_icon = '✅' if results['indexer']['reachable'] else '❌'
        else:
            manager_icon = '[OK]' if results['manager']['reachable'] else '[FAIL]'
            indexer_icon = '[OK]' if results['indexer']['reachable'] else '[FAIL]'
        
        _safe_print(f"   Manager: {manager_icon}")
        _safe_print(f"   Indexer: {indexer_icon}")
        
        # Exit with appropriate code
        if results['manager']['reachable']:
            _safe_print("\n🎉 Validation completed successfully!")
            return 0
        else:
            _safe_print("\n❌ Validation failed - check configuration and network connectivity")
            return 1
    
    except Exception as e:
        _safe_print(f"❌ Validation error: {e}")
        return 1


if __name__ == "__main__":
    # Set up console encoding for Windows
    if platform.system() == "Windows":
        try:
            # Try to set UTF-8 encoding for Windows console
            import codecs
            sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'replace')
            sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'replace')
        except Exception:
            # If that fails, we'll use ASCII fallbacks in the print functions
            pass
    
    sys.exit(asyncio.run(main()))