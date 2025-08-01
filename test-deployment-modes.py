#!/usr/bin/env python3
"""
Test Both Deployment Modes
Verify Local (STDIO) and Remote (HTTP/SSE) modes work correctly
"""

import os
import sys
import subprocess
import time
import json
from pathlib import Path

def test_stdio_mode():
    """Test STDIO mode functionality."""
    print("🧪 Testing STDIO Mode (Local/Standard)")
    print("=" * 50)
    
    try:
        # Set STDIO mode
        env = os.environ.copy()
        env['MCP_TRANSPORT'] = 'stdio'
        
        # Start server process
        cmd = ['python3', 'wazuh-mcp-server', '--stdio']
        process = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env
        )
        
        # Send MCP initialize message
        init_message = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "test-client", "version": "1.0.0"}
            }
        }
        
        # Send message and get response
        stdout, stderr = process.communicate(
            input=json.dumps(init_message) + '\n',
            timeout=10
        )
        
        if process.returncode == 0 and stdout:
            response = json.loads(stdout.strip())
            if response.get('result'):
                print("✅ STDIO mode working correctly")
                print(f"   Server: {response['result'].get('serverInfo', {}).get('name', 'Unknown')}")
                print(f"   Protocol: {response['result'].get('protocolVersion', 'Unknown')}")
                return True
        
        print("❌ STDIO mode failed")
        if stderr:
            print(f"   Error: {stderr[:200]}")
        return False
        
    except subprocess.TimeoutExpired:
        print("❌ STDIO mode timeout")
        process.kill()
        return False
    except Exception as e:
        print(f"❌ STDIO mode error: {e}")
        return False

def test_remote_mode():
    """Test Remote mode functionality."""
    print("\n🧪 Testing Remote Mode (HTTP/SSE)")
    print("=" * 50)
    
    try:
        import httpx
        
        # Test remote server endpoints
        base_url = "http://localhost:3000"
        token = "wazuh_test"
        headers = {"Authorization": f"Bearer {token}"}
        
        async def test_endpoints():
            async with httpx.AsyncClient(timeout=5.0) as client:
                # Test health endpoint
                health_response = await client.get(f"{base_url}/health")
                if health_response.status_code == 200:
                    print("✅ Health endpoint working")
                else:
                    print(f"❌ Health endpoint failed: {health_response.status_code}")
                    return False
                
                # Test capabilities endpoint
                caps_response = await client.get(f"{base_url}/capabilities", headers=headers)
                if caps_response.status_code == 200:
                    caps = caps_response.json()
                    print("✅ Capabilities endpoint working")
                    print(f"   Tools: {caps.get('tools_count', 0)}")
                    print(f"   Resources: {caps.get('resources_count', 0)}")
                    return True
                else:
                    print(f"❌ Capabilities endpoint failed: {caps_response.status_code}")
                    return False
        
        import asyncio
        return asyncio.run(test_endpoints())
        
    except ImportError:
        print("⚠️  httpx not available for remote testing")
        return None
    except Exception as e:
        print(f"❌ Remote mode error: {e}")
        return False

def main():
    """Main test runner."""
    print("🔬 Wazuh MCP Server - Deployment Mode Testing")
    print("=" * 60)
    print(f"Started at: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    
    # Test STDIO mode (default/recommended)
    stdio_result = test_stdio_mode()
    
    # Test Remote mode (advanced)
    remote_result = test_remote_mode()
    
    # Summary
    print("\n" + "=" * 60)
    print("📊 TEST RESULTS SUMMARY")
    print("=" * 60)
    
    print(f"{'✅' if stdio_result else '❌'} STDIO Mode (Local/Standard): {'PASS' if stdio_result else 'FAIL'}")
    
    if remote_result is None:
        print("⚠️  Remote Mode (HTTP/SSE): SKIPPED (httpx not available)")
    else:
        print(f"{'✅' if remote_result else '❌'} Remote Mode (HTTP/SSE): {'PASS' if remote_result else 'FAIL'}")
    
    print("\n📋 Deployment Recommendations:")
    if stdio_result:
        print("✅ Use STDIO mode for standard Claude Desktop integration")
        print("   - Best performance and compatibility")
        print("   - No network configuration needed")
        print("   - Direct JSON-RPC communication")
    
    if remote_result:
        print("✅ Remote mode available for advanced deployments")
        print("   - Custom Connectors support")
        print("   - Reverse proxy compatible")
        print("   - Production-ready with authentication")
    
    print("\n🚀 Next Steps:")
    print("1. Run: ./configure-wazuh.sh")
    print("2. Choose transport mode:")
    print("   - Option 1: Local (STDIO) - Recommended for most users")
    print("   - Option 2: Remote (HTTP/SSE) - For advanced deployments")
    print("3. Follow the Claude Desktop integration instructions")
    
    # Return success if at least one mode works
    return 0 if (stdio_result or remote_result) else 1

if __name__ == "__main__":
    sys.exit(main())