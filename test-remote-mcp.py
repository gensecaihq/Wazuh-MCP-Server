#!/usr/bin/env python3
"""
Test Remote MCP Server Compliance
Validate that the remote MCP server meets Claude Desktop requirements
"""

import asyncio
import json
import os
import sys
from pathlib import Path

import httpx

# Add src directory to Python path
current_dir = Path(__file__).resolve().parent
src_dir = current_dir / "src"
sys.path.insert(0, str(src_dir))

async def test_remote_mcp_server():
    """Test remote MCP server endpoints."""
    # Get URL from environment or use default
    base_url = os.getenv("MCP_PUBLIC_URL", "http://localhost:3000")
    token = os.getenv("MCP_AUTH_TOKEN", "wazuh_test")  # Get token from env or use test token
    headers = {"Authorization": f"Bearer {token}"}
    
    print("🧪 Testing Remote MCP Server Compliance")
    print("=" * 50)
    print(f"Testing URL: {base_url}")
    print(f"Using Token: {token[:12]}..." if len(token) > 12 else f"Using Token: {token}")
    
    async with httpx.AsyncClient(timeout=10.0) as client:
        
        # Test 1: Health check (no auth required)
        print("\n🏥 Test 1: Health Check")
        try:
            response = await client.get(f"{base_url}/health")
            if response.status_code == 200:
                health = response.json()
                print(f"✅ Health check passed: {health['status']}")
            else:
                print(f"❌ Health check failed: {response.status_code}")
        except Exception as e:
            print(f"❌ Health check error: {e}")
        
        # Test 2: Root endpoint info
        print("\n🏠 Test 2: Server Info")
        try:
            response = await client.get(f"{base_url}/")
            if response.status_code == 200:
                info = response.json()
                print(f"✅ Server info: {info['name']} v{info['version']}")
                print(f"   Transport: {info['transport']}")
                print(f"   Endpoints: {list(info['endpoints'].keys())}")
            else:
                print(f"❌ Server info failed: {response.status_code}")
        except Exception as e:
            print(f"❌ Server info error: {e}")
        
        # Test 3: OAuth metadata
        print("\n🔐 Test 3: OAuth Metadata")
        try:
            response = await client.get(f"{base_url}/.well-known/oauth-authorization-server")
            if response.status_code == 200:
                oauth = response.json()
                print(f"✅ OAuth metadata available")
                print(f"   Issuer: {oauth['issuer']}")
                print(f"   Scopes: {oauth['scopes_supported']}")
            else:
                print(f"❌ OAuth metadata failed: {response.status_code}")
        except Exception as e:
            print(f"❌ OAuth metadata error: {e}")
        
        # Test 4: Capabilities (with auth)
        print("\n🛠️ Test 4: Server Capabilities")
        try:
            response = await client.get(f"{base_url}/capabilities", headers=headers)
            if response.status_code == 200:
                caps = response.json()
                print(f"✅ Capabilities retrieved")
                print(f"   Tools: {caps['tools_count']}")
                print(f"   Resources: {caps['resources_count']}")
            elif response.status_code == 401:
                print(f"❌ Authentication failed - check bearer token")
            else:
                print(f"❌ Capabilities failed: {response.status_code}")
        except Exception as e:
            print(f"❌ Capabilities error: {e}")
        
        # Test 5: MCP Protocol - Initialize
        print("\n🔄 Test 5: MCP Protocol - Initialize")
        try:
            mcp_request = {
                "jsonrpc": "2.0",
                "id": "1",
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "test-client", "version": "1.0.0"}
                }
            }
            response = await client.post(f"{base_url}/message", 
                                       json=mcp_request, 
                                       headers=headers)
            if response.status_code == 200:
                result = response.json()
                print(f"✅ MCP Initialize successful")
                print(f"   Protocol: {result['result']['protocolVersion']}")
                print(f"   Server: {result['result']['serverInfo']['name']}")
            else:
                print(f"❌ MCP Initialize failed: {response.status_code}")
                print(f"   Response: {response.text[:200]}")
        except Exception as e:
            print(f"❌ MCP Initialize error: {e}")
        
        # Test 6: MCP Protocol - List Tools
        print("\n🔧 Test 6: MCP Protocol - List Tools")
        try:
            mcp_request = {
                "jsonrpc": "2.0",
                "id": "2", 
                "method": "tools/list",
                "params": {}
            }
            response = await client.post(f"{base_url}/message",
                                       json=mcp_request,
                                       headers=headers)
            if response.status_code == 200:
                result = response.json()
                tools = result['result']['tools']
                print(f"✅ Tools list retrieved: {len(tools)} tools")
                if tools:
                    print(f"   Sample tool: {tools[0]['name']}")
            else:
                print(f"❌ Tools list failed: {response.status_code}")
        except Exception as e:
            print(f"❌ Tools list error: {e}")
        
        # Test 7: MCP Tool Call
        print("\n⚡ Test 7: MCP Protocol - Tool Call")
        try:
            mcp_request = {
                "jsonrpc": "2.0",
                "id": "3",
                "method": "tools/call",
                "params": {
                    "name": "get_wazuh_alerts",
                    "arguments": {"limit": 5}
                }
            }
            response = await client.post(f"{base_url}/message",
                                       json=mcp_request,
                                       headers=headers)
            if response.status_code == 200:
                result = response.json()
                if 'result' in result and 'content' in result['result']:
                    print(f"✅ Tool call successful")
                    content = result['result']['content'][0]['text']
                    data = json.loads(content)
                    print(f"   Retrieved {data.get('total', 0)} alerts")
                else:
                    print(f"❌ Tool call returned unexpected format")
            else:
                print(f"❌ Tool call failed: {response.status_code}")
                print(f"   Response: {response.text[:200]}")
        except Exception as e:
            print(f"❌ Tool call error: {e}")
        
        # Test 8: SSE Endpoint
        print("\n📡 Test 8: SSE Endpoint")
        try:
            response = await client.get(f"{base_url}/sse", 
                                      headers={**headers, "Accept": "text/event-stream"},
                                      timeout=5.0)
            if response.status_code == 200:
                # Read first few events
                content = response.text[:500]
                if "data:" in content:
                    print(f"✅ SSE endpoint working")
                    print(f"   Sample events received")
                else:
                    print(f"❌ SSE endpoint not streaming properly")
            else:
                print(f"❌ SSE endpoint failed: {response.status_code}")
        except httpx.TimeoutException:
            print(f"✅ SSE endpoint streaming (timed out after 5s, expected)")
        except Exception as e:
            print(f"❌ SSE endpoint error: {e}")

def print_claude_desktop_config():
    """Print Claude Desktop configuration example."""
    base_url = os.getenv("MCP_PUBLIC_URL", "http://localhost:3000")
    token = os.getenv("MCP_AUTH_TOKEN", "wazuh_test")
    
    print("\n" + "=" * 50)
    print("🖥️ CLAUDE DESKTOP CONFIGURATION")
    print("=" * 50)
    print()
    print("Add this to your Claude Desktop settings (Settings > Connectors):")
    print()
    print(f"🔗 Server URL: {base_url}")
    print("🔑 Authentication: Bearer Token")
    print(f"🎫 Token: {token}")
    print()
    print("Or use as Custom Connector:")
    print()
    print("```")
    print(f"Server URL: {base_url}")
    print("Authentication: Bearer")
    print(f"Token: {token}")
    print("```")
    print()
    print("🔧 Available Endpoints:")
    print("   - /sse (Server-Sent Events)")
    print("   - /message (MCP Protocol Messages)")
    print("   - /capabilities (Server Capabilities)")
    print("   - /health (Health Check)")

async def main():
    """Main test runner."""
    try:
        await test_remote_mcp_server()
        print_claude_desktop_config()
        
        print("\n" + "=" * 50)
        print("✅ Remote MCP Server Testing Complete")
        print("=" * 50)
        print()
        print("Next Steps:")
        print("1. Use the Bearer token from configure-wazuh.sh")
        print("2. Add server as Custom Connector in Claude Desktop")
        print("3. Test MCP tools in Claude Desktop")
        print()
        return 0
        
    except KeyboardInterrupt:
        print("\n🛑 Testing interrupted by user")
        return 1
    except Exception as e:
        print(f"\n❌ Testing failed: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(asyncio.run(main()))