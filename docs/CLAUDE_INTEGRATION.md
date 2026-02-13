# Claude Desktop Integration Guide

This guide covers all methods for connecting the Wazuh MCP Server to Claude Desktop.

## Prerequisites

- **Claude Pro, Max, Team, or Enterprise plan** (required for custom connectors)
- Your Wazuh MCP Server deployed and accessible via **HTTPS**
- Custom Connectors feature is currently in **beta**

## Quick Setup

### Step 1: Deploy Your Server

Ensure your Wazuh MCP Server is running and publicly accessible:

```bash
docker compose up -d
curl https://your-server-domain.com/health
```

### Step 2: Add Custom Connector

1. Open **Claude Desktop**
2. Go to **Settings** → **Connectors**
3. Click **"Add custom connector"**
4. Enter your MCP server URL:
   - **Recommended (Streamable HTTP):** `https://your-server-domain.com/mcp`
   - **Legacy (SSE):** `https://your-server-domain.com/sse`
5. In **Advanced settings**, add your Bearer token for authentication
6. Click **Connect**

### Step 3: Enable Tools

1. In your chat interface, click the **"Search and tools"** button
2. Find your Wazuh connector in the list
3. Click **"Connect"** to authenticate
4. Enable/disable specific tools as needed

---

## Authentication Modes

The server supports three authentication modes via `AUTH_MODE` environment variable:

| Mode | `AUTH_MODE` | Use Case | Claude Desktop Support |
|------|-------------|----------|----------------------|
| **OAuth** | `oauth` | Production with Claude Desktop | ✅ Native (recommended) |
| **Bearer Token** | `bearer` | API/Programmatic access | ✅ Via Advanced settings |
| **Authless** | `none` | Development/Testing | ✅ Direct connect |

### OAuth Mode (Recommended)

OAuth with Dynamic Client Registration (DCR) provides the best Claude Desktop experience.

```bash
AUTH_MODE=oauth docker compose up -d
```

**How it works:**
1. Claude Desktop discovers OAuth endpoints via `/.well-known/oauth-authorization-server`
2. Automatically registers as a client (DCR)
3. Handles authorization flow seamlessly

**OAuth Endpoints:**
- Discovery: `/.well-known/oauth-authorization-server`
- Authorization: `/oauth/authorize`
- Token: `/oauth/token`
- Registration: `/oauth/register` (DCR)

### Bearer Token Mode

For API access or when OAuth is not available:

```bash
AUTH_MODE=bearer docker compose up -d
```

**Step 1: Get API Key**
```bash
docker compose logs wazuh-mcp-remote-server | grep "API key"
```

**Step 2: Exchange for JWT Token**
```bash
curl -X POST https://your-server-domain.com/auth/token \
  -H "Content-Type: application/json" \
  -d '{"api_key": "wazuh_your-generated-api-key"}'
```

**Step 3:** Add the token in Claude Desktop's Advanced settings.

### Authless Mode (Development Only)

For local development and testing only. **Not recommended for production.**

```bash
AUTH_MODE=none docker compose up -d
```

---

## Supported Features

| Feature | Status |
|---------|--------|
| Tools | ✅ Supported |
| Prompts | ✅ Supported |
| Resources | ✅ Supported |
| Text/Image Results | ✅ Supported |
| Resource Subscriptions | ❌ Not yet supported |
| Sampling | ❌ Not yet supported |

---

## Common Mistake: Using JSON Config

**❌ This will NOT work** — the JSON config is for local stdio servers only:
```json
{
  "mcpServers": {
    "wazuh-security": {
      "url": "https://your-server.com/mcp",
      "headers": { "Authorization": "Bearer ..." }
    }
  }
}
```

This produces the error:
```
Could not load app settings
"path": ["mcpServers", "wazuh-security", "command"]
"message": "Required"
```

**✅ Correct approach:** Use **Settings → Connectors** UI as described above.

---

## Requirements Checklist

- ✅ Claude Pro, Max, Team, or Enterprise plan
- ✅ Use **Connectors UI** (Settings → Connectors), NOT `claude_desktop_config.json`
- ✅ Server must be accessible via **HTTPS** (production)
- ✅ Use `/mcp` endpoint (Streamable HTTP) or `/sse` endpoint (legacy)
- ✅ Authentication: OAuth (recommended), Bearer token, or Authless (dev only)

---

## Programmatic Access

### SSE Endpoint

```python
import httpx
import asyncio

async def connect_to_mcp_sse():
    """Connect to MCP server using SSE endpoint."""
    async with httpx.AsyncClient() as client:
        # Get authentication token first
        auth_response = await client.post(
            "http://localhost:3000/auth/token",
            json={"api_key": "your-api-key"}
        )
        token = auth_response.json()["access_token"]

        # Connect to SSE endpoint
        async with client.stream(
            "GET",
            "http://localhost:3000/sse",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "text/event-stream",
                "Origin": "http://localhost"
            }
        ) as response:
            async for chunk in response.aiter_text():
                print(f"Received: {chunk}")

asyncio.run(connect_to_mcp_sse())
```

### JSON-RPC Endpoint

```python
import httpx

async def query_wazuh_mcp():
    async with httpx.AsyncClient() as client:
        # Get authentication token
        auth_response = await client.post(
            "http://localhost:3000/auth/token",
            json={"api_key": "your-api-key"}
        )
        token = auth_response.json()["access_token"]

        # Make JSON-RPC request
        response = await client.post(
            "http://localhost:3000/",
            headers={
                "Authorization": f"Bearer {token}",
                "Origin": "http://localhost"
            },
            json={
                "jsonrpc": "2.0",
                "id": "1",
                "method": "tools/list"
            }
        )
        return response.json()
```

---

[← Back to README](../README.md)
