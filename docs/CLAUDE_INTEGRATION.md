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
4. Enter your MCP server URL: `https://your-server-domain.com/mcp`
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

Each user connects through Claude's OAuth flow and signs in once with their own API key. The token they get carries that key's identity and scopes, so RBAC, rate limits and the audit log are per user.

```bash
# Give each user a key (API_KEYS JSON), or one shared key:
echo "MCP_API_KEY=wazuh_$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')" >> .env
AUTH_MODE=oauth docker compose up -d
```

**How it works:**
1. Claude discovers the endpoints via `/.well-known/oauth-authorization-server`
2. The browser opens `/oauth/authorize`, which shows a sign-in page
3. The user pastes their `wazuh_` API key; the grant is capped at that key's scopes (a read-only key can't obtain `wazuh:write`, whatever the client asks for)
4. Claude exchanges the code (PKCE S256) for access and refresh tokens

Without a configured key nobody can sign in — OAuth mode fails closed.

**OAuth Endpoints:**
- Discovery (authorization server): `/.well-known/oauth-authorization-server` (RFC 8414)
- Discovery (protected resource): `/.well-known/oauth-protected-resource` (RFC 9728)
- Authorization: `/oauth/authorize`
- Token: `/oauth/token`
- Revocation: `/oauth/revoke` (RFC 7009)
- Registration: `/oauth/register` — only when `OAUTH_ENABLE_DCR=true` (off by default)

### Bearer Token Mode

For API access or when OAuth is not available:

```bash
AUTH_MODE=bearer docker compose up -d
```

**Step 1: Set an API Key**

Set it in `.env` before starting (a generated key is never shown in production):
```bash
echo "MCP_API_KEY=wazuh_$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')" >> .env
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
- ✅ Use the `/mcp` endpoint (Streamable HTTP); the legacy `/sse` transport is not supported
- ✅ Authentication: OAuth (recommended), Bearer token, or Authless (dev only)

---

## Programmatic Access

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
