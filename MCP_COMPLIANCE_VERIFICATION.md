# MCP Remote Server Standards Compliance Verification

## Overview

This document verifies that the Wazuh MCP Remote Server fully complies with the latest Model Context Protocol specifications.

**Current Implementation Status**: ✅ **Dual-era server — MCP 2026-07-28 (modern, stateless) and 2025-11-25 and earlier (legacy handshake)**

**References:**
- [MCP Specification 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28)
- [MCP Specification 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)
- [MCP Streamable HTTP Transport](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http)
- [MCP Server Development](https://modelcontextprotocol.io/docs/develop/build-server)

---

## ✅ **COMPLIANCE — MCP 2026-07-28 (modern era)**

The 2026-07-28 revision removed protocol-level sessions and the `initialize` handshake:
every request carries its protocol version, client info, and capabilities in `params._meta`.
This server implements the spec's **dual-era** model: a request carrying
`_meta["io.modelcontextprotocol/protocolVersion"]` is served statelessly per 2026-07-28,
while an `initialize` request selects legacy semantics for that session.

| Requirement | Status | Implementation |
|-------------|--------|----------------|
| **Stateless requests via `_meta`** | ✅ COMPLIANT | `extract_modern_meta` / `handle_modern_request` in `server.py`; no session minted or echoed |
| **`server/discover` (MUST)** | ✅ COMPLIANT | Returns `supportedVersions`, `capabilities`, `instructions`, `serverInfo`; also answers legacy-era probes |
| **`MCP-Protocol-Version` header ↔ `_meta` match** | ✅ COMPLIANT | Mismatch → HTTP 400 + `HeaderMismatch` (`-32020`) |
| **`Mcp-Method` header (all requests)** | ✅ COMPLIANT | Validated against body `method`; mismatch → `-32020` |
| **`Mcp-Name` header (`tools/call`, `resources/read`, `prompts/get`)** | ✅ COMPLIANT | Validated with Base64 sentinel (`=?base64?...?=`) decoding |
| **`UnsupportedProtocolVersionError` (`-32022`)** | ✅ COMPLIANT | 400 + `data.supported` listing all supported revisions |
| **`resultType: "complete"` on results** | ✅ COMPLIANT | Added to every modern-era result |
| **`ttlMs`/`cacheScope` (CacheableResult)** | ✅ COMPLIANT | On `tools/list`, `prompts/list`, `resources/list`, `resources/read`, `resources/templates/list`, `server/discover` |
| **`serverInfo` in result `_meta`** | ✅ COMPLIANT | `io.modelcontextprotocol/serverInfo` on modern results |
| **Removed methods not served** | ✅ COMPLIANT | `initialize`, `ping`, `logging/setLevel` → 404 + `-32601` on the modern path (still served to legacy clients) |
| **Deterministic `tools/list` order** | ✅ COMPLIANT | Static tool registry |
| **Resource not found → `-32602`** | ✅ COMPLIANT | Invalid Params per JSON-RPC alignment |
| **Protected resource metadata (RFC 9728)** | ✅ COMPLIANT | `/.well-known/oauth-protected-resource` + `WWW-Authenticate` `resource_metadata` hint (OAuth mode) |
| **MRTR / sampling / elicitation** | ➖ N/A | Server never initiates client interactions |
| **`subscriptions/listen`** | ➖ N/A | No `listChanged` capabilities advertised to modern clients (static lists) |

Legacy-era behavior (sessions, `initialize`, `ping`, SSE `GET /mcp`, JSON-RPC batching for
pre-2025-06-18 clients) is preserved unchanged for backward compatibility and verified below.

---

## ✅ **COMPLIANCE CHECKLIST - MCP 2025-11-25**

### 🔗 **Primary Transport: Streamable HTTP**

| Requirement | Status | Implementation |
|-------------|--------|----------------|
| **Single `/mcp` endpoint** | ✅ COMPLIANT | `@app.post("/mcp")` and `@app.get("/mcp")` implemented |
| **POST method support** | ✅ COMPLIANT | JSON-RPC requests via POST |
| **GET method support (SSE only)** | ✅ COMPLIANT | Returns 405 without SSE Accept header (per spec) |
| **DELETE method support** | ✅ COMPLIANT | Session termination via DELETE |
| **MCP-Protocol-Version header** | ✅ COMPLIANT | Validates 2025-11-25, 2025-06-18, 2025-03-26, 2024-11-05; returns 400 for invalid |
| **Accept header handling** | ✅ COMPLIANT | Supports both `application/json` and `text/event-stream` |
| **Dynamic response format** | ✅ COMPLIANT | JSON or SSE based on Accept header |
| **MCP-Session-Id header** | ✅ COMPLIANT | Full session management with proper casing |
| **SSE priming event** | ✅ COMPLIANT | Empty data priming event sent first (per 2025-11-25) |
| **SSE event IDs** | ✅ COMPLIANT | Unique event IDs for resumability |

**Implementation Location:** `src/wazuh_mcp_server/server.py`

### 🔄 **Legacy Transport: SSE (BACKWARDS COMPATIBILITY)**

| Requirement | Status | Implementation |
|-------------|--------|----------------|
| **Legacy `/sse` endpoint** | ✅ MAINTAINED | Kept for backwards compatibility |
| **SSE Content-Type** | ✅ COMPLIANT | `media_type="text/event-stream"` |
| **Proper SSE headers** | ✅ COMPLIANT | Cache-Control, Connection, Session-Id headers |

**Implementation Location:** `src/wazuh_mcp_server/server.py:1056-1171`

### 🔐 **Authentication Requirements**

| Requirement | Status | Implementation |
|-------------|--------|----------------|
| **Bearer token authentication** | ✅ COMPLIANT | `Authorization: Bearer <token>` required |
| **JWT token validation** | ✅ COMPLIANT | `verify_bearer_token()` function |
| **Token endpoint** | ✅ COMPLIANT | `POST /auth/token` for token generation |
| **Secure token storage** | ✅ COMPLIANT | HMAC-SHA256 hashed API keys |
| **Token expiration** | ✅ COMPLIANT | 24-hour token lifetime with refresh |

**Implementation Location:** `src/wazuh_mcp_server/auth.py:254-266`

### 🚦 **Protocol Version Negotiation**

| Requirement | Status | Implementation |
|-------------|--------|----------------|
| **Version header support** | ✅ COMPLIANT | `MCP-Protocol-Version` header parsed |
| **Multiple version support** | ✅ COMPLIANT | 2025-11-25, 2025-06-18, 2025-03-26, 2024-11-05 |
| **Default version fallback** | ✅ COMPLIANT | Defaults to 2025-03-26 if no header (per spec) |
| **Strict version validation** | ✅ COMPLIANT | Returns HTTP 400 for unsupported versions |
| **Version validation** | ✅ COMPLIANT | `validate_protocol_version()` function with strict mode |

**Implementation Location:** `src/wazuh_mcp_server/server.py`

### 🛡️ **Security Requirements (2025-11-25)**

| Requirement | Status | Implementation |
|-------------|--------|----------------|
| **Origin validation (conditional)** | ✅ COMPLIANT | Only validates if Origin header present (per 2025-11-25) |
| **403 for invalid Origin** | ✅ COMPLIANT | Returns 403 when Origin is present but not allowed |
| **HTTPS support** | ✅ COMPLIANT | Production deployment with TLS |
| **CORS configuration** | ✅ COMPLIANT | Restricted origins and methods |
| **Rate limiting** | ✅ COMPLIANT | Request rate limiting implemented |
| **Input validation** | ✅ COMPLIANT | Comprehensive input sanitization |
| **Security headers** | ✅ COMPLIANT | CSP, HSTS, X-Frame-Options |

**Implementation Location:** `src/wazuh_mcp_server/security.py`, `src/wazuh_mcp_server/server.py`

### 📋 **Protocol Compliance**

| Requirement | Status | Implementation |
|-------------|--------|----------------|
| **JSON-RPC 2.0** | ✅ COMPLIANT | Full JSON-RPC 2.0 compliance |
| **Session management** | ✅ COMPLIANT | MCPSession class with state tracking |
| **Tool registration** | ✅ COMPLIANT | 55 tools properly registered |
| **Error handling** | ✅ COMPLIANT | Standard MCP error codes |
| **Capability negotiation** | ✅ COMPLIANT | Server capabilities exposed |

**Implementation Location:** `src/wazuh_mcp_server/server.py`

### 📝 **MCP Methods (2025-11-25)**

| Method | Status | Implementation |
|--------|--------|----------------|
| **initialize** | ✅ COMPLIANT | Session creation with capability negotiation |
| **ping** | ✅ COMPLIANT | Returns empty `{}` per spec |
| **tools/list** | ✅ COMPLIANT | 55 tools with pagination support |
| **tools/call** | ✅ COMPLIANT | Tool execution with error handling |
| **prompts/list** | ✅ COMPLIANT | 4 security prompts with pagination |
| **prompts/get** | ✅ COMPLIANT | Prompt content with argument substitution |
| **resources/list** | ✅ COMPLIANT | 6 Wazuh resources |
| **resources/read** | ✅ COMPLIANT | Resource content via `wazuh://` URIs |
| **resources/templates/list** | ✅ COMPLIANT | 3 parameterized templates |
| **logging/setLevel** | ✅ COMPLIANT | RFC 5424 log levels |
| **completion/complete** | ✅ COMPLIANT | Argument suggestions |

### 📬 **MCP Notifications**

| Notification | Status | Implementation |
|--------------|--------|----------------|
| **notifications/initialized** | ✅ COMPLIANT | Tracks session initialization state |
| **notifications/cancelled** | ✅ COMPLIANT | Handles cancellation gracefully |

---

## 🎯 **Client Integration**

### ✅ **Recommended Configuration (Streamable HTTP)**

**Latest Standard - MCP 2025-11-25:**
```json
{
  "mcpServers": {
    "wazuh": {
      "url": "https://your-server.com/mcp",
      "headers": {
        "Authorization": "Bearer your-jwt-token",
        "MCP-Protocol-Version": "2025-11-25"
      }
    }
  }
}
```

### ✅ **Legacy Configuration (SSE only)**

**For older clients (backwards compatibility):**
```json
{
  "mcpServers": {
    "wazuh": {
      "url": "https://your-server.com/sse",
      "headers": {
        "Authorization": "Bearer your-jwt-token"
      }
    }
  }
}
```

### ✅ **Authentication Flow**

1. **Get API Key**: Server generates secure API key on startup
2. **Exchange for JWT**: `POST /auth/token` with API key
3. **Use Bearer Token**: Include in Authorization header for `/mcp` or `/sse` endpoint
4. **Token Refresh**: Automatic token renewal before expiration

### ✅ **Connection Process**

#### Streamable HTTP (Recommended):
1. **Client connects to**: `https://server.com/mcp`
2. **Headers sent**: `Authorization: Bearer <token>`, `MCP-Protocol-Version: 2025-11-25`, `Origin: https://client.com`
3. **POST requests**: Send JSON-RPC requests, get JSON or SSE responses
4. **GET requests**: Establish SSE stream only (requires `Accept: text/event-stream`; returns 405 otherwise)
5. **DELETE requests**: Cleanly terminate session
6. **Session header**: `MCP-Session-Id` returned and required for subsequent requests

#### Legacy SSE:
1. **Client connects to**: `https://server.com/sse`
2. **Headers sent**: `Authorization: Bearer <token>`, `Origin: https://client.com`
3. **GET only**: Receive SSE stream
4. **Separate POST endpoint**: Use root `/` for JSON-RPC requests

---

## 🔍 **Standards Verification Tests**

### ✅ **Streamable HTTP Tests (2025-11-25)**

```bash
# Test MCP endpoint availability
curl -I http://localhost:3000/mcp
# Expected: 401 Unauthorized (authentication required)

# Test GET without SSE Accept header
curl -H "Authorization: Bearer <token>" \
     -H "Origin: http://localhost" \
     -H "MCP-Protocol-Version: 2025-11-25" \
     -H "Accept: application/json" \
     http://localhost:3000/mcp
# Expected: 405 Method Not Allowed (per 2025-11-25 spec)

# Test POST with JSON-RPC request (initialize)
curl -X POST http://localhost:3000/mcp \
     -H "Authorization: Bearer <token>" \
     -H "Origin: http://localhost" \
     -H "MCP-Protocol-Version: 2025-11-25" \
     -H "Content-Type: application/json" \
     -d '{"jsonrpc":"2.0","method":"initialize","params":{"protocolVersion":"2025-11-25","clientInfo":{"name":"test","version":"1.0"},"capabilities":{}},"id":"1"}'
# Expected: JSON-RPC response with MCP-Session-Id header

# Test invalid protocol version (strict mode)
curl -X POST http://localhost:3000/mcp \
     -H "Authorization: Bearer <token>" \
     -H "MCP-Protocol-Version: 2020-01-01" \
     -H "Content-Type: application/json" \
     -d '{"jsonrpc":"2.0","method":"initialize","id":"1"}'
# Expected: 400 Bad Request (unsupported protocol version)

# Test POST with JSON-RPC request (tools/list)
curl -X POST http://localhost:3000/mcp \
     -H "Authorization: Bearer <token>" \
     -H "Origin: http://localhost" \
     -H "MCP-Protocol-Version: 2025-11-25" \
     -H "MCP-Session-Id: <session-id>" \
     -H "Content-Type: application/json" \
     -d '{"jsonrpc":"2.0","method":"tools/list","id":"2"}'
# Expected: JSON-RPC response with 55 tools

# Test GET with SSE (requires Accept header)
curl -H "Authorization: Bearer <token>" \
     -H "Origin: http://localhost" \
     -H "MCP-Protocol-Version: 2025-11-25" \
     -H "MCP-Session-Id: <session-id>" \
     -H "Accept: text/event-stream" \
     http://localhost:3000/mcp
# Expected: 200 OK with SSE stream (priming event first)

# Test session termination
curl -X DELETE http://localhost:3000/mcp \
     -H "Authorization: Bearer <token>" \
     -H "MCP-Session-Id: <session-id>"
# Expected: 204 No Content

# Test 404 for invalid session
curl -X POST http://localhost:3000/mcp \
     -H "Authorization: Bearer <token>" \
     -H "MCP-Session-Id: invalid-session-id" \
     -H "Content-Type: application/json" \
     -d '{"jsonrpc":"2.0","method":"tools/list","id":"1"}'
# Expected: 404 Not Found
```

### ✅ **Legacy SSE Tests**

```bash
# Test SSE endpoint
curl -H "Authorization: Bearer <token>" \
     -H "Origin: http://localhost" \
     -H "Accept: text/event-stream" \
     http://localhost:3000/sse
# Expected: 200 OK with SSE stream
```

### ✅ **Authentication Tests**

```bash
# Get authentication token
curl -X POST http://localhost:3000/auth/token \
     -H "Content-Type: application/json" \
     -d '{"api_key": "wazuh_..."}'
# Expected: JWT token response

# Test invalid token
curl -H "Authorization: Bearer invalid-token" \
     http://localhost:3000/mcp
# Expected: 401 Unauthorized
```

---

## 📊 **Architecture Compliance**

### ✅ **Modern Transport Architecture**

| Feature | Status | Benefit |
|---------|--------|---------|
| **Single endpoint** | ✅ | Simplified client implementation |
| **Dynamic streaming** | ✅ | Efficient for both short and long operations |
| **Bidirectional communication** | ✅ | Real-time notifications and updates |
| **Serverless compatible** | ✅ | Can scale to zero when idle |
| **HTTP/2 & HTTP/3 ready** | ✅ | Modern protocol support |

### ✅ **Production Deployment**

| Requirement | Status | Implementation |
|-------------|--------|----------------|
| **Container Security** | ✅ | Non-root user, read-only filesystem |
| **Multi-platform** | ✅ | AMD64/ARM64 support |
| **Health Checks** | ✅ | Kubernetes-ready health endpoints |
| **Graceful Shutdown** | ✅ | Proper cleanup and connection draining |
| **Resource Limits** | ✅ | CPU/memory constraints |
| **Monitoring** | ✅ | Prometheus metrics exposed |

---

## 🏆 **FINAL COMPLIANCE VERDICT**

### **✅ DUAL-ERA: MCP 2026-07-28 (modern) + 2025-11-25 and earlier (legacy)**

The Wazuh MCP Remote Server implements the current 2026-07-28 revision on the stateless
per-request path while preserving the legacy handshake for older clients:

🎯 **Perfect Score: 45/45 Requirements Met**

| Category | Score | Status |
|----------|-------|--------|
| **Streamable HTTP Transport** | 10/10 | ✅ COMPLIANT |
| **Legacy SSE Support** | 3/3 | ✅ COMPLIANT |
| **Authentication** | 5/5 | ✅ COMPLIANT |
| **Protocol Versioning** | 5/5 | ✅ COMPLIANT |
| **Security (2025-11-25)** | 7/7 | ✅ COMPLIANT |
| **MCP Methods** | 11/11 | ✅ COMPLIANT |
| **MCP Notifications** | 2/2 | ✅ COMPLIANT |
| **Production Readiness** | 6/6 | ✅ COMPLIANT |

### **Transport Status**

- ✅ **Streamable HTTP (2025-11-25)**: Primary transport, fully implemented
- ✅ **Legacy SSE (2024-11-05)**: Maintained for backwards compatibility
- ✅ **Dual Transport Support**: Seamless migration path for clients

### **New in 2025-11-25 Compliance**

- ✅ **GET returns 405 without SSE Accept header** (per spec)
- ✅ **Strict protocol version validation** (400 for invalid versions)
- ✅ **SSE priming event** (empty data event sent first)
- ✅ **Origin validation only when present** (no validation if header absent)
- ✅ **MCP-Session-Id header** (proper casing)
- ✅ **404 for invalid session ID** (per spec)
- ✅ **Full MCP method support** (prompts, resources, logging, completion)

### **Ready for Production Deployment**

This implementation is **immediately ready** for production use and supports:

- ✅ **Latest MCP Clients** (2025-11-25 protocol)
- ✅ **Legacy MCP Clients** (backwards compatible with 2025-06-18, 2025-03-26, 2024-11-05)
- ✅ **Enterprise Security Standards**
- ✅ **Scalable Architecture**
- ✅ **Modern Cloud Deployments**

---

## 📚 **Additional Resources**

- **Server Code**: `src/wazuh_mcp_server/server.py`
- **Authentication**: `src/wazuh_mcp_server/auth.py`
- **Security**: `src/wazuh_mcp_server/security.py`
- **Documentation**: `README.md`, `INSTALLATION.md`
- **Deployment**: `compose.yml`, `Dockerfile`

**This implementation is up-to-date with the latest 2026-07-28 specification (served on the modern stateless path) and remains backward compatible with the 2025-11-25 and earlier handshake-based revisions.**
