# MCP Protocol Compliance

How the server implements the Model Context Protocol, and what was checked.

## Method

Checked on `main` at `aac0fda` by reading `src/wazuh_mcp_server/server.py` and sending
requests to the ASGI app in-process (the `modern_body`/`modern_headers` helpers from
`tests/integration/test_mcp_protocol.py`, `AUTH_MODE=none`, `AUTHLESS_ALLOW_WRITE=true`,
`ALLOWED_ORIGINS=https://claude.ai`). Responses quoted below are from that run, with the
`correlation_id` values shortened. The protocol, scope-enforcement and OAuth suites
(`test_mcp_protocol.py`, `test_scope_enforcement.py`, `test_oauth*.py`) pass.

Not covered here: interoperability with specific MCP clients, and behavior behind a reverse
proxy.

## Protocol versions

```python
MODERN_PROTOCOL_VERSIONS = ["2026-07-28"]
LEGACY_PROTOCOL_VERSIONS = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"]
```

The server is dual-era:

- **2026-07-28 (modern, stateless).** A request is routed to the modern path when its
  `MCP-Protocol-Version` header is `2026-07-28`, or when
  `params._meta["io.modelcontextprotocol/protocolVersion"]` holds a version that is not a
  legacy revision. No session is created or echoed; `Mcp-Session-Id` is ignored.
- **2024-11-05 to 2025-11-25 (legacy).** `initialize` negotiates the version and creates a
  session identified by `Mcp-Session-Id`. A legacy client whose `_meta` carries a legacy
  version stays on the legacy path.

`GET /health` reports `mcp_protocol_version: "2026-07-28"`,
`legacy_handshake_protocol_version: "2025-11-25"` and the full `supported_protocol_versions`
list.

## Endpoints

| Endpoint | Behavior |
|---|---|
| `POST /mcp` | JSON-RPC (modern or legacy) |
| `GET /mcp` | SSE stream (legacy sessions); 405 unless `Accept` includes `text/event-stream` |
| `DELETE /mcp` | Ends a legacy session: 204, or 404 if unknown. Requires `Mcp-Session-Id`; checks auth, Origin and rate limit. |
| `GET /`, `POST /` | Same routing as `/mcp` |
| `GET`/`POST /sse` | 410 Gone: `{"error":"The legacy /sse transport is not supported. Use the Streamable HTTP endpoint /mcp.","endpoint":"/mcp"}` |

The old HTTP+SSE transport (2024-11-05) is not available; clients must use Streamable HTTP.

## 2026-07-28 (modern) requirements

| Requirement | Result | Evidence |
|---|---|---|
| `server/discover` | Implemented | Returns `supportedVersions` (all five), `capabilities` (`tools`, `prompts`, `resources`, `completions`), `instructions`, `resultType`, `ttlMs: 3600000`, `cacheScope: "private"`, and `serverInfo` in `_meta` |
| `resultType` on results | `"complete"` on every modern success result | `handle_modern_request` |
| CacheableResult hints | `ttlMs` and `cacheScope: "private"` on `server/discover`, `tools/list`, `prompts/list`, `resources/list`, `resources/read`, `resources/templates/list` | `CACHEABLE_METHOD_TTLS` |
| `serverInfo` | `_meta["io.modelcontextprotocol/serverInfo"] = {"name":"Wazuh MCP Server","version":"4.3.0"}` | discover response |
| Modern header without `_meta` | HTTP 400, `-32020` | see below |
| `MCP-Protocol-Version` vs `_meta` mismatch | HTTP 400, `-32020` | `handle_modern_request` |
| `Mcp-Method` must match body `method` | HTTP 400, `-32020` | see below |
| `Mcp-Name` must match `params.name`/`params.uri` for `tools/call`, `prompts/get`, `resources/read` | HTTP 400, `-32020`; `=?base64?...?=` values are decoded first | base64-encoded `Mcp-Name` for `prompts/get` returned 200 |
| Unsupported version | HTTP 400, `-32022` with `data.supported` and `data.requested` | see below |
| Batches | HTTP 400, `-32600` | `"Batch requests are not supported by modern protocol revisions; send one request per POST"` |
| Removed methods (`initialize`, `ping`, `logging/setLevel`) | HTTP 404, `-32601` | `"Method 'initialize' not found"` |
| Notifications | HTTP 202, empty body | `notifications/cancelled` |
| Server-initiated requests (sampling, elicitation, roots) | Not used | The server never sends requests to the client |
| `subscriptions/listen`, list-changed notifications | Not implemented | Lists are static |

Modern header without `_meta`:

```
HTTP 400
{"jsonrpc":"2.0","id":1,"error":{"code":-32020,"message":"Header mismatch: MCP-Protocol-Version header '2026-07-28' requires params._meta['io.modelcontextprotocol/protocolVersion'] on every request","data":{"correlation_id":"…"}}}
```

`Mcp-Method: prompts/list` on a `tools/list` body:

```
HTTP 400
{"jsonrpc":"2.0","id":1,"error":{"code":-32020,"message":"Header mismatch: Mcp-Method header 'prompts/list' does not match body method 'tools/list'","data":{"correlation_id":"…"}}}
```

Unsupported version (`2099-01-01`):

```
HTTP 400
{"jsonrpc":"2.0","id":1,"error":{"code":-32022,"message":"Unsupported protocol version","data":{"supported":["2026-07-28","2025-11-25","2025-06-18","2025-03-26","2024-11-05"],"requested":"2099-01-01","correlation_id":"…"}}}
```

## Legacy (2024-11-05 to 2025-11-25) requirements

| Requirement | Result |
|---|---|
| `initialize` | Returns `protocolVersion` (the client's if it is a legacy revision, otherwise `2025-11-25`), `capabilities`, `serverInfo`, `instructions`, and an `Mcp-Session-Id` header. The `MCP-Protocol-Version` response header carries the negotiated version. |
| Declared capabilities | `logging: {}`, `prompts: {listChanged: false}`, `resources: {subscribe: false, listChanged: false}`, `tools: {listChanged: false}`, `completions: {}` |
| `notifications/initialized` | 202, marks the session initialized |
| `ping` | `{}` |
| `logging/setLevel` | Accepts the eight RFC 5424 levels; returns `{}`. The server does not send `notifications/message`. |
| `completion/complete` | Returns `{"completion":{"values":[...],"total":n,"hasMore":bool}}` |
| Unknown `Mcp-Session-Id` | HTTP 404 (`"Session not found. Please start a new session with InitializeRequest."`) |
| Missing `MCP-Protocol-Version` | Treated as `2025-03-26`, echoed in the response header |
| Unsupported `MCP-Protocol-Version` | HTTP 400, `-32022` with the same `data` as above and `id: null` (the header is checked before the body is parsed) |
| Request without session that is not `initialize` | Served, but no session is stored and no `Mcp-Session-Id` is returned |
| JSON-RPC batches | Accepted on the legacy path; at most 100 items; an empty batch is `-32600`; a batch of only notifications/responses returns 202 |

## Shared behavior

### Methods

`tools/list`, `tools/call`, `prompts/list`, `prompts/get`, `resources/list`, `resources/read`,
`resources/templates/list`, `completion/complete` and `server/discover` are served on both
paths. Notifications handled: `notifications/initialized`, `notifications/cancelled` (logged;
in-flight calls are not interrupted).

### Catalogue

| List | Count |
|---|---|
| Tools | 55 with a write-scoped token (41 read, 14 write); 41 with a read-only token. A clusters file adds `list_wazuh_clusters`. `WAZUH_TOOLSETS`/`WAZUH_DISABLED_TOOLS` reduce the list. |
| Prompts | 5 |
| Resources | 6 (`wazuh://manager/info`, `wazuh://agents/summary`, `wazuh://alerts/recent`, `wazuh://cluster/status`, `wazuh://rules/summary`, `wazuh://vulnerabilities/critical`) |
| Resource templates | 3 (`wazuh://agents/{agent_id}/info`, `.../alerts`, `.../vulnerabilities`) |

### Tools

- Every tool has `annotations`. Write tools: `readOnlyHint: false`,
  `destructiveHint: true` (false for the five reversal tools: `wazuh_unisolate_host`, `wazuh_enable_user`, `wazuh_restore_file`, `wazuh_firewall_allow`, `wazuh_host_allow`), `idempotentHint: false`,
  `openWorldHint: false`. Read tools: `readOnlyHint: true`, `openWorldHint` true only for
  `search_external_context`.
- Every `inputSchema` has `additionalProperties: false`; undeclared arguments are refused.
- Business refusals (missing scope, confirmation required, disabled tool, unknown argument) are
  tool results with `isError: true`, for example:

  ```
  {"content":[{"type":"text","text":"Unknown argument(s) for 'get_wazuh_agents': bogus. Valid arguments: agent_id, limit, status."}],"isError":true}
  ```

### Pagination

`tools/list`, `prompts/list` and `resources/list` return everything in one page. The `cursor`
parameter is accepted and ignored, and no `nextCursor` is returned.

### Error codes

| Code | Meaning | When |
|---|---|---|
| `-32700` | Parse error | Invalid JSON (HTTP 400) |
| `-32600` | Invalid request | Malformed request, empty batch, batch over 100 items, any batch on the modern path |
| `-32601` | Method not found | Unknown method; removed methods on the modern path (HTTP 404) |
| `-32602` | Invalid params | Validation errors, unknown tool name (`"Unknown tool: nope. Use 'tools/list' to see available tools."`) |
| `-32603` | Internal error | Unhandled exception; details are logged, not returned |
| `-32002` | Resource not found | `resources/read` with an unknown URI (`"Resource not found: wazuh://nope"`), both paths |
| `-32020` | Header mismatch | Modern path header/body checks |
| `-32022` | Unsupported protocol version | Unknown `MCP-Protocol-Version` header or modern `_meta` version |

Error responses include `data.correlation_id`, the request's correlation id from the monitoring middleware, for tracing in the server logs.

### SSE

`GET /mcp` with `Accept: text/event-stream` opens a stream for a legacy session. The first
event is a priming event with an id and empty data; after that the server sends a comment
(`: keepalive`) every 30 seconds. Event ids are `<stream id>-<n>`, where the stream id is random
per stream, so ids are unique across a session's streams:

```
id: de347ee3e345-1
retry: 3000
data: 

```

`Last-Event-ID` is accepted but nothing is replayed; the stream carries no server messages.
POST responses are always `application/json`, even when the client accepts
`text/event-stream`.

### Transport security

- `Origin` present and not in `ALLOWED_ORIGINS`: HTTP 403 (`{"detail":"Origin not allowed: https://evil.example"}`).
  A missing `Origin` is accepted.
- CORS preflight allows `Mcp-Method`, `Mcp-Name`, `MCP-Protocol-Version`, `MCP-Session-Id`,
  `Last-Event-ID` and `Authorization`; `MCP-Session-Id` and `MCP-Protocol-Version` are exposed.
- Authentication (bearer, OAuth or none) applies to `/mcp` and `/`. With `OAUTH_ISSUER_URL`
  set, 401 responses point to `/.well-known/oauth-protected-resource` (RFC 9728) via
  `WWW-Authenticate`.

See [docs/security/README.md](docs/security/README.md) for authentication, scopes and rate
limits.

## Known gaps

- No pagination (single page for all lists).
- No server-to-client messages: no `notifications/message` logging, no progress
  notifications, no list-changed notifications, no resource subscriptions.
- `notifications/cancelled` does not stop an in-flight tool call.
- `Last-Event-ID` resumption has nothing to replay.

## References

- [MCP specification 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28)
- [MCP specification 2025-11-25](https://modelcontextprotocol.io/specification/2025-11-25)
