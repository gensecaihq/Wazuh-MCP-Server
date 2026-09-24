# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- **Manager TLS is verified by default** (#127): `WAZUH_ALLOW_SELF_SIGNED` defaults to `false`; earlier versions sent the Manager API password without verifying the certificate, even with `WAZUH_VERIFY_SSL=true`. New `WAZUH_CA_BUNDLE` (and per-cluster `ca_bundle`) for private CAs, checked at startup and passed to httpx as an SSL context. TLS failures now say why and how to fix them instead of "Cannot connect". Stock self-signed Manager certificates need reissuing or an explicit opt-out; see UPGRADING.md.
- **OAuth now requires sign-in.** `/oauth/authorize` auto-approved every request, and the pre-registered public client was registered for read+write, so anyone who could reach the server got a `wazuh:write` token and could run active response. Users now sign in with their `wazuh_` API key; the grant is capped at that key's scopes and tokens carry the key's identity, so RBAC, rate limits and the audit log are per user. A refresh-token replay revokes that grant only, instead of every user of the shared client. DCR rejects grant types and auth methods the server doesn't implement.
- **OpenID Connect sign-in** (#123): with `OAUTH_IDP_ISSUER`, OAuth users authenticate at Entra ID, Google Workspace, Okta or another OIDC provider; ID tokens are verified (RS256 via JWKS, iss/aud/exp/nonce), tenant/domain/user allow-lists and group-to-scope mapping apply, and tokens carry the user's identity. Unverified e-mail addresses are never used as identity, and open Google or multi-tenant Entra issuers without an allow-list are refused at startup.
- **Tokens are bound to their API key**: revoking or rotating the key ends its bearer JWTs and the OAuth access tokens from sign-ins with it (they used to stay valid until expiry). Tokens must carry `exp`; refresh tokens are refused as access tokens. `MCP_API_KEY` gets a stable id derived from the key, identical across replicas and restarts.
- **Protected-target checks cover every blocking tool.** `wazuh_firewall_drop` and `wazuh_host_deny` never checked `WAZUH_PROTECTED_IPS`/loopback/the Manager, and leading-zero or IPv4-mapped IPv6 spellings (`127.000.000.001`, `::ffff:7f00:1`) slipped past `wazuh_block_ip`'s check.
- **No IP blocks through the generic tool** (#124): `wazuh_active_response` refuses `!firewall-drop` and `!host-deny` and points to `wazuh_firewall_drop` / `wazuh_host_deny`; free-form parameters could carry CIDR ranges or short IP forms past the protected-target check. The block tools also refuse agent `000` (the Manager) unless `WAZUH_ALLOW_MANAGER_AR=true`.
- **Guard-rails on destructive tools** (#125): write tools require `confirm=true` by default in production (`WAZUH_REQUIRE_ACTION_CONFIRMATION` overrides; all write tools advertise the flag); `wazuh_quarantine_file` refuses system and agent directories (`WAZUH_QUARANTINE_DENY_PREFIXES` extends the list, `WAZUH_QUARANTINE_ALLOW_PREFIXES` restricts it); restarting the Manager needs `WAZUH_ALLOW_MANAGER_AR=true`; fleet-wide blocks need `WAZUH_ALLOW_FLEET_AR=true`. Invalid values for these switches fail at startup.
- **Tool output is redacted in every mode**: credentials in log lines were only redacted for compact alerts; `compact=false`, GCF output, manager logs and resource reads returned them verbatim. Log redaction also covers tracebacks, structured `extra` fields and bare JWTs.
- **Bounded session store** (#126): stored client metadata is truncated, and the in-memory store is capped (`MAX_SESSIONS`, `MAX_SESSIONS_PER_PRINCIPAL`), reclaiming expired sessions before evicting the least recently active. Previously a client could store up to ~1 MB of metadata per session with no limit on sessions.
- `RATE_LIMIT_REQUESTS`/`RATE_LIMIT_WINDOW` now apply to `/mcp` and `/`, which used hard-coded constants.
- Chunked request bodies are size-capped while streaming (they were buffered in full first); failed authentication on the MCP endpoints is rate limited; `DELETE /mcp` checks Origin; `resources/read` no longer returns raw backend exception text; the Trivy filesystem scan in CI actually gates.

- **OAuth follow-ups (second audit)**: an expired API key now ends the OAuth tokens and refresh grants issued from it, and narrowing a key's scopes narrows tokens already issued (bearer and OAuth). A user-editable `preferred_username` can no longer satisfy `OAUTH_IDP_ALLOWED_USERS` or pose as a vouched e-mail. `OAUTH_ENABLE_DCR` together with `OAUTH_IDP_ISSUER` is refused at startup, because IdP sign-in has no consent step and a self-registered client could collect other users' codes. IdP refresh chains end one `OAUTH_REFRESH_TOKEN_TTL` after sign-in instead of rotating indefinitely. The sign-in page's CSP allowed only `'self'` in `form-action`, which blocked the redirect back to Claude in Chrome. A full dynamic-registration table now evicts idle clients instead of refusing every registration.
- **Active response (second audit)**: `wazuh_active_response` also refuses `quarantine`, `kill-process` and `disable-account`, which skipped the dedicated tools' path, PID and username checks. `wazuh_quarantine_file` refuses Windows spellings that reached system directories (trailing dots or spaces, `::$INDEX_ALLOCATION` and other streams, 8.3 short names). An IPv6 Manager address is protected exactly (it was unprotected when bracketed and a whole /32 when not). Audit lines record the cluster an action ran on.

### Added
- **Local LLM stack** (`compose.local-llm.yml`, [Local LLM Guide](docs/LOCAL_LLM.md)): vLLM v0.30.0 (Qwen3.6-35B-A3B FP8 by default, tool calling + reasoning parsers, text-only, not published on a host port) and Open WebUI next to the server. The guide covers Ollama for single analysts and LiteLLM as an optional gateway, with its identity and approval caveats. Replaces the mcphost quick start (mcphost is unmaintained).
- **Toolsets**: `WAZUH_TOOLSETS` and `WAZUH_DISABLED_TOOLS` limit which tools are exposed. Hidden tools are removed from `tools/list` and refused by `tools/call`; unknown names fail at startup. The full catalogue is ~6.6k tokens; on qwen3.5:9b (Ollama, Apple M5) trimming to 38 tools cut median response time from 15.8s to 10.9s with no change in tool-selection accuracy.
- **MCP tool annotations** on every tool (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`), derived from scope, so clients and gateways can gate approvals.
- **Tool-selection eval** (`evals/tool_selection.py`): 25 SOC scenarios, including two prompt-injection cases, run against any OpenAI-compatible endpoint (vLLM, Ollama, LiteLLM proxy). Scores tool choice and argument validity without executing anything.

### Changed
- Tool input schemas are closed (`additionalProperties: false`). When `WAZUH_REQUIRE_ACTION_CONFIRMATION` is on, write tools declare the `confirm` flag, which strict clients previously had no way to send.

### Fixed (September 2026 production audit)
- **Deploy paths**: the README Quick Start, `deploy.py`/`deploy.bat` and `docker run --env-file` all failed as documented (no `AUTH_SECRET_KEY` under compose's production mode, loopback bind inside the container, generated API key redacted from the logs). All three are verified working end to end.
- **Active response semantics** (checked against the Wazuh v4.14 source): `duration` never did anything (the agent zeroes the timeout for API-dispatched `!` commands), so blocks were permanent; `all_agents` sent `agents_list=all`, which the API rejects; results claimed execution when Wazuh only confirms delivery; `check_file_quarantine` could never return true.
- **Per-agent tools returned fleet-wide numbers**: `perform_risk_assessment` and the ISO 27001 dashboard / gap analysis ignored `agent_id` for vulnerabilities, alerts and SCA; `get_wazuh_vulnerability_summary` ignored `time_range`.
- **Search**: `AND`/`OR`/`NOT` in `search_security_events` were matched as literal words, silently emptying results.
- **Resilience**: `/ready` could starve tool calls (unauthenticated, not rate limited, one Manager call each) and ignored memory pressure; a Redis outage looked like "session not found"; an open SSE stream blocked SIGTERM forever; legacy requests stored a session per call.
- **Config**: `ENVIRONMENT=prod`, `AUTH_MODE` typos, `RATE_LIMIT_REQUESTS=0`, bad `SESSION_TTL_SECONDS`, `YDC_VERIFY_SSL=1` and malformed `clusters.json` values were silently misread; they now fail at startup.
- **MCP conformance**: `Mcp-Method`/`Mcp-Name` blocked by CORS preflight; business refusals (scope, confirmation, disabled tool) now reach the model as `isError` results; `resources/templates/list` entries are readable; resource-not-found is `-32002`; JSON-RPC envelope and batch validation; SSE event ids unique per session.
- **Second audit**:
  - Credential redaction truncated tool results: `Authorization: .+` removed everything after the first match on one-line JSON, including later alerts and totals, and other patterns ate closing quotes.
  - Server:
    - `WEB_CONCURRENCY` (set by Heroku and others) stopped the server from starting.
    - `SESSION_TTL_SECONDS` above 1800 had no effect.
    - `/ready` fetched every Redis session.
    - `/` blocked tool arguments containing attack strings and diverged from `/mcp` (it is now an alias of it).
    - An unhashable notification `method` returned 500, `"id": true` was answered as `1`, and `/mcp` dropped the request id on validation errors.
  - Tools:
    - An explicit `null` agent, rule or data field failed `get_top_security_threats`, `analyze_alert_patterns` and `get_iso27001_alerts`.
    - `wazuh_check_blocked_ip` did not canonicalise the IP.
    - `search_security_events` accepted levels such as `-1`.
    - `limit` defaults could exceed a lowered `MAX_ALERTS_PER_QUERY`.
  - Startup:
    - A host with a port or path (`WAZUH_HOST=https://host:55000/`), or a CA bundle that isn't PEM, now fails at startup instead of on every call.
    - The key generated in development when none is configured is read-only, as the README states (it had write access).
    - A malformed `MCP_API_KEY` or unparseable `API_KEYS` stops startup instead of falling back to an unknown generated key; `/ready` reports why the Manager check failed (`wazuh_manager_reason`) and logs the cause.
    - Quoted values from `docker run --env-file` (`MCP_API_KEY_SCOPES="wazuh:read wazuh:write"`) are unquoted.
  - Deploy:
    - `.env.example` no longer sets `ENVIRONMENT=development`, which switched `docker run --env-file` into development mode.
    - Source runs bind `127.0.0.1` by default.
    - `compose.dev.yml` publishes on loopback.
    - `compose.yml` allows 30 s for shutdown.
    - Images are only published from commits whose tests pass.
    - `python -m wazuh_mcp_server --help` prints usage.
- Many smaller fixes: `process_id: true` meant PID 1, Windows paths couldn't be quarantined, `rule.groups` counts depended on order, rules summary stopped at 500, manager-log limits above 500 errored, HTTP-date `Retry-After` crashed, unknown tool arguments were silently ignored, oversized results are truncated with a note.

### Changed
- `/sse` answers **410 Gone** (the legacy HTTP+SSE transport never worked); use `/mcp`.
- The Docker image ships `redis` and `gcf-python`, and no longer includes pip.
- `compose.yml` mounts `./config` read-only and its healthcheck always probes the in-container port 3000.

### Fixed
- **Missing `resultType` under MCP 2026-07-28** (#121): routing onto the modern stateless path keyed only on `params._meta`, so a request carrying `MCP-Protocol-Version: 2026-07-28` without that `_meta` fell through to the legacy handler — which minted a session and returned a result without `resultType` while echoing the modern version header. A modern header now always selects the modern path (missing `_meta` → `-32020`), modern batches are rejected with `-32600`, and `/` routes modern requests the same way as `/mcp`.
- **Unknown tools reported as permission errors**: `tools/call` with a nonexistent tool name returned "requires 'wazuh:write' scope" because the scope lookup fails closed; it now returns "Unknown tool".

### Changed
- `/health` and `/ready` report `mcp_protocol_version` as the latest served revision (`2026-07-28`); the version offered during `initialize` moved to `legacy_handshake_protocol_version`.

## [4.3.0] - 2026-08-06

### Security
- **Credential redaction now actually runs**: the log sanitizer was attached to the root logger, whose filters are skipped for records propagating up from child loggers — so passwords/tokens from the API clients and auth layer were logged in cleartext. It now attaches to the emitting handlers, and the patterns additionally redact URL-embedded credentials and the token after an `Authorization:` label.
- **RBAC scope boundary and OAuth flows are now tested**: every one of the 14 write tools is verified denied to a read-only token, and the OAuth PKCE/single-use-code/refresh-rotation/revocation/DCR paths have a dedicated suite. A branch-coverage floor is enforced in CI.

### Fixed
- **Circuit-breaker deadlock**: a half-open trial that raised an unmonitored exception (e.g. `ValueError` on a 4xx/invalid-JSON response) or hit a 429 left the breaker stuck HALF_OPEN with its single-trial gate set, so every later call returned HTTP 503 until restart — bricking all Wazuh tools on that client. The trial now always releases the gate and re-arms.
- **Active-response and ISO 27001 correctness against stock Wazuh**: the generic `wazuh_active_response` tool (validator rejected the `!` the allowlist required) now works; `wazuh_firewall_allow`/`wazuh_host_allow` no longer silently re-block (they require an operator-deployed undo script via `WAZUH_AR_FIREWALL_UNDO_COMMAND`/`WAZUH_AR_HOSTDENY_UNDO_COMMAND` and refuse otherwise); `disable_user` sets `alert.data.dstuser`; `check_file_quarantine` uses `GET /syscheck/{agent_id}`; `search_wazuh_manager_logs` uses `search=`; ISO A.8.15 reads the nested analysisd stats (was always 0); and an Indexer failure no longer scores A.8.8 as perfect compliance.
- **MCP dual-era routing**: a legacy client whose `_meta` carried a legacy protocol version is no longer hijacked onto the modern stateless path (which rejected it with a self-contradictory `UnsupportedProtocolVersionError` and livelocked the retry).

### Added
- **MCP 2026-07-28 protocol support (dual-era)**: modern stateless requests (per-request `_meta` protocol version/capabilities, `server/discover`, `Mcp-Method`/`Mcp-Name` header validation with Base64 sentinel decoding, `resultType`, `ttlMs`/`cacheScope` cache hints, `-32020`/`-32022` spec error codes) served alongside the legacy `initialize` handshake and `Mcp-Session-Id` sessions for clients on 2024-11-05 through 2025-11-25.
- **OAuth protected resource metadata (RFC 9728)**: `/.well-known/oauth-protected-resource` endpoint and `resource_metadata` hint in `WWW-Authenticate` when `OAUTH_ISSUER_URL` is set.
- **`rule_groups` filter on `get_wazuh_alerts`** — query alert categories (e.g. `authentication_failed`, `firewall`) via a `terms` query on `rule.groups` (#86).
- **`search_external_context` tool** (optional, contributed by @mouse-value-add, #85): You.com web search for security context, enabled only when `YDC_API_KEY` is set; isolated behind its own circuit breaker.
- **Published Docker image**: multi-arch (amd64/arm64) images pushed to `ghcr.io/gensecaihq/wazuh-mcp-server` on releases and `main` (#69).
- **Multi-cluster support (opt-in)** via `WAZUH_CLUSTERS_FILE`/`./config/clusters.json` (#77): named clusters with per-cluster Manager/Indexer credentials and `${ENV_VAR}` secret interpolation, an optional `cluster_id` argument on every tool, a `list_wazuh_clusters` tool, per-cluster info in `/health`, and OpenSearch Cross-Cluster Search routing via `ccs_prefix` (including `"*"` for fleet-wide reads). Without a clusters file, single-cluster env-var behavior is unchanged.
- **`get_alerts_aggregated` tool**: summarizes a whole time window via Indexer aggregations (`size=0`) with no per-document limit — true total count plus top rules, severity levels, and agents (#81).
- **ISO 27001:2022 compliance tools** (contributed by @andrzej-piotrowski-pl, #74): `get_iso27001_dashboard`, `get_iso27001_control_detail`, `get_iso27001_gap_analysis`, `get_iso27001_alerts`, `get_sca_policy_checks`, the `iso27001_assessment` guided prompt, and `ISO27001` as a `run_compliance_check` framework (Annex A control mapping to live Wazuh data).
- **Relative timestamps**: `timestamp_start`/`timestamp_end` now accept OpenSearch date math (`now-24h`, `now-7d/d`) in addition to ISO 8601 (#73).
- **Plain-HTTP Indexer support**: `WAZUH_INDEXER_SSL` (and an `http://` prefix on `WAZUH_INDEXER_HOST`) allow pointing at a non-TLS OpenSearch node; `WAZUH_INDEXER_VERIFY_SSL` is now honored (#78).
- **`MCP_API_KEY_SCOPES`** to grant the env API key write access (read-only by default).

### Changed
- **RBAC fails closed**: a token with no scope claim is read-only; write is opt-in. The 14 state-changing tools (active response + rollback) require `wazuh:write`. `/auth/token` mints the API key's actual scopes instead of always read+write.
- **`AUTH_SECRET_KEY` required in production**: with `ENVIRONMENT=production` and `AUTH_MODE != none`, the server refuses to start without it (prevents per-restart token invalidation and cross-instance auth failures).
- **OAuth hardened**: mandatory S256 PKCE, single-use authorization codes, refresh-token rotation with replay detection, an effective revocation denylist, and DCR off by default with redirect-URI validation.
- **Indexer queries** use `term` (not `match`) for exact keyword/IP filters; `hits.total` parsing tolerates both int and object forms; 401/403 returns a clear credentials message.
- **Dependencies** trimmed (removed unused `fastmcp`, `passlib`, `aiofiles`) and pinned with upper bounds; tool count is now **55** (including the optional `search_external_context`).

### Fixed
- **ISO 27001 tools no longer query the removed Manager `/alerts` endpoint** (404 on Wazuh 4.8+): the dashboard, control detail, and alert-mapping paths now read alert evidence from the Indexer, with rule-group filtering, so alert-backed controls stop reporting false `no_evidence` gaps (#84).
- **System metrics never collected**: `MetricsCollector` is now started/stopped in the app lifespan, so `/metrics` reports real CPU/memory (previously always `0`).
- **Circuit breaker tripped on 429**: an upstream rate-limit no longer opens the breaker (5xx still does).
- **`tools/list` `nextCursor: null`**: confirmed resolved — list responses omit the cursor field (#75).
- Documentation corrected for accuracy: real env-var reference, 55-tool inventory, removed non-existent config keys, and the no-built-in-TLS (reverse-proxy) note.

## [4.2.1] - 2026-03-26

### Fixed
- **Session delete crash**: `sessions.delete()` replaced with `sessions.remove()` — `SessionManager` exposes `remove()`, not `delete()`. Would crash with `AttributeError` on expired session cleanup.
- **Scope enforcement bypass**: Write tools now denied when `_auth_token` is `None` on session, instead of silently skipping the scope check.
- **Agent ID regex**: Changed `{3,5}` to `{1,5}` — Wazuh manager agent `"0"` and short IDs like `"1"`, `"12"` were incorrectly rejected.
- **ACTIVE_CONNECTIONS counter leak**: `/sse` endpoint no longer leaks counter on early errors (session validation moved before counter increment).
- **WazuhClient.close() error handling**: `aclose()` failures no longer prevent indexer and cache cleanup (wrapped in try/finally).
- **verify_bearer_token null crash**: Added null guard — calling with `None` no longer raises `AttributeError`.
- **block_ip without agent_id**: `"all"` is now passed through to Wazuh API instead of being filtered out, which caused a 400 error.
- **config_validator Fernet crash**: Invalid `MASTER_KEY` env var no longer crashes server on import — falls back to generated key with warning.
- **config_validator int() crash**: Non-numeric `WAZUH_PORT`/`SSE_PORT` now reports validation error instead of unhandled `ValueError`.
- **Indexer agg_search null client**: `_execute_agg_search` now calls `_ensure_initialized()` — prevents `AttributeError` when `self.client` is `None` after close.
- **json.dumps non-serializable crash**: Added `default=str` to all `json.dumps` calls in tool handlers and resources/read — Wazuh API responses containing datetime objects no longer crash serialization.
- **WazuhClient.initialize() connection leak**: Now closes existing httpx client before creating new one on re-initialization.
- **Re-auth retry response validation**: After 401 retry, response is now validated for `"data"` key, consistent with normal request path.
- **OAuth refresh unbounded memory**: `refresh_access_token` now evicts expired tokens when `access_tokens` exceeds 5000 entries.
- **Risk assessment default**: Zero risk factors now correctly returns `"low"` instead of `"medium"`.
- **firewall_allow/host_allow IP validation**: Added missing `_validate_ip()` call before active response execution.
- **OAuth state URL encoding**: `state` parameter in error redirect now properly URL-encoded via `urlencode()`.
- **Indexer timeout handling**: `_execute_agg_search` now catches `httpx.TimeoutException` alongside `ConnectError`.
- **Indexer close() cleanup**: Now sets `self.client = None` in finally block to prevent use-after-close.
- **Module-level init safety**: `AuthManager` and `SecurityManager` now handle malformed env vars (`TOKEN_LIFETIME_HOURS`, `RATE_LIMIT_REQUESTS`, `RATE_LIMIT_WINDOW`) with try/except and sensible defaults.
- **CPU metric**: `MetricsCollector` now reuses a persistent `psutil.Process()` instance — `cpu_percent()` no longer always returns 0.0.
- **Circuit breaker HALF_OPEN race**: Added `_half_open_trial_in_progress` flag to allow only one concurrent trial request.
- **Truncation warnings**: Added to vulnerability search tools (was only on alert tools).

### Removed
- **Dead code**: `_dict_contains_text` helper and its 6 tests removed (replaced by Elasticsearch query passthrough in v4.2.0).

### Changed
- **Version alignment**: Synchronized version across `__init__.py`, `pyproject.toml`, `Dockerfile`, `compose.yml`, and `requirements.txt`.
- **Tests**: 84 tests (13 regression tests added, 6 dead-code tests removed).

## [4.2.0] - 2026-03-25

### Security
- **Per-tool RBAC scope enforcement**: 14 active response/rollback tools now require `wazuh:write` scope; all other tools require `wazuh:read`. Scopes checked on every `tools/call` and `tools/list` filtered by token permissions
- **Authless mode guardrails**: `AUTH_MODE=none` now defaults to read-only scopes. New `AUTHLESS_ALLOW_WRITE=true` env var required to enable destructive operations without authentication
- **Output sanitization**: Passwords, API keys, tokens, and Authorization headers are redacted from alert `full_log` text before returning to MCP clients, preventing credential leakage to LLMs
- **Audit logging for destructive operations**: All write-scope tool invocations logged with client ID, session ID, and arguments via dedicated `wazuh_mcp_server.audit` logger

### Fixed
- **MCPResponse.model_dump() for falsy results**: `result=0`, `""`, `[]` are now correctly serialized per JSON-RPC 2.0 spec
- **Duplicate REQUEST_COUNT metrics**: `/mcp` and `/sse` endpoints no longer double-count requests already tracked by monitoring middleware
- **Duplicate CircuitBreaker class**: Removed redundant class from `security.py` that shadowed the production version in `resilience.py`
- **Unused variable and import lint issues**: Clean ruff pass across all source files

### Performance
- **Targeted Elasticsearch queries**: `analyze_security_threat`, `check_ioc_reputation`, `check_blocked_ip`, `check_agent_isolation`, and `check_user_status` now use `query_string` queries instead of fetching unfiltered alerts for client-side text matching
- **search_security_events limit capped**: Reduced from 10,000 to 1,000 to prevent Elasticsearch `max_result_window` errors and MCP token overflows
- **Result truncation warnings**: Results hitting the requested limit include a `_warning` field suggesting more specific filters

### Changed
- **Auth token propagation**: `verify_authentication()` now returns `AuthToken` (not bool), stored on session for downstream scope checks
- **Time range enum sync**: All tool schemas now expose the full set of valid time ranges (`1h`, `6h`, `12h`, `1d`, `24h`, `7d`, `30d`)
- **Metrics endpoint normalization**: Added `/sse`, `/docs`, `/openapi.json` to `_KNOWN_ENDPOINTS`
- **WazuhClient.close() hardened**: Now clears client, token, and cache references
- **pytest asyncio_mode**: Added `asyncio_mode = "auto"` to `pyproject.toml`
- **Version bump**: 4.1.1 -> 4.2.0

### Tests
- **77 tests** (up from 54): Added coverage for RBAC scope mapping, authless guardrails, output sanitization, truncation warnings, falsy JSON-RPC results, metrics normalization, time range completeness, and close() cleanup

## [4.1.1] - 2026-03-15

### Security
- **OAuth revocation timing attack fix**: `/oauth/revoke` now uses `secrets.compare_digest` for constant-time client secret comparison
- **Security middleware false positives fix**: Header scanning now skips standard HTTP/transport headers (Content-Type, Authorization, etc.) that legitimately contain semicolons and special characters

### Fixed
- **`get_top_security_threats` crash on default params**: `validate_limit(None, max_val=50)` returned 100 which exceeded max, causing `ToolValidationError` when `limit` was omitted. Added `default` parameter to `validate_limit` with automatic clamping to valid range
- **`analyze_alert_patterns` wrong default**: `min_frequency` defaulted to 100 instead of schema-declared 5
- **`get_wazuh_critical_vulnerabilities` wrong default**: `limit` defaulted to 100 instead of schema-declared 50
- **`/mcp` endpoint metrics accuracy**: `REQUEST_COUNT` now records actual status code in `finally` block instead of always recording 200 before processing
- **`/sse` endpoint session validation**: Now returns 404 for invalid/expired session IDs, consistent with `/mcp` endpoint and MCP spec
- **Test suite `jose` import**: Updated `test_dependencies` to import `jwt` (PyJWT) instead of `jose` (python-jose), which was removed in v4.1.0
- **`BulkheadIsolation.get_semaphore` dead code**: Removed redundant nested condition that was always True
- **`validate_positive_int` truthiness bug**: `max_val=0` check now uses `is not None` instead of falsy evaluation
- **`compose.dev.yml` broken**: Changed build target from `builder` (wrong WORKDIR, no CMD, no PYTHONPATH) to `production`; updated stale branch references

## [4.1.0] - 2026-03-11

### Security
- **X-Forwarded-For IP spoofing fix**: `get_client_ip` now returns the rightmost untrusted IP instead of the first (attacker-controlled) IP, preventing rate limit bypass
- **Trusted proxies empty string fix**: Empty `TRUSTED_PROXIES` env var no longer includes empty string in the trusted set
- **OAuth revocation authentication**: `/oauth/revoke` endpoint now validates client credentials per RFC 7009
- **Redis credential leakage fix**: Redis connection error logs no longer expose the full URL containing passwords
- **Health endpoint hardened**: Error details from Wazuh/Indexer connections no longer exposed to unauthenticated clients
- **validate_token null safety**: `validate_token` no longer crashes with `AttributeError` when called with `None`

### Fixed
- **Batch request TypeError**: Non-dict items in JSON-RPC batch requests now return proper error responses instead of crashing the entire batch
- **process_id validation**: `wazuh_kill_process` and `wazuh_check_process` now properly require `process_id` parameter instead of silently defaulting to 100
- **Session DELETE 404**: `close_mcp_session` now correctly returns 404 for non-existent sessions instead of relying on unreachable `KeyError` handler
- **SSE metrics accuracy**: Request status code metrics now recorded after request processing, not before (previously all requests counted as 200)
- **WazuhIndexerClient resource leak**: `initialize()` now closes existing HTTP client before creating a new one
- **RedisSessionStore race condition**: Added async lock to `_ensure_initialized` to prevent concurrent double-initialization

### Changed
- **JWT library migration**: Replaced abandoned `python-jose` (no 3.5.0 release exists) with actively maintained `pyjwt[crypto]>=2.9.0`
- **Dependency versions**: Fixed `cryptography>=44.0.0` (was >=46.0.5 which doesn't exist)
- **Version alignment**: Synchronized version across Dockerfile, compose.yml, requirements.txt, pyproject.toml (was 4.0.7 in several places)
- **Stale branch references**: Updated all `mcp-remote` branch references to `main` across Dockerfile, compose.yml, and labels

### CI/CD
- **Release workflow fix**: Docker release condition now triggers on tag pushes (was checking for non-existent `mcp-remote` branch)
- **Semgrep action update**: Migrated from deprecated `returntocorp/semgrep-action` to `semgrep/semgrep-action`
- **Pinned CI dependencies**: Trivy action pinned to v0.31.0 (was `@master`), TruffleHog pinned to v3.88.0 (was `@main`)
- **Gitleaks updated**: Bumped from v8.18.4 to v8.21.2
- **Build job gating**: Build now depends on lint, test, and syntax-check (was syntax-check only)
- **Removed unused mypy**: No longer installed in CI lint job since it was never executed
- **Docker build action**: Updated `docker/build-push-action` from v5 to v6

### Infrastructure
- **Dockerfile**: Updated Trivy flag from deprecated `--security-checks` to `--scanners`; fixed misleading PYTHONFAULTHANDLER comment
- **compose.yml**: Removed unnecessary `NET_BIND_SERVICE` capability (port 3000 > 1024); removed unused volume definition
- **README**: Fixed Python badge (3.11+ not 3.13+)

## [4.0.9] - 2026-03-02

### Security
- **Session fixation prevention**: Server now always generates UUIDs for new sessions; client-provided session IDs are only used to look up existing sessions
- **Origin validation hardened**: Removed insecure wildcard suffix matching (`*.example.com`) and overly-permissive localhost substring matching; only exact match and explicit `*` wildcard are allowed
- **Command injection prevention**: All active response and rollback methods now sanitize arguments, blocking shell metacharacters (`;`, `|`, `` ` ``, `$`, etc.)
- **Auth token scopes**: Empty scopes list (`[]`) now correctly denies all access; previously returned True like `None` (full access)
- **Bounded token storage**: Auth token store evicts oldest entries when exceeding 10,000 tokens
- **OAuth bounded stores**: Authorization codes (1,000 max), access/refresh tokens (5,000 max), and client registrations (1,000 max) are now bounded to prevent memory exhaustion
- **Rate limiter bounded memory**: Added `MAX_TRACKED_CLIENTS = 10,000` with automatic cleanup of stale entries
- **Redis URL logging**: Removed Redis URLs (which may contain passwords) from log messages

### Fixed
- **Circuit breaker tripping on user errors**: Narrowed `expected_exception` from `Exception` to specific connection/server error types so `ValueError` doesn't trip the circuit
- **Retry logic defeated by exception wrapping**: 5xx `HTTPStatusError`, `ConnectError`, and `TimeoutException` now propagate directly to tenacity instead of being wrapped
- **SSE ACTIVE_CONNECTIONS double-decrement**: Moved decrement into SSE generator `finally` block with `track_connection` flag to prevent gauge going negative
- **IPv6 validation**: Replaced regex-based IP validation with `ipaddress.ip_address()` for proper IPv4 and IPv6 support
- **SanitizingLogFilter dict args**: Fixed crash when log record args is a dict instead of a tuple
- **Redis KEYS command**: Replaced `KEYS` (O(N) blocking) with `SCAN` (cursor-based iteration) in `RedisSessionStore`
- **Indexer retry logic**: `_search()` now lets 5xx, ConnectError, and TimeoutException propagate for tenacity retry
- **`check_agent_isolation`**: Now checks alert history for isolation evidence instead of using disconnected status as a proxy
- **`check_user_status`**: Now searches active response alert history instead of returning hardcoded data

### Added
- `_sanitize_ar_argument()` static method on `WazuhClient` for input sanitization of active response commands
- `group_by` parameter validation with whitelist of allowed fields
- `level` parameter format validation (must match `^[0-9]{1,2}\+?$`)
- 21 new test cases covering all audit v2 fixes (54 total tests)

### Changed
- `CircuitBreakerConfig.expected_exception` now accepts `Union[Type[Exception], Tuple[Type[Exception], ...]]`
- `WazuhClient` circuit breaker uses `(ConnectionError, httpx.ConnectError, httpx.TimeoutException, httpx.HTTPStatusError)` instead of `Exception`

## [4.0.8] - 2026-02-26

### Fixed
- **Auth bypass on root endpoint**: The `/` MCP endpoint was missing authentication, allowing unauthenticated access to all tools when `AUTH_MODE=bearer`
- **`_run_sync` RuntimeError catch**: Method raised RuntimeError as a safety guard but then caught its own exception in the `except` block, silently falling through
- **`__contains__` async bug**: `SessionManager.__contains__` was defined as `async def` but Python's `in` operator doesn't `await`, always returning a truthy coroutine object
- **`/auth/token` bypassing auth_manager**: Token endpoint compared raw API key strings instead of using `auth_manager.validate_api_key()` with proper format checks and constant-time hash comparison
- **`search_security_events` ignoring query**: The `query` parameter was validated but never passed to the indexer, returning unfiltered results
- **`cleanup_expired` signature mismatch**: `SessionManager.cleanup_expired()` didn't accept `timeout_minutes` parameter, causing TypeError when called from `HealthRecovery._recover_memory_pressure`
- **Monitoring middleware not registered**: `setup_monitoring_middleware()` was defined but never registered on the FastAPI app, so no request tracking or correlation IDs were applied
- **Prometheus `/metrics` empty**: `generate_latest()` was called without the custom `REGISTRY`, returning empty default registry instead of actual metrics

### Added
- Security middleware now registered on the FastAPI app, adding security headers (X-Content-Type-Options, X-Frame-Options, etc.) to all responses
- `"12h"` added to `VALID_TIME_RANGES` and `"1d": 24` added to `_TIME_RANGE_HOURS` for consistent time range support
- `"pending"` added to agent status enum in tool schema to match `VALID_AGENT_STATUSES`
- Max size guard on `_initialized_sessions` dict to prevent unbounded memory growth (capped at 10,000 entries)
- 23 new test cases covering audit fixes (33 total tests, up from 10)

### Changed
- `MCPResponse` now overrides Pydantic v2 `model_dump()` instead of deprecated v1 `dict()` method
- `get_alerts` in `WazuhIndexerClient` refactored to use `_search()` helper for consistent retry logic
- `analyze_security_threat`, `check_ioc_reputation`, and `check_blocked_ip` use recursive dict search instead of O(n) `json.dumps()` per alert
- `_search()` in `WazuhIndexerClient` now accepts optional `sort` parameter

### Removed
- Dead `create_auth_endpoints()` function, `TokenRequest`/`TokenResponse` classes, and unused `HTTPException` import from `auth.py`

## [4.0.7] - 2026-02-25

### Added
- 19 new action/verification/rollback tools (48 tools total):
  - 9 active response tools: block_ip, isolate_host, kill_process, disable_user, quarantine_file, active_response, firewall_drop, host_deny, restart
  - 5 verification tools: check_blocked_ip, check_agent_isolation, check_process, check_user_status, check_file_quarantine
  - 5 rollback tools: unisolate_host, enable_user, restore_file, firewall_allow, host_allow
- Input validation for action tool parameters (IP addresses, file paths, usernames, AR commands)
- Batch request size limit (MAX_BATCH_SIZE=100) to prevent resource exhaustion
- SSE keepalive loop cancellation on client disconnect
- `fastmcp>=2.14.0` added to pyproject.toml dependencies

### Fixed
- **Circuit breaker race condition**: State transitions now use asyncio.Lock for thread safety
- **Retry on non-transient errors**: Narrowed retry scope to 5xx and connection errors only (was retrying 400/401/404)
- **Circuit breaker monitoring always "unknown"**: Fixed `cb._state` → `cb.state.value` attribute mismatch
- **Unbounded Prometheus metric cardinality**: Endpoint labels now normalized to fixed set
- **JSONDecodeError crashes**: Added handling at all 5 `response.json()` call sites in wazuh_client.py and wazuh_indexer.py
- **Wazuh Indexer init race condition**: Added asyncio.Lock with double-check pattern
- **Non-deterministic cache keys**: Replaced `hash()` with `sorted()` for stable cross-process keys
- **Premature metrics increment**: Removed hardcoded status_code=200 counter before request processing
- **Session cleanup on every request**: Throttled to run at most every 60 seconds
- **10 broken MCP tools** calling non-existent Wazuh Manager API endpoints
- **get_wazuh_alerts** now queries Wazuh Indexer instead of non-existent Manager API endpoint
- **3 broken endpoints**: `/manager/stats/all` → `/manager/stats`, `/cluster/health` → `/cluster/healthcheck`, `/manager/stats/logcollector` → `/manager/stats/analysisd`
- **get_rules_summary** calling non-existent `/rules/summary` endpoint — now aggregates from `/rules`
- **CI release workflow**: Removed `|| true` that silenced test failures
- **CI security workflow**: Replaced `|| true` with `continue-on-error: true` for proper visibility

### Removed
- 4 dead-code methods with non-existent API endpoints (get_incidents, create_incident, update_incident, get_manager_version_check)

## [4.0.6] - 2025-02-14

### Added
- MCP protocol version 2025-06-18 support
- Wazuh OpenClaw Autopilot integration documentation
- MCP_API_KEY environment variable for API key configuration

### Fixed
- Missing dependencies in pyproject.toml
- Connection refused error when WAZUH_HOST includes protocol prefix
- Resource leak: close Wazuh client and connection pools on shutdown
- Multiple bugs in resilience, session management, and client initialization
- MCP notification handler and monitoring bugs
- MCP authentication security improvements

### Changed
- Migrated from on_event to lifespan event handlers
- Improved Dockerfile security scanning and added type hints
- Replaced magic numbers with production constants
- Improved .env.example security defaults
- Streamlined README and moved detailed docs to docs/

## [4.0.2] - 2025-01-15

### Added
- Initial remote MCP server release with Streamable HTTP transport
- Full MCP 2025-11-25 specification compliance
- 29 Wazuh security tools (alerts, agents, vulnerabilities, analysis, monitoring)
- OAuth 2.0 with PKCE and Dynamic Client Registration
- Bearer token authentication with auto-generated API keys
- Wazuh Indexer client for vulnerability queries (Wazuh 4.8.0+)
- Prometheus metrics and health check endpoints
- Circuit breaker and retry logic for API resilience
- Docker multi-stage build with Trivy security scanning
- Redis-backed session store (optional)
