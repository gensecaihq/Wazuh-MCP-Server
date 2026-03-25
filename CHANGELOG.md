# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
