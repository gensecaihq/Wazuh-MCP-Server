# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
