# Production-Readiness Audit — Findings & Remediation

A block-by-block audit of the server (MCP protocol/dispatch, Wazuh API clients, auth/OAuth,
security middleware, resilience, config, and the deploy surface). Findings were verified
against the code by tracing each path; the fixes below are covered by regression tests in
`tests/integration/test_audit_hardening.py` and validated against a live server driven through
the [MCP Inspector](https://github.com/modelcontextprotocol/inspector) CLI.

Verified accurate as part of the audit: **55 tools / 14 write-scoped / 5 prompts** (perfect
registration↔dispatch bijection), fail-closed RBAC (read-only sessions are denied write tools
at call time, not merely hidden from `tools/list`), OAuth PKCE-S256/single-use-code/refresh-
rotation, and the dual-era MCP protocol negotiation.

## Fixed in this change

### Safety — Active Response (state-changing)
- **Fleet-wide escalation via non-numeric agent target.** `execute_active_response` filtered the
  agent list to numeric IDs and, when none survived (e.g. an LLM passed a hostname), sent the PUT
  with no `agents_list` — which Wazuh interprets as **all agents**. A block/isolate/kill could fan
  out to the whole fleet. Now refuses when a supplied target yields no numeric ID, and never
  dispatches a targeting action without an explicit `agents_list`.
- **Fleet-wide block via stringly-typed `all_agents`.** `bool("false")` is `True`, so
  `all_agents="false"` blocked every agent. Now parsed with `validate_boolean`.
- **No manager (agent 000) protection.** `isolate_host`/`kill_process`/`disable_user`/
  `quarantine_file`/`active_response` accepted `agent_id="000"` — the Wazuh manager itself, a
  self-inflicted control-plane DoS. Now refused unless `WAZUH_ALLOW_MANAGER_AR=true`.
- **`wazuh_restart` used the raw target.** Discarded the normalized agent id (`/agents/1/restart`
  → 400); now uses the zero-padded form and routes `000` through the `manager` keyword.

### Crashes / protocol correctness (server.py)
- **Exotic JSON-RPC `id` → HTTP 500 + batch loss.** A spec-valid fractional id (`1.5`) or an
  array/object id crashed error-response construction; in a batch it discarded every already-
  computed response. `id` widened to allow `float`; both response constructors normalize the id.
- **`arguments: null` / non-string tool name → HTTP 500.** Now return clean `-32602`-class errors.

### Security middleware / resilience
- **Circuit-breaker deadlock on cancellation.** A half-open trial cancelled mid-flight
  (`asyncio.CancelledError` is a `BaseException`) left the trial gate set, stranding the breaker
  in HALF_OPEN and 503-ing every later call until restart. Gate now released on any BaseException.
- **Memory kill-switch 503'd `/health` and ignored `MAX_MEMORY_MB`.** Liveness/readiness/metrics
  probes are now exempt (no restart-loop under load), and the threshold honors `MAX_MEMORY_MB`.
- **WAF body scan rejected legitimate SIEM tool calls.** The injection-pattern scan ran over the
  `/mcp` JSON-RPC body, so searching for attack indicators (`../`, shell metacharacters) 400'd.
  Body scan now skipped for JSON-RPC endpoints (per-parameter typed validation still applies);
  size limits and header/query scanning are unchanged.
- **Log redaction missed Basic-auth and exception objects.** `Basic <base64>` (how the Wazuh
  Manager client authenticates) and exception args now redacted.

### Configuration / secrets
- **Placeholder `AUTH_SECRET_KEY` passed the production gate.** `cp .env.example .env` +
  `ENVIRONMENT=production` signed tokens with a value published in this repo. The gate now rejects
  placeholder/short keys and requires ≥32 chars; the example ships the key unset (commented).
- **Truthy env values disabled TLS.** `WAZUH_VERIFY_SSL=1` / `=yes` parsed as `False` (and
  `WAZUH_INDEXER_SSL=1` sent credentials over plain HTTP). A shared strict `env_bool` now accepts
  `1/true/yes/on` and raises on garbage.
- **`WAZUH_ALLOW_SELF_SIGNED` was a no-op.** Documented but never plumbed into the client. Now
  wired: effective verify = `WAZUH_VERIFY_SSL and not WAZUH_ALLOW_SELF_SIGNED`.

### Correctness (Wazuh clients)
- **Alert totals capped at 10,000.** Document searches lacked `track_total_hits`, so summary/KPI
  tools plateaued at `10000`. Now set.
- **`level` filter silently dropped for an int input**, returning *all* alerts. Now coerced via
  `str()` and raises on genuinely-bad input.
- **CVE lookup was case-sensitive** (`cve-2021-44228` → 0 hits). Now upper-cased.
- **`_compact_alert` crashed on an explicit-null `data`/`agent`/`rule`**, failing the whole call.

### Auth
- **OAuth refresh burned a valid token on a `client_id` mismatch.** The token was consumed/revoked
  before the client check, so a wrong-id request permanently killed a legitimate grant. Now
  validated before consumption; the token is restored for a correct retry.

## Fixed in follow-up (verification & correctness)

- **Active-Response verification queries now use structured filters.** `check_blocked_ip`,
  `check_agent_isolation`, and `check_user_status` built free-text `"X AND Y"` queries that route
  through `simple_query_string` (where `AND` is a literal term with `default_operator=AND`) and so
  reliably matched nothing — the verification layer for the state-changing tools reported false
  negatives. Now they use `srcip`/`rule_groups`/`agent_id`/time-bounded filters. `check_agent_isolation`
  no longer equates "disconnected" with "isolated" (Wazuh host-isolation keeps the manager link).
- **`check_process`** queries the specific PID instead of paging the first 500 processes (a
  still-running target beyond the page was reported killed) and surfaces the inventory scan time.
- **`check_file_quarantine`** no longer false-positives on any path containing the substring
  "quarantine"; it keys off a FIM deletion of the exact path.
- **`get_sca_policy_checks` score** counts applicable checks only (was `passed/total`, so 50 passed
  + 50 N/A read as 50%).
- **`get_top_security_threats` ranking** no longer saturates — severity is weighted highest, so a
  chatty level-3 rule no longer outranks a targeted level-15 attack.
- **Tool descriptions** corrected where they overstated capability (`analyze_security_threat` is
  local-alert correlation not "AI-powered"; `check_ioc_reputation` is local sightings not an
  external feed; the "log collector stats" tool returns analysisd stats; `block` `duration` is
  advisory, governed by the manager `<timeout>`).
- **Redis session store no longer wiped on shutdown** — a single pod restart previously 404'd every
  other instance's live sessions; TTL handles expiry.

## Deferred (tracked, not addressed)

These need larger design changes or are lower-impact; grouped for follow-up.

- **MCP protocol semantics:** `/sse` does not emit the legacy `event: endpoint` frame a true
  2024-11-05 HTTP+SSE client expects; session handler state (capabilities/negotiated version) is
  not persisted after `initialize`; initialization is tracked but not enforced. Multi-worker
  deployments should prefer stateless modern `_meta` requests until session persistence lands.
- **Redis session store:** `get()` returns a copy vs a live dict (write-through divergence vs
  in-memory); `cleanup_expired` is a no-op. Redis mode is opt-in.
- **Active Response semantics:** `!host-isolation`/`!kill-process`/`!quarantine`/`!enable-account`
  are not stock Wazuh scripts — these tools require operator-deployed AR scripts (the zero-affected
  guard fails safe, and descriptions now note this).
- **Read-tool scoping:** `get_iso27001_dashboard`/`perform_risk_assessment` apply `agent_id` only to
  part of their data.
- **Deploy:** `wazuh-mcp-server` is not yet published to PyPI (README `pip install` 404s until the
  `PUBLISH_PYPI` gate is enabled); the documented `--scale` command conflicts with `container_name`;
  Dockerfile pre-`FROM` ARGs leave OCI version/created labels empty; the healthcheck hardcodes
  port 3000; CI tests only Python 3.13 despite a 3.11+ floor.
- **Dead code:** `config_validator.py` (413 lines) is never invoked; `resilience.py`'s module-level
  breakers are misconfigured but unused; several declared Prometheus metrics are never emitted.
