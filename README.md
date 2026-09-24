<div align="center">

# Wazuh MCP Server

**A Model Context Protocol (MCP) server for the Wazuh SIEM.**

Lets an MCP client — Claude, Open WebUI backed by a local model, or any client that speaks Streamable HTTP — query alerts, agents, vulnerabilities and compliance data, and dispatch active responses, with scope-based access control and audit logging.

[![CI](https://github.com/gensecaihq/Wazuh-MCP-Server/actions/workflows/ci.yml/badge.svg)](https://github.com/gensecaihq/Wazuh-MCP-Server/actions/workflows/ci.yml)
[![Security Audit](https://github.com/gensecaihq/Wazuh-MCP-Server/actions/workflows/security.yml/badge.svg)](https://github.com/gensecaihq/Wazuh-MCP-Server/actions/workflows/security.yml)
[![Release](https://img.shields.io/github/v/release/gensecaihq/Wazuh-MCP-Server?color=2ea44f&label=release)](https://github.com/gensecaihq/Wazuh-MCP-Server/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/downloads/)
[![MCP 2026-07-28](https://img.shields.io/badge/MCP-2026--07--28-6E56CF)](https://modelcontextprotocol.io/specification/2026-07-28)
[![Wazuh 4.8.0–4.14.7](https://img.shields.io/badge/Wazuh-4.8.0–4.14.7-005792?logo=wazuh&logoColor=white)](WAZUH_COMPATIBILITY.md)
[![GHCR image](https://img.shields.io/badge/ghcr.io-image-2496ED?logo=docker&logoColor=white)](https://github.com/gensecaihq/Wazuh-MCP-Server/pkgs/container/wazuh-mcp-server)

[Quick Start](#quick-start) · [Clients](#connecting-clients) · [Tools](#tools) · [Security](#security-model) · [Configuration](#configuration) · [Docs](#documentation) · [Changelog](CHANGELOG.md) · [Upgrading](UPGRADING.md)

</div>

---

## Overview

- **55 tools** in 8 toolsets: alerts, agents, vulnerabilities, threat analysis, compliance (PCI-DSS, HIPAA, SOX, GDPR, NIST, ISO 27001:2022), manager/cluster health, and active response with verification and rollback. Also 5 guided prompts, 6 resources and 3 resource templates.
- **Read-only by default.** The 14 state-changing tools require the `wazuh:write` scope, which is never granted implicitly.
- **MCP transport:** Streamable HTTP at `/mcp`. Serves protocol revision 2026-07-28 (stateless requests) and the `initialize` handshake for 2025-11-25, 2025-06-18, 2025-03-26 and 2024-11-05. The legacy HTTP+SSE endpoint `/sse` returns `410 Gone`.
- **Authentication:** bearer tokens minted from an API key, OAuth 2.0 (authorization code + PKCE) with API-key sign-in, or no auth for local development.
- **Deployment:** Docker Compose or a published multi-arch image; optional Redis for multi-instance sessions; optional multi-cluster routing.
- **Local models:** a vLLM + Open WebUI stack (`compose.local-llm.yml`) and toolset filtering for small models. The only tool that calls a service outside your Wazuh deployment is the optional `search_external_context` (You.com), which can be disabled on its own.

Supported Wazuh versions: 4.8.0 through 4.14.7. Alert, vulnerability and alert-backed compliance tools need the Wazuh Indexer. See [WAZUH_COMPATIBILITY.md](WAZUH_COMPATIBILITY.md).

---

## Quick Start

Requires Docker with Compose v2 and a Wazuh Manager API user.

```bash
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server
cp .env.example .env
```

Set the Wazuh connection in `.env`:

```env
WAZUH_HOST=your-wazuh-manager
WAZUH_USER=your-api-user
WAZUH_PASS=your-api-password

# Needed for alert, vulnerability and alert-backed compliance tools
WAZUH_INDEXER_HOST=your-wazuh-indexer
WAZUH_INDEXER_USER=your-indexer-user
WAZUH_INDEXER_PASS=your-indexer-password
```

Generate the signing secret and an API key. `compose.yml` runs the server with `ENVIRONMENT=production`, which refuses to start without `AUTH_SECRET_KEY`:

```bash
echo "AUTH_SECRET_KEY=$(openssl rand -hex 32)" >> .env
echo "MCP_API_KEY=wazuh_$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')" >> .env
```

Start the server and check it:

```bash
docker compose up -d
curl http://localhost:3000/health     # liveness
curl http://localhost:3000/ready      # checks Manager/Indexer reachability
```

Exchange the API key for a bearer token (valid for `TOKEN_LIFETIME_HOURS`, default 24):

```bash
curl -s -X POST http://localhost:3000/auth/token -H 'Content-Type: application/json' \
  -d "{\"api_key\": \"$(grep ^MCP_API_KEY= .env | cut -d= -f2)\"}"
```

The key is read-only. To allow active-response tools, add `MCP_API_KEY_SCOPES=wazuh:read wazuh:write` to `.env`, restart, and mint a new token.

Compose publishes the port on `127.0.0.1` only. The server speaks plain HTTP; put a TLS-terminating reverse proxy in front before exposing it (set `MCP_BIND` to change the host bind address).

`python3 deploy.py` (or `deploy.bat` on Windows) performs the same steps, generating `AUTH_SECRET_KEY` and `MCP_API_KEY` if they are missing.

### Pre-built image

Multi-arch images (amd64, arm64) are published to GitHub Container Registry and can be pulled without logging in:

```bash
docker pull ghcr.io/gensecaihq/wazuh-mcp-server:latest   # tracks main
docker pull ghcr.io/gensecaihq/wazuh-mcp-server:4.3.0    # latest tagged release
```

`latest` is built from `main` and includes the changes listed under *Unreleased* in the [changelog](CHANGELOG.md); `4.3.0` does not. Release tags are published without a `v` prefix (`4.3.0`, `4.3`); releases after 4.3.0 also get a `v`-prefixed alias.

```bash
docker run -d --name wazuh-mcp-server --env-file .env -e MCP_HOST=0.0.0.0 \
  -p 127.0.0.1:3000:3000 ghcr.io/gensecaihq/wazuh-mcp-server:latest
```

`MCP_HOST=0.0.0.0` is required inside a container because `.env.example` sets `MCP_HOST=127.0.0.1` for bare-metal installs.

---

## Connecting Clients

All clients use the Streamable HTTP endpoint `https://<your-host>/mcp`.

| Client | Auth mode | How it authenticates |
|--------|-----------|----------------------|
| Claude custom connectors (claude.ai, Claude Desktop) | `oauth` | OAuth authorization code with PKCE. The server pre-registers a public client, `claude-desktop`, for Claude's callback URLs. Users sign in on the server's `/oauth/authorize` page with a `wazuh_` API key (the grant is capped at that key's scopes), or at your OpenID Connect provider when `OAUTH_IDP_ISSUER` is set. |
| Open WebUI, LibreChat, scripts and other MCP clients | `bearer` (default) | `Authorization: Bearer <token>` using a token from `POST /auth/token`. |

In OAuth mode, set `OAUTH_ISSUER_URL` to the server's public HTTPS URL (otherwise it is derived from each request, which behind a proxy may not be the public URL). Dynamic Client Registration (`/oauth/register`) is off unless `OAUTH_ENABLE_DCR=true`.

Guides: [Claude Integration](docs/CLAUDE_INTEGRATION.md) · [Local LLMs](docs/LOCAL_LLM.md)

---

## Local LLMs

The server does not call a model; it only executes tools. To keep SIEM data on-premises, pair it with a local model:

```bash
cat >> .env <<EOF
VLLM_API_KEY=$(openssl rand -hex 32)
WEBUI_SECRET_KEY=$(openssl rand -hex 32)
EOF
docker compose -f compose.yml -f compose.local-llm.yml up -d
```

This adds vLLM (default model Qwen3.6-35B-A3B FP8, about 42 GB of VRAM on one NVIDIA GPU; not published on a host port) and Open WebUI on `127.0.0.1:8080`. In Open WebUI's admin settings, add an MCP (Streamable HTTP) tool server at `http://wazuh-main-server:3000/mcp` with a bearer token.

For smaller models, expose fewer tools with `WAZUH_TOOLSETS` / `WAZUH_DISABLED_TOOLS`, and check tool selection before rollout with `evals/tool_selection.py` (25 SOC scenarios, including two prompt-injection cases, against any OpenAI-compatible endpoint; no tools are executed). Model sizing, Ollama and LiteLLM are covered in the [Local LLM Guide](docs/LOCAL_LLM.md).

---

## Tools

55 tools, grouped into toolsets that can be enabled with `WAZUH_TOOLSETS` (comma-separated; default all). **R** = `wazuh:read`, **W** = `wazuh:write`.

| Toolset | Count | Tools |
|---------|-------|-------|
| `alerts` | 5 R | `get_wazuh_alerts`, `get_wazuh_alert_summary`, `get_alerts_aggregated`, `analyze_alert_patterns`, `search_security_events` |
| `agents` | 6 R | `get_wazuh_agents`, `get_wazuh_running_agents`, `check_agent_health`, `get_agent_processes`, `get_agent_ports`, `get_agent_configuration` |
| `vulnerabilities` | 3 R | `get_wazuh_vulnerabilities`, `get_wazuh_critical_vulnerabilities`, `get_wazuh_vulnerability_summary` |
| `analysis` | 5 R | `analyze_security_threat`, `check_ioc_reputation`, `perform_risk_assessment`, `get_top_security_threats`, `generate_security_report` |
| `web_search` | 1 R | `search_external_context` — You.com web search; returns a "not enabled" result unless `YDC_API_KEY` is set |
| `compliance` | 6 R | `run_compliance_check` (PCI-DSS, HIPAA, SOX, GDPR, NIST, ISO27001), `get_iso27001_dashboard`, `get_iso27001_control_detail`, `get_iso27001_gap_analysis`, `get_iso27001_alerts`, `get_sca_policy_checks` |
| `system` | 10 R | `get_wazuh_statistics`, `get_wazuh_weekly_stats`, `get_wazuh_cluster_health`, `get_wazuh_cluster_nodes`, `get_wazuh_rules_summary`, `get_wazuh_remoted_stats`, `get_wazuh_log_collector_stats`, `search_wazuh_manager_logs`, `get_wazuh_manager_error_logs`, `validate_wazuh_connection` |
| `response` — containment | 9 W | `wazuh_block_ip`, `wazuh_isolate_host`, `wazuh_kill_process`, `wazuh_disable_user`, `wazuh_quarantine_file`, `wazuh_firewall_drop`, `wazuh_host_deny`, `wazuh_active_response`, `wazuh_restart` |
| `response` — rollback | 5 W | `wazuh_unisolate_host`, `wazuh_enable_user`, `wazuh_restore_file`, `wazuh_firewall_allow`, `wazuh_host_allow` |
| `response` — verification | 5 R | `wazuh_check_blocked_ip`, `wazuh_check_agent_isolation`, `wazuh_check_process`, `wazuh_check_user_status`, `wazuh_check_file_quarantine` |

- Totals: 41 read tools, 14 write tools. Tokens without `wazuh:write` do not see the write tools in `tools/list`.
- In multi-cluster mode a 56th tool, `list_wazuh_clusters` (`system`, read), is added and every tool accepts an optional `cluster_id`.
- `WAZUH_DISABLED_TOOLS` hides individual tools. Hidden tools are removed from `tools/list` and refused by `tools/call`; unknown toolset or tool names stop the server at startup.
- Every tool carries MCP annotations derived from its scope: read tools are `readOnlyHint: true`; containment tools are `destructiveHint: true`; rollback tools are `destructiveHint: false`; only `search_external_context` is `openWorldHint: true`.
- Input schemas are closed (`additionalProperties: false`); undeclared arguments are refused.
- Timestamp filters accept ISO 8601 or OpenSearch date math (`now-24h`).
- Prompts: `security_investigation`, `threat_hunt`, `compliance_audit`, `vulnerability_assessment`, `iso27001_assessment`.

Per-tool parameters: [API documentation](docs/api/).

### Active response behaviour

- Results report `execution_status: "dispatched"`: Wazuh confirms the command was delivered to the agent, not that it ran. Confirm the effect with the matching `wazuh_check_*` tool.
- Blocks are permanent until removed. Wazuh ignores the timeout for API-triggered commands, so a positive `duration` is refused.
- `wazuh_firewall_allow` and `wazuh_host_allow` require an operator-deployed undo command (`WAZUH_AR_FIREWALL_UNDO_COMMAND`, `WAZUH_AR_HOSTDENY_UNDO_COMMAND`); without one they refuse.

---

## Security Model

| Control | Behaviour |
|---------|-----------|
| **Scopes (RBAC)** | Each tool requires `wazuh:read` or `wazuh:write`. A token without a scope claim is read-only. `MCP_API_KEY` is read-only unless `MCP_API_KEY_SCOPES` includes `wazuh:write`. With `AUTH_MODE=none`, write tools are disabled unless `AUTHLESS_ALLOW_WRITE=true`. |
| **Bearer tokens** | JWTs signed with `AUTH_SECRET_KEY`, must carry `exp`, and are bound to the API key they were minted from: revoking or rotating the key invalidates its tokens. Refresh tokens are not accepted as access tokens. |
| **OAuth** | Authorization code flow with mandatory S256 PKCE, single-use codes, refresh-token rotation with replay detection, and revocation. Users sign in with a `wazuh_` API key, so scopes, rate limits and audit entries are per user. |
| **Action guardrails** | IP-blocking tools refuse loopback, the Manager's address (when `WAZUH_HOST` is an IP) and anything in `WAZUH_PROTECTED_IPS`; the generic active-response tool does not dispatch IP blocks. Actions and restarts aimed at agent `000` (the Manager) need `WAZUH_ALLOW_MANAGER_AR=true`; fleet-wide blocks need `WAZUH_ALLOW_FLEET_AR=true`; quarantine refuses system and agent directories. In production, write tools require `confirm=true` (`WAZUH_REQUIRE_ACTION_CONFIRMATION`). |
| **Audit log** | Every write-tool call is logged before and after execution (logger `wazuh_mcp_server.audit`) with the principal, session, arguments and outcome. |
| **Redaction** | Credentials and tokens are redacted from tool output in every response format, and from server logs. |
| **Input validation** | Typed validation of agent IDs, IPs, paths and command names; Indexer queries are built as Query DSL, not by string interpolation. |
| **Rate limiting** | Sliding window per authenticated principal (default 100 requests per 60 s; `RATE_LIMIT_REQUESTS`, `RATE_LIMIT_WINDOW`). Failed authentication is rate limited by client IP. Set `TRUSTED_PROXIES` when running behind a proxy. |
| **Resilience** | Circuit breaker on Wazuh calls: opens after 5 consecutive failures, retries after 60 s. Oversized tool results are truncated with a note (`MAX_TOOL_RESPONSE_CHARS`). |
| **Container** | Runs as UID 1000; `compose.yml` sets a read-only root filesystem, `cap_drop: ALL` and `no-new-privileges`. The runtime image does not include pip. |

There is no built-in TLS listener; terminate TLS at a reverse proxy or load balancer. Report vulnerabilities as described in [SECURITY.md](SECURITY.md).

---

## Configuration

All settings are environment variables (usually via `.env`). The ones most deployments touch:

| Variable | Default | Purpose |
|----------|---------|---------|
| `WAZUH_HOST`, `WAZUH_USER`, `WAZUH_PASS` | — | Manager API connection (required) |
| `WAZUH_PORT` | `55000` | Manager API port |
| `WAZUH_CA_BUNDLE` | — | CA PEM for verifying the Manager/Indexer. The stock Manager certificate needs reissuing or `WAZUH_ALLOW_SELF_SIGNED=true`; see [Manager TLS](docs/configuration.md#manager-tls) |
| `WAZUH_INDEXER_HOST`, `WAZUH_INDEXER_USER`, `WAZUH_INDEXER_PASS` | — | Indexer connection; an `http://` host prefix selects plain HTTP |
| `WAZUH_INDEXER_PORT` | `9200` | Indexer port |
| `ENVIRONMENT` | `development` | `production` requires a strong `AUTH_SECRET_KEY` (unless `AUTH_MODE=none`) |
| `AUTH_MODE` | `bearer` | `bearer`, `oauth` or `none` |
| `AUTH_SECRET_KEY` | generated per process outside production | Token signing key; use the same value on every instance |
| `MCP_API_KEY` / `API_KEYS` | generated per process if unset (printed only in development) | A single `wazuh_` key, or a JSON list of hashed keys with per-key scopes |
| `MCP_API_KEY_SCOPES` | `wazuh:read` | Space-separated scopes for `MCP_API_KEY` |
| `MCP_HOST`, `MCP_PORT` | `0.0.0.0`, `3000` | Bind address and port |
| `ALLOWED_ORIGINS` | `https://claude.ai,http://localhost:3000` | CORS allow-list (exact match) |
| `WAZUH_TOOLSETS`, `WAZUH_DISABLED_TOOLS` | all enabled | Limit the exposed tools |
| `REDIS_URL` | — | Shared session store for multi-instance deployments |
| `WAZUH_CLUSTERS_FILE` | `./config/clusters.json` | Multi-cluster topology; single-cluster mode when absent |
| `RESPONSE_FORMAT` | `json` | `gcf` encodes alert, event and vulnerability collections in the compact GCF format (lossless; falls back to JSON if the encoder is unavailable) |
| `YDC_API_KEY` | — | Enables `search_external_context` |

Complete reference, including OAuth TTLs, rate limits, sessions and active-response settings: [Configuration Guide](docs/configuration.md). Multi-cluster setup: [Multi-Cluster Guide](docs/MULTI_CLUSTER.md) and [`config/clusters.json.example`](config/clusters.json.example).

### Running from source

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[redis,gcf]"      # extras are optional
python -m wazuh_mcp_server
```

Requires Python 3.11 or later.

---

## HTTP Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/mcp` | POST, GET, DELETE | MCP Streamable HTTP |
| `/` | POST, GET | Same handler as `/mcp` |
| `/sse` | GET, POST | Returns `410 Gone`; use `/mcp` |
| `/health` | GET | Liveness; no dependency checks |
| `/ready` | GET | Readiness; 503 when the Manager, Indexer or memory headroom check fails |
| `/metrics` | GET | Prometheus metrics |
| `/auth/token` | POST | Exchange an API key for a bearer JWT |
| `/.well-known/oauth-authorization-server` | GET | OAuth metadata (RFC 8414), `AUTH_MODE=oauth` only |
| `/.well-known/oauth-protected-resource` | GET | Protected-resource metadata (RFC 9728), `AUTH_MODE=oauth` only |
| `/oauth/authorize`, `/oauth/token`, `/oauth/revoke`, `/oauth/register` | GET/POST | OAuth endpoints, `AUTH_MODE=oauth` only (`/oauth/register` requires `OAUTH_ENABLE_DCR=true`) |
| `/docs`, `/redoc`, `/openapi.json` | GET | OpenAPI documentation |

---

## Project Layout

```
src/wazuh_mcp_server/
├── server.py          # FastAPI app, MCP protocol handling, tool definitions and dispatch
├── toolsets.py        # Toolset membership, WAZUH_TOOLSETS resolution, tool annotations
├── auth.py            # API keys and bearer JWTs
├── oauth.py           # OAuth 2.0 authorization server (PKCE, API-key sign-in)
├── config.py          # Environment configuration and startup validation
├── security.py        # Rate limiting, CORS, input validation, log redaction
├── clusters.py        # Multi-cluster registry and Cross-Cluster Search routing
├── session_store.py   # In-memory and Redis session storage
├── resilience.py      # Circuit breakers, retries, graceful shutdown
├── monitoring.py      # Prometheus metrics, structured logging
├── gcf_format.py      # Optional GCF response encoding
└── api/
    ├── wazuh_client.py    # Wazuh Manager REST API client
    └── wazuh_indexer.py   # Wazuh Indexer (OpenSearch) client
```

---

## Documentation

| Document | Contents |
|----------|----------|
| [Configuration Guide](docs/configuration.md) | Every environment variable, auth modes, RBAC |
| [Claude Integration](docs/CLAUDE_INTEGRATION.md) | Connecting Claude custom connectors |
| [Local LLM Guide](docs/LOCAL_LLM.md) | vLLM, Open WebUI, Ollama, LiteLLM, tool-selection eval |
| [Multi-Cluster](docs/MULTI_CLUSTER.md) | Named clusters and Cross-Cluster Search |
| [Operations](docs/OPERATIONS.md) | Deployment, monitoring, maintenance |
| [Advanced Features](docs/ADVANCED_FEATURES.md) | Multi-instance deployment, compact output |
| [Troubleshooting](docs/TROUBLESHOOTING.md) | Common problems and fixes |
| [API Reference](docs/api/) | Per-tool parameters |
| [Security Hardening](docs/security/) | Hardening guidance |
| [MCP Compliance](MCP_COMPLIANCE_VERIFICATION.md) | Protocol conformance notes |
| [Wazuh Compatibility](WAZUH_COMPATIBILITY.md) | Supported Wazuh versions |
| [Upgrading](UPGRADING.md) · [Changelog](CHANGELOG.md) · [Security Policy](SECURITY.md) | Release notes and policies |

Related project: [Wazuh Autopilot](https://github.com/gensecaihq/Wazuh-Autopilot) builds automated SOC workflows on top of this server.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Bugs and feature requests go to [Issues](https://github.com/gensecaihq/Wazuh-MCP-Server/issues), questions to [Discussions](https://github.com/gensecaihq/Wazuh-MCP-Server/discussions), and security reports to a private [security advisory](https://github.com/gensecaihq/Wazuh-MCP-Server/security/advisories/new).

---

## License

[MIT](LICENSE)

---

## Acknowledgments

Thanks to everyone who has contributed code, reviews, bug reports and design feedback. See also [ACKNOWLEDGMENTS.md](ACKNOWLEDGMENTS.md).

**Code and pull requests**

- [@alokemajumder](https://github.com/alokemajumder) — maintainer; architecture, MCP transport, security hardening, releases
- [@gensecai-dev](https://github.com/gensecai-dev) — the 19 action, verification and rollback tools, broken-endpoint fixes, production hardening
- [@andrzej-piotrowski-pl](https://github.com/andrzej-piotrowski-pl) — ISO 27001:2022 compliance tools: Annex A control mapping, domain scoring, gap analysis (#74)
- [@blackwell-systems](https://github.com/blackwell-systems) — opt-in GCF response encoding for record tools (#102, #104)
- [@lucascruzb](https://github.com/lucascruzb) — period-wide alert aggregation via scroll, the basis of `get_alerts_aggregated` (#79)
- [@kanylbullen](https://github.com/kanylbullen) — compact output mode for token-efficient responses (#65)
- [@mouse-value-add](https://github.com/mouse-value-add) — optional You.com web-search context (#85)
- [@DrRSatzteil](https://github.com/DrRSatzteil) — `tools/list` pagination fix (#70)
- [@SiM22](https://github.com/SiM22) — MCP 2025-06-18 support for Windsurf compatibility (#66)
- [@aiunmukto](https://github.com/aiunmukto) — `.env.example`, CI workflow and Glama registry listing (#12)
- [@Karibusan](https://github.com/Karibusan) — dependency fixes (#38)
- [@lwsinclair](https://github.com/lwsinclair) — MseeP.ai listing (#9)
- [@markeclaudio](https://github.com/markeclaudio) — OIDC sign-in and Manager TLS verification by default (#123, #127); active-response guard-rails and session bounds (#124–#126, in review)
- [@MilkyWay88](https://github.com/MilkyWay88) and [@taylorwalton](https://github.com/taylorwalton) — early pull requests on configuration, logging and packaging

**Bug reports and discussions**

[@cbassonbgroup](https://github.com/cbassonbgroup), [@cybersentinel-06](https://github.com/cybersentinel-06), [@daod-arshad](https://github.com/daod-arshad), [@mamema](https://github.com/mamema), [@marcolinux46](https://github.com/marcolinux46), [@matveevandrey](https://github.com/matveevandrey), [@punkpeye](https://github.com/punkpeye), [@tonyliu9189](https://github.com/tonyliu9189), [@Uberkarhu](https://github.com/Uberkarhu), [@bl4ck5w4n07](https://github.com/bl4ck5w4n07), [@gnix45](https://github.com/gnix45), [@hackdefendr](https://github.com/hackdefendr), [@melmasry1987](https://github.com/melmasry1987), [@Vasanth120v](https://github.com/Vasanth120v), [@wqfh](https://github.com/wqfh)

**Built on and works with**

- [Wazuh](https://wazuh.com/) — open source security platform
- [Model Context Protocol](https://modelcontextprotocol.io/) — the protocol this server implements
- [vLLM](https://github.com/vllm-project/vllm), [Ollama](https://ollama.com/) and [Open WebUI](https://github.com/open-webui/open-webui) — local model serving and chat, used in the local LLM stack

---

<details>
<summary><strong>Contributors</strong></summary>

<!-- CONTRIBUTORS-START -->
### Contributors

| Avatar | Username | Contributions |
|--------|----------|---------------|
| <img src="https://github.com/alokemajumder.png" width="40" height="40" style="border-radius: 50%"/> | [@alokemajumder](https://github.com/alokemajumder) | 💻 Code, 🐛 Issues, 🔀 PRs, 💬 Discussions |
| <img src="https://github.com/Karibusan.png" width="40" height="40" style="border-radius: 50%"/> | [@Karibusan](https://github.com/Karibusan) | 💻 Code, 🐛 Issues, 🔀 PRs |
| <img src="https://github.com/gensecai-dev.png" width="40" height="40" style="border-radius: 50%"/> | [@gensecai-dev](https://github.com/gensecai-dev) | 💻 Code, 🔀 PRs, 💬 Discussions |
| <img src="https://github.com/aiunmukto.png" width="40" height="40" style="border-radius: 50%"/> | [@aiunmukto](https://github.com/aiunmukto) | 💻 Code, 🔀 PRs |
| <img src="https://github.com/andrzej-piotrowski-pl.png" width="40" height="40" style="border-radius: 50%"/> | [@andrzej-piotrowski-pl](https://github.com/andrzej-piotrowski-pl) | 💻 Code, 🔀 PRs |
| <img src="https://github.com/blackwell-systems.png" width="40" height="40" style="border-radius: 50%"/> | [@blackwell-systems](https://github.com/blackwell-systems) | 💻 Code, 🔀 PRs |
| <img src="https://github.com/kanylbullen.png" width="40" height="40" style="border-radius: 50%"/> | [@kanylbullen](https://github.com/kanylbullen) | 💻 Code, 🔀 PRs |
| <img src="https://github.com/lucascruzb.png" width="40" height="40" style="border-radius: 50%"/> | [@lucascruzb](https://github.com/lucascruzb) | 💻 Code, 🔀 PRs |
| <img src="https://github.com/lwsinclair.png" width="40" height="40" style="border-radius: 50%"/> | [@lwsinclair](https://github.com/lwsinclair) | 💻 Code, 🔀 PRs |
| <img src="https://github.com/mouse-value-add.png" width="40" height="40" style="border-radius: 50%"/> | [@mouse-value-add](https://github.com/mouse-value-add) | 💻 Code, 🔀 PRs |
| <img src="https://github.com/SiM22.png" width="40" height="40" style="border-radius: 50%"/> | [@SiM22](https://github.com/SiM22) | 💻 Code, 🔀 PRs |
| <img src="https://github.com/DrRSatzteil.png" width="40" height="40" style="border-radius: 50%"/> | [@DrRSatzteil](https://github.com/DrRSatzteil) | 🔀 PRs |
| <img src="https://github.com/MilkyWay88.png" width="40" height="40" style="border-radius: 50%"/> | [@MilkyWay88](https://github.com/MilkyWay88) | 🔀 PRs |
| <img src="https://github.com/taylorwalton.png" width="40" height="40" style="border-radius: 50%"/> | [@taylorwalton](https://github.com/taylorwalton) | 🔀 PRs |
| <img src="https://github.com/cbassonbgroup.png" width="40" height="40" style="border-radius: 50%"/> | [@cbassonbgroup](https://github.com/cbassonbgroup) | 🐛 Issues |
| <img src="https://github.com/cybersentinel-06.png" width="40" height="40" style="border-radius: 50%"/> | [@cybersentinel-06](https://github.com/cybersentinel-06) | 🐛 Issues |
| <img src="https://github.com/daod-arshad.png" width="40" height="40" style="border-radius: 50%"/> | [@daod-arshad](https://github.com/daod-arshad) | 🐛 Issues |
| <img src="https://github.com/mamema.png" width="40" height="40" style="border-radius: 50%"/> | [@mamema](https://github.com/mamema) | 🐛 Issues |
| <img src="https://github.com/marcolinux46.png" width="40" height="40" style="border-radius: 50%"/> | [@marcolinux46](https://github.com/marcolinux46) | 🐛 Issues |
| <img src="https://github.com/matveevandrey.png" width="40" height="40" style="border-radius: 50%"/> | [@matveevandrey](https://github.com/matveevandrey) | 🐛 Issues |
| <img src="https://github.com/punkpeye.png" width="40" height="40" style="border-radius: 50%"/> | [@punkpeye](https://github.com/punkpeye) | 🐛 Issues |
| <img src="https://github.com/tonyliu9189.png" width="40" height="40" style="border-radius: 50%"/> | [@tonyliu9189](https://github.com/tonyliu9189) | 🐛 Issues |
| <img src="https://github.com/Uberkarhu.png" width="40" height="40" style="border-radius: 50%"/> | [@Uberkarhu](https://github.com/Uberkarhu) | 🐛 Issues |
| <img src="https://github.com/bl4ck5w4n07.png" width="40" height="40" style="border-radius: 50%"/> | [@bl4ck5w4n07](https://github.com/bl4ck5w4n07) | 💬 Discussions |
| <img src="https://github.com/gnix45.png" width="40" height="40" style="border-radius: 50%"/> | [@gnix45](https://github.com/gnix45) | 💬 Discussions |
| <img src="https://github.com/hackdefendr.png" width="40" height="40" style="border-radius: 50%"/> | [@hackdefendr](https://github.com/hackdefendr) | 💬 Discussions |
| <img src="https://github.com/melmasry1987.png" width="40" height="40" style="border-radius: 50%"/> | [@melmasry1987](https://github.com/melmasry1987) | 💬 Discussions |
| <img src="https://github.com/Vasanth120v.png" width="40" height="40" style="border-radius: 50%"/> | [@Vasanth120v](https://github.com/Vasanth120v) | 💬 Discussions |
| <img src="https://github.com/wqfh.png" width="40" height="40" style="border-radius: 50%"/> | [@wqfh](https://github.com/wqfh) | 💬 Discussions |

**Legend:** 💻 Code · 🐛 Issues · 🔀 Pull Requests · 💬 Discussions
<!-- CONTRIBUTORS-END -->

> Auto-updated by [GitHub Actions](.github/workflows/update-contributors.yml)

</details>
