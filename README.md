<div align="center">

# 🛡️ Wazuh MCP Server

### Talk to your SIEM in plain language.

**Query alerts, hunt threats, triage vulnerabilities, and run active responses across your entire Wazuh deployment — through natural conversation with any AI assistant.**

[![CI](https://github.com/gensecaihq/Wazuh-MCP-Server/actions/workflows/ci.yml/badge.svg)](https://github.com/gensecaihq/Wazuh-MCP-Server/actions/workflows/ci.yml)
[![Security Audit](https://github.com/gensecaihq/Wazuh-MCP-Server/actions/workflows/security.yml/badge.svg)](https://github.com/gensecaihq/Wazuh-MCP-Server/actions/workflows/security.yml)
[![Release](https://img.shields.io/github/v/release/gensecaihq/Wazuh-MCP-Server?color=2ea44f&label=release)](https://github.com/gensecaihq/Wazuh-MCP-Server/releases/latest)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

[![Python 3.11+](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/downloads/)
[![MCP 2026-07-28](https://img.shields.io/badge/MCP-2026--07--28-6E56CF)](https://modelcontextprotocol.io/specification/2026-07-28)
[![Wazuh 4.8.0–4.14.7](https://img.shields.io/badge/Wazuh-4.8.0–4.14.7-005792?logo=wazuh&logoColor=white)](WAZUH_COMPATIBILITY.md)
[![GHCR image](https://img.shields.io/badge/ghcr.io-image-2496ED?logo=docker&logoColor=white)](https://github.com/gensecaihq/Wazuh-MCP-Server/pkgs/container/wazuh-mcp-server)
[![Stars](https://img.shields.io/github/stars/gensecaihq/Wazuh-MCP-Server?style=flat&color=f5a623)](https://github.com/gensecaihq/Wazuh-MCP-Server/stargazers)

**55 security tools** · **dual-era MCP** (2026-07-28 + legacy) · **multi-cluster** · **fully air-gappable** · **production-hardened**

[**Quick Start**](#quick-start) · [**Tools**](#55-security-tools) · [**Security**](#security) · [**Docs**](docs/) · [**Changelog**](CHANGELOG.md) · [**Upgrading**](UPGRADING.md)

</div>

---

## What This Does

Your Wazuh SIEM generates thousands of alerts, vulnerability findings, and agent events daily. Investigating them means juggling dashboards, writing API queries, and manually correlating data across tools.

This MCP server turns that workflow into a conversation:

```
You:    "Show me critical alerts from the last hour"
AI:     [calls get_wazuh_alerts] Found 3 critical alerts:
        1. SSH brute force from 10.0.1.45 → agent-003 (Rule 5712, Level 10)
        2. Rootkit detection on agent-007 (Rule 510, Level 12)
        3. FIM change /etc/shadow on agent-001 (Rule 550, Level 10)

You:    "Block that source IP on agent-003"
AI:     [calls wazuh_block_ip] Blocked 10.0.1.45 via firewall-drop on agent-003.

You:    "Which agents have unpatched critical CVEs?"
AI:     [calls get_wazuh_critical_vulnerabilities] 3 agents with critical vulnerabilities...
```

It works with **Claude Desktop**, **Open WebUI + Ollama** (fully local, air-gapped), **mcphost**, or any MCP-compliant client.

---

## Works With Cloud AND Local LLMs

This is a standard MCP tool server. It doesn't care what LLM you use — it just executes tools and returns results.

| Mode | LLM | Client | Data leaves your network? |
|------|-----|--------|--------------------------|
| **Cloud** | Claude, GPT, etc. | Claude Desktop, any MCP client | Yes (to LLM provider) |
| **Local** | Llama, Qwen, Mistral via Ollama | Open WebUI, mcphost, IBM/mcp-cli | **No. Fully air-gappable.** |

**For security teams that can't send SIEM data to cloud APIs** (compliance, air-gapped networks, data sovereignty), the local mode with Ollama keeps everything on-premises. Both modes coexist — same server, same tools, same API.

### Quick Start: Local LLM with mcphost

```bash
# 1. Start the MCP server
docker compose up -d

# 2. Install mcphost (Go binary, no dependencies)
go install github.com/mark3labs/mcphost@latest

# 3. Configure
cat > ~/.mcphost.yml << 'EOF'
mcpServers:
  wazuh:
    type: remote
    url: http://localhost:3000/mcp
    headers: ["Authorization: Bearer ${env://MCP_API_KEY}"]
EOF

# 4. Chat with your SIEM using a local model
export MCP_API_KEY="your-key-from-server-logs"
mcphost --model ollama/qwen2.5:7b
```

### Quick Start: Multi-User SOC with Open WebUI

Open WebUI v0.6.31+ connects to our `/mcp` endpoint natively. Add it as an MCP tool server in Admin Settings, and your entire team gets AI-powered SIEM analysis with conversation history, RBAC, and a web UI.

---

## 55 Security Tools

Every tool is validated, rate-limited, scope-checked, and audit-logged.

| Category | Tools | What They Do |
|----------|-------|-------------|
| **Alerts** (5) | `get_wazuh_alerts` `get_wazuh_alert_summary` `get_alerts_aggregated` `analyze_alert_patterns` `search_security_events` | Query, filter, search, and aggregate alert data via the Indexer. Timestamps accept ISO 8601 or relative date math (`now-24h`); `get_alerts_aggregated` summarizes a whole period with no document limit |
| **Agents** (6) | `get_wazuh_agents` `get_wazuh_running_agents` `check_agent_health` `get_agent_processes` `get_agent_ports` `get_agent_configuration` | Monitor agent status, running processes, open ports, and configs |
| **Vulnerabilities** (3) | `get_wazuh_vulnerabilities` `get_wazuh_critical_vulnerabilities` `get_wazuh_vulnerability_summary` | Query CVEs by severity, agent, and package |
| **Security Analysis** (6) | `analyze_security_threat` `check_ioc_reputation` `search_external_context` `perform_risk_assessment` `get_top_security_threats` `generate_security_report` | Threat analysis, IOC lookup, optional web context, risk scoring, security reports |
| **Compliance** (6) | `run_compliance_check` `get_iso27001_dashboard` `get_iso27001_control_detail` `get_iso27001_gap_analysis` `get_iso27001_alerts` `get_sca_policy_checks` | Compliance scoring for PCI-DSS, HIPAA, SOX, GDPR, NIST, and ISO 27001:2022 (Annex A control mapping, gap analysis, SCA detail) |
| **System** (10) | `get_wazuh_statistics` `get_wazuh_cluster_health` `get_wazuh_cluster_nodes` `get_wazuh_rules_summary` `search_wazuh_manager_logs` `get_wazuh_manager_error_logs` `get_wazuh_log_collector_stats` `get_wazuh_remoted_stats` `get_wazuh_weekly_stats` `validate_wazuh_connection` | Cluster health, rules, manager logs, stats, connectivity |
| **Active Response** (9) | `wazuh_block_ip` `wazuh_isolate_host` `wazuh_kill_process` `wazuh_disable_user` `wazuh_quarantine_file` `wazuh_firewall_drop` `wazuh_host_deny` `wazuh_active_response` `wazuh_restart` | Block IPs, isolate hosts, kill processes, quarantine files |
| **Verification** (5) | `wazuh_check_blocked_ip` `wazuh_check_agent_isolation` `wazuh_check_process` `wazuh_check_user_status` `wazuh_check_file_quarantine` | Verify active response actions took effect |
| **Rollback** (5) | `wazuh_unisolate_host` `wazuh_enable_user` `wazuh_restore_file` `wazuh_firewall_allow` `wazuh_host_allow` | Undo active response actions |

The 14 state-changing tools (Active Response + Rollback) require the `wazuh:write` scope; everything else needs only `wazuh:read`. ISO 27001 also adds an `iso27001_assessment` guided prompt (5 prompts total).

---

## Quick Start

### Prerequisites

- Docker 20.10+ with Compose v2
- Wazuh 4.8.0–4.14.7 with API access enabled

### Deploy

```bash
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server
cp .env.example .env
```

Edit `.env`:
```env
WAZUH_HOST=your-wazuh-server
WAZUH_USER=your-api-user
WAZUH_PASS=your-api-password
```

```bash
docker compose up -d
curl http://localhost:3000/health
```

### Pre-built image

A multi-arch image (amd64/arm64) is published to GitHub Container Registry on every release and on every push to `main`:

```bash
docker pull ghcr.io/gensecaihq/wazuh-mcp-server:latest   # main branch
docker pull ghcr.io/gensecaihq/wazuh-mcp-server:4.3.0    # pinned release
```

```bash
docker run -d --name wazuh-mcp-server --env-file .env -p 3000:3000 \
  ghcr.io/gensecaihq/wazuh-mcp-server:latest
```

### Connect Claude Desktop

1. **Settings** → **Connectors** → **Add custom connector**
2. URL: `https://your-server/mcp`
3. Add Bearer token in Advanced settings

> Detailed setup: [Claude Integration Guide](docs/CLAUDE_INTEGRATION.md)

---

## Security

This server sits between an LLM and your SIEM. Security is not optional.

| Layer | What It Does |
|-------|-------------|
| **RBAC** | Per-tool scope enforcement, **fail-closed**: a token with no scope claim gets read-only, never write. The 14 state-changing tools (active response + rollback) require `wazuh:write`, which is **opt-in** (`MCP_API_KEY_SCOPES="wazuh:read wazuh:write"`). Authless mode is read-only unless `AUTHLESS_ALLOW_WRITE=true`. |
| **Audit Logging** | Every destructive tool call (block IP, isolate host, kill process) is logged with client ID, session, timestamp, and full arguments. |
| **Output Sanitization** | Credentials, tokens, and API keys in alert `full_log` fields are redacted before reaching the LLM. Prevents credential leakage through AI responses. |
| **Input Validation** | Every parameter validated: regex agent IDs, `ipaddress` module for IPs, shell metacharacter blocking for active response, Elasticsearch Query DSL (no string interpolation). |
| **Rate Limiting** | Per-principal sliding window (keyed on the authenticated client + trusted-proxy IP), with a short retry-after backoff — seconds until the oldest request leaves the window, not a fixed multi-minute block. |
| **Circuit Breakers** | Wazuh API failures trigger fail-fast for 60s, auto-recover. Single trial in HALF_OPEN state. |
| **Log Sanitization** | Global filter redacts passwords, tokens, secrets from all server logs. |
| **Container Hardening** | Non-root user, read-only filesystem, `CAP_DROP ALL`, `no-new-privileges`. |

```bash
# Generate a secure API key
python -c "import secrets; print('wazuh_' + secrets.token_urlsafe(32))"
```

---

## Configuration

### Required

| Variable | Description |
|----------|-------------|
| `WAZUH_HOST` | Wazuh Manager hostname or IP |
| `WAZUH_USER` | API username |
| `WAZUH_PASS` | API password |

### Optional

| Variable | Default | Description |
|----------|---------|-------------|
| `ENVIRONMENT` | `development` | `production` enforces stricter checks (see below) |
| `WAZUH_PORT` | `55000` | Manager API port |
| `WAZUH_VERIFY_SSL` | `true` | Verify the Manager's TLS certificate |
| `MCP_HOST` | `0.0.0.0` | Server bind address |
| `MCP_PORT` | `3000` | Server port |
| `AUTH_MODE` | `bearer` | `oauth`, `bearer`, or `none` |
| `AUTH_SECRET_KEY` | auto (dev only) | JWT signing key. **Required when `ENVIRONMENT=production`** (the server refuses to start without it) — set the same value on every instance |
| `MCP_API_KEY` | auto (dev only) | Pre-set API key (`wazuh_…`) |
| `MCP_API_KEY_SCOPES` | `wazuh:read` | Scopes for `MCP_API_KEY`. Add `wazuh:write` to enable active-response tools |
| `AUTHLESS_ALLOW_WRITE` | `false` | Allow active response in authless mode |
| `ALLOWED_ORIGINS` | `https://claude.ai,...` | CORS origins (comma-separated) |
| `TRUSTED_PROXIES` | — | Proxy IPs to trust for `X-Forwarded-For` (correct per-client rate limiting behind a proxy) |
| `REDIS_URL` | — | Redis URL for multi-instance session storage |
| `RESPONSE_FORMAT` | `json` | Wire format for alert/event/vulnerability results: `json` or `gcf` (see below) |

### Response encoding (GCF)

Alert, security-event, and vulnerability tools return uniform record collections
under a `data.affected_items` array. Setting `RESPONSE_FORMAT=gcf` encodes those
responses as a [Graph Compact Format](https://gcformat.com) generic wire instead
of JSON, factoring the repeated field names into a single header so the response
uses fewer tokens when it crosses the LLM boundary.

It is opt-in, lossless, and every response stays complete (a format change only,
no cross-turn deduplication, so no alert is ever omitted). If encoding fails —
or the encoder isn't installed — the tool falls back to JSON. It composes with
the existing `compact` field-projection parameter.

The encoder is one zero-dependency package (pinned exact). Install it directly, or via the
`gcf` extra from a source checkout:

```bash
pip install gcf-python==2.5.1        # direct
pip install ".[gcf]"                 # or, from a clone of this repo
```

> **Production note:** the server listens over plain HTTP — terminate TLS at a reverse proxy or load balancer. OAuth knobs (`OAUTH_ENABLE_DCR` — off by default, `OAUTH_*_TTL`) and rate-limit tuning (`RATE_LIMIT_REQUESTS`, `RATE_LIMIT_WINDOW`) are in the [Configuration Guide](docs/configuration.md).

### Wazuh Indexer (for alert search + vulnerabilities)

| Variable | Default | Description |
|----------|---------|-------------|
| `WAZUH_INDEXER_HOST` | — | Indexer hostname (an `http://` prefix selects plain HTTP) |
| `WAZUH_INDEXER_PORT` | `9200` | Indexer port |
| `WAZUH_INDEXER_USER` | — | Indexer username |
| `WAZUH_INDEXER_PASS` | — | Indexer password |
| `WAZUH_INDEXER_SSL` | `true` | Use HTTPS for the Indexer (set `false` for a plain-HTTP OpenSearch node) |
| `WAZUH_INDEXER_VERIFY_SSL` | `true` | Verify the Indexer's TLS certificate |
| `YDC_API_KEY` | — | Optional You.com API key. Enables the `search_external_context` tool |
| `YDC_BASE_URL` | `https://ydc-index.io` | Optional You.com Search API base URL |
| `YDC_VERIFY_SSL` | `true` | Verify You.com TLS certificates independently of Wazuh |
| `WAZUH_CLUSTERS_FILE` | `./config/clusters.json` | Optional multi-cluster topology file (see below) |
| `WAZUH_AR_FIREWALL_UNDO_COMMAND` | — | Custom active-response command that removes a firewall-drop block. Required for `wazuh_firewall_allow` — stock Wazuh can't unblock via the API |
| `WAZUH_AR_HOSTDENY_UNDO_COMMAND` | — | Custom active-response command that removes a hosts.deny block. Required for `wazuh_host_allow` |

> Full reference: [Configuration Guide](docs/configuration.md)

### Multi-Cluster (optional)

Managing several Wazuh deployments? Drop a `clusters.json` next to your config (see
[`config/clusters.json.example`](config/clusters.json.example)) and every tool gains an
optional `cluster_id` argument plus a `list_wazuh_clusters` tool:

- **No `clusters.json`** → single-cluster behavior from env vars, exactly as before.
- **With `clusters.json`** → named clusters, each with its own Manager (and optionally
  Indexer) credentials; `"${ENV_VAR}"` values are resolved from the environment so secrets
  stay out of the file. The env-configured cluster remains reachable as `default`.
- **Cross-Cluster Search** → point clusters at a shared OpenSearch CCS coordinator and set
  `ccs_prefix` (the remote-cluster name); alert/vulnerability queries become
  `eu:wazuh-alerts-*`. An entry with `"ccs_prefix": "*"` gives you an `all` pseudo-cluster
  that searches every remote cluster at once.

---

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/mcp` | POST/GET/DELETE | MCP Streamable HTTP (recommended) |
| `/sse` | GET | Legacy Server-Sent Events |
| `/health` | GET | Liveness probe — 200 while the process is up (no dependency checks; use for the container healthcheck) |
| `/ready` | GET | Readiness probe — checks Wazuh Manager/Indexer reachability; 503 when a dependency is down |
| `/metrics` | GET | Prometheus metrics |
| `/auth/token` | POST | Exchange API key for JWT (bearer mode) |
| `/.well-known/oauth-authorization-server` | GET | OAuth 2.0 discovery (oauth mode) |
| `/.well-known/oauth-protected-resource` | GET | OAuth protected-resource metadata, RFC 9728 (oauth mode) |
| `/docs` | GET | OpenAPI documentation |

---

## Architecture

```
src/wazuh_mcp_server/
├── server.py           # MCP protocol + 55 tool handlers
├── config.py           # Environment-based configuration
├── auth.py             # JWT + API key authentication
├── oauth.py            # OAuth 2.0 with Dynamic Client Registration
├── security.py         # Rate limiting, CORS, input validation
├── monitoring.py       # Prometheus metrics, structured logging
├── resilience.py       # Circuit breakers, retries, graceful shutdown
├── session_store.py    # Pluggable sessions (in-memory + Redis)
└── api/
    ├── wazuh_client.py    # Wazuh Manager REST API client
    └── wazuh_indexer.py   # Wazuh Indexer (Elasticsearch) client
```

---

## Take It Further: Autonomous Agentic SOC

Combine this MCP server with [**Wazuh Autopilot**](https://github.com/gensecaihq/Wazuh-Autopilot) to build an agentic Security Operations Center.

While this server gives you conversational access to Wazuh, Autopilot runs an eleven-agent AI SOC team on top of it **around the clock** — a seven-stage reactive pipeline (triage → correlation → investigation → response) plus four proactive specialists (vulnerability management, threat intel, threat hunting, detection engineering). Every containment action is gated behind two-tier human approval. Runs on OpenClaw, Hermes, or NVIDIA NemoClaw.

```
Manual SOC:    Alert → Analyst reviews → Hours → Response
Agentic SOC:   Alert → AI triages → Seconds → Response ready for approval
```

[**Explore Wazuh Autopilot**](https://github.com/gensecaihq/Wazuh-Autopilot)

---

## Documentation

| Guide | Description |
|-------|-------------|
| [Claude Integration](docs/CLAUDE_INTEGRATION.md) | Claude Desktop setup and authentication |
| [Configuration](docs/configuration.md) | Full configuration reference |
| [Advanced Features](docs/ADVANCED_FEATURES.md) | HA, serverless, compact mode |
| [API Documentation](docs/api/) | Per-tool documentation |
| [Security](docs/security/) | Security hardening guide |
| [Troubleshooting](docs/TROUBLESHOOTING.md) | Common issues and solutions |
| [Operations](docs/OPERATIONS.md) | Deployment, monitoring, maintenance |

---

## Contributing

We welcome contributions. See [Issues](https://github.com/gensecaihq/Wazuh-MCP-Server/issues) for bugs and feature requests, [Discussions](https://github.com/gensecaihq/Wazuh-MCP-Server/discussions) for questions.

---

## License

[MIT](LICENSE)

---

## Acknowledgments

- [Wazuh](https://wazuh.com/) — Open source security platform
- [Model Context Protocol](https://modelcontextprotocol.io/) — AI tool integration standard
- [Ollama](https://ollama.com/) — Local LLM inference
- [Open WebUI](https://github.com/open-webui/open-webui) — Self-hosted AI chat interface
- [mcphost](https://github.com/mark3labs/mcphost) — MCP CLI host with LLM support

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
