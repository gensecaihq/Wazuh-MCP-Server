# Wazuh MCP Server

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![MCP 2025-11-25](https://img.shields.io/badge/MCP-2025--11--25-green.svg)](https://modelcontextprotocol.io/)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://github.com/gensecaihq/Wazuh-MCP-Server)

**Talk to your SIEM.** Query alerts, hunt threats, check vulnerabilities, and trigger active responses across your entire Wazuh deployment — through natural conversation with any AI assistant.

> **v4.2.1** | 48 security tools | Wazuh 4.8.0–4.14.4 | [Changelog](CHANGELOG.md)

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
AI:     [calls get_critical_vulnerabilities] 3 agents with critical vulnerabilities...
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

## 48 Security Tools

Every tool is validated, rate-limited, scope-checked, and audit-logged.

| Category | Tools | What They Do |
|----------|-------|-------------|
| **Alerts** (4) | `get_wazuh_alerts` `get_wazuh_alert_summary` `analyze_alert_patterns` `search_security_events` | Query, filter, search, and analyze alert data via Elasticsearch |
| **Agents** (6) | `get_wazuh_agents` `get_wazuh_running_agents` `check_agent_health` `get_agent_processes` `get_agent_ports` `get_agent_configuration` | Monitor agent status, running processes, open ports, and configs |
| **Vulnerabilities** (3) | `get_wazuh_vulnerabilities` `get_critical_vulnerabilities` `vulnerability_summary` | Query CVEs by severity, agent, and package |
| **Security Analysis** (6) | `analyze_security_threat` `check_ioc_reputation` `perform_risk_assessment` `get_top_security_threats` `generate_security_report` `run_compliance_check` | Threat analysis, IOC lookup, risk scoring, compliance checks |
| **System** (10) | `get_wazuh_statistics` `get_wazuh_cluster_health` `get_wazuh_rules_summary` `search_wazuh_manager_logs` ... | Cluster health, rules, manager logs, stats |
| **Active Response** (9) | `wazuh_block_ip` `wazuh_isolate_host` `wazuh_kill_process` `wazuh_disable_user` `wazuh_quarantine_file` ... | Block IPs, isolate hosts, kill processes, quarantine files |
| **Verification** (5) | `wazuh_check_blocked_ip` `wazuh_check_agent_isolation` `wazuh_check_process` `wazuh_check_user_status` ... | Verify active response actions took effect |
| **Rollback** (5) | `wazuh_unisolate_host` `wazuh_enable_user` `wazuh_restore_file` `wazuh_firewall_allow` `wazuh_host_allow` | Undo active response actions |

---

## Quick Start

### Prerequisites

- Docker 20.10+ with Compose v2
- Wazuh 4.8.0–4.14.4 with API access enabled

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
| **RBAC** | Per-tool scope enforcement. 14 active response tools require `wazuh:write`. Read-only tokens can query but never trigger actions. Authless mode is read-only by default. |
| **Audit Logging** | Every destructive tool call (block IP, isolate host, kill process) is logged with client ID, session, timestamp, and full arguments. |
| **Output Sanitization** | Credentials, tokens, and API keys in alert `full_log` fields are redacted before reaching the LLM. Prevents credential leakage through AI responses. |
| **Input Validation** | Every parameter validated: regex agent IDs, `ipaddress` module for IPs, shell metacharacter blocking for active response, Elasticsearch Query DSL (no string interpolation). |
| **Rate Limiting** | Per-client sliding window with escalating block duration (10s → 5min). |
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
| `WAZUH_PORT` | `55000` | Manager API port |
| `MCP_HOST` | `0.0.0.0` | Server bind address |
| `MCP_PORT` | `3000` | Server port |
| `AUTH_MODE` | `bearer` | `oauth`, `bearer`, or `none` |
| `AUTH_SECRET_KEY` | auto-generated | JWT signing key |
| `AUTHLESS_ALLOW_WRITE` | `false` | Allow active response in authless mode |
| `ALLOWED_ORIGINS` | `https://claude.ai` | CORS origins (comma-separated) |
| `REDIS_URL` | — | Redis URL for multi-instance session storage |

### Wazuh Indexer (for alert search + vulnerabilities)

| Variable | Default | Description |
|----------|---------|-------------|
| `WAZUH_INDEXER_HOST` | — | Indexer hostname |
| `WAZUH_INDEXER_PORT` | `9200` | Indexer port |
| `WAZUH_INDEXER_USER` | — | Indexer username |
| `WAZUH_INDEXER_PASS` | — | Indexer password |

> Full reference: [Configuration Guide](docs/configuration.md)

---

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/mcp` | POST/GET/DELETE | MCP Streamable HTTP (recommended) |
| `/sse` | GET | Legacy Server-Sent Events |
| `/health` | GET | Health check (no auth required) |
| `/metrics` | GET | Prometheus metrics |
| `/auth/token` | POST | Exchange API key for JWT |
| `/docs` | GET | OpenAPI documentation |

---

## Architecture

```
src/wazuh_mcp_server/
├── server.py           # MCP protocol + 48 tool handlers
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

Combine this MCP server with [**Wazuh OpenClaw Autopilot**](https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot) to build a fully autonomous Security Operations Center.

While this server gives you conversational access to Wazuh, OpenClaw deploys AI agents that **work around the clock** — triaging alerts, correlating incidents, and recommending responses without human intervention.

```
Manual SOC:    Alert → Analyst reviews → Hours → Response
Agentic SOC:   Alert → AI triages → Seconds → Response ready for approval
```

[**Explore OpenClaw Autopilot**](https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot)

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
| <img src="https://github.com/alokemajumder.png" width="40" height="40" style="border-radius: 50%"/> | [@alokemajumder](https://github.com/alokemajumder) | Code, Issues, Discussions |
| <img src="https://github.com/gensecai-dev.png" width="40" height="40" style="border-radius: 50%"/> | [@gensecai-dev](https://github.com/gensecai-dev) | Code, Discussions |
| <img src="https://github.com/aiunmukto.png" width="40" height="40" style="border-radius: 50%"/> | [@aiunmukto](https://github.com/aiunmukto) | Code, PRs |
| <img src="https://github.com/Karibusan.png" width="40" height="40" style="border-radius: 50%"/> | [@Karibusan](https://github.com/Karibusan) | Code, Issues, PRs |
| <img src="https://github.com/lwsinclair.png" width="40" height="40" style="border-radius: 50%"/> | [@lwsinclair](https://github.com/lwsinclair) | Code, PRs |
| <img src="https://github.com/taylorwalton.png" width="40" height="40" style="border-radius: 50%"/> | [@taylorwalton](https://github.com/taylorwalton) | PRs |
| <img src="https://github.com/MilkyWay88.png" width="40" height="40" style="border-radius: 50%"/> | [@MilkyWay88](https://github.com/MilkyWay88) | PRs |
| <img src="https://github.com/kanylbullen.png" width="40" height="40" style="border-radius: 50%"/> | [@kanylbullen](https://github.com/kanylbullen) | Code, PRs |
| <img src="https://github.com/Uberkarhu.png" width="40" height="40" style="border-radius: 50%"/> | [@Uberkarhu](https://github.com/Uberkarhu) | Issues |
| <img src="https://github.com/cbassonbgroup.png" width="40" height="40" style="border-radius: 50%"/> | [@cbassonbgroup](https://github.com/cbassonbgroup) | Issues |
| <img src="https://github.com/cybersentinel-06.png" width="40" height="40" style="border-radius: 50%"/> | [@cybersentinel-06](https://github.com/cybersentinel-06) | Issues |
| <img src="https://github.com/daod-arshad.png" width="40" height="40" style="border-radius: 50%"/> | [@daod-arshad](https://github.com/daod-arshad) | Issues |
| <img src="https://github.com/mamema.png" width="40" height="40" style="border-radius: 50%"/> | [@mamema](https://github.com/mamema) | Issues |
| <img src="https://github.com/marcolinux46.png" width="40" height="40" style="border-radius: 50%"/> | [@marcolinux46](https://github.com/marcolinux46) | Issues |
| <img src="https://github.com/matveevandrey.png" width="40" height="40" style="border-radius: 50%"/> | [@matveevandrey](https://github.com/matveevandrey) | Issues |
| <img src="https://github.com/punkpeye.png" width="40" height="40" style="border-radius: 50%"/> | [@punkpeye](https://github.com/punkpeye) | Issues |
| <img src="https://github.com/tonyliu9189.png" width="40" height="40" style="border-radius: 50%"/> | [@tonyliu9189](https://github.com/tonyliu9189) | Issues |
| <img src="https://github.com/Vasanth120v.png" width="40" height="40" style="border-radius: 50%"/> | [@Vasanth120v](https://github.com/Vasanth120v) | Discussions |
| <img src="https://github.com/gnix45.png" width="40" height="40" style="border-radius: 50%"/> | [@gnix45](https://github.com/gnix45) | Discussions |
| <img src="https://github.com/melmasry1987.png" width="40" height="40" style="border-radius: 50%"/> | [@melmasry1987](https://github.com/melmasry1987) | Discussions |

<!-- CONTRIBUTORS-END -->

> Auto-updated by [GitHub Actions](.github/workflows/update-contributors.yml)

</details>
