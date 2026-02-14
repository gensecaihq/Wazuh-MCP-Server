# Wazuh MCP Server

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.13+](https://img.shields.io/badge/Python-3.13+-blue.svg)](https://www.python.org/downloads/)
[![MCP 2025-11-25](https://img.shields.io/badge/MCP-2025--11--25-green.svg)](https://modelcontextprotocol.io/)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://hub.docker.com/)

**Production-ready MCP server connecting AI assistants to Wazuh SIEM.**

> **Version 4.0.6** | Wazuh 4.8.0 - 4.14.3 | [Full Changelog](CHANGELOG.md)

---

## Why This MCP Server?

Security teams using Wazuh SIEM generate thousands of alerts, vulnerabilities, and events daily. Analyzing this data requires constant context-switching between dashboards, writing API queries, and manually correlating information.

**This MCP server solves that problem** by providing a secure bridge between AI assistants (like Claude) and your Wazuh deployment. Query alerts, analyze threats, check agent health, and generate compliance reports—all through natural conversation.

```
You: "Show me critical alerts from the last 24 hours"
Claude: [Uses get_wazuh_alerts tool] Found 12 critical alerts...

You: "Which agents have unpatched critical vulnerabilities?"
Claude: [Uses get_wazuh_critical_vulnerabilities tool] 3 agents affected...
```

---

## Take It Further: Autonomous Agentic SOC

**Ready to move beyond manual security operations?**

Combine this MCP server with [**Wazuh OpenClaw Autopilot**](https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot) to build a fully autonomous Security Operations Center powered by AI agents.

While this MCP server gives you conversational access to Wazuh, OpenClaw takes it to the next level—deploying AI agents that **work around the clock** to triage alerts, correlate incidents, and recommend responses without human intervention.

| Capability | What It Does |
|------------|--------------|
| **Autonomous Alert Triage** | AI agents continuously analyze incoming alerts, prioritize threats, and create structured incident cases |
| **Intelligent Correlation** | Automatically groups related alerts into attack timelines with blast radius assessment |
| **AI-Powered Response Planning** | Generates actionable response recommendations with risk scoring |
| **Human-in-the-Loop Safety** | Critical actions require Slack approval—automation with guardrails |

```
Traditional SOC: Alert → Analyst reviews → Hours later → Response
Agentic SOC:     Alert → AI triages → Seconds later → Response ready for approval
```

**This is the future of security operations.** Start with the MCP server, scale to autonomous agents.

[**Explore OpenClaw Autopilot →**](https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot)

---

## Features

| Category | Capabilities |
|----------|-------------|
| **MCP Protocol** | 100% compliant with MCP 2025-11-25, Streamable HTTP + Legacy SSE |
| **Security Tools** | 29 specialized tools for alerts, agents, vulnerabilities, compliance |
| **Authentication** | OAuth 2.0 with DCR, Bearer tokens (JWT), or authless mode |
| **Production Ready** | Circuit breakers, rate limiting, graceful shutdown, Prometheus metrics |
| **Deployment** | Docker containerized, multi-platform (AMD64/ARM64), serverless-ready |
| **Token Efficiency** | Compact output mode reduces responses by ~66% |

### 29 Security Tools

| Category | Tools |
|----------|-------|
| **Alerts** (3) | `get_wazuh_alerts`, `get_wazuh_alert_summary`, `analyze_alert_patterns` |
| **Agents** (6) | `get_wazuh_agents`, `get_wazuh_running_agents`, `check_agent_health`, `get_agent_processes`, `get_agent_ports`, `get_agent_configuration` |
| **Vulnerabilities** (3) | `get_wazuh_vulnerabilities`, `get_wazuh_critical_vulnerabilities`, `get_wazuh_vulnerability_summary` |
| **Security Analysis** (7) | `search_security_events`, `analyze_security_threat`, `check_ioc_reputation`, `perform_risk_assessment`, `get_top_security_threats`, `generate_security_report`, `run_compliance_check` |
| **System** (10) | `get_wazuh_statistics`, `get_wazuh_weekly_stats`, `get_wazuh_cluster_health`, `get_wazuh_cluster_nodes`, `get_wazuh_rules_summary`, `get_wazuh_remoted_stats`, `get_wazuh_log_collector_stats`, `search_wazuh_manager_logs`, `get_wazuh_manager_error_logs`, `validate_wazuh_connection` |

---

## Quick Start

### Prerequisites

- Docker 20.10+ with Compose v2.20+
- Wazuh 4.8.0 - 4.14.3 with API access

### 1. Clone and Configure

```bash
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server
cp .env.example .env
```

Edit `.env` with your Wazuh credentials:

```env
WAZUH_HOST=https://your-wazuh-server.com
WAZUH_USER=your-api-user
WAZUH_PASS=your-api-password
```

### 2. Deploy

```bash
python deploy.py
# Or: docker compose up -d
```

### 3. Verify

```bash
curl http://localhost:3000/health
```

### 4. Connect Claude Desktop

1. Go to **Settings** → **Connectors** → **Add custom connector**
2. Enter: `https://your-server-domain.com/mcp`
3. Add authentication in Advanced settings

> **Detailed setup:** [Claude Integration Guide](docs/CLAUDE_INTEGRATION.md)

---

## Configuration

### Required Variables

| Variable | Description |
|----------|-------------|
| `WAZUH_HOST` | Wazuh server URL |
| `WAZUH_USER` | API username |
| `WAZUH_PASS` | API password |

### Optional Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `WAZUH_PORT` | `55000` | API port |
| `MCP_HOST` | `0.0.0.0` | Server bind address |
| `MCP_PORT` | `3000` | Server port |
| `AUTH_MODE` | `bearer` | `oauth`, `bearer`, or `none` |
| `AUTH_SECRET_KEY` | auto | JWT signing key |
| `ALLOWED_ORIGINS` | `https://claude.ai` | CORS origins |
| `REDIS_URL` | - | Redis URL for serverless mode |

### Wazuh Indexer (Required for vulnerabilities in 4.8.0+)

| Variable | Description |
|----------|-------------|
| `WAZUH_INDEXER_HOST` | Indexer hostname |
| `WAZUH_INDEXER_PORT` | Indexer port (default: 9200) |
| `WAZUH_INDEXER_USER` | Indexer username |
| `WAZUH_INDEXER_PASS` | Indexer password |

---

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `/mcp` | **Recommended** - Streamable HTTP (MCP 2025-11-25) |
| `/sse` | Legacy SSE endpoint |
| `/health` | Health check |
| `/metrics` | Prometheus metrics |
| `/docs` | OpenAPI documentation |
| `/auth/token` | Token exchange (bearer mode) |

---

## Documentation

| Guide | Description |
|-------|-------------|
| [Claude Integration](docs/CLAUDE_INTEGRATION.md) | Claude Desktop setup, authentication modes |
| [Advanced Features](docs/ADVANCED_FEATURES.md) | HA, serverless, compact mode, MCP compliance |
| [Troubleshooting](docs/TROUBLESHOOTING.md) | Common issues and solutions |
| [Operations](docs/OPERATIONS.md) | Deployment, monitoring, maintenance |
| [API Documentation](docs/api/) | Tool-specific documentation |
| [Security](docs/security/) | Security configuration and best practices |

---

## Project Structure

```
src/wazuh_mcp_server/
├── server.py           # MCP server with 29 tools
├── config.py           # Configuration management
├── auth.py             # JWT authentication
├── oauth.py            # OAuth 2.0 with DCR
├── security.py         # Rate limiting, CORS
├── monitoring.py       # Prometheus metrics
├── resilience.py       # Circuit breakers, retries
├── session_store.py    # Pluggable sessions
└── api/
    ├── wazuh_client.py    # Wazuh Manager API
    └── wazuh_indexer.py   # Wazuh Indexer API
```

---

## Security

- **Authentication**: JWT tokens, OAuth 2.0 with DCR
- **Rate Limiting**: Per-client request throttling
- **Input Validation**: SQL injection and XSS protection
- **Container Security**: Non-root user, read-only filesystem

```bash
# Generate secure API key
openssl rand -hex 32

# Set file permissions
chmod 600 .env
```

---

## Contributing

We welcome contributions! Please see:
- [Issues](https://github.com/gensecaihq/Wazuh-MCP-Server/issues) - Bug reports and feature requests
- [Discussions](https://github.com/gensecaihq/Wazuh-MCP-Server/discussions) - Questions and ideas

---

## License

MIT License - see [LICENSE](LICENSE)

---

## Acknowledgments

- [Wazuh](https://wazuh.com/) - Open source security platform
- [Model Context Protocol](https://modelcontextprotocol.io/) - AI integration standard
- [FastAPI](https://fastapi.tiangolo.com/) - Python web framework

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
