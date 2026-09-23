# Local LLMs: vLLM, Ollama, and LiteLLM

This server never calls a model. It is an MCP tool server; the model and the MCP client sit in front of it. For SOCs that can't send SIEM data to a cloud API, run all three on-prem:

```
analyst ─► Open WebUI / LibreChat (MCP client) ──► vLLM or Ollama (model)
                     │
                     └── MCP /mcp ──► Wazuh MCP Server ──► Wazuh Manager / Indexer
```

| | Ollama | vLLM |
|---|---|---|
| Best for | One analyst, laptop or workstation | A team sharing one GPU server |
| Concurrency | `OLLAMA_NUM_PARALLEL` defaults to 1 | Continuous batching |
| Repeated tool catalogue (~6.6k tokens) | Cached per slot; with one slot, concurrent users evict each other | Prefix caching on by default, shared across all requests |
| Hardware | Apple Silicon, consumer GPUs, CPU | NVIDIA/AMD datacenter or workstation GPUs |
| Ops | Single binary | Container + GPU drivers |

## vLLM (team / production)

`compose.local-llm.yml` adds vLLM and Open WebUI next to the server. It requires an NVIDIA GPU with the NVIDIA Container Toolkit, and the server's own `.env` settings (Wazuh connection, `AUTH_SECRET_KEY`, `MCP_API_KEY`) must already be in place. Then add the two stack secrets:

```bash
cat >> .env <<EOF
VLLM_API_KEY=$(openssl rand -hex 32)
WEBUI_SECRET_KEY=$(openssl rand -hex 32)
EOF
docker compose -f compose.yml -f compose.local-llm.yml up -d
```

The first start downloads the model into the `vllm-cache` volume. For an air-gapped host, populate that volume on a connected machine (or mount a directory of weights and point `VLLM_MODEL` at the path), then set `HF_HUB_OFFLINE=1`.

vLLM is not published on a host port: its `--api-key` only protects the `/v1`-style routes, so it stays on the compose network and only Open WebUI reaches it.

### Models

Pinned to vLLM v0.30.0. Tool calling needs `--enable-auto-tool-choice` plus the parser that matches the model's chat format.

| Model | VRAM | `.env` settings |
|---|---|---|
| Qwen3.6-35B-A3B FP8 (default) | ~42 GB (1× L40S / A6000 / H100) | defaults |
| gpt-oss-20b | ~16 GB (1× RTX 4090 / L4 24 GB) | `VLLM_MODEL=openai/gpt-oss-20b` `VLLM_TOOL_PARSER=openai` `VLLM_REASONING_PARSER=openai_gptoss` `VLLM_EXTRA_ARGS=` |
| Qwen3.6-27B FP8 | ~33 GB | `VLLM_MODEL=Qwen/Qwen3.6-27B-FP8` |

Notes:

- Don't add `--trust-remote-code`; none of these need it, and it runs Python from the model repo.
- `--language-model-only` (the default `VLLM_EXTRA_ARGS`) skips the Qwen vision encoder, leaving more memory for KV cache and removing the multimodal input path. Clear it for text-only models such as gpt-oss.
- vLLM supports only `tool_choice="auto"` for gpt-oss.
- With `tool_choice="auto"`, v0.30.0 doesn't constrain tool arguments to the schema. vLLM main has `--tool-strict-level parameter` (not yet released); once available, add it to `VLLM_EXTRA_ARGS` — every tool here has a closed schema (`additionalProperties: false`), so it applies cleanly.
- vLLM's own MCP integration (`--tool-server`, Responses API `type: "mcp"`) expects MCP servers on the legacy SSE transport, registered at startup. This server does not offer that transport (`/sse` returns `410`), so put an MCP client such as Open WebUI in front instead.

### Connect Open WebUI

Open WebUI listens on `http://127.0.0.1:8080` (`WEBUI_BIND` / `WEBUI_PORT` change this). The first account created becomes the admin.

1. Mint a bearer token for Open WebUI. With `AUTH_MODE=bearer` (the default), `/auth/token` exchanges an API key for a JWT bound to that key and valid for `TOKEN_LIFETIME_HOURS` (default 24; raise it for a service connection, maximum 8760):
   ```bash
   curl -s -X POST http://127.0.0.1:3000/auth/token \
     -H 'Content-Type: application/json' -d "{\"api_key\": \"$MCP_API_KEY\"}"
   ```
   ```json
   {"access_token": "eyJhbGciOiJI...", "token_type": "bearer", "expires_in": 86400}
   ```
   Use a read-only key (leave `MCP_API_KEY_SCOPES` unset) unless the team should be able to run active response from chat. Rotating or revoking the key invalidates the token.
2. In Open WebUI go to **Admin settings → Integrations → External Tool Servers → Add Connection**. Type **MCP (Streamable HTTP)**, URL `http://wazuh-main-server:3000/mcp`, authentication **Bearer**, key = the token.
3. MCP connections are admin-managed; use the connection's access control to make it available to users or groups.

Open WebUI's **OAuth 2.1** option registers itself through dynamic client registration. On this server that requires `AUTH_MODE=oauth`, `OAUTH_ENABLE_DCR=true`, and an `OAUTH_ISSUER_URL` that both the analyst's browser and the Open WebUI container can reach; the pre-registered `claude-desktop` client accepts only Claude's redirect URIs. Bearer is the simpler choice for this stack. See [Claude Integration](CLAUDE_INTEGRATION.md) for the OAuth sign-in flow.

## Ollama (single analyst)

Check the context window first. Ollama sizes its default by VRAM, and below 24 GiB it is 4k tokens, smaller than the full tool catalogue:

```bash
OLLAMA_CONTEXT_LENGTH=16384 ollama serve
ollama pull qwen3.5:9b
```

Then point Open WebUI (or LibreChat) at `http://localhost:11434` and add the MCP server as above. The hostname `wazuh-main-server` resolves only inside the compose network; a client running elsewhere uses the published port, `http://127.0.0.1:3000/mcp` by default (from inside a Docker container on the same host, `http://host.docker.internal:3000/mcp`). On a laptop, trim the catalogue (next section) — it's the cheapest latency win.

## Trim the tool catalogue

Every request carries every tool definition (~6.6k tokens for all 55). Measured with the eval below on qwen3.5:9b (Ollama, Apple M5, temperature 0):

| Catalogue | Tokens | Scenarios passed | Median response |
|---|---|---|---|
| All 55 tools | ~6.6k | 25/25 | 15.8 s |
| `alerts,agents,vulnerabilities,analysis,response` (38 tools) | ~4.9k | 21/21 (same 21 as the full run) | 10.9 s |

On these scenarios the smaller catalogue didn't change accuracy — it made every answer faster. Accuracy effects show up with weaker models and harder, multi-step requests, so measure your own. Expose only what the deployment needs:

```bash
WAZUH_TOOLSETS=alerts,agents,vulnerabilities,analysis   # read-only triage
WAZUH_DISABLED_TOOLS=wazuh_restart,wazuh_active_response
```

Toolsets: `alerts`, `agents`, `vulnerabilities`, `analysis`, `web_search`, `compliance`, `system`, `response`. `web_search` is the only one that sends data off-box (to You.com) — leave it out when air-gapped.

## Measure it: tool-selection eval

`evals/tool_selection.py` runs 25 SOC scenarios against any OpenAI-compatible endpoint and scores the model's first tool call — right tool, arguments valid against the schema, expected values, and no write tool on two prompt-injection cases. Tools are never executed and no Wazuh is needed.

```bash
pip install -e .
python evals/tool_selection.py --base-url http://localhost:11434/v1 --model qwen3.5:9b
python evals/tool_selection.py --base-url http://vllm-host:8000/v1 --api-key "$VLLM_API_KEY" --model soc-model
WAZUH_TOOLSETS=alerts,agents,response python evals/tool_selection.py ...   # compare a trimmed catalogue
```

Run it before rolling out a new model or a new `WAZUH_TOOLSETS` choice. `--repeat 3 --temperature 0.7` shows how stable the choices are. The bundled scenarios are single-turn and direct — a floor check that a capable 9B model already passes; add scenarios from your own analysts' questions to `evals/scenarios.json` to separate models.

## LiteLLM (optional gateway)

LiteLLM Proxy is worth adding when you want one place for model keys, spend tracking, and failover across several model backends (vLLM, Ollama, a cloud fallback). It can also front MCP servers. It is **not** a security boundary for this server:

- **No approval step of its own.** With `require_approval: "never"` the proxy executes tool calls itself; with any other value it returns them to the calling client. It can hide tools (`allowed_tools` / `disallowed_tools`), but it does not ask a person.
- **Identity.** With a static `bearer_token`, every LiteLLM user reaches Wazuh as one identity — `wazuh:read`/`wazuh:write` and the audit log stop meaning anything per user. Keep per-user tokens (OAuth / token exchange) or give LiteLLM a read-only token.
- **Protocol.** Stable LiteLLM (v1.102) speaks the 2025-11-25 MCP handshake, which this server still supports.
- **Track record.** 2026 brought an MCP authentication bypass (CVE-2026-59822, fixed in 1.84.0) and a pre-auth SQL injection (CVE-2026-42208, fixed in 1.83.7), both in CISA KEV, plus malicious PyPI releases 1.82.7 and 1.82.8. Pin an exact version and upgrade deliberately.

Minimal registration, read-only, with containment tools hidden as a second layer:

```yaml
model_list:
  - model_name: soc-model
    litellm_params:
      model: hosted_vllm/soc-model
      api_base: http://vllm:8000/v1
      api_key: os.environ/VLLM_API_KEY

mcp_servers:
  wazuh:
    url: http://wazuh-main-server:3000/mcp
    transport: http
    auth_type: bearer_token
    auth_value: os.environ/WAZUH_MCP_READONLY_TOKEN
    disallowed_tools:
      - wazuh_isolate_host
      - wazuh_kill_process
      - wazuh_block_ip
      - wazuh_firewall_drop
      - wazuh_host_deny
      - wazuh_disable_user
      - wazuh_quarantine_file
      - wazuh_active_response
      - wazuh_restart
```

`WAZUH_MCP_READONLY_TOKEN` is a JWT from `/auth/token` minted with a read-only key; it expires after `TOKEN_LIFETIME_HOURS`, so set that to cover the rotation interval. `disallowed_tools` entries must match the live tool names exactly; a name that does not match fails silently and leaves the tool callable. Keep this server's audit log as the record of which write tools ran.

## Guard-rails that apply regardless of client

- Every tool carries MCP annotations — write tools are `destructiveHint: true` (except the reversal tools), read tools `readOnlyHint: true`. Clients that support approval prompts use these.
- Write tools require the `wazuh:write` scope and are hidden from read-only tokens.
- `WAZUH_REQUIRE_ACTION_CONFIRMATION=true` makes write tools demand `confirm=true`, and advertises the flag in their schemas.
- Agent `000` (the manager) is refused as an active-response target unless `WAZUH_ALLOW_MANAGER_AR=true`.
