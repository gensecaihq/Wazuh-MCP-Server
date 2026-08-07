# Multi-Cluster Guide

Manage several Wazuh deployments from one MCP server. Multi-cluster is **opt-in** — with no
clusters file the server behaves exactly as a single-cluster deployment configured from
environment variables.

## How it works

- **No clusters file** → single cluster from the env vars (`WAZUH_HOST`, `WAZUH_INDEXER_HOST`, …). Tools take no `cluster_id`.
- **Clusters file present** (`WAZUH_CLUSTERS_FILE`, default `./config/clusters.json`) → each entry becomes a named cluster with its own Manager (and optional Indexer) credentials. Every tool gains an optional `cluster_id` argument, a `list_wazuh_clusters` tool appears, and `/health`/`/ready` report the configured clusters.

The env-configured cluster remains reachable as `default`, so existing automation keeps working.

## Configuration

Copy the example and edit it:

```bash
cp config/clusters.json.example config/clusters.json
```

```json
{
  "default_cluster": "prod-eu",
  "clusters": [
    {
      "id": "prod-eu",
      "wazuh_host": "wazuh-eu.example.com",
      "wazuh_port": 55000,
      "wazuh_user": "${WAZUH_EU_USER}",
      "wazuh_pass": "${WAZUH_EU_PASS}",
      "verify_ssl": true,
      "indexer_host": "ccs-coordinator.example.com",
      "indexer_user": "${INDEXER_USER}",
      "indexer_pass": "${INDEXER_PASS}",
      "ccs_prefix": "eu"
    },
    {
      "id": "prod-us",
      "wazuh_host": "wazuh-us.example.com",
      "wazuh_user": "${WAZUH_US_USER}",
      "wazuh_pass": "${WAZUH_US_PASS}",
      "indexer_host": "ccs-coordinator.example.com",
      "indexer_user": "${INDEXER_USER}",
      "indexer_pass": "${INDEXER_PASS}",
      "ccs_prefix": "us"
    }
  ]
}
```

### Fields

| Field | Required | Description |
|-------|----------|-------------|
| `id` | ✅ | Cluster identifier used as the `cluster_id` tool argument (`[A-Za-z0-9_.*-]`, ≤64 chars) |
| `wazuh_host` / `wazuh_user` / `wazuh_pass` | ✅ | Manager API connection |
| `wazuh_port` | | Manager API port (default `55000`) |
| `verify_ssl` | | Verify the Manager TLS cert (default `true`) |
| `indexer_host` / `indexer_user` / `indexer_pass` | | Indexer connection (required for alert/vulnerability tools on this cluster) |
| `indexer_port` / `indexer_ssl` / `indexer_verify_ssl` | | Indexer options (defaults `9200` / `true` / `true`) |
| `ccs_prefix` | | OpenSearch Cross-Cluster Search remote name (see below) |
| `default_cluster` (top level) | | Which `id` is used when a tool omits `cluster_id` (defaults to `default`, the env cluster) |

**Secrets never live in the file.** Any value of the form `${ENV_VAR}` is resolved from the
environment at load time — set those variables via your secret manager / `.env`.

## Routing tools to a cluster

Every tool accepts an optional `cluster_id`:

```json
{ "name": "get_wazuh_alerts", "arguments": { "limit": 20, "cluster_id": "prod-us" } }
```

Omit `cluster_id` to use the default cluster. Use `list_wazuh_clusters` to see what's configured:

```json
{ "name": "list_wazuh_clusters", "arguments": {} }
```

## Cross-Cluster Search (CCS)

If your Wazuh Indexers are joined by an OpenSearch **Cross-Cluster Search** coordinator, set
`ccs_prefix` to the remote-cluster name. Indexer queries for that cluster are then qualified
against the remote — e.g. `eu:wazuh-alerts-*` instead of `wazuh-alerts-*`.

A special entry with `"ccs_prefix": "*"` searches **every** remote cluster the coordinator
knows about — useful as an `all` pseudo-cluster for fleet-wide alert and vulnerability reads:

```json
{
  "id": "all",
  "wazuh_host": "wazuh-eu.example.com",
  "wazuh_user": "${WAZUH_EU_USER}",
  "wazuh_pass": "${WAZUH_EU_PASS}",
  "indexer_host": "ccs-coordinator.example.com",
  "indexer_user": "${INDEXER_USER}",
  "indexer_pass": "${INDEXER_PASS}",
  "ccs_prefix": "*"
}
```

```json
{ "name": "get_alerts_aggregated", "arguments": { "cluster_id": "all", "timestamp_start": "now-24h" } }
```

## Notes

- A single unreachable cluster does not stop the server; tools targeting it surface the connection error per call.
- RBAC scopes apply the same way across all clusters — a `wazuh:write` token is required for active-response tools on any cluster, and destructive calls are audited with the target `cluster_id`.
- `docker compose` mounts `./config` into the container, so `config/clusters.json` is picked up automatically.

---

[← Configuration](configuration.md) · [Operations](OPERATIONS.md) · [Back to README](../README.md)
