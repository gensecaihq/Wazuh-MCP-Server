# Multi-Cluster Guide

One server can route tool calls to several Wazuh deployments. Multi-cluster mode is opt-in: without a clusters file the server runs as a single-cluster deployment configured from environment variables, and tool schemas are unchanged.

## How it works

The server reads `WAZUH_CLUSTERS_FILE` (default `./config/clusters.json`, relative to the working directory; `/app/config/clusters.json` in the container).

| | No clusters file | Clusters file present |
|---|---|---|
| Clusters | One, from `WAZUH_HOST`, `WAZUH_INDEXER_HOST`, … | The environment cluster (id `default`) plus one per file entry |
| Tool arguments | Unchanged | Every tool except `list_wazuh_clusters` gains an optional `cluster_id` |
| `list_wazuh_clusters` | Not listed | Listed (in the `system` toolset) |
| Tool count | 55 | 56 |

`WAZUH_HOST`, `WAZUH_USER` and `WAZUH_PASS` are still required in multi-cluster mode (startup fails without them), because the environment cluster is always loaded as `default`. The id `default` is therefore reserved and cannot be used in the file.

Connections are opened lazily on first use, so an unreachable cluster does not prevent startup; tools targeting it return the connection error.

## Configuration

```bash
cp config/clusters.json.example config/clusters.json
```

`compose.yml` mounts `./config` read-only at `/app/config`, so the file is picked up on the next `docker compose up -d`. The example defines `prod-eu`, `prod-us` and an `all` entry (see [Cross-Cluster Search](#cross-cluster-search-ccs)):

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
      "indexer_port": 9200,
      "indexer_user": "${INDEXER_USER}",
      "indexer_pass": "${INDEXER_PASS}",
      "indexer_ssl": true,
      "indexer_verify_ssl": true,
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

| Field | Required | Default | Notes |
|-------|:--------:|---------|-------|
| `id` | yes | | 1–64 characters from `A-Z a-z 0-9 _ . * -`; unique; not `default` |
| `wazuh_host` | yes | | A leading `http://` or `https://` and trailing `/` are stripped |
| `wazuh_user`, `wazuh_pass` | yes | | Manager API credentials |
| `wazuh_port` | | `55000` | 1–65535 |
| `verify_ssl` | | `true` | Manager TLS verification. See [TLS](#tls) |
| `indexer_host` | | | Needed for alert and vulnerability tools on this cluster. An `http://` prefix selects plain HTTP |
| `indexer_port` | | `9200` | 1–65535 |
| `indexer_user`, `indexer_pass` | | | Indexer credentials |
| `indexer_ssl` | | `true` | Ignored when `indexer_host` has an explicit scheme |
| `indexer_verify_ssl` | | `true` | Indexer TLS verification |
| `ca_bundle` | | global `WAZUH_CA_BUNDLE` | CA PEM trusted for this cluster's Manager and Indexer instead of the system store. The file must exist at startup, even when verification is off. Not used for a connection whose `verify_ssl` / `indexer_verify_ssl` is `false` |
| `request_timeout_seconds` | | `30` | 1–300 |
| `ccs_prefix` | | | Cross-Cluster Search remote name |
| `default_cluster` (top level) | | `default` | Cluster used when `cluster_id` is omitted |

### Secrets

A value written as exactly `${VAR_NAME}` is replaced with that environment variable at startup. Put the credentials in `.env` (or your secret manager) rather than in the file. References are resolved for whole values only, not inside longer strings.

### TLS

Each entry sets its own TLS behaviour; the environment TLS switches apply only to the `default` cluster.

| Setting | Applies to file entries? |
|---------|--------------------------|
| `WAZUH_CA_BUNDLE` | Yes, as the default for `ca_bundle` |
| `WAZUH_ALLOW_SELF_SIGNED` | No |
| `WAZUH_VERIFY_SSL`, `WAZUH_INDEXER_VERIFY_SSL` | No; use `verify_ssl` / `indexer_verify_ssl` |

Certificates are verified by default. For a Manager that still uses the stock API certificate (self-signed for `CN=wazuh.com` with no subjectAltName), verification cannot succeed even with the certificate as `ca_bundle`: reissue it with a subjectAltName for `wazuh_host` and set `ca_bundle` to the signing CA, or set `"verify_ssl": false` for that entry. The startup warning about disabled verification covers only the `default` cluster, so an entry with `verify_ssl: false` is not logged. See [Manager TLS](configuration.md#manager-tls) for how to reissue the certificate.

### Validation

The file is validated at startup. Any error stops the server with a message naming the cluster and field, for example:

```
cluster 'eu': invalid verify_ssl: expected a boolean (true/false), got 'enabled'
cluster 'eu': invalid wazuh_port: wazuh_port must be between 1 and 65535, got 70000
cluster 'eu': invalid request_timeout_seconds: request_timeout_seconds must be <= 300, got 301
cluster 'eu': ca_bundle file does not exist: /app/certs/eu-ca.pem
clusters file references unset environment variable 'NOPE_UNSET'
clusters file ./config/clusters.json: duplicate cluster id 'default'
```

- Booleans accept JSON `true`/`false`, numbers, or the strings `true/false`, `1/0`, `yes/no`, `y/n`, `on/off` (so `"${VERIFY_SSL}"` resolving to `"false"` disables verification as intended). Anything else is an error.
- The file must be a JSON object with a non-empty `clusters` list, each entry an object with a valid, unique `id`.
- `default_cluster` must name a configured cluster.

## Routing tools to a cluster

```json
{"name": "get_wazuh_alerts", "arguments": {"limit": 20, "cluster_id": "prod-us"}}
```

Omit `cluster_id` to use `default_cluster`. The `cluster_id` schema description names the current default:

```json
{"type": "string", "description": "Target Wazuh cluster (default: prod-eu). Use list_wazuh_clusters to see configured clusters."}
```

`list_wazuh_clusters` takes no arguments. Output with the example file:

```
Configured Wazuh Clusters:
{
  "multi_cluster": true,
  "default_cluster": "prod-eu",
  "clusters": [
    "default",
    "prod-eu",
    "prod-us",
    "all"
  ]
}
```

An unknown id is rejected with a JSON-RPC invalid-params error:

```json
{"code": -32602, "message": "Unknown cluster_id 'nope'. Configured clusters: all, default, prod-eu, prod-us"}
```

## Cross-Cluster Search (CCS)

When your Indexers are joined through an OpenSearch Cross-Cluster Search coordinator, point `indexer_host` at the coordinator and set `ccs_prefix` to the remote cluster name. Indexer queries for that entry then target `<prefix>:<index>`, for example `eu:wazuh-alerts-*`.

`"ccs_prefix": "*"` queries every remote cluster the coordinator knows, which gives a fleet-wide pseudo-cluster:

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
{"name": "get_alerts_aggregated", "arguments": {"cluster_id": "all", "timestamp_start": "now-24h"}}
```

The prefix applies only to Indexer queries (alerts, events, vulnerabilities). Manager API tools called with `cluster_id: "all"` go to that entry's `wazuh_host`, a single Manager.

## Limitations

- **Readiness:** `/ready` probes only the environment-configured cluster (`default`), even when `default_cluster` points elsewhere. It lists the configured clusters under `clusters` but does not check them. `/health` does not report clusters. Use `validate_wazuh_connection` with a `cluster_id` to test a specific cluster.
- **Audit log:** write-tool audit entries record the tool, principal, session and arguments, but not the target `cluster_id`.
- **Scopes:** RBAC is per token, not per cluster. A token with `wazuh:write` can run active response on every configured cluster.
- **Connection settings:** `MAX_CONNECTIONS` and `REQUEST_TIMEOUT_SECONDS` apply only to the `default` cluster. File entries use `request_timeout_seconds` and a fixed limit of 10 concurrent Manager requests.
- **Protected targets:** `WAZUH_PROTECTED_IPS` and the active-response switches (`WAZUH_ALLOW_MANAGER_AR`, `WAZUH_ALLOW_FLEET_AR`, `WAZUH_REQUIRE_ACTION_CONFIRMATION`, quarantine prefixes) apply to every cluster. Each cluster's own `wazuh_host` is protected from IP blocks when it is an IP address.
- **Toolsets:** `list_wazuh_clusters` belongs to the `system` toolset and is hidden when `WAZUH_TOOLSETS` excludes it.
- **Reloading:** the file is read once at startup; restart the server after editing it.

---

[Configuration](configuration.md) · [Operations](OPERATIONS.md) · [Back to README](../README.md)
