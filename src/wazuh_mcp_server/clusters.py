"""
Multi-cluster support (opt-in): route tools to named Wazuh clusters.

When a clusters file is present (WAZUH_CLUSTERS_FILE, default ./config/clusters.json),
the server builds one WazuhClient per configured cluster and tools accept an optional
cluster_id argument. When the file is absent, the server runs exactly as before with a
single cluster configured from environment variables — no cluster_id required.

Cross-Cluster Search (CCS): a cluster entry may set "ccs_prefix" so Indexer queries
target a remote cluster through a shared CCS coordinator (index patterns become
"<prefix>:wazuh-alerts-*"). An entry with "ccs_prefix": "*" queries every remote
cluster configured on the coordinator — useful as an "all" pseudo-cluster for
fleet-wide alert and vulnerability reads.

Example clusters.json:

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
          "indexer_user": "${IDX_USER}",
          "indexer_pass": "${IDX_PASS}",
          "ccs_prefix": "eu"
        }
      ]
    }

Values of the form "${ENV_VAR}" are resolved from the environment at load time, so
credentials never need to live in the file itself.
"""

import json
import logging
import os
import re
from typing import Any, Dict, List, Optional

from wazuh_mcp_server.config import WazuhConfig

logger = logging.getLogger(__name__)

CLUSTER_ID_PATTERN = re.compile(r"^[A-Za-z0-9_.*-]{1,64}$")

_ENV_REF = re.compile(r"^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$")


def _resolve_env(value: Any) -> Any:
    """Resolve "${ENV_VAR}" references so secrets stay out of the clusters file."""
    if isinstance(value, str):
        match = _ENV_REF.match(value.strip())
        if match:
            resolved = os.getenv(match.group(1))
            if resolved is None:
                raise ValueError(f"clusters file references unset environment variable {match.group(1)!r}")
            return resolved
    return value


def _as_bool(value: Any, default: bool) -> bool:
    """Coerce a clusters-file value to bool. An env ref resolves to a STRING, and
    bool("false") is True — so a "${VERIFY_SSL}" of "false" would silently stay on.
    Parse the string form instead of relying on truthiness."""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    return str(value).strip().lower() in ("true", "1", "yes", "y", "on")


class ClusterRegistry:
    """Holds one WazuhClient per configured cluster plus the default cluster id."""

    def __init__(self, clients: Dict[str, Any], default_id: str, multi_cluster: bool):
        self._clients = clients
        self.default_id = default_id
        # True only when a clusters file defined the topology — gates the
        # cluster_id tool parameter and the list_wazuh_clusters tool
        self.multi_cluster = multi_cluster

    @property
    def cluster_ids(self) -> List[str]:
        return list(self._clients)

    def get(self, cluster_id: Optional[str]):
        """Resolve a cluster_id (None → default cluster) to its WazuhClient."""
        if cluster_id is None or cluster_id == "":
            cluster_id = self.default_id
        client = self._clients.get(cluster_id)
        if client is None:
            raise ValueError(
                f"Unknown cluster_id '{cluster_id}'. Configured clusters: {', '.join(sorted(self._clients))}"
            )
        return client

    async def close(self) -> None:
        for client in self._clients.values():
            try:
                await client.close()
            except Exception:
                pass


def _cluster_config(entry: Dict[str, Any]) -> WazuhConfig:
    """Build a WazuhConfig from one clusters-file entry."""
    resolved = {k: _resolve_env(v) for k, v in entry.items()}

    for key in ("wazuh_host", "wazuh_user", "wazuh_pass"):
        if not resolved.get(key):
            raise ValueError(f"cluster '{entry.get('id', '?')}' is missing required field '{key}'")

    return WazuhConfig(
        wazuh_host=resolved["wazuh_host"],
        wazuh_user=resolved["wazuh_user"],
        wazuh_pass=resolved["wazuh_pass"],
        wazuh_port=int(resolved.get("wazuh_port", 55000)),
        verify_ssl=_as_bool(resolved.get("verify_ssl"), True),
        wazuh_indexer_host=resolved.get("indexer_host"),
        wazuh_indexer_port=int(resolved.get("indexer_port", 9200)),
        wazuh_indexer_user=resolved.get("indexer_user"),
        wazuh_indexer_pass=resolved.get("indexer_pass"),
        wazuh_indexer_ssl=_as_bool(resolved.get("indexer_ssl"), True),
        wazuh_indexer_verify_ssl=_as_bool(resolved.get("indexer_verify_ssl"), True),
        request_timeout_seconds=int(resolved.get("request_timeout_seconds", 30)),
    )


def load_cluster_registry(default_client, clusters_file: Optional[str] = None) -> ClusterRegistry:
    """
    Build the cluster registry.

    default_client is the env-configured WazuhClient (today's single-cluster path).
    Without a clusters file it is the only entry, keyed "default", and nothing about
    the server's behavior changes. With a clusters file, each entry gets its own
    client (all connections are established lazily on first use) and tools accept
    cluster_id; the env-configured cluster stays reachable as "default" unless the
    file overrides default_cluster.
    """
    from wazuh_mcp_server.api.wazuh_client import WazuhClient

    path = clusters_file or os.getenv("WAZUH_CLUSTERS_FILE", "./config/clusters.json")

    if not os.path.isfile(path):
        return ClusterRegistry({"default": default_client}, "default", multi_cluster=False)

    with open(path, encoding="utf-8") as fh:
        try:
            data = json.load(fh)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in clusters file {path}: {e}")

    entries = data.get("clusters")
    if not isinstance(entries, list) or not entries:
        raise ValueError(f"clusters file {path} must contain a non-empty 'clusters' list")

    clients: Dict[str, Any] = {"default": default_client}
    for entry in entries:
        cluster_id = str(entry.get("id", "")).strip()
        if not CLUSTER_ID_PATTERN.match(cluster_id):
            raise ValueError(f"clusters file {path}: invalid or missing cluster id {cluster_id!r}")
        if cluster_id in clients:
            raise ValueError(f"clusters file {path}: duplicate cluster id '{cluster_id}'")
        config = _cluster_config(entry)
        client = WazuhClient(config)
        ccs_prefix = str(entry.get("ccs_prefix", "") or "")
        if ccs_prefix and client._indexer_client is not None:
            client._indexer_client.ccs_prefix = ccs_prefix.strip().rstrip(":")
        clients[cluster_id] = client

    default_id = str(data.get("default_cluster") or "default")
    if default_id not in clients:
        raise ValueError(f"clusters file {path}: default_cluster '{default_id}' is not a configured cluster")

    logger.info(f"Multi-cluster mode: {len(clients)} clusters loaded from {path} (default: {default_id})")
    return ClusterRegistry(clients, default_id, multi_cluster=True)
