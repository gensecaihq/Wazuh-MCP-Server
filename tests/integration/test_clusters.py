"""Tests for opt-in multi-cluster support (#77): clusters file, routing, and CCS prefixes."""

import json
import os

import pytest

os.environ.setdefault("WAZUH_HOST", "localhost")
os.environ.setdefault("WAZUH_USER", "test")
os.environ.setdefault("WAZUH_PASS", "test")
os.environ.setdefault("AUTH_MODE", "none")

import httpx  # noqa: E402

from wazuh_mcp_server import server as mcp_server  # noqa: E402
from wazuh_mcp_server.api.wazuh_indexer import WazuhIndexerClient  # noqa: E402
from wazuh_mcp_server.clusters import ClusterRegistry, load_cluster_registry  # noqa: E402


def _clusters_file(tmp_path, payload):
    path = tmp_path / "clusters.json"
    path.write_text(json.dumps(payload))
    return str(path)


class TestClusterRegistry:
    def test_no_file_single_cluster_unchanged(self, tmp_path):
        sentinel = object()
        registry = load_cluster_registry(sentinel, clusters_file=str(tmp_path / "missing.json"))
        assert registry.multi_cluster is False
        assert registry.default_id == "default"
        assert registry.get(None) is sentinel
        assert registry.get("") is sentinel
        with pytest.raises(ValueError, match="Unknown cluster_id"):
            registry.get("nope")

    def test_clusters_file_with_env_interpolation(self, tmp_path, monkeypatch):
        monkeypatch.setenv("EU_PASS", "s3cret")
        path = _clusters_file(
            tmp_path,
            {
                "default_cluster": "eu",
                "clusters": [
                    {
                        "id": "eu",
                        "wazuh_host": "wazuh-eu.example.com",
                        "wazuh_user": "api-eu",
                        "wazuh_pass": "${EU_PASS}",
                        "indexer_host": "ccs.example.com",
                        "indexer_user": "idx",
                        "indexer_pass": "idx",
                        "ccs_prefix": "eu",
                    },
                    {
                        "id": "us",
                        "wazuh_host": "wazuh-us.example.com",
                        "wazuh_user": "api-us",
                        "wazuh_pass": "plain",
                    },
                ],
            },
        )
        sentinel = object()
        registry = load_cluster_registry(sentinel, clusters_file=path)
        assert registry.multi_cluster is True
        assert registry.default_id == "eu"
        assert sorted(registry.cluster_ids) == ["default", "eu", "us"]
        # env-configured cluster stays reachable
        assert registry.get("default") is sentinel
        eu = registry.get("eu")
        assert eu.config.wazuh_pass == "s3cret"
        assert eu._indexer_client is not None
        assert eu._indexer_client.ccs_prefix == "eu"
        # default_cluster resolution
        assert registry.get(None) is eu

    def test_invalid_configs_rejected(self, tmp_path, monkeypatch):
        sentinel = object()
        base = {"id": "a", "wazuh_host": "h", "wazuh_user": "u", "wazuh_pass": "p"}

        with pytest.raises(ValueError, match="non-empty 'clusters' list"):
            load_cluster_registry(sentinel, clusters_file=_clusters_file(tmp_path, {"clusters": []}))

        with pytest.raises(ValueError, match="duplicate cluster id"):
            load_cluster_registry(sentinel, clusters_file=_clusters_file(tmp_path, {"clusters": [base, base]}))

        with pytest.raises(ValueError, match="missing required field"):
            load_cluster_registry(
                sentinel, clusters_file=_clusters_file(tmp_path, {"clusters": [{"id": "b", "wazuh_host": "h"}]})
            )

        with pytest.raises(ValueError, match="unset environment variable"):
            load_cluster_registry(
                sentinel,
                clusters_file=_clusters_file(
                    tmp_path, {"clusters": [{**base, "wazuh_pass": "${NO_SUCH_ENV_VAR_12345}"}]}
                ),
            )

        with pytest.raises(ValueError, match="default_cluster"):
            load_cluster_registry(
                sentinel, clusters_file=_clusters_file(tmp_path, {"default_cluster": "zz", "clusters": [base]})
            )


class TestCcsPrefix:
    def test_index_patterns_qualified(self):
        plain = WazuhIndexerClient(host="idx", username="u", password="p")
        assert plain._qualified("wazuh-alerts-*") == "wazuh-alerts-*"

        ccs = WazuhIndexerClient(host="idx", username="u", password="p", ccs_prefix="eu")
        assert ccs._qualified("wazuh-alerts-*") == "eu:wazuh-alerts-*"

        wildcard = WazuhIndexerClient(host="idx", username="u", password="p", ccs_prefix="*")
        assert wildcard._qualified("wazuh-alerts-*") == "*:wazuh-alerts-*"


class _StubClient:
    def __init__(self, label):
        self.label = label
        self.calls = []

    async def get_alerts(self, **kwargs):
        self.calls.append(kwargs)
        return {"data": {"affected_items": [], "total_affected_items": 0, "cluster": self.label}}


class TestToolRouting:
    def _http(self):
        transport = httpx.ASGITransport(app=mcp_server.app)
        return httpx.AsyncClient(transport=transport, base_url="http://testserver")

    @pytest.mark.asyncio
    async def test_cluster_id_routes_to_named_cluster(self, monkeypatch):
        default, eu = _StubClient("default"), _StubClient("eu")
        registry = ClusterRegistry({"default": default, "eu": eu}, "default", multi_cluster=True)
        monkeypatch.setattr(mcp_server, "cluster_registry", registry)

        body = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "get_wazuh_alerts", "arguments": {"limit": 5, "cluster_id": "eu"}},
        }
        async with self._http() as client:
            resp = await client.post("/mcp", json=body)
        assert resp.status_code == 200
        assert not resp.json()["result"]["isError"]
        assert len(eu.calls) == 1 and not default.calls
        # cluster_id is routing metadata, not a Wazuh API filter
        assert "cluster_id" not in eu.calls[0]

    @pytest.mark.asyncio
    async def test_unknown_cluster_id_returns_error(self, monkeypatch):
        registry = ClusterRegistry({"default": _StubClient("default")}, "default", multi_cluster=True)
        monkeypatch.setattr(mcp_server, "cluster_registry", registry)

        body = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "get_wazuh_alerts", "arguments": {"cluster_id": "nope"}},
        }
        async with self._http() as client:
            resp = await client.post("/mcp", json=body)
        assert resp.status_code == 200
        assert resp.json()["error"]["code"] == -32602
        assert "Unknown cluster_id" in resp.json()["error"]["message"]

    @pytest.mark.asyncio
    async def test_tools_list_advertises_cluster_id_and_list_tool(self, monkeypatch):
        registry = ClusterRegistry({"default": _StubClient("d"), "eu": _StubClient("eu")}, "eu", multi_cluster=True)
        monkeypatch.setattr(mcp_server, "cluster_registry", registry)

        async with self._http() as client:
            resp = await client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
        tools = resp.json()["result"]["tools"]
        by_name = {t["name"]: t for t in tools}
        assert "list_wazuh_clusters" in by_name
        assert "cluster_id" in by_name["get_wazuh_alerts"]["inputSchema"]["properties"]

        # single-cluster mode: no schema change and no clusters tool
        single = ClusterRegistry({"default": _StubClient("d")}, "default", multi_cluster=False)
        monkeypatch.setattr(mcp_server, "cluster_registry", single)
        async with self._http() as client:
            resp = await client.post("/mcp", json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        tools = resp.json()["result"]["tools"]
        by_name = {t["name"]: t for t in tools}
        assert "list_wazuh_clusters" not in by_name
        assert "cluster_id" not in by_name["get_wazuh_alerts"]["inputSchema"]["properties"]

    @pytest.mark.asyncio
    async def test_list_wazuh_clusters_tool(self, monkeypatch):
        registry = ClusterRegistry({"default": _StubClient("d"), "eu": _StubClient("eu")}, "eu", multi_cluster=True)
        monkeypatch.setattr(mcp_server, "cluster_registry", registry)

        body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "list_wazuh_clusters"}}
        async with self._http() as client:
            resp = await client.post("/mcp", json=body)
        assert resp.status_code == 200
        text = resp.json()["result"]["content"][0]["text"]
        assert "eu" in text and "default" in text


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
