"""
MCP protocol tests: 2026-07-28 (modern, stateless) and legacy (initialize handshake) eras.

The server is dual-era per the 2026-07-28 spec — requests carrying
params._meta["io.modelcontextprotocol/protocolVersion"] are served statelessly,
while initialize selects legacy session semantics.
"""

import base64
import os

import pytest

# Server config is read from the environment at import time
os.environ.setdefault("WAZUH_HOST", "localhost")
os.environ.setdefault("WAZUH_USER", "test")
os.environ.setdefault("WAZUH_PASS", "test")
os.environ.setdefault("AUTH_MODE", "none")

import httpx  # noqa: E402

from wazuh_mcp_server import server as mcp_server  # noqa: E402

MODERN = "2026-07-28"
META_VERSION = "io.modelcontextprotocol/protocolVersion"
META_CLIENT_INFO = "io.modelcontextprotocol/clientInfo"
META_SERVER_INFO = "io.modelcontextprotocol/serverInfo"


def _client():
    transport = httpx.ASGITransport(app=mcp_server.app)
    return httpx.AsyncClient(transport=transport, base_url="http://testserver")


def modern_body(method, params=None, request_id=1):
    params = dict(params or {})
    params["_meta"] = {
        META_VERSION: MODERN,
        META_CLIENT_INFO: {"name": "TestClient", "version": "1.0.0"},
        "io.modelcontextprotocol/clientCapabilities": {},
    }
    return {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}


def modern_headers(method, name=None):
    headers = {"MCP-Protocol-Version": MODERN, "Mcp-Method": method}
    if name is not None:
        headers["Mcp-Name"] = name
    return headers


class TestModernEra:
    @pytest.mark.asyncio
    async def test_server_discover(self):
        async with _client() as client:
            resp = await client.post(
                "/mcp", json=modern_body("server/discover"), headers=modern_headers("server/discover")
            )
        assert resp.status_code == 200
        result = resp.json()["result"]
        assert result["resultType"] == "complete"
        assert MODERN in result["supportedVersions"]
        assert "2025-11-25" in result["supportedVersions"]
        assert "tools" in result["capabilities"]
        assert result["ttlMs"] > 0
        assert result["cacheScope"] in ("public", "private")
        assert result["_meta"][META_SERVER_INFO]["name"] == "Wazuh MCP Server"
        # Stateless: no protocol-level session is minted or echoed
        assert "mcp-session-id" not in {k.lower() for k in resp.headers}

    @pytest.mark.asyncio
    async def test_tools_list_carries_cacheable_result_fields(self):
        async with _client() as client:
            resp = await client.post("/mcp", json=modern_body("tools/list"), headers=modern_headers("tools/list"))
        assert resp.status_code == 200
        result = resp.json()["result"]
        assert result["resultType"] == "complete"
        assert result["ttlMs"] > 0
        assert result["cacheScope"] == "private"
        assert len(result["tools"]) > 40  # read-scope tools only (write tools filtered in read-only mode)
        assert META_SERVER_INFO in result["_meta"]

    @pytest.mark.asyncio
    async def test_tools_list_deterministic_order(self):
        async with _client() as client:
            r1 = await client.post("/mcp", json=modern_body("tools/list"), headers=modern_headers("tools/list"))
            r2 = await client.post("/mcp", json=modern_body("tools/list"), headers=modern_headers("tools/list"))
        names1 = [t["name"] for t in r1.json()["result"]["tools"]]
        names2 = [t["name"] for t in r2.json()["result"]["tools"]]
        assert names1 == names2

    @pytest.mark.asyncio
    async def test_method_header_mismatch_rejected(self):
        headers = modern_headers("prompts/list")  # wrong: body says tools/list
        async with _client() as client:
            resp = await client.post("/mcp", json=modern_body("tools/list"), headers=headers)
        assert resp.status_code == 400
        assert resp.json()["error"]["code"] == -32020

    @pytest.mark.asyncio
    async def test_missing_protocol_version_header_rejected(self):
        async with _client() as client:
            resp = await client.post("/mcp", json=modern_body("tools/list"), headers={"Mcp-Method": "tools/list"})
        assert resp.status_code == 400
        assert resp.json()["error"]["code"] == -32020

    @pytest.mark.asyncio
    async def test_unsupported_version_returns_error_with_supported_list(self):
        body = modern_body("tools/list")
        body["params"]["_meta"][META_VERSION] = "2099-01-01"
        headers = {"MCP-Protocol-Version": "2099-01-01", "Mcp-Method": "tools/list"}
        async with _client() as client:
            resp = await client.post("/mcp", json=body, headers=headers)
        assert resp.status_code == 400
        error = resp.json()["error"]
        assert error["code"] == -32022
        assert MODERN in error["data"]["supported"]
        assert error["data"]["requested"] == "2099-01-01"

    @pytest.mark.asyncio
    async def test_removed_methods_not_served_on_modern_path(self):
        for method in ("ping", "initialize", "logging/setLevel"):
            async with _client() as client:
                resp = await client.post("/mcp", json=modern_body(method), headers=modern_headers(method))
            assert resp.status_code == 404, method
            assert resp.json()["error"]["code"] == -32601, method

    @pytest.mark.asyncio
    async def test_mcp_name_header_required_and_validated(self):
        params = {"name": "security_investigation", "arguments": {"incident_type": "malware"}}
        # Missing Mcp-Name → header mismatch
        async with _client() as client:
            resp = await client.post("/mcp", json=modern_body("prompts/get", params), headers=modern_headers("prompts/get"))
        assert resp.status_code == 400
        assert resp.json()["error"]["code"] == -32020

        # Matching Mcp-Name → served
        async with _client() as client:
            resp = await client.post(
                "/mcp",
                json=modern_body("prompts/get", params),
                headers=modern_headers("prompts/get", name="security_investigation"),
            )
        assert resp.status_code == 200
        assert resp.json()["result"]["resultType"] == "complete"

    @pytest.mark.asyncio
    async def test_mcp_name_base64_sentinel_decoding(self):
        params = {"name": "security_investigation"}
        encoded = "=?base64?" + base64.b64encode(b"security_investigation").decode() + "?="
        async with _client() as client:
            resp = await client.post(
                "/mcp",
                json=modern_body("prompts/get", params),
                headers=modern_headers("prompts/get", name=encoded),
            )
        assert resp.status_code == 200
        assert resp.json()["result"]["resultType"] == "complete"


class TestLegacyEra:
    @pytest.mark.asyncio
    async def test_initialize_handshake_still_works(self):
        body = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "LegacyClient", "version": "1.0"},
            },
        }
        async with _client() as client:
            resp = await client.post("/mcp", json=body, headers={"MCP-Protocol-Version": "2025-11-25"})
        assert resp.status_code == 200
        result = resp.json()["result"]
        assert result["protocolVersion"] == "2025-11-25"
        assert "capabilities" in result
        # Legacy sessions are still minted
        assert resp.headers.get("MCP-Session-Id")

    @pytest.mark.asyncio
    async def test_initialize_with_modern_version_counter_offers_latest_legacy(self):
        body = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": MODERN, "capabilities": {}, "clientInfo": {}},
        }
        async with _client() as client:
            resp = await client.post("/mcp", json=body)
        assert resp.status_code == 200
        # Modern revisions have no handshake — the server counter-offers its latest legacy revision
        assert resp.json()["result"]["protocolVersion"] == "2025-11-25"

    @pytest.mark.asyncio
    async def test_legacy_ping_and_tools_list_unchanged(self):
        async with _client() as client:
            ping = await client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
            tools = await client.post("/mcp", json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        assert ping.status_code == 200
        assert ping.json()["result"] == {}
        assert tools.status_code == 200
        assert len(tools.json()["result"]["tools"]) > 40

    @pytest.mark.asyncio
    async def test_server_discover_answers_legacy_probes(self):
        """A dual-era client probes with server/discover before falling back to initialize."""
        async with _client() as client:
            resp = await client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "server/discover"})
        assert resp.status_code == 200
        result = resp.json()["result"]
        assert MODERN in result["supportedVersions"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
