"""
Regression tests for the second September 2026 audit (tools, active response, runtime, deploy).

Each test pins a defect that was reproduced before it was fixed.
"""

import json
import logging
import os
import sys
from datetime import datetime, timedelta, timezone

os.environ.setdefault("AUTH_MODE", "none")

import httpx  # noqa: E402
import pytest  # noqa: E402

from wazuh_mcp_server import server as mcp_server  # noqa: E402
from wazuh_mcp_server.api.wazuh_client import WazuhClient  # noqa: E402
from wazuh_mcp_server.auth import AuthToken  # noqa: E402
from wazuh_mcp_server.clusters import ClusterRegistry  # noqa: E402
from wazuh_mcp_server.config import ConfigurationError, WazuhConfig, env_unquoted, normalize_host  # noqa: E402
from wazuh_mcp_server.security import ToolValidationError, validate_quarantine_path  # noqa: E402


def _session():
    s = mcp_server.MCPSession("t", None)
    s._auth_token = AuthToken(
        token="t", api_key_id="tester", created_at=datetime.now(timezone.utc), scopes=["wazuh:read", "wazuh:write"]
    )
    return s


def _client(host="10.9.9.9"):
    return WazuhClient(WazuhConfig(wazuh_host=host, wazuh_user="u", wazuh_pass="p"))


def _http():
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=mcp_server.app), base_url="http://testserver")


def _alerts(items):
    return {"data": {"affected_items": items, "total_affected_items": len(items)}}


class TestOutputRedactionKeepsResultIntact:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("compact", [True, False])
    async def test_later_alerts_survive_and_json_stays_valid(self, monkeypatch, compact):
        class Stub:
            async def get_alerts(self, **kw):
                return _alerts(
                    [
                        {"rule": {"id": "1"}, "full_log": "curl -H Authorization: Bearer abc"},
                        {"rule": {"id": "2", "level": 15, "description": "ransomware detected"}},
                        {"rule": {"id": "3"}, "full_log": "password=hunter2 user=bob"},
                    ]
                )

        monkeypatch.setattr(mcp_server, "cluster_registry", ClusterRegistry({"default": Stub()}, "default", False))
        result = await mcp_server.handle_tools_call(
            {"name": "get_wazuh_alerts", "arguments": {"compact": compact}}, _session()
        )
        text = result["content"][0]["text"]
        # Authorization: .+ used to delete everything after the first match on one-line JSON
        parsed = json.loads(text[text.index("{") :])
        assert "ransomware detected" in text and "abc" not in text and "hunter2" not in text
        assert parsed["data"]["total_affected_items"] == 3


class TestAuditLinesNameTheCluster:
    @pytest.mark.asyncio
    async def test_cluster_recorded(self, monkeypatch, caplog):
        class Stub:
            async def isolate_host(self, agent_id):
                return {"data": {"total_affected_items": 1, "failed_items": []}}

        registry = ClusterRegistry({"default": Stub(), "eu": Stub()}, "default", True)
        monkeypatch.setattr(mcp_server, "cluster_registry", registry)
        monkeypatch.setattr(mcp_server, "_require_action_confirmation", lambda: False)
        with caplog.at_level(logging.WARNING):
            await mcp_server.handle_tools_call(
                {"name": "wazuh_isolate_host", "arguments": {"agent_id": "001", "cluster_id": "eu"}}, _session()
            )
        lines = [r.getMessage() for r in caplog.records if r.getMessage().startswith("AUDIT")]
        assert lines and all("cluster=eu" in line for line in lines)


class TestIpv6ManagerIsProtected:
    def test_bracketed_manager_address_is_protected_exactly(self):
        client = _client("[2001:db8::1]")
        assert client._is_protected_target("2001:db8::1")
        # /32 used to cover a whole provider-sized IPv6 network
        assert not client._is_protected_target("2001:db8:ffff::5")

    def test_ipv4_manager_still_protected(self):
        assert _client("10.9.9.9")._is_protected_target("10.9.9.9")


class TestWindowsQuarantinePaths:
    @pytest.mark.parametrize(
        "path",
        [
            r"C:\Windows.\System32\drivers\x.sys",
            r"C:\Windows \System32\x.dll",
            r"C:\Windows::$INDEX_ALLOCATION\System32\x",
            r"C:\PROGRA~1\ossec-agent\ossec.conf",
            r"C:\Users\bob\evil.exe:hidden",
        ],
    )
    def test_spellings_that_reach_system_directories_refused(self, path):
        with pytest.raises(ToolValidationError):
            validate_quarantine_path(path)

    def test_ordinary_user_file_accepted(self):
        assert validate_quarantine_path(r"C:\Users\bob\Downloads\evil.exe")


class TestGenericActiveResponseRefusesValidatedCommands:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "command,params,dedicated",
        [
            ("quarantine", {"file": "/etc/shadow"}, "wazuh_quarantine_file"),
            ("!kill-process", {"pid": "1"}, "wazuh_kill_process"),
            ("disable-account", {"user": "root"}, "wazuh_disable_user"),
        ],
    )
    async def test_refused_with_pointer(self, command, params, dedicated):
        client = _client()
        sent = []

        async def fake_exec(data):
            sent.append(data)
            return {}

        client.execute_active_response = fake_exec
        with pytest.raises(ValueError, match=dedicated):
            await client.run_active_response("001", command, params)
        assert sent == []


class TestExplicitNullAlertFields:
    @pytest.fixture
    def client(self):
        class Indexer:
            async def get_alerts(self, **kw):
                return _alerts([{"rule": None, "agent": None, "data": None}, {"rule": {"id": "5", "level": 12}}])

        c = _client()
        c._indexer_client = Indexer()

        async def get_alerts(**kw):
            return await c._indexer_client.get_alerts(**kw)

        c.get_alerts = get_alerts
        return c

    @pytest.mark.asyncio
    async def test_top_threats(self, client):
        assert await client.get_top_security_threats(10, "24h")

    @pytest.mark.asyncio
    async def test_alert_patterns(self, client):
        assert await client.analyze_alert_patterns("24h", 1)

    @pytest.mark.asyncio
    async def test_iso27001_alerts(self, client):
        assert "error" not in await client.get_iso27001_alerts("24h")


class TestCheckBlockedIpCanonicalises:
    @pytest.mark.asyncio
    async def test_mapped_ipv4_queried_as_sent_by_block_tools(self):
        seen = {}

        class Indexer:
            async def get_alerts(self, **kw):
                seen.update(kw)
                return _alerts([])

        client = _client()
        client._indexer_client = Indexer()
        await client.check_blocked_ip("::ffff:1.2.3.4")
        assert seen["srcip"] == "1.2.3.4"


class TestSearchLevelValidation:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("level", ["-1", "99999999999999999999", "16", "abc"])
    async def test_out_of_range_levels_refused(self, level):
        result = await mcp_server.handle_tools_call(
            {"name": "search_security_events", "arguments": {"query": "ssh", "level": level}}, _session()
        )
        assert result["isError"] is True and "level" in result["content"][0]["text"]


class TestSchemaDefaults:
    @pytest.mark.asyncio
    async def test_default_never_above_maximum(self, monkeypatch):
        import dataclasses

        monkeypatch.setattr(mcp_server, "config", dataclasses.replace(mcp_server.config, MAX_ALERTS_PER_QUERY=50))
        tools = (await mcp_server.handle_tools_list({}, _session()))["tools"]
        for tool in tools:
            for prop in tool["inputSchema"].get("properties", {}).values():
                if "default" in prop and "maximum" in prop:
                    assert prop["default"] <= prop["maximum"], tool["name"]


class TestHostValidation:
    @pytest.mark.parametrize("host", ["https://127.0.0.1:47102/", "wazuh:55000", "[2001:db8::1]:55000", "h/api"])
    def test_port_or_path_in_host_refused(self, host):
        with pytest.raises(ConfigurationError):
            normalize_host(host)

    @pytest.mark.parametrize(
        "host,expected",
        [("https://10.0.0.1/", "10.0.0.1"), ("2001:db8::1", "[2001:db8::1]"), ("[2001:db8::1]", "[2001:db8::1]")],
    )
    def test_hosts_normalised(self, host, expected):
        assert normalize_host(host) == expected


class TestQuotedEnvValues:
    @pytest.mark.parametrize("raw", ['"wazuh:read wazuh:write"', "'wazuh:read wazuh:write'", "wazuh:read wazuh:write"])
    def test_one_pair_of_quotes_stripped(self, monkeypatch, raw):
        monkeypatch.setenv("MCP_API_KEY_SCOPES", raw)
        assert env_unquoted("MCP_API_KEY_SCOPES") == "wazuh:read wazuh:write"

    def test_key_scopes_survive_docker_env_file_quotes(self, monkeypatch):
        from wazuh_mcp_server.auth import AuthManager

        monkeypatch.setenv("MCP_API_KEY_SCOPES", '"wazuh:read wazuh:write"')
        assert AuthManager._configured_key_scopes() == ["wazuh:read", "wazuh:write"]


class TestSessionTtl:
    def test_expiry_follows_store_ttl(self, monkeypatch):
        class Store:
            ttl_seconds = 7200

        monkeypatch.setattr(mcp_server, "_session_store", Store())
        session = mcp_server.MCPSession("s", None)
        session.last_activity = datetime.now(timezone.utc) - timedelta(minutes=40)
        # a fixed 30 minutes used to expire sessions Redis still held
        assert not session.is_expired()

    def test_in_memory_default_unchanged(self):
        session = mcp_server.MCPSession("s", None)
        session.last_activity = datetime.now(timezone.utc) - timedelta(minutes=31)
        assert session.is_expired()


class TestRootEndpointMatchesMcp:
    @pytest.mark.asyncio
    async def test_attack_strings_in_tool_arguments_not_blocked_on_root(self):
        body = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "../../etc/passwd union select", "version": "1"},
            },
        }
        async with _http() as client:
            root = await client.post("/", json=body, headers={"Accept": "application/json, text/event-stream"})
            mcp = await client.post("/mcp", json=body, headers={"Accept": "application/json, text/event-stream"})
        assert root.status_code == mcp.status_code == 200

    @pytest.mark.asyncio
    async def test_non_sse_get_answers_like_mcp(self):
        async with _http() as client:
            root = await client.get("/", headers={"Accept": "application/json"})
            mcp = await client.get("/mcp", headers={"Accept": "application/json"})
        assert root.status_code == mcp.status_code
        assert "mcp-session-id" not in root.headers


class TestJsonRpcEdgeCases:
    async def _post(self, path, body):
        async with _http() as client:
            return await client.post(path, json=body, headers={"Accept": "application/json, text/event-stream"})

    @pytest.mark.asyncio
    @pytest.mark.parametrize("path", ["/", "/mcp"])
    async def test_unhashable_notification_method_is_not_a_500(self, path):
        assert (await self._post(path, {"jsonrpc": "2.0", "method": []})).status_code < 500

    def test_boolean_id_rejected(self):
        with pytest.raises(ValueError):
            mcp_server.MCPRequest(jsonrpc="2.0", id=True, method="ping")

    @pytest.mark.asyncio
    async def test_validation_error_keeps_the_request_id(self):
        resp = await self._post("/mcp", {"jsonrpc": "2.0", "id": 7, "method": "ping", "params": []})
        assert resp.json()["id"] == 7

    @pytest.mark.asyncio
    async def test_completion_with_non_string_uri_is_invalid_params(self):
        request = mcp_server.MCPRequest(
            jsonrpc="2.0",
            id=1,
            method="completion/complete",
            params={"ref": {"type": "ref/resource", "uri": 5}, "argument": {"name": "a", "value": ""}},
        )
        response = await mcp_server.process_mcp_request(request, _session())
        assert response.error["code"] == -32602


class TestEntryPoint:
    def test_workers_pinned_so_web_concurrency_cannot_break_startup(self, monkeypatch):
        import uvicorn

        from wazuh_mcp_server import __main__ as entry

        captured = {}
        monkeypatch.setattr(uvicorn, "run", lambda app, **kw: captured.update(kw))
        monkeypatch.setattr(sys, "argv", ["wazuh_mcp_server"])
        monkeypatch.setenv("WEB_CONCURRENCY", "2")
        entry.main()
        assert captured["workers"] == 1

    def test_help_does_not_start_the_server(self, monkeypatch, capsys):
        import uvicorn

        from wazuh_mcp_server import __main__ as entry

        monkeypatch.setattr(uvicorn, "run", lambda *a, **kw: pytest.fail("server started"))
        monkeypatch.setattr(sys, "argv", ["wazuh_mcp_server", "--help"])
        entry.main()
        assert "usage" in capsys.readouterr().out


class TestReadyWithRedis:
    @pytest.mark.asyncio
    async def test_ready_does_not_fail_on_the_redis_branch(self, monkeypatch):
        from wazuh_mcp_server.session_store import RedisSessionStore

        class FakeRedisStore(RedisSessionStore):
            def __init__(self):
                self.ttl_seconds = 1800

            async def count(self):
                return 3

        monkeypatch.setattr(mcp_server, "_session_store", FakeRedisStore())
        monkeypatch.setattr(mcp_server, "_ready_cache", None)
        async with _http() as client:
            body = (await client.get("/ready")).json()
        assert body.get("metrics", {}).get("total_sessions") == 3, body


class TestDeployVerdictGaps:
    @pytest.mark.parametrize("key", ["wazuh_short", "not-a-wazuh-key", "wazuh_" + "a" * 44])
    def test_malformed_mcp_api_key_stops_startup(self, monkeypatch, key):
        from wazuh_mcp_server.config import ServerConfig

        monkeypatch.setenv("MCP_API_KEY", key)
        # used to log a warning and run with a generated key nobody knew
        with pytest.raises(ConfigurationError, match="MCP_API_KEY"):
            ServerConfig.from_env()

    @pytest.mark.parametrize("raw", ["[{bad json", '{"id": "k"}'])
    def test_unusable_api_keys_stops_startup(self, monkeypatch, raw):
        from wazuh_mcp_server.config import ServerConfig

        monkeypatch.delenv("MCP_API_KEY", raising=False)
        monkeypatch.setenv("API_KEYS", raw)
        with pytest.raises(ConfigurationError, match="API_KEYS"):
            ServerConfig.from_env()

    @pytest.mark.asyncio
    async def test_ready_names_the_manager_failure(self, monkeypatch, caplog):
        class Client:
            _indexer_client = None

            async def ping_manager(self):
                raise ConnectionError("TLS certificate verification failed for wazuh.internal. The stock ...")

        monkeypatch.setattr(mcp_server, "wazuh_client", Client())
        monkeypatch.setattr(mcp_server, "_ready_cache", None)
        monkeypatch.setattr(mcp_server, "_last_manager_failure", None)
        with caplog.at_level(logging.ERROR):
            async with _http() as client:
                body = (await client.get("/ready")).json()
        assert body["services"]["wazuh_manager_reason"] == "tls_verification_failed"
        assert "wazuh.internal" not in json.dumps(body)  # unauthenticated endpoint: category only
        assert any("wazuh.internal" in r.getMessage() for r in caplog.records)
