"""
Regression tests for the September 2026 production-readiness audit.

Each test pins a defect that was reproduced before it was fixed.
"""

import json
import os
from datetime import datetime, timezone

os.environ.setdefault("AUTH_MODE", "none")

import httpx  # noqa: E402
import pytest  # noqa: E402

from wazuh_mcp_server import server as mcp_server  # noqa: E402
from wazuh_mcp_server.api.wazuh_client import WazuhClient  # noqa: E402
from wazuh_mcp_server.auth import AuthToken  # noqa: E402
from wazuh_mcp_server.clusters import ClusterRegistry, load_cluster_registry  # noqa: E402
from wazuh_mcp_server.config import ConfigurationError, ServerConfig, WazuhConfig  # noqa: E402
from wazuh_mcp_server.security import ToolValidationError, validate_agent_id, validate_limit  # noqa: E402


def _http():
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=mcp_server.app), base_url="http://testserver")


def _session():
    s = mcp_server.MCPSession("t", None)
    s._auth_token = AuthToken(
        token="t", api_key_id="tester", created_at=datetime.now(timezone.utc), scopes=["wazuh:read", "wazuh:write"]
    )
    return s


def _client(protected=""):
    os.environ["WAZUH_PROTECTED_IPS"] = protected
    try:
        return WazuhClient(WazuhConfig(wazuh_host="10.9.9.9", wazuh_user="u", wazuh_pass="p"))
    finally:
        os.environ.pop("WAZUH_PROTECTED_IPS", None)


class TestNumericArguments:
    @pytest.mark.parametrize("value", [True, False, 1.5, float("inf"), float("nan")])
    def test_non_integers_rejected(self, value):
        # process_id=true used to become PID 1; Infinity raised OverflowError
        with pytest.raises(ToolValidationError):
            validate_limit(value, max_val=999999)

    @pytest.mark.parametrize("value,expected", [("12", 12), (12.0, 12), (7, 7)])
    def test_integers_and_numeric_strings_accepted(self, value, expected):
        assert validate_limit(value, max_val=100) == expected

    @pytest.mark.parametrize("raw,expected", [("1", "001"), ("0001", "001"), ("00001", "001"), ("12345", "12345")])
    def test_agent_ids_normalised(self, raw, expected):
        assert validate_agent_id(raw) == expected


class TestProtectedTargets:
    @pytest.mark.parametrize(
        "ip", ["127.0.0.1", "127.000.000.001", "::ffff:7f00:1", "10.9.9.9", "010.009.009.009", "::ffff:10.0.0.53"]
    )
    def test_protected_forms_detected(self, ip):
        assert _client("10.0.0.53")._is_protected_target(ip)

    def test_mapped_ipv4_is_sent_as_plain_ipv4(self):
        assert WazuhClient._validate_ip("::ffff:203.0.113.5") == "203.0.113.5"

    @pytest.mark.parametrize("ip", ["fe80::1%eth0", "1.2.3", "999.1.1.1"])
    def test_invalid_rejected(self, ip):
        with pytest.raises(ValueError):
            WazuhClient._validate_ip(ip)

    @pytest.mark.asyncio
    @pytest.mark.parametrize("method", ["firewall_drop", "host_deny"])
    async def test_firewall_drop_and_host_deny_refuse_protected(self, method):
        client = _client()
        sent = []

        async def execute(data):
            sent.append(data)
            return {}

        client.execute_active_response = execute
        with pytest.raises(ValueError, match="protected target"):
            await getattr(client, method)("001", "127.0.0.1")
        assert not sent


class TestWindowsPaths:
    def test_backslash_allowed_only_in_file_paths(self):
        assert WazuhClient._sanitize_ar_argument(r"C:\Users\bob\evil.exe", "file_path") == r"C:\Users\bob\evil.exe"
        with pytest.raises(ValueError):
            WazuhClient._sanitize_ar_argument(r"a\b", "username")
        with pytest.raises(ValueError):
            WazuhClient._sanitize_ar_argument("/tmp/a;rm -rf /", "file_path")


class _Indexer:
    def __init__(self):
        self.calls = []

    async def get_vulnerability_summary(self, **kw):
        self.calls.append(("vuln_summary", kw))
        return {"data": {"critical": 0, "high": 0}}

    async def get_alerts(self, **kw):
        self.calls.append(("alerts", kw))
        return {"hits": {"total": {"value": 0}, "hits": []}}


class TestAgentScoping:
    @pytest.mark.asyncio
    async def test_risk_assessment_scopes_every_source(self):
        client = _client()
        client._indexer_client = indexer = _Indexer()

        async def request(method, endpoint, **kw):
            return {"data": {"affected_items": [{"id": "001", "status": "active"}]}}

        client._request = request
        await client.perform_risk_assessment(agent_id="001")
        assert ("vuln_summary", {"agent_id": "001"}) in indexer.calls
        assert any(name == "alerts" and kw.get("agent_id") == "001" for name, kw in indexer.calls)

    @pytest.mark.asyncio
    async def test_iso_dashboard_scopes_agents_and_alerts(self):
        client = _client()
        requests, alert_calls = [], []

        async def request(method, endpoint, **kw):
            requests.append((endpoint, kw.get("params")))
            return {"data": {"affected_items": [{"id": "001", "name": "a"}]}}

        async def get_alerts(**kw):
            alert_calls.append(kw)
            return {"data": {"affected_items": []}}

        client._request = request
        client.get_alerts = get_alerts
        await client.get_iso27001_dashboard(agent_id="001")
        agents_params = next(p for e, p in requests if e == "/agents")
        assert agents_params["agents_list"] == "001"
        assert alert_calls[0]["agent_id"] == "001"
        assert all(e in ("/agents", "/manager/stats/analysisd", "/sca/001") for e, _ in requests)

    @pytest.mark.asyncio
    async def test_vulnerability_summary_filters(self):
        client = _client()
        client._indexer_client = indexer = _Indexer()
        await client.get_vulnerability_summary("7d", agent_id="002")
        assert indexer.calls[-1] == ("vuln_summary", {"agent_id": "002", "detected_since": "now-7d"})
        await client.get_vulnerability_summary()
        assert indexer.calls[-1] == ("vuln_summary", {"agent_id": None, "detected_since": None})


class TestConfigFailsFast:
    @pytest.mark.parametrize("env", ["prod", "PRODUCTION", "production"])
    def test_prod_spellings_enforce_production_checks(self, monkeypatch, env):
        monkeypatch.setenv("ENVIRONMENT", env)
        monkeypatch.setenv("AUTH_MODE", "bearer")
        monkeypatch.setenv("AUTH_SECRET_KEY", "change_me_to_a_random_secret")
        with pytest.raises(ConfigurationError, match="placeholder"):
            ServerConfig.from_env()

    @pytest.mark.parametrize("var,value", [("ENVIRONMENT", "staging"), ("AUTH_MODE", "oauht")])
    def test_unknown_values_rejected(self, monkeypatch, var, value):
        monkeypatch.setenv(var, value)
        with pytest.raises(ConfigurationError):
            ServerConfig.from_env()

    @pytest.mark.parametrize("value", ["0", "-5", "30m"])
    def test_session_ttl_validated_when_redis_configured(self, monkeypatch, value):
        from wazuh_mcp_server.session_store import create_session_store

        monkeypatch.setenv("REDIS_URL", "redis://127.0.0.1:6399/0")
        monkeypatch.setenv("SESSION_TTL_SECONDS", value)
        with pytest.raises(ConfigurationError):
            create_session_store()

    @pytest.mark.parametrize("var,value", [("RATE_LIMIT_REQUESTS", "0"), ("MAX_MEMORY_MB", "1")])
    def test_limits_validated(self, monkeypatch, var, value):
        from wazuh_mcp_server.security import MemoryManager, SecurityManager

        monkeypatch.setenv(var, value)
        with pytest.raises(ConfigurationError):
            SecurityManager() if var.startswith("RATE") else MemoryManager()


class TestClustersFile:
    def _load(self, tmp_path, data):
        path = tmp_path / "clusters.json"
        path.write_text(json.dumps(data))
        return load_cluster_registry(object(), str(path))

    BASE = {"id": "c2", "wazuh_host": "h", "wazuh_user": "u", "wazuh_pass": "p"}

    @pytest.mark.parametrize(
        "data",
        [
            {"clusters": [{**BASE, "verify_ssl": "enabled"}]},
            {"clusters": [{**BASE, "wazuh_port": 0}]},
            {"clusters": [{**BASE, "request_timeout_seconds": -1}]},
            [BASE],
            {"clusters": ["c2"]},
        ],
    )
    def test_invalid_rejected(self, tmp_path, data):
        with pytest.raises(ValueError):
            self._load(tmp_path, data)

    def test_host_normalised(self, tmp_path):
        registry = self._load(tmp_path, {"clusters": [{**self.BASE, "wazuh_host": "https://h/"}]})
        assert registry.get("c2").config.wazuh_host == "h"


class TestHttpSurface:
    @pytest.mark.asyncio
    async def test_cors_preflight_allows_2026_headers(self):
        headers = {
            "Origin": "https://claude.ai",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type, mcp-protocol-version, mcp-method, mcp-name",
        }
        async with _http() as client:
            resp = await client.options("/mcp", headers=headers)
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_legacy_sse_answers_gone(self):
        async with _http() as client:
            resp = await client.get("/sse", headers={"Accept": "text/event-stream"})
        assert resp.status_code == 410 and resp.json()["endpoint"] == "/mcp"

    @pytest.mark.asyncio
    async def test_session_store_outage_is_503(self, monkeypatch):
        from wazuh_mcp_server.session_store import SessionStoreUnavailable

        async def down(*a, **k):
            raise SessionStoreUnavailable("redis down")

        monkeypatch.setattr(mcp_server.sessions, "get_or_create", down, raising=False)
        monkeypatch.setattr(mcp_server, "get_or_create_session", down)
        body = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-11-25",
                "capabilities": {},
                "clientInfo": {"name": "t", "version": "1"},
            },
        }
        async with _http() as client:
            resp = await client.post("/mcp", json=body, headers={"Accept": "application/json, text/event-stream"})
        assert resp.status_code == 503 and resp.headers["retry-after"] == "5"


class TestToolsCallScoping:
    @pytest.mark.asyncio
    async def test_vulnerability_summary_tool_passes_agent_and_window(self, monkeypatch):
        calls = []

        class Stub:
            async def get_vulnerability_summary(self, time_range=None, agent_id=None):
                calls.append((time_range, agent_id))
                return {}

        monkeypatch.setattr(mcp_server, "cluster_registry", ClusterRegistry({"default": Stub()}, "default", False))
        args = {"time_range": "30d", "agent_id": "5"}
        await mcp_server.handle_tools_call({"name": "get_wazuh_vulnerability_summary", "arguments": args}, _session())
        await mcp_server.handle_tools_call({"name": "get_wazuh_vulnerability_summary", "arguments": {}}, _session())
        assert calls == [("30d", "005"), (None, None)]


class TestWazuhApiSemantics:
    @pytest.mark.asyncio
    async def test_block_duration_refused_not_silently_permanent(self, monkeypatch):
        calls = []

        class Stub:
            async def block_ip(self, *a, **k):
                calls.append((a, k))
                return {}

        monkeypatch.setattr(mcp_server, "cluster_registry", ClusterRegistry({"default": Stub()}, "default", False))
        args = {"ip_address": "198.51.100.7", "agent_id": "001", "duration": 3600}
        result = await mcp_server.handle_tools_call({"name": "wazuh_block_ip", "arguments": args}, _session())
        assert result["isError"] is True and "duration" in result["content"][0]["text"]
        assert not calls
        args["duration"] = 0
        await mcp_server.handle_tools_call({"name": "wazuh_block_ip", "arguments": args}, _session())
        assert calls

    @pytest.mark.asyncio
    async def test_ar_result_says_dispatched_not_executed(self):
        client = _client()

        async def request(method, path, json=None, params=None):
            return {"data": {"total_affected_items": 1, "total_failed_items": 0, "failed_items": []}}

        client._request = request
        result = await client.execute_active_response({"command": "!host-isolation", "agent_list": ["001"]})
        assert result["data"]["execution_status"] == "dispatched"

    @pytest.mark.parametrize(
        "query,expected",
        [
            ("sshd AND fail*", "sshd + fail*"),
            ("root OR admin", "root | admin"),
            ('ssh NOT "accepted password"', 'ssh -"accepted password"'),
            ('"error AND warning" AND sshd', '"error AND warning" + sshd'),
        ],
    )
    def test_boolean_words_become_simple_query_operators(self, query, expected):
        from wazuh_mcp_server.api.wazuh_indexer import _to_simple_query_syntax

        assert _to_simple_query_syntax(query) == expected

    @pytest.mark.asyncio
    @pytest.mark.parametrize("event,expected", [({"timestamp": "2026-09-23T10:00:00Z"}, True), (None, False)])
    async def test_quarantine_from_fim_deleted_alert(self, event, expected):
        client = _client()
        seen = {}

        class Indexer:
            async def latest_fim_event(self, agent_id, path, kind):
                seen.update(agent_id=agent_id, path=path, kind=kind)
                return event

        client._indexer_client = Indexer()
        result = await client.check_file_quarantine("001", "/tmp/evil")
        assert result["data"]["quarantined"] is expected
        assert seen == {"agent_id": "001", "path": "/tmp/evil", "kind": "deleted"}

    @pytest.mark.asyncio
    async def test_quarantine_fallback_refuses_q_operators(self):
        client = _client()
        client._indexer_client = None
        with pytest.raises(ValueError, match="Indexer"):
            await client.check_file_quarantine("001", "/tmp/x,type=deleted")

    @pytest.mark.asyncio
    async def test_rules_summary_counts_every_page(self):
        client = _client()
        pages = {0: [{"level": 3, "groups": ["a"]}] * 500, 500: [{"level": 5, "groups": ["b"]}] * 200}

        async def request(method, path, params=None, **kw):
            return {"data": {"affected_items": pages.get(params["offset"], []), "total_affected_items": 700}}

        client._request = request
        summary = (await client.get_rules_summary())["data"]
        assert summary["total_rules"] == 700 and summary["by_level"] == {3: 500, 5: 200}

    def test_retry_after_http_date(self):
        from email.utils import format_datetime

        from wazuh_mcp_server.api.wazuh_client import _retry_after_seconds

        future = format_datetime(datetime.now(timezone.utc).replace(microsecond=0), usegmt=True)
        assert _retry_after_seconds("12") == 12
        assert _retry_after_seconds(future) in (0, 1)
        assert _retry_after_seconds("garbage") == 30
