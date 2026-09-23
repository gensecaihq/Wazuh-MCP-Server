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


class TestUnknownArguments:
    @pytest.mark.asyncio
    async def test_misspelled_filter_refused_not_ignored(self, monkeypatch):
        calls = []

        class Stub:
            async def get_alerts(self, **kw):
                calls.append(kw)
                return {"data": {"affected_items": []}}

        monkeypatch.setattr(mcp_server, "cluster_registry", ClusterRegistry({"default": Stub()}, "default", False))
        result = await mcp_server.handle_tools_call(
            {"name": "get_wazuh_alerts", "arguments": {"agentid": "001"}}, _session()
        )
        assert result["isError"] is True and "agentid" in result["content"][0]["text"]
        assert not calls


class TestOutputRedaction:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("compact", [True, False])
    async def test_credentials_redacted_in_every_mode(self, monkeypatch, compact):
        class Stub:
            async def get_alerts(self, **kw):
                alert = {"rule": {"id": "1"}, "full_log": "login failed user=bob password=hunter2 token=abc123"}
                return {"data": {"affected_items": [alert], "total_affected_items": 1}}

        monkeypatch.setattr(mcp_server, "cluster_registry", ClusterRegistry({"default": Stub()}, "default", False))
        result = await mcp_server.handle_tools_call(
            {"name": "get_wazuh_alerts", "arguments": {"compact": compact}}, _session()
        )
        text = result["content"][0]["text"]
        assert "hunter2" not in text and "abc123" not in text

    @pytest.mark.asyncio
    async def test_manager_logs_redacted(self, monkeypatch):
        class Stub:
            async def search_manager_logs(self, query, limit):
                return {"data": {"affected_items": [{"description": "db password=hunter2 rejected"}]}}

        monkeypatch.setattr(mcp_server, "cluster_registry", ClusterRegistry({"default": Stub()}, "default", False))
        result = await mcp_server.handle_tools_call(
            {"name": "search_wazuh_manager_logs", "arguments": {"query": "password"}}, _session()
        )
        assert "hunter2" not in result["content"][0]["text"]


class TestBearerTokenBinding:
    @pytest.fixture
    def minted(self, monkeypatch):
        from wazuh_mcp_server.auth import APIKey, auth_manager, create_access_token

        secret = "test-secret-key-at-least-32-characters-long"
        monkeypatch.setattr(mcp_server.config, "AUTH_SECRET_KEY", secret)
        key = APIKey(id="k1", name="k1", key_hash="x", created_at=datetime.now(timezone.utc), scopes=["wazuh:read"])
        monkeypatch.setitem(auth_manager.api_keys, "k1", key)
        return key, secret, create_access_token

    @pytest.mark.asyncio
    async def test_revoking_the_key_ends_its_tokens(self, minted):
        from wazuh_mcp_server.auth import verify_bearer_token

        key, secret, mint = minted
        token = mint({"sub": "k1", "scope": "wazuh:read"}, secret)
        assert (await verify_bearer_token(f"Bearer {token}")).api_key_id == "jwt:k1"
        key.active = False
        with pytest.raises(ValueError):
            await verify_bearer_token(f"Bearer {token}")

    @pytest.mark.asyncio
    @pytest.mark.parametrize("claims", [{"type": "refresh"}, {"exp": None}])
    async def test_refresh_or_non_expiring_tokens_refused(self, minted, claims):
        import jwt as pyjwt

        from wazuh_mcp_server.auth import verify_bearer_token

        _, secret, _ = minted
        payload = {"sub": "k1", "scope": "wazuh:read", "exp": int(datetime.now(timezone.utc).timestamp()) + 600}
        payload.update(claims)
        payload = {k: v for k, v in payload.items() if v is not None}
        with pytest.raises(ValueError):
            await verify_bearer_token(f"Bearer {pyjwt.encode(payload, secret, algorithm='HS256')}")

    def test_env_key_id_is_stable_across_instances(self, monkeypatch):
        from wazuh_mcp_server.auth import AuthManager

        monkeypatch.setenv("MCP_API_KEY", "wazuh_" + "a" * 43)
        assert list(AuthManager().api_keys) == list(AuthManager().api_keys)


class TestBodyLimit:
    @pytest.mark.asyncio
    async def test_chunked_upload_stops_at_the_limit(self):
        consumed = 0

        async def receive():
            nonlocal consumed
            consumed += 1
            return {"type": "http.request", "body": b"x" * (1024 * 1024), "more_body": consumed < 200}

        status = {}

        async def send(message):
            if message["type"] == "http.response.start":
                status["code"] = message["status"]

        scope = {
            "type": "http",
            "method": "POST",
            "path": "/auth/token",
            "raw_path": b"/auth/token",
            "query_string": b"",
            "headers": [(b"content-type", b"application/json"), (b"host", b"t")],
            "client": ("127.0.0.1", 1),
            "server": ("t", 80),
            "scheme": "http",
            "http_version": "1.1",
            "root_path": "",
        }
        await mcp_server.app(scope, receive, send)
        # No Content-Length: the body used to be buffered in full before the size check
        assert status["code"] == 413 and consumed <= 3


class TestEndpointGuards:
    @pytest.mark.asyncio
    async def test_root_rejects_unsupported_protocol_version(self):
        async with _http() as client:
            resp = await client.post(
                "/", json={"jsonrpc": "2.0", "id": 1, "method": "ping"}, headers={"MCP-Protocol-Version": "2099-01-01"}
            )
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_delete_checks_origin(self):
        async with _http() as client:
            resp = await client.delete("/mcp", headers={"MCP-Session-Id": "x", "Origin": "https://evil.example"})
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_failed_auth_is_rate_limited(self, monkeypatch):
        from fastapi import HTTPException

        from wazuh_mcp_server.security import RateLimiter

        async def reject(*a, **k):
            raise HTTPException(status_code=401, detail="bad token")

        monkeypatch.setattr(mcp_server, "verify_authentication", reject)
        monkeypatch.setattr(mcp_server, "rate_limiter", RateLimiter(max_requests=5, window_seconds=60))
        async with _http() as client:
            codes = [
                (await client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"})).status_code
                for _ in range(8)
            ]
        assert codes[:5] == [401] * 5 and 429 in codes[5:]


class TestResources:
    async def _read(self, monkeypatch, uri, stub):
        monkeypatch.setattr(mcp_server, "wazuh_client", stub)
        request = mcp_server.MCPRequest(jsonrpc="2.0", id=1, method="resources/read", params={"uri": uri})
        return await mcp_server.process_mcp_request(request, _session())

    @pytest.mark.asyncio
    async def test_advertised_agent_template_is_readable(self, monkeypatch):
        seen = {}

        class Stub:
            async def get_agents(self, agent_id=None, **kw):
                seen["agent_id"] = agent_id
                return {"data": {"affected_items": [{"id": agent_id}]}}

        resp = await self._read(monkeypatch, "wazuh://agents/1/info", Stub())
        assert resp.error is None and seen["agent_id"] == "001"

    @pytest.mark.asyncio
    async def test_unknown_uri_is_resource_not_found(self, monkeypatch):
        resp = await self._read(monkeypatch, "wazuh://nope", object())
        assert resp.error["code"] == -32002

    @pytest.mark.asyncio
    async def test_backend_error_is_internal_and_not_leaked(self, monkeypatch):
        class Stub:
            async def get_manager_info(self):
                raise ConnectionError("connect to https://10.0.0.5:55000 failed: user=wazuh-wui")

        resp = await self._read(monkeypatch, "wazuh://manager/info", Stub())
        assert resp.error["code"] == -32603
        assert "10.0.0.5" not in json.dumps(resp.error)


class TestLegacySessions:
    @pytest.mark.asyncio
    async def test_only_initialize_stores_a_session(self):
        before = len(await mcp_server.sessions.get_all())
        async with _http() as client:
            for _ in range(5):
                r = await client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
                assert r.status_code == 200 and "MCP-Session-Id" not in r.headers
            init = await client.post(
                "/mcp",
                json={
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": "2025-11-25",
                        "capabilities": {},
                        "clientInfo": {"name": "t", "version": "1"},
                    },
                },
            )
        assert init.headers.get("MCP-Session-Id")
        assert len(await mcp_server.sessions.get_all()) == before + 1


class TestAlertSummaryAndSize:
    @pytest.mark.asyncio
    async def test_rule_groups_counted_per_group(self):
        client = _client()

        class Indexer:
            async def get_alerts(self, **kw):
                items = [
                    {"rule": {"groups": g}}
                    for g in (["sshd", "authentication_failed"], ["authentication_failed", "sshd"], ["sshd"])
                ]
                return {"data": {"affected_items": items, "total_affected_items": 3}}

        client._indexer_client = Indexer()
        groups = (await client.get_alert_summary("24h", "rule.groups"))["data"]["groups"]
        assert groups == {"sshd": 3, "authentication_failed": 2}

    @pytest.mark.asyncio
    async def test_non_string_group_by_is_a_validation_error(self):
        result = await mcp_server.handle_tools_call(
            {"name": "get_wazuh_alert_summary", "arguments": {"group_by": ["rule.id"]}}, _session()
        )
        assert result["isError"] is True and "group_by" in result["content"][0]["text"]

    @pytest.mark.asyncio
    async def test_oversized_result_truncated_with_notice(self, monkeypatch):
        monkeypatch.setattr(mcp_server, "MAX_TOOL_RESPONSE_CHARS", 1000)

        class Stub:
            async def get_rules_summary(self):
                return {"data": {"blob": "x" * 5000}}

        monkeypatch.setattr(mcp_server, "cluster_registry", ClusterRegistry({"default": Stub()}, "default", False))
        result = await mcp_server.handle_tools_call({"name": "get_wazuh_rules_summary", "arguments": {}}, _session())
        text = result["content"][0]["text"]
        assert len(text) < 1300 and "Truncated" in text


class TestInputEdgeCases:
    @pytest.mark.parametrize("value", ["2026-13-45", "2026-09-23T25:99:99Z"])
    def test_impossible_timestamps_rejected(self, value):
        from wazuh_mcp_server.security import validate_timestamp

        with pytest.raises(ToolValidationError):
            validate_timestamp(value)

    def test_real_timestamps_and_date_math_accepted(self):
        from wazuh_mcp_server.security import validate_timestamp

        assert validate_timestamp("2026-09-23T14:00:00Z") == "2026-09-23T14:00:00Z"
        assert validate_timestamp("now-24h") == "now-24h"

    @pytest.mark.asyncio
    async def test_active_response_parameters_must_be_an_object(self):
        result = await mcp_server.handle_tools_call(
            {
                "name": "wazuh_active_response",
                "arguments": {"agent_id": "001", "command": "!restart-wazuh", "parameters": ["a"]},
            },
            _session(),
        )
        assert result["isError"] is True and "parameters" in result["content"][0]["text"]

    def test_all_alongside_other_toolsets_means_all(self):
        from wazuh_mcp_server.toolsets import ALL_TOOLS, resolve_enabled_tools

        assert resolve_enabled_tools("all,alerts", None) == ALL_TOOLS


class TestJsonRpcEnvelope:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "body",
        [
            {"jsonrpc": "1.0", "id": 1, "method": "ping"},
            {"id": 1, "method": "ping"},
            {"jsonrpc": "2.0", "id": None, "method": "ping"},
        ],
    )
    async def test_invalid_envelope_rejected(self, body):
        async with _http() as client:
            resp = await client.post("/mcp", json=body)
        assert resp.status_code == 400 and resp.json()["error"]["code"] == -32600

    @pytest.mark.asyncio
    @pytest.mark.parametrize("batch", [[1, 2], [{"jsonrpc": "2.0", "id": 1}]])
    async def test_invalid_batch_items_answered_not_dropped(self, batch):
        async with _http() as client:
            resp = await client.post("/", json=batch)
        assert resp.status_code == 200
        assert all(item["error"]["code"] == -32600 for item in resp.json())


class TestParamTypes:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "method,params",
        [
            ("logging/setLevel", {"level": 5}),
            ("prompts/get", {"name": "security_incident_analysis", "arguments": ["x"]}),
            (
                "completion/complete",
                {"ref": {"type": "ref/prompt", "name": "x"}, "argument": {"name": "a", "value": 5}},
            ),
        ],
    )
    async def test_wrong_types_are_invalid_params(self, method, params):
        request = mcp_server.MCPRequest(jsonrpc="2.0", id=1, method=method, params=params)
        resp = await mcp_server.process_mcp_request(request, _session())
        assert resp.error["code"] == -32602


class TestInitializeHeader:
    @pytest.mark.asyncio
    async def test_header_matches_negotiated_version(self):
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
            resp = await client.post("/mcp", json=body)
        assert resp.headers["MCP-Protocol-Version"] == resp.json()["result"]["protocolVersion"] == "2025-11-25"


class TestSseEventIds:
    @pytest.mark.asyncio
    async def test_streams_on_one_session_have_distinct_ids(self):
        session = mcp_server.MCPSession("s", None)
        first = [await mcp_server.generate_sse_events(session).__anext__() for _ in range(2)]
        ids = [chunk.split("\n")[0] for chunk in first]
        assert ids[0].startswith("id: ") and ids[0] != ids[1]
