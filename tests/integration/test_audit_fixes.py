"""
Regression tests for the v4.3.0 end-to-end audit fixes.
Grouped by wave; each test pins a specific confirmed defect that was fixed.
"""

import os
from datetime import datetime, timezone

# Must be set before importing the server module, which freezes config from env
# at import time. This file sorts first alphabetically, so it is often the first
# importer of the server module across the whole test session.
os.environ.setdefault("AUTH_MODE", "none")

import pytest

from wazuh_mcp_server import server as mcp_server
from wazuh_mcp_server.auth import AuthToken
from wazuh_mcp_server.clusters import ClusterRegistry
from wazuh_mcp_server.server import MCPSession, handle_tools_call


def _session(scopes=("wazuh:read",)):
    s = MCPSession("t", None)
    s.authenticated = True
    s._auth_token = AuthToken(
        token="t", api_key_id="tester", created_at=datetime.now(timezone.utc), scopes=list(scopes)
    )
    return s


class _StubClient:
    def __init__(self):
        self.calls = []

    async def get_sca_policy_checks(self, agent_id, policy_id):
        self.calls.append(("get_sca_policy_checks", agent_id, policy_id))
        return {"data": {"affected_items": []}}


@pytest.fixture
def stub_cluster(monkeypatch):
    stub = _StubClient()
    monkeypatch.setattr(mcp_server, "cluster_registry", ClusterRegistry({"default": stub}, "default", False))
    return stub


# ---- W1: get_sca_policy_checks was 100% broken (validate_input wrong signature) ----
class TestScaPolicyChecks:
    def test_validate_policy_id(self):
        from wazuh_mcp_server.security import ToolValidationError, validate_policy_id

        assert validate_policy_id("cis_debian10") == "cis_debian10"
        assert validate_policy_id("cis_apple_macOS_12.0") == "cis_apple_macOS_12.0"
        with pytest.raises(ToolValidationError):
            validate_policy_id(None)
        with pytest.raises(ToolValidationError):
            validate_policy_id("bad id!")

    @pytest.mark.asyncio
    async def test_tool_dispatches_without_error(self, stub_cluster):
        result = await handle_tools_call(
            {"name": "get_sca_policy_checks", "arguments": {"agent_id": "001", "policy_id": "cis_debian10"}},
            _session(),
        )
        assert result["isError"] is False
        assert stub_cluster.calls == [("get_sca_policy_checks", "001", "cis_debian10")]


# ---- W1: OAuth regression — pre-registered client is public, usable without a secret ----
class TestOAuthPreRegisteredClientPublic:
    def _mgr(self):
        from types import SimpleNamespace

        from wazuh_mcp_server.oauth import OAuthManager

        return OAuthManager(
            SimpleNamespace(
                AUTH_SECRET_KEY="test-secret-key-at-least-32-characters-long",
                OAUTH_ENABLE_DCR=False,
                OAUTH_ACCESS_TOKEN_TTL=3600,
                OAUTH_REFRESH_TOKEN_TTL=86400,
                OAUTH_AUTHORIZATION_CODE_TTL=600,
                OAUTH_ISSUER_URL="",
            )
        )

    def test_preregistered_client_is_public(self):
        mgr = self._mgr()
        client = mgr.clients["claude-desktop"]
        assert client.client_secret == ""
        assert client.token_endpoint_auth_method == "none"
        assert mgr.client_requires_secret(client) is False

    def test_full_pkce_flow_without_secret(self):
        import base64
        import hashlib
        import secrets as _secrets

        mgr = self._mgr()
        verifier = _secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        redirect = "https://claude.ai/api/mcp/auth_callback"

        # validate_client with no secret must resolve the public client...
        client = mgr.validate_client("claude-desktop", None)
        assert client is not None
        # ...and the confidential-secret gate must NOT apply.
        assert mgr.client_requires_secret(client) is False

        code = mgr.create_authorization_code("claude-desktop", redirect, "wazuh:read", challenge, "S256")
        tokens = mgr.exchange_code_for_tokens(code, "claude-desktop", redirect, verifier)
        assert tokens["access_token"]
        assert mgr.validate_access_token(tokens["access_token"]) is not None


# ---- W1: legacy / endpoint hardened like /mcp ----
class TestLegacyRootEndpointHardened:
    def _http(self, monkeypatch):
        import httpx

        monkeypatch.setattr(mcp_server.config, "AUTH_MODE", "none")
        return httpx.AsyncClient(transport=httpx.ASGITransport(app=mcp_server.app), base_url="http://testserver")

    @pytest.mark.asyncio
    async def test_scalar_body_is_400_not_500(self, monkeypatch):
        async with self._http(monkeypatch) as client:
            resp = await client.post("/", content="123", headers={"Content-Type": "application/json"})
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_deep_nested_body_is_400_not_500(self, monkeypatch):
        payload = "[" * 500 + "]" * 500
        async with self._http(monkeypatch) as client:
            resp = await client.post("/", content=payload, headers={"Content-Type": "application/json"})
        assert resp.status_code == 400


# ---- W1: aggregate_alerts tolerates a legacy integer hits.total ----
class TestAggregateAlertsIntTotal:
    @pytest.mark.asyncio
    async def test_int_total_does_not_crash(self):
        from wazuh_mcp_server.api.wazuh_indexer import WazuhIndexerClient

        indexer = WazuhIndexerClient(host="localhost", username="u", password="p")

        async def fake_body(index, body):
            # Legacy OpenSearch form: hits.total is a bare int, not {"value": N}
            return {"hits": {"total": 4321, "hits": []}, "aggregations": {}}

        indexer._execute_body = fake_body
        indexer._circuit_breaker = None
        result = await indexer.aggregate_alerts(timestamp_start="now-24h")
        assert result["total_alerts"] == 4321


# ---- W1: previously-ignored client tuning env vars now flow through ----
class TestConfigVarsWired:
    def test_server_config_reads_tuning_vars(self, monkeypatch):
        from wazuh_mcp_server.config import ServerConfig

        monkeypatch.setenv("WAZUH_HOST", "h")
        monkeypatch.setenv("WAZUH_USER", "u")
        monkeypatch.setenv("WAZUH_PASS", "p")
        monkeypatch.setenv("REQUEST_TIMEOUT_SECONDS", "45")
        monkeypatch.setenv("MAX_CONNECTIONS", "25")
        monkeypatch.setenv("MAX_ALERTS_PER_QUERY", "5000")
        cfg = ServerConfig.from_env()
        assert cfg.REQUEST_TIMEOUT_SECONDS == 45
        assert cfg.MAX_CONNECTIONS == 25
        assert cfg.MAX_ALERTS_PER_QUERY == 5000

    def test_wazuh_client_uses_tuning(self):
        from wazuh_mcp_server.api.wazuh_client import WazuhClient
        from wazuh_mcp_server.config import WazuhConfig

        client = WazuhClient(
            WazuhConfig(wazuh_host="h", wazuh_user="u", wazuh_pass="p", request_timeout_seconds=45, max_connections=25)
        )
        assert client.config.request_timeout_seconds == 45
        assert client.config.max_connections == 25


# ============================ WAVE 2 ============================


class _FakeResp:
    def raise_for_status(self):
        return None

    def json(self):
        return {"data": {}}


class _FakeHttp:
    async def request(self, *a, **k):
        return _FakeResp()


# ---- W2: cold-start init race — concurrent first requests initialize once ----
class TestColdStartInitRace:
    @pytest.mark.asyncio
    async def test_concurrent_first_requests_initialize_once(self):
        import asyncio

        from wazuh_mcp_server.api.wazuh_client import WazuhClient
        from wazuh_mcp_server.config import WazuhConfig

        client = WazuhClient(WazuhConfig(wazuh_host="h", wazuh_user="u", wazuh_pass="p"))
        client._circuit_breaker = None  # call _execute_request directly, bypass breaker
        calls = {"n": 0}

        async def fake_initialize():
            calls["n"] += 1
            await asyncio.sleep(0.02)  # widen the race window
            client.client = _FakeHttp()
            client.token = "tok"

        client.initialize = fake_initialize
        results = await asyncio.gather(*[client._execute_request("GET", "/x") for _ in range(12)])
        assert calls["n"] == 1
        assert all(r == {"data": {}} for r in results)


# ---- W2: body Content-Length precheck + oversized body → 413 ----
class TestBodySizeDoS:
    @pytest.mark.asyncio
    async def test_oversized_body_rejected(self, monkeypatch):
        import httpx

        monkeypatch.setattr(mcp_server.config, "AUTH_MODE", "none")
        big = "x" * (1024 * 1024 + 1024)  # just over the 1 MB cap
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=mcp_server.app), base_url="http://testserver"
        ) as client:
            resp = await client.post("/mcp", content=big, headers={"Content-Type": "application/json"})
        assert resp.status_code == 413


# ---- W2: middleware rate limiter exempts probes / self-limited endpoints ----
class TestRateLimiterReconciliation:
    def test_exempt_and_self_limited_path_sets(self):
        from wazuh_mcp_server.security import RATE_LIMIT_EXEMPT_PATHS, RATE_LIMIT_SELF_LIMITED_PATHS

        assert {"/health", "/ready", "/metrics"} <= RATE_LIMIT_EXEMPT_PATHS
        assert {"/", "/mcp", "/sse"} <= RATE_LIMIT_SELF_LIMITED_PATHS

    @pytest.mark.asyncio
    async def test_probe_endpoint_not_middleware_rate_limited(self, monkeypatch):
        import httpx

        # Force the middleware limiter to deny everything.
        monkeypatch.setattr(mcp_server.security_manager.rate_limiter, "is_allowed", lambda key: (False, 30))
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=mcp_server.app), base_url="http://testserver"
        ) as client:
            # /health is exempt → not 429 even though the limiter denies all.
            health = await client.get("/health")
        assert health.status_code == 200


# ---- W2: JWT principal key is stable per-subject, not a shared "jwt_auth" ----
class TestPrincipalKey:
    @pytest.mark.asyncio
    async def test_jwt_sub_becomes_api_key_id(self, monkeypatch):
        from wazuh_mcp_server.auth import create_access_token, verify_bearer_token

        secret = "test-secret-key-at-least-32-characters-long"
        # verify_bearer_token decodes with get_config().AUTH_SECRET_KEY (the shared
        # singleton, i.e. mcp_server.config); sign the tokens with the same key.
        monkeypatch.setattr(mcp_server.config, "AUTH_SECRET_KEY", secret)
        tok_a = create_access_token({"sub": "key-A", "scope": "wazuh:read"}, secret)
        tok_b = create_access_token({"sub": "key-B", "scope": "wazuh:read"}, secret)

        a = await verify_bearer_token(f"Bearer {tok_a}")
        b = await verify_bearer_token(f"Bearer {tok_b}")
        assert a.api_key_id == "jwt:key-A"
        assert b.api_key_id == "jwt:key-B"
        assert a.api_key_id != b.api_key_id


# ---- W2: circuit breaker treats a 4xx during the half-open trial as liveness ----
class TestCircuitBreaker4xxDuringTrial:
    @pytest.mark.asyncio
    async def test_service_alive_error_closes_half_open_trial(self):
        from wazuh_mcp_server.resilience import CircuitBreaker, CircuitBreakerConfig, CircuitBreakerState

        cb = CircuitBreaker(
            CircuitBreakerConfig(failure_threshold=1, recovery_timeout=0, expected_exception=(ConnectionError,))
        )

        async def _raise(exc):
            raise exc

        with pytest.raises(ConnectionError):
            await cb._call(_raise, ConnectionError("down"))
        assert cb.state == CircuitBreakerState.OPEN

        # Trial hits a 4xx (client error), surfaced as a _service_alive-marked ValueError.
        err = ValueError("HTTP 404")
        err._service_alive = True
        with pytest.raises(ValueError):
            await cb._call(_raise, err)

        # Server answered → recovery proven → breaker CLOSED, not stranded OPEN.
        assert cb.state == CircuitBreakerState.CLOSED
        assert cb._half_open_trial_in_progress is False


# ---- W2: /ready degrades to 503 when a configured Indexer is unavailable ----
class TestReadyDegradesOnIndexerOutage:
    @pytest.mark.asyncio
    async def test_indexer_unavailable_returns_503(self, monkeypatch):
        import httpx

        async def ok():
            return {"data": {"affected_items": [{"version": "4.14.7"}]}}

        class _StubIndexer:
            async def health_check(self):
                # health_check() never raises — it returns this on an outage.
                return {"status": "unavailable"}

        monkeypatch.setattr(mcp_server.wazuh_client, "ping_manager", ok)
        monkeypatch.setattr(mcp_server.wazuh_client, "_indexer_client", _StubIndexer())
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=mcp_server.app), base_url="http://testserver"
        ) as client:
            resp = await client.get("/ready")
        assert resp.status_code == 503
        assert resp.json()["services"]["wazuh_indexer"] == "unhealthy"


# ---- W2: summary tools report the true total + truncation flag ----
class TestSummaryTruncationTruth:
    @pytest.mark.asyncio
    async def test_alert_summary_reports_true_total_and_truncation(self):
        from wazuh_mcp_server.api.wazuh_client import WazuhClient
        from wazuh_mcp_server.config import WazuhConfig

        client = WazuhClient(WazuhConfig(wazuh_host="h", wazuh_user="u", wazuh_pass="p"))

        class _Idx:
            async def get_alerts(self, **kwargs):
                # 3 sampled docs, but 50,000 truly matched.
                return {
                    "data": {
                        "affected_items": [{"rule": {"id": "1"}}] * 3,
                        "total_affected_items": 50000,
                    }
                }

        client._indexer_client = _Idx()
        out = (await client.get_alert_summary("24h", "rule.id"))["data"]
        assert out["total_alerts"] == 50000
        assert out["alerts_sampled"] == 3
        assert out["truncated"] is True
        assert "truncation_warning" in out


# ============================ WAVE 3 — LLM safety ============================


def _ar_client(monkeypatch=None, protected=""):
    from wazuh_mcp_server.api.wazuh_client import WazuhClient
    from wazuh_mcp_server.config import WazuhConfig

    if monkeypatch is not None:
        monkeypatch.setenv("WAZUH_PROTECTED_IPS", protected)
    return WazuhClient(WazuhConfig(wazuh_host="10.0.0.1", wazuh_user="u", wazuh_pass="p"))


class TestBlockIpGuardrails:
    @pytest.mark.asyncio
    async def test_refuses_without_explicit_target(self):
        client = _ar_client()
        with pytest.raises(ValueError, match="explicit target"):
            await client.block_ip("8.8.8.8")

    @pytest.mark.asyncio
    async def test_refuses_protected_manager_ip(self):
        client = _ar_client()  # manager host is 10.0.0.1
        with pytest.raises(ValueError, match="protected target"):
            await client.block_ip("10.0.0.1", agent_id="001")

    @pytest.mark.asyncio
    async def test_refuses_loopback(self):
        client = _ar_client()
        with pytest.raises(ValueError, match="protected target"):
            await client.block_ip("127.0.0.1", agent_id="001")

    @pytest.mark.asyncio
    async def test_env_protected_cidr(self, monkeypatch):
        client = _ar_client(monkeypatch, protected="203.0.113.0/24")
        with pytest.raises(ValueError, match="protected target"):
            await client.block_ip("203.0.113.9", agent_id="001")

    @pytest.mark.asyncio
    async def test_explicit_agent_target_reaches_execute(self, monkeypatch):
        client = _ar_client()
        captured = {}

        async def fake_exec(data):
            captured.update(data)
            return {"data": {"total_affected_items": 1}}

        client.execute_active_response = fake_exec
        await client.block_ip("8.8.8.8", agent_id="007")
        assert captured["agent_list"] == ["007"]


class TestActiveResponseNoOpDetection:
    @pytest.mark.asyncio
    async def test_zero_affected_is_failure(self):
        client = _ar_client()

        async def fake_request(method, endpoint, **kwargs):
            # Unconfigured AR command: HTTP 200 but nothing happened.
            return {"data": {"total_affected_items": 0, "total_failed_items": 0, "failed_items": []}}

        client._request = fake_request
        with pytest.raises(ValueError, match="0 agents"):
            await client.execute_active_response({"command": "!host-isolation", "agent_list": ["001"]})


class TestActionConfirmationGate:
    @pytest.mark.asyncio
    async def test_write_tool_requires_confirm_when_enabled(self, monkeypatch, stub_cluster):
        monkeypatch.setenv("WAZUH_REQUIRE_ACTION_CONFIRMATION", "true")
        # The gate raises before the tool body (like scope enforcement), caught upstream.
        with pytest.raises(ValueError, match="confirm"):
            await handle_tools_call(
                {"name": "wazuh_block_ip", "arguments": {"ip_address": "8.8.8.8", "agent_id": "001"}},
                _session(scopes=("wazuh:read", "wazuh:write")),
            )


class TestServerInstructionsTrustBoundary:
    def test_instructions_declare_untrusted_output(self):
        assert "UNTRUSTED DATA" in mcp_server.SERVER_INSTRUCTIONS
        assert "block_ip" in mcp_server.SERVER_INSTRUCTIONS


# ==================== WAVE 3 — compliance honesty ====================


class TestComplianceHonesty:
    def test_unmapped_framework_is_not_assessable(self):
        from wazuh_mcp_server.api.wazuh_client import WazuhClient

        # HIPAA keywords with only generic CIS policies present → cannot honestly assess.
        agent_data = [
            {
                "agent_id": "001",
                "agent_name": "web-01",
                "sca_items": [
                    {"policy_id": "cis_debian10", "name": "CIS Debian", "pass": 90, "fail": 10, "total_checks": 100}
                ],
            }
        ]
        out = WazuhClient._format_compliance_result("HIPAA", ["hipaa", "health"], agent_data)["data"]
        assert out["assessment"] == "not_assessable"
        assert "overall_status" not in out  # never a fabricated pass/fail

    def test_mapped_framework_reports_coverage_not_passfail(self):
        from wazuh_mcp_server.api.wazuh_client import WazuhClient

        agent_data = [
            {
                "agent_id": "001",
                "agent_name": "web-01",
                "sca_items": [
                    {"policy_id": "cis_debian10", "name": "CIS Debian", "pass": 80, "fail": 20, "total_checks": 100}
                ],
            }
        ]
        out = WazuhClient._format_compliance_result("ISO27001", ["cis", "iso"], agent_data)["data"]
        assert out["assessment"] == "hardening_coverage"
        assert out["hardening_coverage_pct"] == 80
        assert "overall_status" not in out
        assert "disclaimer" in out

    @pytest.mark.asyncio
    async def test_iso_dashboard_surfaces_coverage_not_passfail(self):
        from types import SimpleNamespace

        from wazuh_mcp_server.api.wazuh_client import WazuhClient
        from wazuh_mcp_server.config import WazuhConfig

        client = WazuhClient(
            WazuhConfig(wazuh_host="h", wazuh_user="u", wazuh_pass="p", wazuh_indexer_host="localhost")
        )

        async def fake_request(method, endpoint, **kwargs):
            if endpoint == "/agents":
                return {"data": {"affected_items": [{"id": "001", "name": "web-01"}]}}
            if endpoint == "/manager/stats/analysisd":
                return {"data": {"affected_items": [{"total_events_decoded": 5}]}}
            return {"data": {"affected_items": []}}

        async def fake_alerts(**kwargs):
            # A pile of malware alerts must NOT raise the score (old inverted bug).
            return {"data": {"affected_items": [{"rule": {"groups": ["malware"]}}] * 40, "total_affected_items": 40}}

        client._request = fake_request
        client.get_alerts = fake_alerts
        client._indexer_client = SimpleNamespace(
            get_vulnerabilities=lambda **k: _async_val({"data": {"affected_items": []}})
        )
        data = (await client.get_iso27001_dashboard())["data"]
        assert data["assessment_type"] == "control_coverage_indicator"
        assert data["controls_mapped"] == data["controls_mapped"]  # present
        assert data["controls_total"] == 93
        assert "overall_status" not in data
        assert data["posture"] in (
            "insufficient_data",
            "weak_where_measured",
            "moderate_where_measured",
            "strong_where_measured",
        )
        # Alert-based controls are unscored (not inverted by volume).
        alert_controls = [c for c in data["controls"] if c["data_source"] == "alerts"]
        assert alert_controls and all(c["score"] is None for c in alert_controls)


def _async_val(value):
    async def _coro():
        return value

    return _coro()


# ============================ WAVE 4 — P2/P3 ============================


class TestCompletionRefResource:
    @pytest.mark.asyncio
    async def test_ref_resource_uri_does_not_crash(self):
        from wazuh_mcp_server.server import handle_completion_complete

        # A ref/resource identifies by `uri` (not `name`); the old code did None.lower().
        out = await handle_completion_complete(
            {"ref": {"type": "ref/resource", "uri": "wazuh://agents"}, "argument": {"name": "id", "value": "0"}},
            _session(),
        )
        assert "completion" in out
        assert out["completion"]["values"] == ["001", "002", "003", "004", "005"]


class TestOriginWildcardProduction:
    def test_wildcard_rejected_in_production(self, monkeypatch):
        from wazuh_mcp_server.server import validate_origin_header

        monkeypatch.setenv("ENVIRONMENT", "production")
        with pytest.raises(Exception):  # HTTPException 403
            validate_origin_header("https://evil.example", "*")

    def test_wildcard_allowed_in_development(self, monkeypatch):
        from wazuh_mcp_server.server import validate_origin_header

        monkeypatch.setenv("ENVIRONMENT", "development")
        # No raise = allowed.
        validate_origin_header("https://anything.example", "*")


class TestClustersBoolParsing:
    def test_string_false_is_false(self):
        from wazuh_mcp_server.clusters import _as_bool

        assert _as_bool("false", True) is False
        assert _as_bool("0", True) is False
        assert _as_bool("true", False) is True
        assert _as_bool(None, True) is True
        assert _as_bool(True, False) is True


class TestOAuthMetadataRfc8414:
    def _mgr(self, dcr):
        from types import SimpleNamespace

        from wazuh_mcp_server.oauth import OAuthManager

        return OAuthManager(
            SimpleNamespace(
                AUTH_SECRET_KEY="test-secret-key-at-least-32-characters-long",
                OAUTH_ENABLE_DCR=dcr,
                OAUTH_ACCESS_TOKEN_TTL=3600,
                OAUTH_REFRESH_TOKEN_TTL=86400,
                OAUTH_AUTHORIZATION_CODE_TTL=600,
                OAUTH_ISSUER_URL="https://mcp.example",
            )
        )

    def test_registration_endpoint_omitted_when_dcr_off(self):
        from types import SimpleNamespace

        meta = self._mgr(dcr=False).get_metadata(
            SimpleNamespace(url=SimpleNamespace(scheme="https", netloc="mcp.example"), headers={})
        )
        assert "registration_endpoint" not in meta
        assert "none" in meta["token_endpoint_auth_methods_supported"]

    def test_registration_endpoint_present_when_dcr_on(self):
        from types import SimpleNamespace

        meta = self._mgr(dcr=True).get_metadata(
            SimpleNamespace(url=SimpleNamespace(scheme="https", netloc="mcp.example"), headers={})
        )
        assert meta["registration_endpoint"].endswith("/oauth/register")


class TestCheckBlockedIpScopesAgent:
    @pytest.mark.asyncio
    async def test_agent_id_is_passed_to_query(self):
        from wazuh_mcp_server.api.wazuh_client import WazuhClient
        from wazuh_mcp_server.config import WazuhConfig

        client = WazuhClient(WazuhConfig(wazuh_host="h", wazuh_user="u", wazuh_pass="p"))
        seen = {}

        class _Idx:
            async def get_alerts(self, **kwargs):
                seen.update(kwargs)
                return {"data": {"affected_items": [{}], "total_affected_items": 1}}

        client._indexer_client = _Idx()
        out = (await client.check_blocked_ip("8.8.8.8", agent_id="007"))["data"]
        assert seen["agent_id"] == "007"
        assert out["scope"] == "agent"
        assert out["blocked"] is True


class TestControlDetailVulnPackageFields:
    @pytest.mark.asyncio
    async def test_critical_vuln_reads_package_name_version(self):
        from wazuh_mcp_server.api.wazuh_client import WazuhClient
        from wazuh_mcp_server.config import WazuhConfig

        client = WazuhClient(WazuhConfig(wazuh_host="h", wazuh_user="u", wazuh_pass="p", wazuh_indexer_host="x"))

        async def fake_request(method, endpoint, **kwargs):
            if endpoint == "/agents":
                return {"data": {"affected_items": [{"id": "001", "name": "web-01"}]}}
            return {"data": {"affected_items": []}}

        class _Idx:
            async def get_vulnerabilities(self, **kwargs):
                return {
                    "data": {
                        "affected_items": [
                            {"cve": "CVE-1", "severity": "Critical", "package": {"name": "openssl", "version": "1.1"}}
                        ]
                    }
                }

        client._request = fake_request
        client._indexer_client = _Idx()
        detail = await client.get_iso27001_control_detail("A.8.8", agent_id="001")
        block = detail["data"]["controls"][0]
        crit = block["evidence"]["critical_vulnerabilities"][0]
        assert crit["name"] == "openssl"
        assert crit["version"] == "1.1"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
