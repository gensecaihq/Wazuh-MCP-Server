"""Regression tests for the production-readiness audit fixes.

Each test pins a specific confirmed bug so it cannot silently regress:
  - fleet-wide active-response escalation on a non-numeric agent target
  - stringly-typed all_agents="false" being treated as truthy
  - exotic JSON-RPC ids (fractional/array) crashing error-response construction
  - tools/call with arguments=null / non-string name crashing to -32603
  - OAuth refresh burning a valid token on a client_id mismatch
  - strict boolean env parsing (1/yes/on) and placeholder AUTH_SECRET_KEY rejection
  - _compact_alert surviving an explicit-null data/agent/rule
  - the alert level filter not being silently dropped for an int input
  - the circuit-breaker half-open gate being released on cancellation
"""

import asyncio

import pytest

from wazuh_mcp_server.api.wazuh_client import WazuhClient
from wazuh_mcp_server.config import WazuhConfig


def _client():
    return WazuhClient(WazuhConfig(wazuh_host="localhost", wazuh_user="u", wazuh_pass="p", verify_ssl=False))


class TestActiveResponseFleetGuard:
    @pytest.mark.asyncio
    async def test_non_numeric_agent_refused_not_fanned_out(self):
        """A hostname target must raise, never dispatch with an absent agents_list (= all agents)."""
        client = _client()
        called = {"n": 0}

        async def fake_request(*a, **k):
            called["n"] += 1
            return {"data": {"total_affected_items": 1, "total_failed_items": 0, "failed_items": []}}

        client._request = fake_request
        with pytest.raises(ValueError, match="numeric agent ID"):
            await client.execute_active_response({"command": "!host-isolation", "agent_list": ["web-01"]})
        assert called["n"] == 0  # never reached the manager

    @pytest.mark.asyncio
    async def test_numeric_agent_still_dispatched(self):
        client = _client()
        sent = {}

        async def fake_request(method, path, json=None, params=None):
            sent["params"] = params
            return {"data": {"total_affected_items": 1, "total_failed_items": 0, "failed_items": []}}

        client._request = fake_request
        await client.execute_active_response({"command": "!host-isolation", "agent_list": ["001"]})
        assert sent["params"]["agents_list"] == "001"

    @pytest.mark.asyncio
    async def test_explicit_all_keyword_allowed(self):
        client = _client()
        sent = {}

        async def fake_request(method, path, json=None, params=None):
            sent["params"] = params
            return {"data": {"total_affected_items": 1, "total_failed_items": 0, "failed_items": []}}

        client._request = fake_request
        await client.execute_active_response({"command": "!host-isolation", "agent_list": ["all"]})
        assert sent["params"]["agents_list"] == "all"


class TestStringBooleanCoercion:
    def test_all_agents_false_string_is_false(self):
        from wazuh_mcp_server.security import validate_boolean

        assert validate_boolean("false", default=False, param_name="all_agents") is False
        assert validate_boolean("0", default=False, param_name="all_agents") is False
        assert validate_boolean("no", default=False, param_name="all_agents") is False
        assert validate_boolean("true", default=False, param_name="all_agents") is True


class TestJsonRpcIdHardening:
    def test_fractional_id_does_not_crash_error_response(self):
        from wazuh_mcp_server.server import create_error_response

        # Must not raise; 1.5 is a valid JSON-RPC Number id and is preserved.
        resp = create_error_response(1.5, -32600, "bad")
        assert resp.id == 1.5

    def test_array_id_coerced_to_null(self):
        from wazuh_mcp_server.server import create_error_response, create_success_response

        assert create_error_response([1, 2], -32600, "bad").id is None
        assert create_success_response({"x": 1}, {"ok": True}).id is None


class TestCompactAlertNullSafety:
    def test_explicit_null_fields_do_not_crash(self):
        from wazuh_mcp_server.server import _compact_alert

        out = _compact_alert({"timestamp": "t", "agent": None, "rule": None, "data": None})
        assert out["timestamp"] == "t"
        assert "agent" not in out and "srcip" not in out


class TestAlertLevelFilter:
    @pytest.mark.asyncio
    async def test_int_level_not_silently_dropped(self):
        """An int level must build a gte range clause, not vanish (returning all alerts)."""
        from wazuh_mcp_server.api.wazuh_indexer import WazuhIndexerClient

        client = WazuhIndexerClient(host="localhost", username="u", password="p")
        captured = {}

        async def fake_exec(index, query, size=100, sort=None):
            captured["query"] = query
            return {"hits": {"hits": [], "total": {"value": 0}}}

        client._execute_search = fake_exec
        await client.get_alerts(level=10)  # int, not "10"
        clauses = captured["query"].get("bool", {}).get("must", [])
        assert any(c.get("range", {}).get("rule.level", {}).get("gte") == 10 for c in clauses), clauses


class TestOAuthRefreshClientMismatch:
    def _mgr(self):
        from types import SimpleNamespace

        from wazuh_mcp_server.oauth import OAuthManager

        return OAuthManager(
            SimpleNamespace(
                AUTH_SECRET_KEY="k" * 40,
                OAUTH_ISSUER_URL="",
                OAUTH_ENABLE_DCR=False,
                OAUTH_ACCESS_TOKEN_TTL=3600,
                OAUTH_REFRESH_TOKEN_TTL=86400,
                OAUTH_AUTHORIZATION_CODE_TTL=600,
                TRUSTED_PROXIES="",
                ENVIRONMENT="development",
            )
        )

    def _issue(self, mgr):
        import base64
        import hashlib
        import secrets as _s

        verifier = _s.token_urlsafe(64)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
        redirect = "https://claude.ai/api/mcp/auth_callback"
        code = mgr.create_authorization_code("claude-desktop", redirect, "wazuh:read", challenge, "S256")
        return mgr.exchange_code_for_tokens(code, "claude-desktop", redirect, verifier)

    def test_mismatched_client_id_does_not_burn_token(self):
        mgr = self._mgr()
        tokens = self._issue(mgr)
        rt = tokens["refresh_token"]
        # Wrong client_id → invalid_grant, but the token must remain usable for a correct retry.
        with pytest.raises(ValueError, match="invalid_grant"):
            mgr.refresh_access_token(rt, "some-other-client")
        rotated = mgr.refresh_access_token(rt, "claude-desktop")
        assert rotated["access_token"]


class TestEnvBool:
    def test_truthy_and_falsy_spellings(self, monkeypatch):
        from wazuh_mcp_server.config import env_bool

        for v in ("1", "yes", "on", "true", "Y"):
            monkeypatch.setenv("X_FLAG", v)
            assert env_bool("X_FLAG", False) is True
        for v in ("0", "no", "off", "false"):
            monkeypatch.setenv("X_FLAG", v)
            assert env_bool("X_FLAG", True) is False

    def test_garbage_raises(self, monkeypatch):
        from wazuh_mcp_server.config import ConfigurationError, env_bool

        monkeypatch.setenv("X_FLAG", "maybe")
        with pytest.raises(ConfigurationError):
            env_bool("X_FLAG", False)


class TestProductionSecretGate:
    def _prod_env(self, monkeypatch, secret):
        monkeypatch.setenv("ENVIRONMENT", "production")
        monkeypatch.setenv("AUTH_MODE", "bearer")
        monkeypatch.setenv("WAZUH_HOST", "localhost")
        monkeypatch.setenv("WAZUH_USER", "u")
        monkeypatch.setenv("WAZUH_PASS", "p")
        if secret is not None:
            monkeypatch.setenv("AUTH_SECRET_KEY", secret)
        else:
            monkeypatch.delenv("AUTH_SECRET_KEY", raising=False)

    def test_placeholder_secret_rejected(self, monkeypatch):
        from wazuh_mcp_server.config import ConfigurationError, ServerConfig

        self._prod_env(monkeypatch, "CHANGE_ME_GENERATE_WITH_openssl_rand_hex_32")
        with pytest.raises(ConfigurationError):
            ServerConfig.from_env()

    def test_short_secret_rejected(self, monkeypatch):
        from wazuh_mcp_server.config import ConfigurationError, ServerConfig

        self._prod_env(monkeypatch, "tooshort")
        with pytest.raises(ConfigurationError):
            ServerConfig.from_env()

    def test_missing_secret_rejected(self, monkeypatch):
        from wazuh_mcp_server.config import ConfigurationError, ServerConfig

        self._prod_env(monkeypatch, None)
        with pytest.raises(ConfigurationError):
            ServerConfig.from_env()

    def test_strong_secret_accepted(self, monkeypatch):
        from wazuh_mcp_server.config import ServerConfig

        self._prod_env(monkeypatch, "a1b2c3d4e5f6071829304a5b6c7d8e9f00112233445566778899aabbccddeeff")
        cfg = ServerConfig.from_env()
        assert cfg.ENVIRONMENT == "production"


class TestManagerAgentGuard:
    def test_agent_000_refused_by_default(self):
        from wazuh_mcp_server.server import _guard_manager_agent

        for aid in ("0", "00", "000"):
            with pytest.raises(ValueError, match="manager"):
                _guard_manager_agent(aid, "wazuh_isolate_host")

    def test_real_agent_allowed(self):
        from wazuh_mcp_server.server import _guard_manager_agent

        # Should not raise for a normal agent id.
        _guard_manager_agent("001", "wazuh_isolate_host")
        _guard_manager_agent("042", "wazuh_kill_process")

    def test_opt_in_allows_manager(self, monkeypatch):
        from wazuh_mcp_server.server import _guard_manager_agent

        monkeypatch.setenv("WAZUH_ALLOW_MANAGER_AR", "true")
        _guard_manager_agent("000", "wazuh_isolate_host")  # no raise when explicitly opted in


class TestCircuitBreakerCancellation:
    @pytest.mark.asyncio
    async def test_half_open_trial_gate_released_on_cancellation(self):
        from wazuh_mcp_server.resilience import CircuitBreaker, CircuitBreakerConfig, CircuitBreakerState

        cb = CircuitBreaker(CircuitBreakerConfig(failure_threshold=1, recovery_timeout=0))
        # Force OPEN with an elapsed recovery window so the next call enters a HALF_OPEN trial.
        cb.state = CircuitBreakerState.OPEN
        cb.last_failure_time = 0.0

        async def hang():
            await asyncio.sleep(10)

        wrapped = cb(hang)
        task = asyncio.create_task(wrapped())
        await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        # The gate must be released — otherwise every later call 503s forever.
        assert cb._half_open_trial_in_progress is False
