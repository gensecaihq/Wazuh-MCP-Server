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


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
