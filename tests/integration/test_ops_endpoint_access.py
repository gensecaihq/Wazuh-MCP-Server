"""
Operational endpoints (/health, /ready, /metrics, API docs) are unauthenticated by design.

OPS_ALLOWED_IPS limits them to the listed clients (TCP peer, never a forwarded header), with
/health always open to loopback so the container healthcheck keeps working. API_DOCS_ENABLED
switches /docs, /redoc and /openapi.json off, by default in production. A refused request is
answered exactly like an unknown path.
"""

import dataclasses
import os

import pytest

os.environ.setdefault("WAZUH_HOST", "localhost")
os.environ.setdefault("WAZUH_USER", "test")
os.environ.setdefault("WAZUH_PASS", "test")
os.environ.setdefault("AUTH_MODE", "none")

import httpx  # noqa: E402

from wazuh_mcp_server import server as mcp_server  # noqa: E402
from wazuh_mcp_server.config import ConfigurationError, ServerConfig, parse_ip_allowlist  # noqa: E402

MONITOR = "192.168.130.10"
OUTSIDER = "203.0.113.9"
OPS_AND_DOCS = ["/health", "/ready", "/metrics", "/docs", "/redoc", "/openapi.json"]


@pytest.fixture(autouse=True)
def _isolated(monkeypatch):
    """Fresh /ready cache and a /ready that never calls Wazuh, so each test sees only the guard."""
    monkeypatch.setattr(mcp_server, "_ready_cache", None)

    async def healthy():
        """Pretend the Manager answered."""
        return {"data": {"affected_items": [{"version": "4.14.0"}]}}

    monkeypatch.setattr(mcp_server.wazuh_client, "get_manager_info", healthy)


def _configure(monkeypatch, allowed=(), docs=True):
    """Install a config with the given OPS_ALLOWED_IPS (raw entries) and API_DOCS_ENABLED."""
    entries = parse_ip_allowlist(",".join(allowed), "OPS_ALLOWED_IPS")
    monkeypatch.setattr(
        mcp_server, "config", dataclasses.replace(mcp_server.config, OPS_ALLOWED_IPS=entries, API_DOCS_ENABLED=docs)
    )


async def _get(path, client_ip, root_path="", **kwargs):
    """GET `path` through the ASGI app as if the TCP peer were `client_ip`."""
    transport = httpx.ASGITransport(app=mcp_server.app, client=(client_ip, 51000), root_path=root_path)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        return await client.get(path, follow_redirects=False, **kwargs)


class TestUnsetIsUnchanged:
    """Without OPS_ALLOWED_IPS every client reaches the endpoints, as before."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("path", OPS_AND_DOCS)
    async def test_any_client_reaches_ops_and_docs(self, monkeypatch, path):
        """Backward compatible default."""
        _configure(monkeypatch)
        response = await _get(path, OUTSIDER)
        assert response.status_code != 404, path


class TestAllowList:
    """With OPS_ALLOWED_IPS only listed clients (and loopback for /health) get through."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("path", OPS_AND_DOCS)
    async def test_outsider_gets_a_plain_404(self, monkeypatch, path):
        """A refused request looks exactly like an unknown path."""
        _configure(monkeypatch, allowed=[MONITOR])
        refused = await _get(path, OUTSIDER)
        unknown = await _get("/definitely-not-a-route", OUTSIDER)
        assert refused.status_code == 404
        assert refused.json() == unknown.json()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("path", OPS_AND_DOCS)
    async def test_listed_client_gets_through(self, monkeypatch, path):
        """The monitoring host reaches every operational endpoint."""
        _configure(monkeypatch, allowed=[MONITOR])
        response = await _get(path, MONITOR)
        assert response.status_code in (200, 503), (path, response.status_code)

    @pytest.mark.asyncio
    async def test_cidr_and_ipv6_entries(self, monkeypatch):
        """Networks match every address inside them; IPv6 and IPv4-mapped peers are handled."""
        _configure(monkeypatch, allowed=["192.168.130.0/24", "fd00::/64"])
        assert (await _get("/metrics", "192.168.130.77")).status_code == 200
        assert (await _get("/metrics", "fd00::1234")).status_code == 200
        assert (await _get("/metrics", "::ffff:192.168.130.77")).status_code == 200
        assert (await _get("/metrics", "192.168.131.1")).status_code == 404
        assert (await _get("/metrics", "fd00:1::1")).status_code == 404

    @pytest.mark.asyncio
    async def test_loopback_keeps_health_only(self, monkeypatch):
        """The container healthcheck (localhost) always reaches /health, nothing else unless listed."""
        _configure(monkeypatch, allowed=[MONITOR])
        for loopback in ("127.0.0.1", "::1"):
            assert (await _get("/health", loopback)).status_code == 200
            assert (await _get("/metrics", loopback)).status_code == 404
            assert (await _get("/ready", loopback)).status_code == 404
        _configure(monkeypatch, allowed=[MONITOR, "127.0.0.1"])
        assert (await _get("/metrics", "127.0.0.1")).status_code == 200

    @pytest.mark.asyncio
    async def test_forwarded_headers_do_not_grant_access(self, monkeypatch):
        """Only the peer address counts; a spoofed X-Forwarded-For / X-Real-IP is ignored."""
        _configure(monkeypatch, allowed=[MONITOR])
        headers = {"X-Forwarded-For": MONITOR, "X-Real-IP": MONITOR, "Forwarded": f"for={MONITOR}"}
        assert (await _get("/metrics", OUTSIDER, headers=headers)).status_code == 404

    @pytest.mark.asyncio
    async def test_refusal_is_indistinguishable_from_unknown_path(self, monkeypatch):
        """Same status, body and header names as a 404 for a path that does not exist."""
        _configure(monkeypatch, allowed=[MONITOR])
        refused = await _get("/metrics", OUTSIDER)
        unknown = await _get("/definitely-not-a-route", OUTSIDER)
        assert (refused.status_code, refused.content) == (unknown.status_code, unknown.content)
        assert set(refused.headers) == set(unknown.headers)

    @pytest.mark.asyncio
    @pytest.mark.parametrize("path", ["/metrics/", "/health/", "/docs/", "/openapi.json/", "/ready//"])
    async def test_trailing_slash_variants_are_refused(self, monkeypatch, path):
        """No redirect to the canonical path, which would confirm the endpoint exists."""
        _configure(monkeypatch, allowed=[MONITOR])
        assert (await _get(path, OUTSIDER)).status_code == 404

    @pytest.mark.asyncio
    async def test_root_path_does_not_bypass(self, monkeypatch):
        """Mounted under a prefix (uvicorn --root-path), the prefixed paths are still guarded."""
        _configure(monkeypatch, allowed=[MONITOR], docs=False)
        assert (await _get("/api/metrics", OUTSIDER, root_path="/api")).status_code == 404
        assert (await _get("/api/openapi.json", MONITOR, root_path="/api")).status_code == 404
        assert (await _get("/api/metrics", MONITOR, root_path="/api")).status_code == 200

    def test_missing_client_address_is_refused(self, monkeypatch):
        """No client in the ASGI scope (e.g. a Unix socket) is treated as not allowed."""
        from types import SimpleNamespace

        _configure(monkeypatch, allowed=[MONITOR])
        for scope in ({"client": None}, {}, {"client": ("", 0)}):
            request = SimpleNamespace(scope=scope)
            assert mcp_server._ops_access_allowed("/metrics", request, mcp_server.config) is False
            assert mcp_server._ops_access_allowed("/health", request, mcp_server.config) is False

    @pytest.mark.asyncio
    async def test_unknown_peer_is_refused(self, monkeypatch):
        """No usable client address (e.g. a Unix socket) is treated as not allowed."""
        _configure(monkeypatch, allowed=[MONITOR])
        assert (await _get("/metrics", "not-an-ip")).status_code == 404

    @pytest.mark.asyncio
    async def test_mcp_and_oauth_discovery_unaffected(self, monkeypatch):
        """The guard covers only the operational paths; client-facing endpoints are untouched."""
        _configure(monkeypatch, allowed=[MONITOR])
        transport = httpx.ASGITransport(app=mcp_server.app, client=(OUTSIDER, 51000))
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            response = await client.post(
                "/mcp",
                json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
                headers={"Accept": "application/json, text/event-stream"},
            )
        assert response.status_code != 404


class TestApiDocsSwitch:
    """API_DOCS_ENABLED=false removes the docs for everyone, listed clients included."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("path", ["/docs", "/docs/oauth2-redirect", "/redoc", "/openapi.json"])
    async def test_docs_off_for_everyone(self, monkeypatch, path):
        """Even an allowed client and loopback get 404."""
        _configure(monkeypatch, allowed=[MONITOR], docs=False)
        assert (await _get(path, MONITOR)).status_code == 404
        assert (await _get(path, "127.0.0.1")).status_code == 404

    @pytest.mark.parametrize("docs", [True, False])
    def test_oauth_metadata_links_docs_only_when_served(self, docs):
        """RFC 8414 service_documentation is advertised only when /docs answers."""
        from types import SimpleNamespace

        from wazuh_mcp_server.oauth import OAuthManager

        manager = OAuthManager(
            SimpleNamespace(
                AUTH_SECRET_KEY="test-secret-key-at-least-32-characters-long",
                OAUTH_ENABLE_DCR=False,
                OAUTH_ACCESS_TOKEN_TTL=3600,
                OAUTH_REFRESH_TOKEN_TTL=86400,
                OAUTH_AUTHORIZATION_CODE_TTL=600,
                OAUTH_ISSUER_URL="https://mcp.example",
                API_DOCS_ENABLED=docs,
            )
        )
        request = SimpleNamespace(url=SimpleNamespace(scheme="https", netloc="mcp.example"), headers={})
        assert ("service_documentation" in manager.get_metadata(request)) is docs

    @pytest.mark.asyncio
    async def test_docs_off_leaves_probes_alone(self, monkeypatch):
        """Switching docs off does not touch /health or /metrics."""
        _configure(monkeypatch, docs=False)
        assert (await _get("/health", OUTSIDER)).status_code == 200
        assert (await _get("/metrics", OUTSIDER)).status_code == 200


class TestConfigParsing:
    """OPS_ALLOWED_IPS and API_DOCS_ENABLED are validated in ServerConfig.from_env."""

    @pytest.fixture
    def env(self, monkeypatch):
        """Minimal valid environment for ServerConfig.from_env; returns monkeypatch."""
        for var in ("OPS_ALLOWED_IPS", "API_DOCS_ENABLED", "AUTH_SECRET_KEY", "API_KEYS"):
            monkeypatch.delenv(var, raising=False)
        monkeypatch.setenv("AUTH_MODE", "none")
        monkeypatch.setenv("ENVIRONMENT", "development")
        return monkeypatch

    def test_entries_are_normalised(self, env):
        """Addresses become /32 or /128 networks, blanks are skipped."""
        env.setenv("OPS_ALLOWED_IPS", " 192.168.130.10, ,10.0.0.0/8,fd00::1 ")
        assert ServerConfig.from_env().OPS_ALLOWED_IPS == ("192.168.130.10/32", "10.0.0.0/8", "fd00::1/128")

    @pytest.mark.parametrize("bad", ["prometheus.local", "10.0.0.300", "10.0.0.0/33", "192.168.1.1:9090"])
    def test_invalid_entry_fails_startup(self, env, bad):
        """A typo stops the server instead of leaving the endpoints open or closed by accident."""
        env.setenv("OPS_ALLOWED_IPS", f"127.0.0.1,{bad}")
        with pytest.raises(ConfigurationError, match="OPS_ALLOWED_IPS"):
            ServerConfig.from_env()

    @pytest.mark.parametrize(
        "environment,value,expected",
        [
            ("development", None, True),
            ("production", None, False),
            ("production", "", False),
            ("production", "true", True),
            ("development", "off", False),
        ],
    )
    def test_api_docs_default_follows_environment(self, env, environment, value, expected):
        """Docs are on in development and off in production unless set explicitly."""
        env.setenv("ENVIRONMENT", environment)
        env.setenv("AUTH_MODE", "none")
        if value is not None:
            env.setenv("API_DOCS_ENABLED", value)
        assert ServerConfig.from_env().API_DOCS_ENABLED is expected

    def test_api_docs_invalid_value_fails_startup(self, env):
        """API_DOCS_ENABLED is a strict boolean."""
        env.setenv("API_DOCS_ENABLED", "maybe")
        with pytest.raises(ConfigurationError, match="API_DOCS_ENABLED"):
            ServerConfig.from_env()
