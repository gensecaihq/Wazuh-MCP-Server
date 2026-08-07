"""
Liveness vs readiness tests.

/health must stay 200 while the process is up even when Wazuh is unreachable —
otherwise a SIEM outage fails the container healthcheck and restart-loops a live
server. /ready is where dependency health is reported.
"""

import os

import pytest

os.environ.setdefault("WAZUH_HOST", "localhost")
os.environ.setdefault("WAZUH_USER", "test")
os.environ.setdefault("WAZUH_PASS", "test")
os.environ.setdefault("AUTH_MODE", "none")

import httpx  # noqa: E402

from wazuh_mcp_server import server as mcp_server  # noqa: E402


def _client():
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=mcp_server.app), base_url="http://testserver")


@pytest.mark.asyncio
async def test_health_is_liveness_and_ignores_wazuh(monkeypatch):
    # Even if the Wazuh manager call would fail, liveness stays healthy.
    async def boom():
        raise RuntimeError("wazuh down")

    monkeypatch.setattr(mcp_server.wazuh_client, "get_manager_info", boom)
    async with _client() as client:
        resp = await client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "healthy"
    assert body["version"]
    # Liveness must not include dependency status.
    assert "services" not in body


@pytest.mark.asyncio
async def test_ready_reports_dependency_failure_as_503(monkeypatch):
    async def boom():
        raise RuntimeError("wazuh down")

    # /ready uses the uncached ping_manager probe so a fresh outage isn't cache-masked.
    monkeypatch.setattr(mcp_server.wazuh_client, "ping_manager", boom)
    async with _client() as client:
        resp = await client.get("/ready")
    assert resp.status_code == 503
    assert resp.json()["services"]["wazuh_manager"] == "unhealthy"


@pytest.mark.asyncio
async def test_ready_healthy_when_manager_reachable(monkeypatch):
    async def ok():
        return {"data": {"affected_items": [{"version": "4.14.7"}]}}

    monkeypatch.setattr(mcp_server.wazuh_client, "ping_manager", ok)
    # No indexer configured in the test client → indexer_status not_configured (healthy overall).
    monkeypatch.setattr(mcp_server.wazuh_client, "_indexer_client", None)
    async with _client() as client:
        resp = await client.get("/ready")
    assert resp.status_code == 200
    assert resp.json()["status"] == "healthy"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
