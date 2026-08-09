"""Tests for optional GCF response encoding (RESPONSE_FORMAT=gcf).

The format is opt-in and lossless: the default preserves JSON output exactly,
and gcf mode round-trips back to the original result.
"""

import os

# Server config is frozen from env at import time; set before importing it.
os.environ.setdefault("WAZUH_HOST", "localhost")
os.environ.setdefault("WAZUH_USER", "test")
os.environ.setdefault("WAZUH_PASS", "test")
os.environ.setdefault("AUTH_MODE", "none")

import json  # noqa: E402
from datetime import datetime, timezone  # noqa: E402

import pytest  # noqa: E402

from wazuh_mcp_server.gcf_format import gcf_enabled, render_result  # noqa: E402

SAMPLE = {
    "data": {
        "affected_items": [
            {
                "timestamp": "2026-08-08T00:00:00Z",
                "agent": {"id": "001", "name": "web-01"},
                "rule": {"id": "5710", "description": "sshd failed login", "level": 5},
            },
            {
                "timestamp": "2026-08-08T00:01:00Z",
                "agent": {"id": "002", "name": "web-02"},
                "rule": {"id": "100010", "description": "Multiple auth failures", "level": 10},
            },
        ],
        "total_affected_items": 2,
    }
}


def _demap(x):
    if isinstance(x, dict):
        return {k: _demap(v) for k, v in x.items()}
    if isinstance(x, list):
        return [_demap(v) for v in x]
    return x


def test_default_is_json(monkeypatch):
    monkeypatch.delenv("RESPONSE_FORMAT", raising=False)
    assert gcf_enabled() is False
    out = render_result("Wazuh Alerts", SAMPLE, compact=True)
    label, body = out.split("\n", 1)
    assert label == "Wazuh Alerts:"
    assert json.loads(body) == SAMPLE


def test_gcf_mode_is_lossless(monkeypatch):
    monkeypatch.setenv("RESPONSE_FORMAT", "gcf")
    assert gcf_enabled() is True
    out = render_result("Wazuh Alerts", SAMPLE, compact=True)
    label, body = out.split("\n", 1)
    assert label == "Wazuh Alerts:"
    assert body.startswith("GCF profile=generic")

    from gcf import decode_generic

    assert _demap(decode_generic(body)) == SAMPLE


def test_gcf_mode_falls_back_to_json_on_error(monkeypatch):
    monkeypatch.setenv("RESPONSE_FORMAT", "gcf")

    # Inject an encoder failure; the helper must not raise, and must fall back to
    # a valid JSON rendering of the result.
    import gcf

    def boom(_data):
        raise ValueError("encode failed")

    monkeypatch.setattr(gcf, "encode_generic", boom)

    out = render_result("Wazuh Alerts", SAMPLE, compact=True)

    label, body = out.split("\n", 1)
    assert label == "Wazuh Alerts:"
    assert not body.startswith("GCF profile=generic")
    assert json.loads(body) == SAMPLE


def test_gcf_mode_falls_back_to_json_when_encoder_missing(monkeypatch):
    """gcf-python is an optional extra; RESPONSE_FORMAT=gcf without it must not break tools."""
    import sys

    monkeypatch.setenv("RESPONSE_FORMAT", "gcf")
    # Simulate the package being absent: a None entry makes `from gcf import ...` raise ImportError.
    monkeypatch.setitem(sys.modules, "gcf", None)

    out = render_result("Wazuh Alerts", SAMPLE, compact=True)

    label, body = out.split("\n", 1)
    assert label == "Wazuh Alerts:"
    assert json.loads(body) == SAMPLE


def _authed_session():
    from wazuh_mcp_server.auth import AuthToken
    from wazuh_mcp_server.server import MCPSession

    s = MCPSession("t", None)
    s.authenticated = True
    s._auth_token = AuthToken(
        token="t",
        api_key_id="tester",
        created_at=datetime.now(timezone.utc),
        scopes=["wazuh:read"],
    )
    return s


class _StubAlertsClient:
    async def get_alerts(self, **kwargs):
        return {
            "data": {
                "affected_items": SAMPLE["data"]["affected_items"],
                "total_affected_items": 2,
            }
        }


@pytest.mark.asyncio
async def test_get_wazuh_alerts_end_to_end_gcf(monkeypatch):
    """Drive a real tool call through the dispatch with RESPONSE_FORMAT=gcf."""
    from wazuh_mcp_server import server as mcp_server
    from wazuh_mcp_server.clusters import ClusterRegistry
    from wazuh_mcp_server.server import handle_tools_call

    monkeypatch.setenv("RESPONSE_FORMAT", "gcf")
    monkeypatch.setattr(
        mcp_server,
        "cluster_registry",
        ClusterRegistry({"default": _StubAlertsClient()}, "default", False),
    )

    out = await handle_tools_call(
        {"name": "get_wazuh_alerts", "arguments": {"limit": 10, "compact": False}},
        _authed_session(),
    )

    assert out["isError"] is False
    text = out["content"][0]["text"]
    assert text.startswith("Wazuh Alerts:\nGCF profile=generic")

    from gcf import decode_generic

    body = text.split("\n", 1)[1]
    decoded = _demap(decode_generic(body))
    assert decoded["data"]["affected_items"] == SAMPLE["data"]["affected_items"]
