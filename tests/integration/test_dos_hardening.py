"""
Rate-limiting and request-parsing hardening tests.
"""

import json
import os

import pytest

from wazuh_mcp_server.security import RateLimiter, parse_json_body_safe


class TestRateLimiterBackoff:
    def test_sliding_window_backoff_is_bounded_by_window(self):
        rl = RateLimiter(max_requests=2, window_seconds=60)
        assert rl.is_allowed("a")[0] is True
        assert rl.is_allowed("a")[0] is True
        allowed, retry_after = rl.is_allowed("a")
        assert allowed is False
        # Not the old fixed 5-minute escalating block — bounded by the window.
        assert 0 < retry_after <= 61

    def test_keys_have_independent_buckets(self):
        rl = RateLimiter(max_requests=2, window_seconds=60)
        rl.is_allowed("client-a")
        rl.is_allowed("client-a")
        assert rl.is_allowed("client-a")[0] is False
        # A different key must not be affected by another client's burst.
        assert rl.is_allowed("client-b")[0] is True


class TestJsonDepthGuard:
    def test_valid_json_parses(self):
        assert parse_json_body_safe(b'{"a": [1, 2, {"b": 3}]}') == {"a": [1, 2, {"b": 3}]}

    def test_deeply_nested_rejected(self):
        payload = b"[" * 500 + b"]" * 500
        with pytest.raises(ValueError, match="deep"):
            parse_json_body_safe(payload, max_depth=64)

    def test_within_limit_ok(self):
        payload = b"[" * 10 + b"1" + b"]" * 10
        assert parse_json_body_safe(payload, max_depth=64) == json.loads(payload)

    def test_brackets_inside_strings_not_counted(self):
        # Many brackets, but all inside a string — depth is 1, must parse fine.
        payload = b'{"note": "[[[[[[[[[[[[[[[[[[[["}'
        assert parse_json_body_safe(payload, max_depth=4) == {"note": "[[[[[[[[[[[[[[[[[[[["}


class TestJsonRpcIdNormalization:
    def test_normalizes_invalid_ids_to_none(self):
        from wazuh_mcp_server.server import _normalize_jsonrpc_id

        assert _normalize_jsonrpc_id(5) == 5
        assert _normalize_jsonrpc_id("abc") == "abc"
        # A JSON-RPC Number id may be a float; a finite float is preserved so the
        # client's request/response correlation isn't broken.
        assert _normalize_jsonrpc_id(1.5) == 1.5
        # Non-finite floats aren't valid JSON, so they still normalize to None.
        assert _normalize_jsonrpc_id(float("inf")) is None
        assert _normalize_jsonrpc_id([1, 2]) is None
        assert _normalize_jsonrpc_id({"x": 1}) is None
        assert _normalize_jsonrpc_id(True) is None
        assert _normalize_jsonrpc_id(None) is None


class TestEndpointRejectsDeepNesting:
    @pytest.mark.asyncio
    async def test_mcp_deep_nested_body_is_400_not_500(self, monkeypatch):
        os.environ.setdefault("WAZUH_HOST", "localhost")
        os.environ.setdefault("WAZUH_USER", "test")
        os.environ.setdefault("WAZUH_PASS", "test")
        import httpx

        from wazuh_mcp_server import server as mcp_server

        # Force authless so the request reaches the body-parse stage regardless of the
        # auth mode config happened to load with at import.
        monkeypatch.setattr(mcp_server.config, "AUTH_MODE", "none")

        payload = "[" * 500 + "]" * 500
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=mcp_server.app), base_url="http://testserver"
        ) as client:
            resp = await client.post("/mcp", content=payload, headers={"Content-Type": "application/json"})
        # The depth guard turns a RecursionError-inducing payload into a clean 400,
        # never a 500 / stack exhaustion.
        assert resp.status_code == 400


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
