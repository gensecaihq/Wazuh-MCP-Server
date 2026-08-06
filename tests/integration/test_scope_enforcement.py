"""
RBAC scope-enforcement tests at the tool-dispatch boundary.

handle_tools_call is the sole executor for every tool on every transport, so this
is where the read/write boundary must hold. These tests drive it directly (rather
than re-implementing the check) so a regression in the server's own gate is caught.
"""

from datetime import datetime, timezone

import pytest

from wazuh_mcp_server import server as mcp_server
from wazuh_mcp_server.auth import AuthToken
from wazuh_mcp_server.clusters import ClusterRegistry
from wazuh_mcp_server.server import WRITE_SCOPE_TOOLS, MCPSession, handle_tools_call


def _session(scopes):
    session = MCPSession("test-session", None)
    session.authenticated = True
    session._auth_token = AuthToken(
        token="t", api_key_id="tester", created_at=datetime.now(timezone.utc), scopes=scopes
    )
    return session


class _StubClient:
    """Records every active-response / tool call instead of hitting Wazuh."""

    def __init__(self):
        self.calls = []

    async def _record(self, name, **kw):
        self.calls.append((name, kw))
        return {"data": {"affected_items": [], "total_affected_items": 0, "total_failed_items": 0, "failed_items": []}}

    async def block_ip(self, *a, **k):
        return await self._record("block_ip", args=a, kwargs=k)

    async def isolate_host(self, *a, **k):
        return await self._record("isolate_host", args=a, kwargs=k)


@pytest.fixture(autouse=True)
def _stub_cluster(monkeypatch):
    stub = _StubClient()
    monkeypatch.setattr(mcp_server, "cluster_registry", ClusterRegistry({"default": stub}, "default", False))
    return stub


class TestReadTokenDeniedWriteTools:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("tool", sorted(WRITE_SCOPE_TOOLS))
    async def test_every_write_tool_denied_to_read_token(self, tool):
        session = _session(["wazuh:read"])
        with pytest.raises(ValueError, match="Insufficient permissions"):
            await handle_tools_call({"name": tool, "arguments": {}}, session)

    @pytest.mark.asyncio
    async def test_write_tool_denied_when_no_token(self):
        session = MCPSession("s", None)
        session._auth_token = None
        with pytest.raises(ValueError, match="Insufficient permissions"):
            await handle_tools_call({"name": "wazuh_block_ip", "arguments": {"ip_address": "1.2.3.4"}}, session)

    @pytest.mark.asyncio
    async def test_read_tool_allowed_for_read_token(self):
        session = _session(["wazuh:read"])
        # get_wazuh_alerts is read-scoped — should not raise on the scope gate.
        result = await handle_tools_call({"name": "list_wazuh_clusters", "arguments": {}}, session)
        assert result["isError"] is False


class TestWriteTokenAllowedAndAudited:
    @pytest.mark.asyncio
    async def test_write_token_dispatches_and_audits(self, _stub_cluster, caplog):
        session = _session(["wazuh:read", "wazuh:write"])
        with caplog.at_level("WARNING", logger="wazuh_mcp_server.audit"):
            result = await handle_tools_call(
                {"name": "wazuh_block_ip", "arguments": {"ip_address": "10.0.0.9"}}, session
            )
        assert result["isError"] is False
        # Reached the client.
        assert any(name == "block_ip" for name, _ in _stub_cluster.calls)
        # Audit record for the destructive op was emitted with the tool name.
        audit_lines = [r.getMessage() for r in caplog.records if r.name == "wazuh_mcp_server.audit"]
        assert any("wazuh_block_ip" in line for line in audit_lines), audit_lines


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
