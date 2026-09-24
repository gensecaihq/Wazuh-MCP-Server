"""
Protected-target guard is enforced on EVERY IP-blocking active-response path.

Regression: `block_ip` refused loopback / the manager / WAZUH_PROTECTED_IPS, but
`firewall_drop`, `host_deny` and the generic `wazuh_active_response` tool sent the
very same `!firewall-drop` / `!host-deny` commands without that check — and the
firewall_drop / host_deny tool handlers also skipped `_guard_manager_agent`, so a
prompt-injected model with `wazuh:write` could cut the SOC off from its own manager
by picking the sibling tool.
"""

import pytest

from wazuh_mcp_server.api.wazuh_client import WazuhClient
from wazuh_mcp_server.config import WazuhConfig

MANAGER_IP = "10.0.10.20"
ANALYST_IP = "10.0.50.7"
ATTACKER_IP = "203.0.113.9"


def _client(monkeypatch, protected=ANALYST_IP):
    """WazuhClient pointed at MANAGER_IP whose active-response executor records payloads instead of calling Wazuh."""
    monkeypatch.setenv("WAZUH_PROTECTED_IPS", protected)
    client = WazuhClient(WazuhConfig(wazuh_host=MANAGER_IP, wazuh_user="u", wazuh_pass="p", verify_ssl=False))
    client.sent = []

    async def fake_exec(data):
        """Record the active-response payload and report one affected item."""
        client.sent.append(data)
        return {"data": {"total_affected_items": 1, "total_failed_items": 0, "failed_items": []}}

    client.execute_active_response = fake_exec
    return client


@pytest.mark.parametrize("target", ["127.0.0.1", "::1", MANAGER_IP, ANALYST_IP])
class TestEveryBlockingPathRefusesProtectedTargets:
    """Tests: every blocking path refuses protected targets."""

    @pytest.mark.asyncio
    async def test_block_ip(self, monkeypatch, target):
        """Block IP."""
        client = _client(monkeypatch)
        with pytest.raises(ValueError, match="protected target"):
            await client.block_ip(target, agent_id="001")
        assert client.sent == []

    @pytest.mark.asyncio
    async def test_firewall_drop(self, monkeypatch, target):
        """Firewall drop."""
        client = _client(monkeypatch)
        with pytest.raises(ValueError, match="protected target"):
            await client.firewall_drop("001", target)
        assert client.sent == []

    @pytest.mark.asyncio
    async def test_host_deny(self, monkeypatch, target):
        """Host deny."""
        client = _client(monkeypatch)
        with pytest.raises(ValueError, match="protected target"):
            await client.host_deny("001", target)
        assert client.sent == []

    @pytest.mark.asyncio
    @pytest.mark.parametrize("command", ["!firewall-drop", "host-deny"])
    async def test_generic_active_response(self, monkeypatch, target, command):
        """The generic tool never dispatches IP blocks; it points at the dedicated tool."""
        client = _client(monkeypatch)
        with pytest.raises(ValueError, match="Use wazuh_(firewall_drop|host_deny)"):
            await client.run_active_response("001", command, {"srcip": target})
        assert client.sent == []


class TestLegitimateTargetsStillDispatch:
    """Tests: legitimate targets still dispatch."""

    @pytest.mark.asyncio
    async def test_attacker_ip_is_blocked_on_every_path(self, monkeypatch):
        """Attacker IP is blocked on every path."""
        client = _client(monkeypatch)
        await client.block_ip(ATTACKER_IP, agent_id="001")
        await client.firewall_drop("001", ATTACKER_IP)
        await client.host_deny("001", ATTACKER_IP)
        assert [d["command"] for d in client.sent] == ["!firewall-drop", "!firewall-drop", "!host-deny"]

    @pytest.mark.asyncio
    async def test_generic_non_blocking_command_ignores_ip_guard(self, monkeypatch):
        """Generic non blocking command ignores IP guard."""
        client = _client(monkeypatch)
        await client.run_active_response("001", "!enable-account", {"user": "bob"})
        assert client.sent[-1]["command"] == "!enable-account"

    @pytest.mark.asyncio
    async def test_generic_parameters_must_be_an_object(self, monkeypatch):
        """Generic parameters must be an object."""
        client = _client(monkeypatch)
        with pytest.raises(ValueError, match="parameters must be an object"):
            await client.run_active_response("001", "!enable-account", ["user=bob"])


class TestGuardCannotBeSidestepped:
    """Spelling tricks that used to slip past the key-based / IPv4-only checks."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "parameters",
        [
            {"SrcIp": "127.0.0.1"},  # case variant of the key
            {"dstip": MANAGER_IP},  # a key nobody listed
            {"srcip": " 127.0.0.1"},  # leading whitespace
            {"srcip": "::ffff:7f00:1"},  # IPv4-mapped IPv6 spelling of 127.0.0.1
            {"srcip": "::ffff:10.0.10.20"},  # IPv4-mapped spelling of the manager
        ],
    )
    async def test_generic_tool_refuses_ip_blocks_whatever_the_parameters(self, monkeypatch, parameters):
        """No parameter spelling gets an IP block through the generic tool."""
        client = _client(monkeypatch)
        for extra in ({}, {"srcip": "10.0.10.0/24"}, {"srcip": "127.1"}, {"x": "srcip=127.0.0.1"}):
            with pytest.raises(ValueError, match="Use wazuh_firewall_drop"):
                await client.run_active_response("001", "!firewall-drop", {**parameters, **extra})
        assert client.sent == []

    @pytest.mark.asyncio
    @pytest.mark.parametrize("target", ["::ffff:7f00:1", "::ffff:10.0.10.20", f"::ffff:{ANALYST_IP}"])
    async def test_ipv4_mapped_ipv6_refused_on_direct_paths(self, monkeypatch, target):
        """IPv4 mapped IPv6 refused on direct paths."""
        client = _client(monkeypatch)
        for call in (
            lambda: client.block_ip(target, agent_id="001"),
            lambda: client.firewall_drop("001", target),
            lambda: client.host_deny("001", target),
        ):
            # The hex spelling is unmapped and refused as protected; the dotted spelling
            # (::ffff:10.0.10.20) never passes _validate_ip's IPv6 regex. Either way: no dispatch.
            with pytest.raises(ValueError, match="protected target|Invalid IP address"):
                await call()
        assert client.sent == []


class TestManagerAgentGuardCoversBlockingTools:
    """The firewall_drop / host_deny / block_ip handlers must refuse agent 000 like the
    other host-level tools do (WAZUH_ALLOW_MANAGER_AR overrides), and a fleet-wide block
    counts as targeting the manager too."""

    @pytest.fixture
    def stub(self, monkeypatch):
        """Install a stub cluster whose blocking methods only record which tool was reached."""

        from wazuh_mcp_server import server as mcp_server
        from wazuh_mcp_server.clusters import ClusterRegistry

        class _Stub:
            """Stand-in Wazuh client recording the blocking calls that got past the handler guards."""

            def __init__(self):
                """Start with no recorded calls."""
                self.calls = []

            async def _ok(self, name, *a, **k):
                """Record the tool name and return a successful active-response payload."""
                self.calls.append(name)
                return {"data": {"total_affected_items": 1, "total_failed_items": 0, "failed_items": []}}

            async def block_ip(self, *a, **k):
                """Record a block_ip dispatch."""
                return await self._ok("block_ip")

            async def firewall_drop(self, *a, **k):
                """Record a firewall_drop dispatch."""
                return await self._ok("firewall_drop")

            async def host_deny(self, *a, **k):
                """Record a host_deny dispatch."""
                return await self._ok("host_deny")

        stub = _Stub()
        monkeypatch.setattr(mcp_server, "cluster_registry", ClusterRegistry({"default": stub}, "default", False))
        monkeypatch.delenv("WAZUH_ALLOW_MANAGER_AR", raising=False)
        monkeypatch.delenv("WAZUH_REQUIRE_ACTION_CONFIRMATION", raising=False)
        return stub

    @staticmethod
    async def _call(name, **arguments):
        """Invoke the named tool through handle_tools_call as an authenticated wazuh:write session."""
        from datetime import datetime, timezone

        from wazuh_mcp_server.auth import AuthToken
        from wazuh_mcp_server.server import MCPSession, handle_tools_call

        s = MCPSession("t", None)
        s.authenticated = True
        s._auth_token = AuthToken(
            token="t", api_key_id="tester", created_at=datetime.now(timezone.utc), scopes=["wazuh:read", "wazuh:write"]
        )
        return await handle_tools_call({"name": name, "arguments": arguments}, s)

    @staticmethod
    def _refused(result, match):
        """Assert the tool returned an MCP isError result whose text contains the expected fragment."""
        assert result.get("isError") is True, result
        assert match in " ".join(c.get("text", "") for c in result["content"]), result

    @pytest.mark.asyncio
    async def test_manager_agent_refused_on_blocking_tools(self, stub):
        """Manager agent refused on blocking tools."""
        self._refused(await self._call("wazuh_firewall_drop", agent_id="000", src_ip=ATTACKER_IP), "agent 000")
        self._refused(await self._call("wazuh_host_deny", agent_id="000", src_ip=ATTACKER_IP), "agent 000")
        self._refused(await self._call("wazuh_block_ip", agent_id="0", ip_address=ATTACKER_IP), "agent 000")
        assert stub.calls == []

    @pytest.mark.asyncio
    async def test_fleet_wide_block_is_not_an_agent_000_target(self, stub, monkeypatch):
        """all_agents has its own opt-in (WAZUH_ALLOW_FLEET_AR); WAZUH_ALLOW_MANAGER_AR isn't needed."""
        monkeypatch.setenv("WAZUH_ALLOW_FLEET_AR", "true")
        await self._call("wazuh_block_ip", all_agents=True, ip_address=ATTACKER_IP)
        assert stub.calls == ["block_ip"]

    @pytest.mark.asyncio
    async def test_real_agents_and_opt_in_still_work(self, stub, monkeypatch):
        """Real agents and opt in still work."""
        await self._call("wazuh_firewall_drop", agent_id="001", src_ip=ATTACKER_IP)
        await self._call("wazuh_host_deny", agent_id="001", src_ip=ATTACKER_IP)
        await self._call("wazuh_block_ip", agent_id="001", ip_address=ATTACKER_IP)
        assert stub.calls == ["firewall_drop", "host_deny", "block_ip"]
        monkeypatch.setenv("WAZUH_ALLOW_MANAGER_AR", "true")
        await self._call("wazuh_firewall_drop", agent_id="000", src_ip=ATTACKER_IP)
        assert stub.calls[-1] == "firewall_drop"
