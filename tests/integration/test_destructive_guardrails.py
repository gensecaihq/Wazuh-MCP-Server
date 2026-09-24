"""
Guard-rails on the destructive active-response tools.

Regressions pinned here:
  - the confirm=true gate was off unless explicitly enabled, even in production;
  - wazuh_quarantine_file accepted any absolute path (/etc/passwd, /boot/vmlinuz,
    the agent's own /var/ossec tree);
  - wazuh_restart target=manager restarted the whole SOC control plane with no opt-in;
  - wazuh_block_ip all_agents=true fanned a block out to the entire fleet with no opt-in.
All of these are reachable by a prompt-injected model holding wazuh:write.
"""

from datetime import datetime, timezone

import pytest

from wazuh_mcp_server import server as mcp_server
from wazuh_mcp_server.auth import AuthToken
from wazuh_mcp_server.clusters import ClusterRegistry
from wazuh_mcp_server.security import ToolValidationError, validate_quarantine_path
from wazuh_mcp_server.server import MCPSession, handle_tools_call


def _session():
    """Authenticated MCP session holding wazuh:read and wazuh:write."""
    s = MCPSession("t", None)
    s.authenticated = True
    s._auth_token = AuthToken(
        token="t", api_key_id="tester", created_at=datetime.now(timezone.utc), scopes=["wazuh:read", "wazuh:write"]
    )
    return s


class _StubClient:
    """Stand-in Wazuh client that records destructive calls instead of dispatching them."""

    def __init__(self):
        """Start with no recorded calls."""
        self.calls = []

    async def _record(self, name, *args, **kwargs):
        """Record the call and return a successful active-response payload."""
        self.calls.append((name, args, kwargs))
        return {"data": {"total_affected_items": 1, "total_failed_items": 0, "failed_items": []}}

    async def quarantine_file(self, agent_id, file_path):
        """Record a quarantine_file dispatch."""
        return await self._record("quarantine_file", agent_id, file_path)

    async def restart_service(self, target):
        """Record a restart_service dispatch."""
        return await self._record("restart_service", target)

    async def block_ip(self, ip_address, duration=0, agent_id=None, all_agents=False):
        """Record a block_ip dispatch."""
        return await self._record("block_ip", ip_address, duration, agent_id, all_agents=all_agents)


@pytest.fixture
def stub(monkeypatch):
    """Install _StubClient as the default cluster and clear every guard-rail variable from the environment."""
    stub = _StubClient()
    monkeypatch.setattr(mcp_server, "cluster_registry", ClusterRegistry({"default": stub}, "default", False))
    # Isolate from the operator's environment.
    for var in (
        "WAZUH_REQUIRE_ACTION_CONFIRMATION",
        "WAZUH_ALLOW_MANAGER_AR",
        "WAZUH_ALLOW_FLEET_AR",
        "WAZUH_QUARANTINE_DENY_PREFIXES",
        "WAZUH_QUARANTINE_ALLOW_PREFIXES",
        "ENVIRONMENT",
    ):
        monkeypatch.delenv(var, raising=False)
    return stub


async def _call(name, **arguments):
    """Invoke the named tool through handle_tools_call with a wazuh:write session."""
    return await handle_tools_call({"name": name, "arguments": arguments}, _session())


def _refused(result, match):
    """Errors raised inside a tool body come back as an MCP isError result, not an exception."""
    assert result.get("isError") is True, result
    text = " ".join(c.get("text", "") for c in result.get("content", []))
    assert match in text, text


# --------------------------------------------------------------------- confirmation gate
class TestConfirmationDefault:
    """Tests: confirmation default."""

    @pytest.mark.asyncio
    async def test_on_by_default_in_production(self, stub, monkeypatch):
        """On by default in production."""
        monkeypatch.setenv("ENVIRONMENT", "production")
        # The refusal is a tool result the model sees, carrying the confirm guidance
        _refused(await _call("wazuh_block_ip", ip_address="8.8.8.8", agent_id="001"), "confirm")
        assert stub.calls == []
        await _call("wazuh_block_ip", ip_address="8.8.8.8", agent_id="001", confirm=True)
        assert stub.calls[-1][0] == "block_ip"

    @pytest.mark.asyncio
    async def test_off_by_default_outside_production(self, stub, monkeypatch):
        """Off by default outside production."""
        monkeypatch.setenv("ENVIRONMENT", "development")
        await _call("wazuh_block_ip", ip_address="8.8.8.8", agent_id="001")
        assert stub.calls[-1][0] == "block_ip"

    @pytest.mark.asyncio
    async def test_explicit_setting_wins_over_environment(self, stub, monkeypatch):
        """Explicit setting wins over environment."""
        monkeypatch.setenv("ENVIRONMENT", "production")
        monkeypatch.setenv("WAZUH_REQUIRE_ACTION_CONFIRMATION", "false")
        await _call("wazuh_block_ip", ip_address="8.8.8.8", agent_id="001")
        assert stub.calls[-1][0] == "block_ip"

    @pytest.mark.asyncio
    async def test_read_tools_never_need_confirmation(self, stub, monkeypatch):
        """Read tools never need confirmation."""
        monkeypatch.setenv("ENVIRONMENT", "production")

        async def get_wazuh_agents(**kwargs):
            """Return an empty agent list."""
            return {"data": {"affected_items": []}}

        stub.get_wazuh_agents = get_wazuh_agents
        stub.get_agents = get_wazuh_agents
        result = await _call("get_wazuh_agents")
        assert result is not None


# --------------------------------------------------------------------- quarantine paths
class TestQuarantinePathPolicy:
    """Tests: quarantine path policy."""

    @pytest.mark.parametrize(
        "path",
        [
            "/etc/passwd",
            "/etc",
            "/boot/vmlinuz",
            "/usr/bin/ls",
            "/lib64/ld-linux-x86-64.so.2",
            "/var/ossec/etc/ossec.conf",
            "/var/lib/docker/overlay2/x",
            "/proc/1/mem",
            "C:\\Windows\\System32\\cmd.exe",
            "c:/windows/notepad.exe",
            "C:\\Program Files (x86)\\App\\app.exe",
        ],
    )
    def test_system_locations_refused(self, path, monkeypatch):
        """System locations refused."""
        monkeypatch.delenv("WAZUH_QUARANTINE_DENY_PREFIXES", raising=False)
        monkeypatch.delenv("WAZUH_QUARANTINE_ALLOW_PREFIXES", raising=False)
        with pytest.raises(ToolValidationError):
            validate_quarantine_path(path)

    @pytest.mark.parametrize(
        "path", ["/home/alice/malware.bin", "/tmp/dropper.sh", "C:\\Users\\bob\\evil.exe", "/opt/app/etc-backup"]
    )
    def test_ordinary_locations_accepted(self, path, monkeypatch):
        """Ordinary locations accepted."""
        monkeypatch.delenv("WAZUH_QUARANTINE_DENY_PREFIXES", raising=False)
        monkeypatch.delenv("WAZUH_QUARANTINE_ALLOW_PREFIXES", raising=False)
        assert validate_quarantine_path(path) == path

    @pytest.mark.parametrize("path", ["relative/file", "malware.bin", "/home/../etc/passwd", "/tmp/a\nb"])
    def test_relative_traversal_and_multiline_refused(self, path):
        """Relative traversal and multiline refused."""
        with pytest.raises(ToolValidationError):
            validate_quarantine_path(path)

    def test_operator_can_override_denylist(self, monkeypatch):
        """Operator can override denylist."""
        monkeypatch.setenv("WAZUH_QUARANTINE_DENY_PREFIXES", "/srv/critical")
        with pytest.raises(ToolValidationError):
            validate_quarantine_path("/srv/critical/db")
        # Configured prefixes add to the defaults; they never re-allow system paths
        with pytest.raises(ToolValidationError):
            validate_quarantine_path("/etc/passwd")

    def test_allowlist_mode(self, monkeypatch):
        """Allowlist mode."""
        monkeypatch.setenv("WAZUH_QUARANTINE_ALLOW_PREFIXES", "/home,/tmp")
        assert validate_quarantine_path("/home/alice/x") == "/home/alice/x"
        with pytest.raises(ToolValidationError, match="ALLOW_PREFIXES"):
            validate_quarantine_path("/opt/app/x")

    @pytest.mark.asyncio
    async def test_handler_applies_the_policy(self, stub):
        """Handler applies the policy."""
        _refused(await _call("wazuh_quarantine_file", agent_id="001", file_path="/etc/shadow"), "protected location")
        assert stub.calls == []
        await _call("wazuh_quarantine_file", agent_id="001", file_path="/home/alice/malware.bin")
        assert stub.calls[-1] == ("quarantine_file", ("001", "/home/alice/malware.bin"), {})


# --------------------------------------------------------------------- manager restart
class TestManagerRestartOptIn:
    """Tests: manager restart opt in."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("target", ["manager", "000", "0"])
    async def test_refused_by_default(self, stub, target):
        """Refused by default."""
        _refused(await _call("wazuh_restart", target=target), "WAZUH_ALLOW_MANAGER_AR")
        assert stub.calls == []

    @pytest.mark.asyncio
    async def test_allowed_with_opt_in(self, stub, monkeypatch):
        """Allowed with opt in."""
        monkeypatch.setenv("WAZUH_ALLOW_MANAGER_AR", "true")
        await _call("wazuh_restart", target="manager")
        assert stub.calls[-1] == ("restart_service", ("manager",), {})

    @pytest.mark.asyncio
    async def test_agent_restart_unaffected(self, stub):
        """Agent restart unaffected."""
        await _call("wazuh_restart", target="7")
        assert stub.calls[-1] == ("restart_service", ("007",), {})


# --------------------------------------------------------------------- fleet-wide block
class TestFleetWideBlockOptIn:
    """Tests: fleet wide block opt in."""

    @pytest.mark.asyncio
    async def test_all_agents_refused_by_default(self, stub):
        """All agents refused by default."""
        _refused(await _call("wazuh_block_ip", ip_address="203.0.113.9", all_agents=True), "WAZUH_ALLOW_FLEET_AR")
        assert stub.calls == []

    @pytest.mark.asyncio
    async def test_all_agents_allowed_with_opt_in(self, stub, monkeypatch):
        """All agents allowed with opt in."""
        monkeypatch.setenv("WAZUH_ALLOW_FLEET_AR", "true")
        await _call("wazuh_block_ip", ip_address="203.0.113.9", all_agents=True)
        assert stub.calls[-1][2]["all_agents"] is True

    @pytest.mark.asyncio
    async def test_single_agent_block_unaffected(self, stub):
        """Single agent block unaffected."""
        await _call("wazuh_block_ip", ip_address="203.0.113.9", agent_id="001")
        assert stub.calls[-1][0] == "block_ip"


class TestQuarantinePathNormalisation:
    """Tests: quarantine path normalisation."""

    @pytest.mark.parametrize(
        "path",
        [
            "//etc/passwd",
            "/./etc/passwd",
            "/etc/./passwd",
            "/tmp/./../etc/passwd",
            "/private/etc/passwd",
            "/Library/Ossec/etc/ossec.conf",
            "/System/Library/x",
            "/Applications/Safari.app/Contents/MacOS/Safari",
            "\\\\etc\\\\passwd",
        ],
    )
    def test_spelling_tricks_do_not_escape_the_denylist(self, path, monkeypatch):
        """Spelling tricks do not escape the denylist."""
        monkeypatch.delenv("WAZUH_QUARANTINE_DENY_PREFIXES", raising=False)
        monkeypatch.delenv("WAZUH_QUARANTINE_ALLOW_PREFIXES", raising=False)
        with pytest.raises(ToolValidationError):
            validate_quarantine_path(path)

    def test_prefix_boundary_is_a_path_component(self, monkeypatch):
        """Prefix boundary is a path component."""
        monkeypatch.delenv("WAZUH_QUARANTINE_DENY_PREFIXES", raising=False)
        monkeypatch.delenv("WAZUH_QUARANTINE_ALLOW_PREFIXES", raising=False)
        # "/etcetera" is not "/etc"
        assert validate_quarantine_path("/etcetera/file") == "/etcetera/file"


class TestConfirmAdvertisedInSchemas:
    """Tests: confirm advertised in schemas."""

    @pytest.mark.asyncio
    async def test_write_tools_expose_optional_confirm(self):
        """Write tools expose optional confirm."""
        from wazuh_mcp_server.server import WRITE_SCOPE_TOOLS, handle_tools_list

        tools = (await handle_tools_list({}, _session()))["tools"]
        by_name = {t["name"]: t for t in tools}
        for name in WRITE_SCOPE_TOOLS:
            assert by_name[name]["inputSchema"]["properties"]["confirm"]["type"] == "boolean", name
            assert "confirm" not in by_name[name]["inputSchema"].get("required", []), name
        read_tool = next(t for t in tools if t["name"] not in WRITE_SCOPE_TOOLS)
        assert "confirm" not in read_tool["inputSchema"].get("properties", {})


class TestSwitchParsing:
    """Active-response switches use the same boolean spellings as every other setting."""

    @pytest.mark.parametrize(
        "value,expected", [("on", True), ("yes", True), ("1", True), ("off", False), ("no", False)]
    )
    def test_confirmation_spellings(self, monkeypatch, value, expected):
        from wazuh_mcp_server.server import _require_action_confirmation

        monkeypatch.setenv("WAZUH_REQUIRE_ACTION_CONFIRMATION", value)
        assert _require_action_confirmation() is expected

    @pytest.mark.parametrize(
        "var", ["WAZUH_REQUIRE_ACTION_CONFIRMATION", "WAZUH_ALLOW_FLEET_AR", "WAZUH_ALLOW_MANAGER_AR"]
    )
    def test_garbage_fails_at_startup(self, monkeypatch, var):
        from wazuh_mcp_server.config import ConfigurationError, ServerConfig

        monkeypatch.setenv(var, "enabled")
        with pytest.raises(ConfigurationError):
            ServerConfig.from_env()
