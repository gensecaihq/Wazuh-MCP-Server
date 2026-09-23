"""
Toolset exposure, MCP tool annotations, and closed input schemas.

Toolsets let an operator shrink the catalogue for small local models; they must hide a tool
from tools/list *and* refuse it in tools/call. Annotations and additionalProperties=false are
what gateways (LiteLLM) and strict function calling (vLLM --tool-strict-level) key off.
"""

import dataclasses
from datetime import datetime, timezone

import pytest

from wazuh_mcp_server import server as mcp_server
from wazuh_mcp_server.auth import AuthToken
from wazuh_mcp_server.config import ConfigurationError, ServerConfig
from wazuh_mcp_server.server import (
    READ_SCOPE_TOOLS,
    WRITE_SCOPE_TOOLS,
    MCPSession,
    handle_tools_call,
    handle_tools_list,
)
from wazuh_mcp_server.toolsets import ALL_TOOLS, REVERSAL_TOOLS, TOOLSETS, resolve_enabled_tools


def _session(scopes=("wazuh:read", "wazuh:write")):
    session = MCPSession("test-session", None)
    session.authenticated = True
    session._auth_token = AuthToken(
        token="t", api_key_id="tester", created_at=datetime.now(timezone.utc), scopes=list(scopes)
    )
    return session


def _enable(monkeypatch, toolsets=None, disabled=None):
    enabled = resolve_enabled_tools(toolsets, disabled)
    monkeypatch.setattr(mcp_server, "config", dataclasses.replace(mcp_server.config, ENABLED_TOOLS=enabled))


async def _listed(session=None):
    return {t["name"]: t for t in (await handle_tools_list({}, session or _session()))["tools"]}


class TestToolsetMapping:
    def test_every_dispatchable_tool_is_in_exactly_one_toolset(self):
        assert ALL_TOOLS == READ_SCOPE_TOOLS | WRITE_SCOPE_TOOLS
        seen = [t for members in TOOLSETS.values() for t in members]
        assert len(seen) == len(set(seen)), "a tool is in more than one toolset"

    def test_reversal_tools_are_write_tools(self):
        assert REVERSAL_TOOLS <= WRITE_SCOPE_TOOLS

    def test_default_enables_everything(self):
        assert resolve_enabled_tools(None, None) == ALL_TOOLS
        assert resolve_enabled_tools("", "") == ALL_TOOLS
        assert resolve_enabled_tools("all", None) == ALL_TOOLS

    def test_selection_and_exclusion(self):
        enabled = resolve_enabled_tools(" Alerts , agents ", "get_agent_ports")
        assert enabled == (TOOLSETS["alerts"] | TOOLSETS["agents"]) - {"get_agent_ports"}

    @pytest.mark.parametrize(
        "toolsets,disabled,match",
        [("alerts,alert", None, "unknown toolset"), (None, "get_wazuh_alertz", "unknown tool")],
    )
    def test_typos_fail_loudly(self, toolsets, disabled, match):
        with pytest.raises(ValueError, match=match):
            resolve_enabled_tools(toolsets, disabled)

    def test_config_rejects_unknown_toolset_at_startup(self, monkeypatch):
        monkeypatch.setenv("WAZUH_TOOLSETS", "alerts,nope")
        with pytest.raises(ConfigurationError, match="nope"):
            ServerConfig.from_env()

    def test_config_resolves_env(self, monkeypatch):
        monkeypatch.setenv("WAZUH_TOOLSETS", "vulnerabilities")
        monkeypatch.setenv("WAZUH_DISABLED_TOOLS", "get_wazuh_vulnerability_summary")
        assert ServerConfig.from_env().ENABLED_TOOLS == {
            "get_wazuh_vulnerabilities",
            "get_wazuh_critical_vulnerabilities",
        }


class TestToolsetEnforcement:
    @pytest.mark.asyncio
    async def test_list_only_shows_enabled_tools(self, monkeypatch):
        _enable(monkeypatch, "alerts")
        assert set(await _listed()) == TOOLSETS["alerts"]

    @pytest.mark.asyncio
    async def test_disabled_tool_hidden_and_refused(self, monkeypatch):
        _enable(monkeypatch, None, "wazuh_isolate_host,search_external_context")
        listed = await _listed()
        assert "wazuh_isolate_host" not in listed and "search_external_context" not in listed
        for name in ("wazuh_isolate_host", "search_external_context"):
            with pytest.raises(ValueError, match="disabled on this server"):
                await handle_tools_call({"name": name, "arguments": {}}, _session())

    @pytest.mark.asyncio
    async def test_scope_filter_still_applies_within_enabled_set(self, monkeypatch):
        _enable(monkeypatch, "response")
        listed = await _listed(_session(["wazuh:read"]))
        assert set(listed) == TOOLSETS["response"] - WRITE_SCOPE_TOOLS


class TestAnnotationsAndSchemas:
    @pytest.mark.asyncio
    async def test_every_tool_annotated_and_closed(self):
        for name, tool in (await _listed()).items():
            assert tool["inputSchema"]["additionalProperties"] is False, name
            ann = tool["annotations"]
            assert ann["readOnlyHint"] is (name not in WRITE_SCOPE_TOOLS), name

    @pytest.mark.asyncio
    async def test_destructive_hints(self):
        listed = await _listed()
        for name in ("wazuh_isolate_host", "wazuh_kill_process", "wazuh_block_ip", "wazuh_active_response"):
            assert listed[name]["annotations"]["destructiveHint"] is True
        for name in REVERSAL_TOOLS:
            assert listed[name]["annotations"]["destructiveHint"] is False
        assert listed["search_external_context"]["annotations"]["openWorldHint"] is True
        assert listed["get_wazuh_alerts"]["annotations"]["openWorldHint"] is False

    @pytest.mark.asyncio
    async def test_confirm_declared_when_confirmation_required(self, monkeypatch):
        # A closed schema must still let a strict client send the confirm flag the gate reads
        monkeypatch.setenv("WAZUH_REQUIRE_ACTION_CONFIRMATION", "true")
        listed = await _listed()
        assert listed["wazuh_block_ip"]["inputSchema"]["properties"]["confirm"]["type"] == "boolean"
        assert "confirm" not in listed["get_wazuh_alerts"]["inputSchema"]["properties"]

    @pytest.mark.asyncio
    async def test_confirm_not_declared_by_default(self, monkeypatch):
        monkeypatch.delenv("WAZUH_REQUIRE_ACTION_CONFIRMATION", raising=False)
        assert "confirm" not in (await _listed())["wazuh_block_ip"]["inputSchema"]["properties"]
