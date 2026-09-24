"""Tool grouping, operator-controlled exposure, and MCP tool annotations.

Kept free of server imports so config validation can use it at startup.

Toolsets exist mainly for smaller local models (vLLM / Ollama): tool-selection accuracy
drops as the catalogue grows, and every tool definition is resent on every request. An
operator can expose only the groups a deployment needs, e.g. ``WAZUH_TOOLSETS=alerts,agents``.
Hidden tools are removed from ``tools/list`` *and* refused by ``tools/call``.
"""

from typing import Dict, FrozenSet, Iterable, Optional

# Every dispatchable tool belongs to exactly one toolset. tests/unit/test_toolsets.py
# asserts this against READ_SCOPE_TOOLS | WRITE_SCOPE_TOOLS, so a new tool can't ship
# without being placed here.
TOOLSETS: Dict[str, FrozenSet[str]] = {
    "alerts": frozenset(
        {
            "get_wazuh_alerts",
            "get_wazuh_alert_summary",
            "get_alerts_aggregated",
            "analyze_alert_patterns",
            "search_security_events",
        }
    ),
    "agents": frozenset(
        {
            "get_wazuh_agents",
            "get_wazuh_running_agents",
            "check_agent_health",
            "get_agent_processes",
            "get_agent_ports",
            "get_agent_configuration",
        }
    ),
    "vulnerabilities": frozenset(
        {
            "get_wazuh_vulnerabilities",
            "get_wazuh_critical_vulnerabilities",
            "get_wazuh_vulnerability_summary",
        }
    ),
    "analysis": frozenset(
        {
            "analyze_security_threat",
            "check_ioc_reputation",
            "perform_risk_assessment",
            "get_top_security_threats",
            "generate_security_report",
        }
    ),
    # Separate from "analysis" because it is the only tool that sends data off-box
    # (indicators go to You.com); air-gapped deployments can drop it on its own.
    "web_search": frozenset({"search_external_context"}),
    "compliance": frozenset(
        {
            "run_compliance_check",
            "get_iso27001_dashboard",
            "get_iso27001_control_detail",
            "get_iso27001_gap_analysis",
            "get_iso27001_alerts",
            "get_sca_policy_checks",
        }
    ),
    "system": frozenset(
        {
            "get_wazuh_statistics",
            "get_wazuh_cluster_health",
            "get_wazuh_cluster_nodes",
            "get_wazuh_rules_summary",
            "search_wazuh_manager_logs",
            "get_wazuh_manager_error_logs",
            "get_wazuh_log_collector_stats",
            "get_wazuh_remoted_stats",
            "get_wazuh_weekly_stats",
            "validate_wazuh_connection",
            "list_wazuh_clusters",
        }
    ),
    # Active response: the state-changing tools plus the read-only checks used to verify them.
    # Write tools are additionally gated by the wazuh:write scope.
    "response": frozenset(
        {
            "wazuh_block_ip",
            "wazuh_isolate_host",
            "wazuh_kill_process",
            "wazuh_disable_user",
            "wazuh_quarantine_file",
            "wazuh_active_response",
            "wazuh_firewall_drop",
            "wazuh_host_deny",
            "wazuh_restart",
            "wazuh_unisolate_host",
            "wazuh_enable_user",
            "wazuh_restore_file",
            "wazuh_firewall_allow",
            "wazuh_host_allow",
            "wazuh_check_blocked_ip",
            "wazuh_check_agent_isolation",
            "wazuh_check_process",
            "wazuh_check_user_status",
            "wazuh_check_file_quarantine",
        }
    ),
}

ALL_TOOLS: FrozenSet[str] = frozenset().union(*TOOLSETS.values())

# Write tools that undo a containment action. They change state but restore access rather
# than remove it, so they are not flagged destructive.
REVERSAL_TOOLS: FrozenSet[str] = frozenset(
    {
        "wazuh_unisolate_host",
        "wazuh_enable_user",
        "wazuh_restore_file",
        "wazuh_firewall_allow",
        "wazuh_host_allow",
    }
)

# Tools whose results depend on systems outside the Wazuh deployment.
OPEN_WORLD_TOOLS: FrozenSet[str] = frozenset({"search_external_context"})


def _split(raw: Optional[str]) -> list:
    return [item.strip().lower() for item in (raw or "").split(",") if item.strip()]


def resolve_enabled_tools(toolsets: Optional[str], disabled_tools: Optional[str]) -> FrozenSet[str]:
    """Resolve WAZUH_TOOLSETS / WAZUH_DISABLED_TOOLS into the set of exposed tools.

    Empty or ``all`` toolsets means every toolset. Unknown names raise ValueError so a typo
    fails at startup instead of silently hiding (or exposing) tools.
    """
    names = _split(toolsets)
    if not names or "all" in names:
        enabled = set(ALL_TOOLS)
    else:
        unknown = [n for n in names if n not in TOOLSETS]
        if unknown:
            raise ValueError(
                f"WAZUH_TOOLSETS: unknown toolset(s) {', '.join(unknown)}. "
                f"Valid: all, {', '.join(sorted(TOOLSETS))}"
            )
        enabled = set().union(*(TOOLSETS[n] for n in names))

    disabled = _split(disabled_tools)
    unknown = [t for t in disabled if t not in ALL_TOOLS]
    if unknown:
        raise ValueError(f"WAZUH_DISABLED_TOOLS: unknown tool(s) {', '.join(unknown)}")
    enabled.difference_update(disabled)
    return frozenset(enabled)


def tool_annotations(name: str, write_tools: Iterable[str]) -> Dict[str, object]:
    """MCP ToolAnnotations for a tool, derived from its scope.

    Hints only (the spec says clients must not rely on them for security), but gateways and
    clients use them to decide which calls need human approval. Authorization is still
    enforced server-side by scope.
    """
    if name in write_tools:
        return {
            "readOnlyHint": False,
            "destructiveHint": name not in REVERSAL_TOOLS,
            "idempotentHint": False,
            "openWorldHint": False,
        }
    return {
        "readOnlyHint": True,
        "openWorldHint": name in OPEN_WORLD_TOOLS,
    }
