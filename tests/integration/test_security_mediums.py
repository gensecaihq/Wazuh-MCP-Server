"""
Security-hardening tests: fail-closed tool scope, agent-id normalization,
and injection-safe indexer free-text search.
"""

import pytest

from wazuh_mcp_server.security import validate_agent_id


class TestFailClosedScope:
    def test_known_read_tool_is_read(self):
        from wazuh_mcp_server.server import _get_tool_scope

        assert _get_tool_scope("get_wazuh_alerts") == "wazuh:read"
        assert _get_tool_scope("wazuh_check_blocked_ip") == "wazuh:read"

    def test_known_write_tool_is_write(self):
        from wazuh_mcp_server.server import _get_tool_scope

        assert _get_tool_scope("wazuh_block_ip") == "wazuh:write"

    def test_unknown_tool_defaults_to_write(self):
        from wazuh_mcp_server.server import _get_tool_scope

        # A tool nobody classified must require write (deny to read tokens), not read.
        assert _get_tool_scope("wazuh_totally_new_tool") == "wazuh:write"

    def test_destructive_named_tool_is_write_even_if_unlisted(self):
        from wazuh_mcp_server.server import _get_tool_scope

        assert _get_tool_scope("wazuh_wipe_and_isolate_everything") == "wazuh:write"

    def test_every_listed_tool_is_partitioned(self):
        """READ_SCOPE_TOOLS and WRITE_SCOPE_TOOLS must not overlap and every write tool
        is write — guards against a tool drifting into both sets."""
        from wazuh_mcp_server.server import READ_SCOPE_TOOLS, WRITE_SCOPE_TOOLS, _get_tool_scope

        assert READ_SCOPE_TOOLS.isdisjoint(WRITE_SCOPE_TOOLS)
        for t in WRITE_SCOPE_TOOLS:
            assert _get_tool_scope(t) == "wazuh:write"
        for t in READ_SCOPE_TOOLS:
            assert _get_tool_scope(t) == "wazuh:read"


class TestAgentIdNormalization:
    def test_short_id_zero_padded(self):
        assert validate_agent_id("1") == "001"
        assert validate_agent_id("12") == "012"

    def test_manager_id_padded(self):
        assert validate_agent_id("0") == "000"

    def test_already_padded_unchanged(self):
        assert validate_agent_id("001") == "001"
        assert validate_agent_id("1234") == "1234"


class TestIndexerFreeTextIsInjectionSafe:
    @pytest.mark.asyncio
    async def test_uses_simple_query_string_without_leading_wildcard(self):
        from wazuh_mcp_server.api.wazuh_indexer import WazuhIndexerClient

        indexer = WazuhIndexerClient(host="localhost", username="u", password="p")
        captured = {}

        async def fake_search(index, query, size=100, sort=None):
            captured["query"] = query
            return {"hits": {"hits": [], "total": {"value": 0}}}

        indexer._search = fake_search
        # A malicious leading-wildcard / regexp-style probe:
        await indexer.get_alerts(query_text="*://evil OR agent.name:/.*/")

        clause = captured["query"]["bool"]["must"][0]
        assert "query_string" not in clause
        sqs = clause["simple_query_string"]
        # Leading wildcard stripped; injection-prone flags absent.
        assert not sqs["query"].startswith("*")
        assert "analyze_wildcard" not in sqs


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
