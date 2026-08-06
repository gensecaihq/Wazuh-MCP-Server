"""
Active-response and Wazuh-API correctness tests (B3 blocker cluster).

Covers the tool-correctness bugs where the client either could never succeed or
returned a misleading success against a stock Wazuh deployment.
"""

import pytest

from wazuh_mcp_server.api.wazuh_client import WazuhClient
from wazuh_mcp_server.config import WazuhConfig


def _client(monkeypatch=None):
    return WazuhClient(WazuhConfig(wazuh_host="localhost", wazuh_user="u", wazuh_pass="p", verify_ssl=False))


class TestGenericActiveResponse:
    @pytest.mark.asyncio
    async def test_command_without_bang_is_normalized_and_accepted(self):
        client = _client()
        sent = {}

        async def fake_exec(data):
            sent.update(data)
            return {"data": {"total_affected_items": 1, "total_failed_items": 0, "failed_items": []}}

        client.execute_active_response = fake_exec
        # Previously "firewall-drop" failed validation-vs-allowlist; now it normalizes.
        await client.run_active_response("001", "firewall-drop")
        assert sent["command"] == "!firewall-drop"

    @pytest.mark.asyncio
    async def test_bang_form_still_accepted(self):
        client = _client()
        sent = {}

        async def fake_exec(data):
            sent.update(data)
            return {"data": {"total_affected_items": 1, "total_failed_items": 0, "failed_items": []}}

        client.execute_active_response = fake_exec
        await client.run_active_response("001", "!kill-process")
        assert sent["command"] == "!kill-process"

    @pytest.mark.asyncio
    async def test_unknown_command_still_rejected(self):
        client = _client()
        with pytest.raises(ValueError, match="Unknown active response command"):
            await client.run_active_response("001", "rm-rf-slash")

    def test_validator_accepts_optional_bang(self):
        from wazuh_mcp_server.security import validate_active_response_command

        assert validate_active_response_command("firewall-drop") == "firewall-drop"
        assert validate_active_response_command("!firewall-drop") == "!firewall-drop"


class TestDisableUserPayload:
    @pytest.mark.asyncio
    async def test_disable_user_sets_dstuser_alert(self):
        client = _client()
        sent = {}

        async def fake_exec(data):
            sent.update(data)
            return {"data": {"total_affected_items": 1, "total_failed_items": 0, "failed_items": []}}

        client.execute_active_response = fake_exec
        await client.disable_user("001", "attacker")
        # Stock disable-account reads the target from alert.data.dstuser.
        assert sent["alert"]["data"]["dstuser"] == "attacker"
        assert "attacker" in sent["arguments"]


class TestRollbackNeverReblocks:
    @pytest.mark.asyncio
    async def test_firewall_allow_refuses_without_undo_command(self, monkeypatch):
        monkeypatch.delenv("WAZUH_AR_FIREWALL_UNDO_COMMAND", raising=False)
        client = _client()
        # Must NOT invoke active response (which would re-block).
        called = False

        async def fake_exec(data):
            nonlocal called
            called = True
            return {}

        client.execute_active_response = fake_exec
        with pytest.raises(ValueError, match="re-block|undo"):
            await client.firewall_allow("001", "10.0.0.5")
        assert called is False

    @pytest.mark.asyncio
    async def test_firewall_allow_uses_configured_undo_command(self, monkeypatch):
        monkeypatch.setenv("WAZUH_AR_FIREWALL_UNDO_COMMAND", "firewall-undrop")
        client = _client()
        sent = {}

        async def fake_exec(data):
            sent.update(data)
            return {"data": {"total_affected_items": 1, "total_failed_items": 0, "failed_items": []}}

        client.execute_active_response = fake_exec
        await client.firewall_allow("001", "10.0.0.5")
        assert sent["command"] == "!firewall-undrop"  # normalized with leading !
        assert sent["alert"]["data"]["srcip"] == "10.0.0.5"


class TestManagerLogSearch:
    @pytest.mark.asyncio
    async def test_search_manager_logs_uses_search_param(self):
        client = _client()
        captured = {}

        async def fake_request(method, endpoint, **kwargs):
            captured["endpoint"] = endpoint
            captured["params"] = kwargs.get("params")
            return {"data": {"affected_items": []}}

        client._request = fake_request
        await client.search_manager_logs("error something", 50)
        # Free text must go through `search`, not `q` (which needs field=value syntax).
        assert "search" in captured["params"]
        assert "q" not in captured["params"]


class TestCheckFileQuarantineRoute:
    @pytest.mark.asyncio
    async def test_uses_per_agent_syscheck_route(self):
        client = _client()
        captured = {}

        async def fake_request(method, endpoint, **kwargs):
            captured["endpoint"] = endpoint
            return {"data": {"affected_items": []}}

        client._request = fake_request
        await client.check_file_quarantine("007", "/etc/passwd")
        assert captured["endpoint"] == "/syscheck/007"


class TestISO27001Scoring:
    def _client_with_indexer(self):
        return WazuhClient(
            WazuhConfig(
                wazuh_host="localhost",
                wazuh_user="u",
                wazuh_pass="p",
                verify_ssl=False,
                wazuh_indexer_host="localhost",
                wazuh_indexer_user="i",
                wazuh_indexer_pass="i",
            )
        )

    async def _run_dashboard(self, client, *, stats_events, vulns_raise):
        async def fake_request(method, endpoint, **kwargs):
            if endpoint == "/agents":
                return {"data": {"affected_items": [{"id": "001", "name": "web-01"}]}}
            if endpoint.startswith("/sca/"):
                return {"data": {"affected_items": []}}
            if endpoint == "/manager/stats/analysisd":
                # Real Wazuh shape: stats live under data.affected_items[0]
                return {"data": {"affected_items": [{"total_events_decoded": stats_events}]}}
            return {"data": {"affected_items": []}}

        async def fake_get_alerts(**kwargs):
            return {"data": {"affected_items": [], "total_affected_items": 0}}

        async def fake_vulns(**kwargs):
            if vulns_raise:
                raise RuntimeError("indexer down")
            return {"data": {"affected_items": []}}

        client._request = fake_request
        client.get_alerts = fake_get_alerts
        client._indexer_client.get_vulnerabilities = fake_vulns
        result = await client.get_iso27001_dashboard()
        return {c["control_id"]: c for c in result["data"]["controls"]}

    @pytest.mark.asyncio
    async def test_logging_control_reads_nested_stats(self):
        """A.8.15 must read data.affected_items[0].total_events_decoded, not data.* —
        the old direct read always saw 0 and reported a false no_data gap."""
        client = self._client_with_indexer()
        controls = await self._run_dashboard(client, stats_events=12345, vulns_raise=False)
        a815 = controls["A.8.15"]
        assert a815["status"] == "active"
        assert a815["evidence_count"] == 12345

    @pytest.mark.asyncio
    async def test_indexer_failure_scores_vuln_control_as_no_data_not_100(self):
        """An Indexer outage must not yield a perfect vulnerability score with high confidence."""
        client = self._client_with_indexer()
        controls = await self._run_dashboard(client, stats_events=1, vulns_raise=True)
        a88 = controls["A.8.8"]
        assert a88["status"] == "no_data"
        assert a88["score"] is None
        assert a88["confidence"] == "none"

    @pytest.mark.asyncio
    async def test_successful_zero_vuln_query_is_full_compliance(self):
        """A successful query returning zero vulns is legitimately 100/pass/high."""
        client = self._client_with_indexer()
        controls = await self._run_dashboard(client, stats_events=1, vulns_raise=False)
        a88 = controls["A.8.8"]
        assert a88["status"] == "pass"
        assert a88["score"] == 100
        assert a88["confidence"] == "high"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
