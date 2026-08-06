"""
Observability tests: JSON log formatter renders correlation IDs, and the
previously-dead auth / rate-limit / session metrics now increment.
"""

import io
import json
import logging

import pytest

from wazuh_mcp_server import monitoring


class TestJsonLogFormatter:
    def test_renders_correlation_id_and_extras(self):
        monitoring.set_correlation_id("corr-123")
        buf = io.StringIO()
        handler = logging.StreamHandler(buf)
        handler.setFormatter(monitoring.JsonLogFormatter())
        record = logging.LogRecord("wazuh_mcp_server.api", logging.INFO, "f.py", 1, "hello", (), None)
        record.tool_name = "get_wazuh_alerts"
        handler.emit(record)
        payload = json.loads(buf.getvalue())
        assert payload["message"] == "hello"
        assert payload["level"] == "INFO"
        assert payload["correlation_id"] == "corr-123"
        assert payload["tool_name"] == "get_wazuh_alerts"

    def test_configure_logging_json_selects_formatter(self, monkeypatch):
        monkeypatch.setenv("LOG_FORMAT", "json")
        root = logging.getLogger()
        saved = list(root.handlers)
        try:
            monitoring.configure_logging()
            assert any(isinstance(h.formatter, monitoring.JsonLogFormatter) for h in root.handlers)
        finally:
            root.handlers = saved


class TestMetricsWired:
    def _sample(self, counter, **labels):
        # Read the current value of a prometheus counter/child.
        c = counter.labels(**labels) if labels else counter
        return c._value.get()

    def test_auth_attempt_metric_increments(self):
        before = self._sample(monitoring.AUTHENTICATION_ATTEMPTS, result="failure")
        monitoring.record_auth_attempt(False)
        assert self._sample(monitoring.AUTHENTICATION_ATTEMPTS, result="failure") == before + 1

    def test_rate_limit_metric_increments(self):
        before = self._sample(monitoring.RATE_LIMIT_HITS, endpoint="mcp")
        monitoring.record_rate_limit_hit("mcp")
        assert self._sample(monitoring.RATE_LIMIT_HITS, endpoint="mcp") == before + 1

    def test_session_events_increment(self):
        before_c = self._sample(monitoring.SESSION_CREATED)
        before_e = self._sample(monitoring.SESSION_EXPIRED)
        monitoring.record_session_event("created")
        monitoring.record_session_event("expired")
        assert self._sample(monitoring.SESSION_CREATED) == before_c + 1
        assert self._sample(monitoring.SESSION_EXPIRED) == before_e + 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
