"""
Log credential-redaction tests.

Regression focus: the sanitizer must run for records emitted by CHILD loggers
(e.g. wazuh_mcp_server.api.wazuh_client) that propagate to the root handler. A
filter attached to the root *logger* is skipped for propagated records, so
redaction has to live on the handlers.
"""

import io
import logging

from wazuh_mcp_server.security import SanitizingLogFilter, install_log_sanitizer


def _capture_root(monkeypatch):
    """Attach a StringIO handler to the root logger and return its buffer."""
    buf = io.StringIO()
    handler = logging.StreamHandler(buf)
    handler.setFormatter(logging.Formatter("%(name)s %(message)s"))
    root = logging.getLogger()
    root.addHandler(handler)
    root.setLevel(logging.DEBUG)
    return buf, handler, root


def test_child_logger_credentials_redacted_via_root_handler():
    buf, handler, root = _capture_root(None)
    try:
        install_log_sanitizer(extra_logger_names=())  # attaches to root handlers, incl. ours

        child = logging.getLogger("wazuh_mcp_server.api.wazuh_client")
        child.propagate = True
        child.error("connect failed url=https://u:hunter2@host password=hunter2 token=abcdef123456")

        out = buf.getvalue()
        assert "hunter2" not in out, f"password leaked: {out!r}"
        assert "abcdef123456" not in out, f"token leaked: {out!r}"
        assert "[REDACTED]" in out
    finally:
        root.removeHandler(handler)


def test_bearer_and_api_key_tokens_redacted():
    buf, handler, root = _capture_root(None)
    try:
        install_log_sanitizer(extra_logger_names=())
        logging.getLogger("wazuh_mcp_server.auth").warning(
            "auth header: Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig api_key=wazuh_secretvalue"
        )
        out = buf.getvalue()
        assert "eyJhbGciOiJIUzI1NiJ9.payload.sig" not in out
        assert "wazuh_secretvalue" not in out
        assert "[REDACTED]" in out
    finally:
        root.removeHandler(handler)


def test_install_is_idempotent():
    root = logging.getLogger()
    before = [h for h in root.handlers]
    install_log_sanitizer(extra_logger_names=())
    install_log_sanitizer(extra_logger_names=())
    for h in before:
        assert sum(isinstance(f, SanitizingLogFilter) for f in h.filters) <= 1


if __name__ == "__main__":
    import pytest

    pytest.main([__file__, "-v"])
