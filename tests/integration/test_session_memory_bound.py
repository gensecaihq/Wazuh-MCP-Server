"""
Session store memory bounds.

Regression: `initialize` stored the client's `capabilities` / `clientInfo` objects
verbatim (request bodies may be up to 1 MB), a fresh session was minted for every
POST without a session id, sessions lived 30 minutes and the in-memory store had no
size limit — so one authenticated, read-only principal could push gigabytes into the
process until the memory kill-switch put the whole server into 503.
"""

from datetime import datetime, timedelta, timezone

import pytest

from wazuh_mcp_server import server as mcp_server
from wazuh_mcp_server.server import (
    MCPSession,
    SessionManager,
    _bounded_capabilities,
    _bounded_client_info,
    get_or_create_session,
    handle_initialize,
)
from wazuh_mcp_server.session_store import InMemorySessionStore


@pytest.fixture
def fresh_store(monkeypatch):
    """Empty in-memory SessionManager installed as the server store, with small caps (50 total, 5 per principal)."""
    store = SessionManager(InMemorySessionStore())
    monkeypatch.setattr(mcp_server, "sessions", store)
    monkeypatch.setattr(mcp_server, "_last_session_cleanup", 0)
    monkeypatch.setattr(mcp_server, "MAX_SESSIONS", 50)
    monkeypatch.setattr(mcp_server, "MAX_SESSIONS_PER_PRINCIPAL", 5)
    return store


class TestBoundedClientMetadata:
    """Tests: bounded client metadata."""

    def test_client_info_is_reduced_to_known_short_fields(self):
        """Client info is reduced to known short fields."""
        raw = {"name": "n" * 5000, "version": "1.0", "title": 42, "payload": "x" * 1_000_000, "nested": {"a": 1}}
        out = _bounded_client_info(raw)
        assert set(out) == {"name", "version", "title"}
        assert len(out["name"]) == 128 and out["title"] == "42"
        assert _bounded_client_info("not-a-dict") == {}
        assert _bounded_client_info(None) == {}

    def test_capabilities_keep_only_top_level_names(self):
        """Capabilities keep only top level names."""
        raw = {f"cap{i}": {"blob": "x" * 100_000} for i in range(200)}
        out = _bounded_capabilities(raw)
        assert len(out) == 32 and all(v is True for v in out.values())
        assert _bounded_capabilities(["list"]) == {}

    @pytest.mark.asyncio
    async def test_initialize_stores_bounded_copies(self):
        """Initialize stores bounded copies."""
        session = MCPSession("s", None)
        big = {"clientInfo": {"name": "c", "junk": "x" * 500_000}, "capabilities": {"roots": {"blob": "y" * 500_000}}}
        await handle_initialize(big, session)
        assert session.client_info == {"name": "c"}
        assert session.capabilities == {"roots": True}


class TestStoreBounds:
    """Tests: store bounds."""

    @pytest.mark.asyncio
    async def test_global_cap_evicts_least_recently_active(self, fresh_store):
        """Global cap evicts least recently active."""
        first = await get_or_create_session(None, None)
        first.last_activity = datetime.now(timezone.utc) - timedelta(minutes=5)
        await fresh_store.set(first.session_id, first)
        for _ in range(60):
            await get_or_create_session(None, None)
        assert len(await fresh_store.get_all()) <= 50
        assert await fresh_store.get(first.session_id) is None  # oldest went first

    @pytest.mark.asyncio
    async def test_expired_sessions_reclaimed_before_evicting_live_ones(self, fresh_store):
        """Expired sessions reclaimed before evicting live ones."""
        live = await get_or_create_session(None, None)
        for _ in range(49):
            s = await get_or_create_session(None, None)
            s.last_activity = datetime.now(timezone.utc) - timedelta(hours=2)  # expired
            await fresh_store.set(s.session_id, s)
        assert len(await fresh_store.get_all()) == 50
        await get_or_create_session(None, None)  # at cap: expired ones are dropped first
        assert await fresh_store.get(live.session_id) is not None

    @pytest.mark.asyncio
    async def test_per_principal_cap(self, fresh_store):
        """Per principal cap."""
        ids = [(await get_or_create_session(None, None, principal="alice")).session_id for _ in range(12)]
        mine = [s for s in (await fresh_store.get_all()).values() if s.principal == "alice"]
        assert len(mine) == 5
        assert ids[-1] in {s.session_id for s in mine} and ids[0] not in {s.session_id for s in mine}
        # Another principal is not affected by alice's churn.
        bob = await get_or_create_session(None, None, principal="bob")
        for _ in range(20):
            await get_or_create_session(None, None, principal="alice")
        assert await fresh_store.get(bob.session_id) is not None

    @pytest.mark.asyncio
    async def test_existing_session_lookup_never_evicts(self, fresh_store):
        """Existing session lookup never evicts."""
        s = await get_or_create_session(None, None, principal="alice")
        for _ in range(10):
            again = await get_or_create_session(s.session_id, None, principal="alice")
            assert again.session_id == s.session_id
        assert len(await fresh_store.get_all()) == 1

    def test_principal_survives_serialization(self):
        """Principal survives serialization."""
        s = MCPSession("s", None)
        s.principal = "alice"
        s.client_info = {"name": "c"}
        restored = SessionManager(InMemorySessionStore())._session_from_dict(s.to_dict())
        assert restored.principal == "alice" and restored.client_info == {"name": "c"}


class TestSharedPrincipalsAndFastPath:
    """Tests: shared principals and fast path."""

    @pytest.mark.asyncio
    async def test_authless_principal_is_not_capped_per_principal(self, fresh_store):
        """Authless principal is not capped per principal."""
        # Everyone in AUTH_MODE=none shares the "authless" principal: only the global cap applies.
        ids = [(await get_or_create_session(None, None, principal="authless")).session_id for _ in range(30)]
        stored = await fresh_store.get_all()
        assert all(i in stored for i in ids)

    @pytest.mark.asyncio
    async def test_fast_path_skips_full_scan_below_bounds(self, fresh_store, monkeypatch):
        """Fast path skips full scan below bounds."""
        calls = {"get_all": 0}
        real_get_all = fresh_store.get_all

        async def counting_get_all():
            """Count full-store scans while delegating to the real get_all."""
            calls["get_all"] += 1
            return await real_get_all()

        monkeypatch.setattr(fresh_store, "get_all", counting_get_all)
        for _ in range(4):  # below MAX_SESSIONS_PER_PRINCIPAL (5) and MAX_SESSIONS (50)
            await get_or_create_session(None, None, principal="alice")
        assert calls["get_all"] == 0

    @pytest.mark.asyncio
    async def test_count_matches_store(self, fresh_store):
        """Count matches store."""
        for _ in range(3):
            await get_or_create_session(None, None)
        assert await fresh_store.count() == 3

    def test_knobs_are_validated_in_config(self, monkeypatch):
        """Knobs are validated in config."""
        from wazuh_mcp_server.config import ConfigurationError, ServerConfig

        monkeypatch.setenv("WAZUH_HOST", "h")
        monkeypatch.setenv("WAZUH_USER", "u")
        monkeypatch.setenv("WAZUH_PASS", "p")
        monkeypatch.setenv("MAX_SESSIONS", "abc")
        with pytest.raises(ConfigurationError):
            ServerConfig.from_env()
        monkeypatch.setenv("MAX_SESSIONS", "0")
        with pytest.raises(ConfigurationError):
            ServerConfig.from_env()
        monkeypatch.setenv("MAX_SESSIONS", "250")
        monkeypatch.setenv("MAX_SESSIONS_PER_PRINCIPAL", "7")
        cfg = ServerConfig.from_env()
        assert (cfg.MAX_SESSIONS, cfg.MAX_SESSIONS_PER_PRINCIPAL) == (250, 7)
