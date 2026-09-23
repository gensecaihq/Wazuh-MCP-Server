"""
Wazuh Manager / Indexer TLS verification defaults.

Regression tests for the "WAZUH_ALLOW_SELF_SIGNED defaults to true" issue: with the
shipped defaults the httpx client was built with verify=False even when the
documented WAZUH_VERIFY_SSL=true was set, so the API credentials (HTTP Basic on
every re-authentication) travelled over an unauthenticated channel.
"""

import pytest

from wazuh_mcp_server.config import ConfigurationError, ServerConfig


@pytest.fixture
def base_env(monkeypatch):
    """Minimal Manager settings with every TLS-related variable cleared; returns monkeypatch for per-test overrides."""
    monkeypatch.setenv("WAZUH_HOST", "wazuh.internal")
    monkeypatch.setenv("WAZUH_USER", "u")
    monkeypatch.setenv("WAZUH_PASS", "p")
    for var in ("WAZUH_VERIFY_SSL", "WAZUH_ALLOW_SELF_SIGNED", "WAZUH_CA_BUNDLE", "WAZUH_INDEXER_VERIFY_SSL"):
        monkeypatch.delenv(var, raising=False)
    return monkeypatch


class TestDefaults:
    """Tests: defaults."""

    def test_defaults_verify_against_system_trust_store(self, base_env):
        """Defaults verify against system trust store."""
        cfg = ServerConfig.from_env()
        assert cfg.WAZUH_VERIFY_SSL is True
        assert cfg.WAZUH_ALLOW_SELF_SIGNED is False
        assert cfg.wazuh_tls_verify is True
        assert cfg.wazuh_indexer_tls_verify is True
        assert cfg.wazuh_tls_verification_disabled is False

    def test_allow_self_signed_disables_verification_explicitly(self, base_env):
        """Allow self signed disables verification explicitly."""
        base_env.setenv("WAZUH_ALLOW_SELF_SIGNED", "true")
        cfg = ServerConfig.from_env()
        assert cfg.wazuh_tls_verify is False
        assert cfg.wazuh_tls_verification_disabled is True

    def test_verify_false_disables_verification(self, base_env):
        """Verify false disables verification."""
        base_env.setenv("WAZUH_VERIFY_SSL", "false")
        assert ServerConfig.from_env().wazuh_tls_verify is False

    def test_indexer_verification_is_independent(self, base_env):
        """Indexer verification is independent."""
        base_env.setenv("WAZUH_INDEXER_VERIFY_SSL", "false")
        cfg = ServerConfig.from_env()
        assert cfg.wazuh_tls_verify is True
        assert cfg.wazuh_indexer_tls_verify is False


class TestCABundle:
    """Tests: CA bundle."""

    def test_ca_bundle_is_used_for_manager_and_indexer(self, base_env, tmp_path):
        """CA bundle is used for manager and indexer."""
        ca = tmp_path / "wazuh-ca.pem"
        ca.write_text("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")
        base_env.setenv("WAZUH_CA_BUNDLE", str(ca))
        cfg = ServerConfig.from_env()
        assert cfg.wazuh_tls_verify == str(ca)
        assert cfg.wazuh_indexer_tls_verify == str(ca)
        assert cfg.wazuh_tls_verification_disabled is False

    def test_missing_ca_bundle_fails_fast(self, base_env, tmp_path):
        """Missing CA bundle fails fast."""
        base_env.setenv("WAZUH_CA_BUNDLE", str(tmp_path / "nope.pem"))
        with pytest.raises(ConfigurationError, match="WAZUH_CA_BUNDLE"):
            ServerConfig.from_env()

    def test_allow_self_signed_wins_over_ca_bundle(self, base_env, tmp_path):
        """Allow self signed wins over CA bundle."""
        # Explicitly opting out of verification must not be silently upgraded.
        ca = tmp_path / "ca.pem"
        ca.write_text("x")
        base_env.setenv("WAZUH_CA_BUNDLE", str(ca))
        base_env.setenv("WAZUH_ALLOW_SELF_SIGNED", "true")
        assert ServerConfig.from_env().wazuh_tls_verify is False


class TestClientsAcceptCAPath:
    """Tests: clients accept CA path."""

    def test_wazuh_client_passes_ca_path_to_httpx(self, tmp_path):
        """Wazuh client passes CA path to httpx."""
        from wazuh_mcp_server.api.wazuh_client import WazuhClient
        from wazuh_mcp_server.config import WazuhConfig

        ca = tmp_path / "ca.pem"
        ca.write_text("x")
        client = WazuhClient(WazuhConfig(wazuh_host="localhost", wazuh_user="u", wazuh_pass="p", verify_ssl=str(ca)))
        assert client.config.verify_ssl == str(ca)

    def test_indexer_client_accepts_ca_path(self, tmp_path):
        """Indexer client accepts CA path."""
        from wazuh_mcp_server.api.wazuh_indexer import WazuhIndexerClient

        ca = tmp_path / "ca.pem"
        ca.write_text("x")
        client = WazuhIndexerClient(host="localhost", verify_ssl=str(ca))
        assert client.verify_ssl == str(ca)


class TestMultiClusterCABundle:
    """Tests: multi cluster CA bundle."""

    def _entry(self, **over):
        """Minimal WAZUH_CLUSTERS entry with keyword overrides."""
        e = {"id": "eu", "wazuh_host": "wazuh-eu.example.com", "wazuh_user": "u", "wazuh_pass": "p"}
        e.update(over)
        return e

    def test_global_bundle_applies_to_cluster_entries(self, monkeypatch, tmp_path):
        """Global bundle applies to cluster entries."""
        from wazuh_mcp_server.clusters import _cluster_config

        ca = tmp_path / "ca.pem"
        ca.write_text("x")
        monkeypatch.setenv("WAZUH_CA_BUNDLE", str(ca))
        cfg = _cluster_config(self._entry())
        assert cfg.verify_ssl == str(ca) and cfg.wazuh_indexer_verify_ssl == str(ca)

    def test_per_cluster_bundle_wins_and_verify_false_still_disables(self, monkeypatch, tmp_path):
        """Per cluster bundle wins and verify false still disables."""
        from wazuh_mcp_server.clusters import _cluster_config

        monkeypatch.delenv("WAZUH_CA_BUNDLE", raising=False)
        ca = tmp_path / "eu-ca.pem"
        ca.write_text("x")
        cfg = _cluster_config(self._entry(ca_bundle=str(ca)))
        assert cfg.verify_ssl == str(ca)
        cfg = _cluster_config(self._entry(ca_bundle=str(ca), verify_ssl=False))
        assert cfg.verify_ssl is False

    def test_missing_cluster_bundle_is_an_error(self, monkeypatch, tmp_path):
        """Missing cluster bundle is an error."""
        from wazuh_mcp_server.clusters import _cluster_config

        monkeypatch.delenv("WAZUH_CA_BUNDLE", raising=False)
        with pytest.raises(ValueError, match="ca_bundle"):
            _cluster_config(self._entry(ca_bundle=str(tmp_path / "missing.pem")))


class TestIgnoredBundleWarning:
    """Tests: ignored bundle warning."""

    def test_bundle_with_verification_off_warns(self, base_env, tmp_path, caplog):
        """Bundle with verification off warns."""
        import logging

        ca = tmp_path / "ca.pem"
        ca.write_text("x")
        base_env.setenv("WAZUH_CA_BUNDLE", str(ca))
        base_env.setenv("WAZUH_ALLOW_SELF_SIGNED", "true")
        with caplog.at_level(logging.WARNING, logger="wazuh_mcp_server.config"):
            assert ServerConfig.from_env().wazuh_tls_verify is False
        assert any("bundle is ignored" in r.getMessage() for r in caplog.records)


class TestCaBundleReachesHttpx:
    @pytest.mark.asyncio
    async def test_bundle_becomes_ssl_context_on_both_clients(self, monkeypatch, tmp_path):
        import ssl as _ssl
        import subprocess

        import httpx

        from wazuh_mcp_server.api.wazuh_client import WazuhClient
        from wazuh_mcp_server.config import WazuhConfig

        ca = tmp_path / "ca.pem"
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                str(tmp_path / "k"),
                "-out",
                str(ca),
                "-days",
                "1",
                "-subj",
                "/CN=t",
            ],
            check=True,
            capture_output=True,
        )
        seen = []
        real = httpx.AsyncClient

        def capture(*a, **kw):
            seen.append(kw.get("verify"))
            return real(*a, **kw)

        monkeypatch.setattr(httpx, "AsyncClient", capture)
        client = WazuhClient(
            WazuhConfig(
                wazuh_host="h",
                wazuh_user="u",
                wazuh_pass="p",
                verify_ssl=str(ca),
                wazuh_indexer_host="i",
                wazuh_indexer_user="u",
                wazuh_indexer_pass="p",
                wazuh_indexer_verify_ssl=str(ca),
            )
        )
        try:
            await client.initialize()
        except Exception:
            pass  # no Manager here; only the client construction matters
        if client._indexer_client is not None:
            try:
                await client._indexer_client._ensure_initialized()
            except Exception:
                pass
        # Manager and Indexer clients both get an SSLContext (a bare path is deprecated in httpx)
        assert len(seen) >= 2 and all(isinstance(v, _ssl.SSLContext) for v in seen), seen
