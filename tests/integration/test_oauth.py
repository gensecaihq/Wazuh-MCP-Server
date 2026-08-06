"""
OAuth 2.0 authorization-server tests.

Exercises the security-critical flows that were previously untested: mandatory
PKCE (S256), single-use authorization codes, refresh-token rotation with replay
detection, the revocation denylist, and DCR redirect-URI validation.
"""

import base64
import hashlib
import secrets
from types import SimpleNamespace

import pytest

from wazuh_mcp_server.oauth import OAuthManager


def _config(dcr=False, issuer=""):
    return SimpleNamespace(
        AUTH_SECRET_KEY="test-secret-key-at-least-32-characters-long",
        OAUTH_ENABLE_DCR=dcr,
        OAUTH_ACCESS_TOKEN_TTL=3600,
        OAUTH_REFRESH_TOKEN_TTL=86400,
        OAUTH_AUTHORIZATION_CODE_TTL=600,
        OAUTH_ISSUER_URL=issuer,
    )


def _pkce():
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def _mgr(**kw):
    return OAuthManager(_config(**kw))


REDIRECT = "https://claude.ai/api/mcp/auth_callback"


class TestPKCE:
    def test_code_creation_requires_pkce(self):
        mgr = _mgr()
        with pytest.raises(ValueError, match="code_challenge is required"):
            mgr.create_authorization_code("claude-desktop", REDIRECT, "wazuh:read", None, "S256")

    def test_code_creation_requires_s256(self):
        mgr = _mgr()
        _, challenge = _pkce()
        with pytest.raises(ValueError, match="S256"):
            mgr.create_authorization_code("claude-desktop", REDIRECT, "wazuh:read", challenge, "plain")

    def test_full_flow_with_correct_verifier(self):
        mgr = _mgr()
        verifier, challenge = _pkce()
        code = mgr.create_authorization_code("claude-desktop", REDIRECT, "wazuh:read", challenge, "S256")
        tokens = mgr.exchange_code_for_tokens(code, "claude-desktop", REDIRECT, verifier)
        assert tokens["access_token"]
        assert tokens["scope"] == "wazuh:read"
        assert mgr.validate_access_token(tokens["access_token"]) is not None

    def test_wrong_verifier_rejected(self):
        mgr = _mgr()
        _, challenge = _pkce()
        code = mgr.create_authorization_code("claude-desktop", REDIRECT, "wazuh:read", challenge, "S256")
        with pytest.raises(ValueError, match="invalid_grant"):
            mgr.exchange_code_for_tokens(code, "claude-desktop", REDIRECT, "wrong-verifier")


class TestSingleUseCode:
    def test_code_cannot_be_replayed(self):
        mgr = _mgr()
        verifier, challenge = _pkce()
        code = mgr.create_authorization_code("claude-desktop", REDIRECT, "wazuh:read", challenge, "S256")
        mgr.exchange_code_for_tokens(code, "claude-desktop", REDIRECT, verifier)
        with pytest.raises(ValueError, match="invalid_grant"):
            mgr.exchange_code_for_tokens(code, "claude-desktop", REDIRECT, verifier)

    def test_redirect_uri_mismatch_rejected(self):
        mgr = _mgr()
        verifier, challenge = _pkce()
        code = mgr.create_authorization_code("claude-desktop", REDIRECT, "wazuh:read", challenge, "S256")
        with pytest.raises(ValueError, match="invalid_grant"):
            mgr.exchange_code_for_tokens(code, "claude-desktop", "https://evil.example/cb", verifier)


class TestRefreshRotation:
    def _issue(self, mgr):
        verifier, challenge = _pkce()
        code = mgr.create_authorization_code("claude-desktop", REDIRECT, "wazuh:read", challenge, "S256")
        return mgr.exchange_code_for_tokens(code, "claude-desktop", REDIRECT, verifier)

    def test_refresh_rotates_the_token(self):
        mgr = _mgr()
        tokens = self._issue(mgr)
        rotated = mgr.refresh_access_token(tokens["refresh_token"], "claude-desktop")
        assert rotated["refresh_token"] != tokens["refresh_token"]
        assert rotated["access_token"] != tokens["access_token"]

    def test_replayed_refresh_token_is_rejected_and_revokes_grant(self):
        mgr = _mgr()
        tokens = self._issue(mgr)
        first = mgr.refresh_access_token(tokens["refresh_token"], "claude-desktop")

        # Replaying the original (now-rotated) refresh token must fail...
        with pytest.raises(ValueError, match="invalid_grant"):
            mgr.refresh_access_token(tokens["refresh_token"], "claude-desktop")

        # ...and per OAuth BCP the whole grant is revoked, so the rotated refresh
        # token and access token are dead too.
        assert mgr.validate_access_token(first["access_token"]) is None
        with pytest.raises(ValueError, match="invalid_grant"):
            mgr.refresh_access_token(first["refresh_token"], "claude-desktop")


class TestRevocation:
    def test_revoked_access_token_is_rejected(self):
        mgr = _mgr()
        verifier, challenge = _pkce()
        code = mgr.create_authorization_code("claude-desktop", REDIRECT, "wazuh:read", challenge, "S256")
        tokens = mgr.exchange_code_for_tokens(code, "claude-desktop", REDIRECT, verifier)
        assert mgr.validate_access_token(tokens["access_token"]) is not None
        assert mgr.revoke_token(tokens["access_token"]) is True
        assert mgr.validate_access_token(tokens["access_token"]) is None


class TestDCR:
    def test_dcr_disabled_by_default(self):
        mgr = _mgr(dcr=False)
        with pytest.raises(ValueError, match="disabled"):
            mgr.register_client({"client_name": "x", "redirect_uris": ["https://ok.example/cb"]})

    def test_dcr_rejects_non_https_redirect(self):
        mgr = _mgr(dcr=True)
        with pytest.raises(ValueError, match="https"):
            mgr.register_client({"client_name": "x", "redirect_uris": ["http://evil.example/cb"]})

    def test_dcr_rejects_fragment_in_redirect(self):
        mgr = _mgr(dcr=True)
        with pytest.raises(ValueError, match="fragment"):
            mgr.register_client({"client_name": "x", "redirect_uris": ["https://ok.example/cb#frag"]})

    def test_dcr_allows_loopback_http_and_https(self):
        mgr = _mgr(dcr=True)
        client = mgr.register_client(
            {"client_name": "dev", "redirect_uris": ["http://127.0.0.1:8080/cb", "https://ok.example/cb"]}
        )
        assert client.client_id.startswith("client_")


class TestScopeBinding:
    def _read_only_client(self, mgr):
        return mgr.register_client(
            {"client_name": "ro", "redirect_uris": ["https://ok.example/cb"], "scope": "wazuh:read"}
        )

    def test_read_only_client_cannot_self_grant_write(self):
        mgr = _mgr(dcr=True)
        client = self._read_only_client(mgr)
        granted = mgr.bound_scope("wazuh:read wazuh:write", client)
        assert granted == "wazuh:read"

    def test_scope_downscoped_through_full_flow(self):
        mgr = _mgr(dcr=True)
        client = self._read_only_client(mgr)
        verifier, challenge = _pkce()
        code = mgr.create_authorization_code(
            client.client_id,
            "https://ok.example/cb",
            mgr.bound_scope("wazuh:read wazuh:write", client),
            challenge,
            "S256",
        )
        tokens = mgr.exchange_code_for_tokens(code, client.client_id, "https://ok.example/cb", verifier)
        assert tokens["scope"] == "wazuh:read"
        tok = mgr.validate_access_token(tokens["access_token"])
        assert tok.scope == "wazuh:read"

    def test_full_scope_client_keeps_write(self):
        mgr = _mgr(dcr=True)
        client = mgr.register_client(
            {"client_name": "rw", "redirect_uris": ["https://ok.example/cb"], "scope": "wazuh:read wazuh:write"}
        )
        assert mgr.bound_scope("wazuh:write", client) == "wazuh:write"


class TestConfidentialClientAuth:
    def test_confidential_client_requires_secret(self):
        mgr = _mgr(dcr=True)
        client = mgr.register_client({"client_name": "c", "redirect_uris": ["https://ok.example/cb"]})
        assert mgr.client_requires_secret(client) is True

    def test_public_client_does_not_require_secret(self):
        mgr = _mgr(dcr=True)
        client = mgr.register_client(
            {
                "client_name": "pub",
                "redirect_uris": ["https://ok.example/cb"],
                "token_endpoint_auth_method": "none",
            }
        )
        assert mgr.client_requires_secret(client) is False

    def test_wrong_secret_rejected(self):
        mgr = _mgr(dcr=True)
        client = mgr.register_client({"client_name": "c", "redirect_uris": ["https://ok.example/cb"]})
        assert mgr.validate_client(client.client_id, "wrong-secret") is None
        assert mgr.validate_client(client.client_id, client.client_secret) is not None


class TestIssuerTrust:
    class _Req:
        def __init__(self, peer, headers):
            self.client = type("C", (), {"host": peer})()
            self.headers = headers
            self.url = type("U", (), {"scheme": "https", "netloc": "real.example"})()

    def test_forwarded_headers_ignored_from_untrusted_peer(self):
        mgr = _mgr()
        req = self._Req("203.0.113.9", {"x-forwarded-host": "attacker.example", "x-forwarded-proto": "https"})
        assert mgr.get_issuer_url(req) == "https://real.example"

    def test_forwarded_headers_honored_from_trusted_proxy(self, monkeypatch):
        mgr = _mgr()
        mgr._trusted_proxies = {"10.0.0.1"}
        req = self._Req("10.0.0.1", {"x-forwarded-host": "public.example", "x-forwarded-proto": "https"})
        assert mgr.get_issuer_url(req) == "https://public.example"

    def test_configured_issuer_wins(self):
        mgr = _mgr(issuer="https://issuer.example/")
        req = self._Req("10.0.0.1", {"x-forwarded-host": "attacker.example"})
        assert mgr.get_issuer_url(req) == "https://issuer.example"


class TestTokenTypeSeparation:
    def test_refresh_token_is_not_accepted_as_access_token(self):
        mgr = _mgr()
        verifier, challenge = _pkce()
        code = mgr.create_authorization_code("claude-desktop", REDIRECT, "wazuh:read", challenge, "S256")
        tokens = mgr.exchange_code_for_tokens(code, "claude-desktop", REDIRECT, verifier)
        # A refresh token must not validate as an access token (type claim checked).
        assert mgr.validate_access_token(tokens["refresh_token"]) is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
