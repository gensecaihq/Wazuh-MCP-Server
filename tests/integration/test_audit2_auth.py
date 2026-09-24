"""
Regression tests for the second September 2026 audit (authentication and OAuth).

Each test pins a defect that was reproduced before it was fixed.
"""

import base64
import hashlib
import os
import secrets
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

os.environ.setdefault("AUTH_MODE", "none")

import httpx  # noqa: E402
import pytest  # noqa: E402
from fastapi import FastAPI  # noqa: E402

from wazuh_mcp_server import auth  # noqa: E402
from wazuh_mcp_server import server as mcp_server  # noqa: E402
from wazuh_mcp_server.oauth import OAuthManager, create_oauth_router  # noqa: E402
from wazuh_mcp_server.oidc import IdentityDenied, OIDCProvider, validate_idp_settings  # noqa: E402

REDIRECT = "https://claude.ai/api/mcp/auth_callback"
SECRET = "test-secret-key-at-least-32-characters-long"


def _oauth_config(**over):
    base = dict(
        AUTH_SECRET_KEY=SECRET,
        OAUTH_ENABLE_DCR=False,
        OAUTH_ACCESS_TOKEN_TTL=3600,
        OAUTH_REFRESH_TOKEN_TTL=86400,
        OAUTH_AUTHORIZATION_CODE_TTL=600,
        OAUTH_ISSUER_URL="https://mcp.example",
    )
    base.update(over)
    return SimpleNamespace(**base)


@pytest.fixture
def keys(monkeypatch):
    manager = auth.AuthManager()
    manager.api_keys = {}
    monkeypatch.setattr(auth, "auth_manager", manager)
    return manager


@pytest.fixture
def mgr():
    return OAuthManager(_oauth_config())


def _pkce():
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def _grant(mgr, subject, kind, scope="wazuh:read wazuh:write"):
    verifier, challenge = _pkce()
    code = mgr.create_authorization_code(
        client_id="claude-desktop",
        redirect_uri=REDIRECT,
        scope=scope,
        code_challenge=challenge,
        code_challenge_method="S256",
        subject=subject,
        subject_kind=kind,
    )
    return mgr.exchange_code_for_tokens(
        code=code, client_id="claude-desktop", redirect_uri=REDIRECT, code_verifier=verifier
    )


async def _principal(monkeypatch, mgr, access_token):
    monkeypatch.setattr(mcp_server, "_oauth_manager", mgr)
    monkeypatch.setattr(mcp_server.config, "AUTH_MODE", "oauth")
    return await mcp_server.verify_authentication(f"Bearer {access_token}", mcp_server.config)


class TestLoginPageCsp:
    @pytest.mark.asyncio
    async def test_form_action_allows_the_client_redirect(self, keys, mgr):
        # Chrome enforces form-action on the 303 that follows the POST; 'self' alone blocked sign-in
        app = FastAPI()
        app.include_router(create_oauth_router(mgr))
        _, challenge = _pkce()
        params = {
            "response_type": "code",
            "client_id": "claude-desktop",
            "redirect_uri": REDIRECT,
            "state": "s",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://mcp.example") as c:
            r = await c.get("/oauth/authorize", params=params)
        assert r.status_code == 200
        assert "form-action 'self' https://claude.ai;" in r.headers["content-security-policy"]


class TestExpiredKeyEndsOAuthGrant:
    def _expired_key(self, keys):
        raw = keys.create_api_key("k", scopes=["wazuh:read", "wazuh:write"])
        key = keys.validate_api_key(raw)
        return key

    @pytest.mark.asyncio
    async def test_access_token_refused_after_key_expiry(self, monkeypatch, keys, mgr):
        key = self._expired_key(keys)
        tokens = _grant(mgr, key.id, "api_key")
        assert await _principal(monkeypatch, mgr, tokens["access_token"])
        key.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        with pytest.raises(Exception):
            await _principal(monkeypatch, mgr, tokens["access_token"])

    def test_refresh_refused_and_grant_revoked_after_key_expiry(self, keys, mgr):
        key = self._expired_key(keys)
        tokens = _grant(mgr, key.id, "api_key")
        key.expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
        with pytest.raises(ValueError, match="invalid_grant"):
            mgr.refresh_access_token(tokens["refresh_token"], "claude-desktop")
        assert mgr.validate_access_token(tokens["access_token"]) is None

    def test_refresh_refused_after_key_removal(self, keys, mgr):
        key = self._expired_key(keys)
        tokens = _grant(mgr, key.id, "api_key")
        del keys.api_keys[key.id]
        with pytest.raises(ValueError, match="invalid_grant"):
            mgr.refresh_access_token(tokens["refresh_token"], "claude-desktop")


class TestNarrowedKeyScopes:
    @pytest.mark.asyncio
    async def test_bearer_token_loses_dropped_scope(self, keys, monkeypatch):
        raw = keys.create_api_key("k", scopes=["wazuh:read", "wazuh:write"])
        key = keys.validate_api_key(raw)
        monkeypatch.setattr(mcp_server.config, "AUTH_SECRET_KEY", SECRET)
        token = auth.create_access_token({"sub": key.id, "scope": "wazuh:read wazuh:write"}, SECRET)
        key.scopes = ["wazuh:read"]
        assert (await auth.verify_bearer_token(f"Bearer {token}")).scopes == ["wazuh:read"]

    @pytest.mark.asyncio
    async def test_oauth_token_and_refresh_lose_dropped_scope(self, monkeypatch, keys, mgr):
        raw = keys.create_api_key("k", scopes=["wazuh:read", "wazuh:write"])
        key = keys.validate_api_key(raw)
        tokens = _grant(mgr, key.id, "api_key")
        key.scopes = ["wazuh:read"]
        assert (await _principal(monkeypatch, mgr, tokens["access_token"])).scopes == ["wazuh:read"]
        refreshed = mgr.refresh_access_token(tokens["refresh_token"], "claude-desktop")
        assert refreshed["scope"] == "wazuh:read"
        assert mgr.validate_access_token(refreshed["access_token"]).scope == "wazuh:read"


def _idp_config(**over):
    base = dict(
        OAUTH_IDP_ISSUER="https://idp.example",
        OAUTH_IDP_CLIENT_ID="mcp",
        OAUTH_IDP_CLIENT_SECRET="",
        OAUTH_IDP_SCOPES="openid email profile",
        OAUTH_IDP_ALLOWED_DOMAINS="",
        OAUTH_IDP_ALLOWED_TENANTS="",
        OAUTH_IDP_ALLOWED_USERS="",
        OAUTH_IDP_GROUP_CLAIM="groups",
        OAUTH_IDP_GROUP_SCOPE_MAP="",
        OAUTH_IDP_DEFAULT_SCOPE="wazuh:read",
        OAUTH_IDP_SUBJECT_CLAIM="email",
        OAUTH_IDP_LOGIN_TTL=600,
    )
    base.update(over)
    return _oauth_config(**base)


def _provider(**over):
    return OIDCProvider(_idp_config(**over), transport=httpx.MockTransport(lambda r: httpx.Response(404)))


class TestAllowListUsesProviderControlledIdentity:
    def test_self_chosen_username_cannot_match_allowed_email(self):
        # Unverified e-mail -> fallback to preferred_username, which self-service IdPs let users set
        p = _provider(OAUTH_IDP_ALLOWED_USERS="admin@corp.example")
        claims = {"sub": "attacker-1", "email": "x@evil.example", "preferred_username": "admin@corp.example"}
        with pytest.raises(IdentityDenied):
            p.authorize(claims)

    def test_self_chosen_plain_username_cannot_match_allowed_sub(self):
        p = _provider(OAUTH_IDP_ALLOWED_USERS="alice")
        with pytest.raises(IdentityDenied):
            p.authorize({"sub": "attacker-1", "preferred_username": "alice"})

    def test_sub_and_vouched_email_still_admit(self):
        p = _provider(OAUTH_IDP_ALLOWED_USERS="sub-42,bob@corp.example")
        assert p.authorize({"sub": "sub-42", "preferred_username": "whoever"}).subject == "whoever"
        vouched = {"sub": "s", "email": "Bob@corp.example", "email_verified": True}
        assert p.authorize(vouched).subject == "bob@corp.example"


class TestNoOpenRegistrationWithIdp:
    def test_startup_refuses_dcr_with_idp(self):
        with pytest.raises(ValueError, match="OAUTH_ENABLE_DCR"):
            validate_idp_settings(_idp_config(OAUTH_ENABLE_DCR=True))

    def test_manager_refuses_registration_with_idp(self):
        m = OAuthManager(_idp_config(OAUTH_ENABLE_DCR=True))
        assert m.requires_idp
        with pytest.raises(ValueError, match="disabled"):
            m.register_client({"redirect_uris": ["https://evil.example/cb"]})


class TestIdpRefreshChainIsBounded:
    def test_rotation_does_not_extend_an_idp_grant(self, mgr):
        tokens = _grant(mgr, "alice@corp.example", "idp_user")
        original = mgr.refresh_tokens[tokens["refresh_token"]]
        original.expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
        refreshed = mgr.refresh_access_token(tokens["refresh_token"], "claude-desktop")
        assert mgr.refresh_tokens[refreshed["refresh_token"]].expires_at == original.expires_at

    def test_api_key_grants_still_rotate_to_a_full_ttl(self, keys, mgr):
        key = keys.validate_api_key(keys.create_api_key("k", scopes=["wazuh:read"]))
        tokens = _grant(mgr, key.id, "api_key", scope="wazuh:read")
        mgr.refresh_tokens[tokens["refresh_token"]].expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
        refreshed = mgr.refresh_access_token(tokens["refresh_token"], "claude-desktop")
        remaining = mgr.refresh_tokens[refreshed["refresh_token"]].expires_at - datetime.now(timezone.utc)
        assert remaining > timedelta(hours=23)


class TestRegistrationTableCannotFillUp:
    def test_idle_registrations_make_room(self):
        m = OAuthManager(_oauth_config(OAUTH_ENABLE_DCR=True))
        for _ in range(1001):
            m.register_client({"redirect_uris": ["https://app.example/cb"]})
        # used to raise "Maximum number of registered clients reached" forever
        assert m.register_client({"redirect_uris": ["https://app.example/cb"]}).client_id in m.clients
        assert "claude-desktop" in m.clients and len(m.clients) <= 1001

    def test_clients_with_live_grants_are_kept(self, keys):
        m = OAuthManager(_oauth_config(OAUTH_ENABLE_DCR=True))
        first = m.register_client({"redirect_uris": [REDIRECT], "token_endpoint_auth_method": "none"})
        verifier, challenge = _pkce()
        m.create_authorization_code(
            client_id=first.client_id,
            redirect_uri=REDIRECT,
            scope="wazuh:read",
            code_challenge=challenge,
            code_challenge_method="S256",
        )
        for _ in range(1001):
            m.register_client({"redirect_uris": ["https://app.example/cb"]})
        assert first.client_id in m.clients


class TestKeysWithoutScopesStayReadOnly:
    @pytest.mark.asyncio
    async def test_oauth_token_keeps_read(self, monkeypatch, keys, mgr):
        key = keys.validate_api_key(keys.create_api_key("k", scopes=[]))
        tokens = _grant(mgr, key.id, "api_key", scope="wazuh:read")
        assert (await _principal(monkeypatch, mgr, tokens["access_token"])).scopes == ["wazuh:read"]
        assert mgr.refresh_access_token(tokens["refresh_token"], "claude-desktop")["scope"] == "wazuh:read"
