"""
OAuth authorization now requires the user to log in with an API key.

/oauth/authorize used to auto-approve every request, so anyone who could reach the server got
a wazuh:read wazuh:write token. These tests drive the real router over HTTP: the login form,
key-bounded scopes, per-user token identity, and refresh-replay revoking one grant only.
"""

import base64
import hashlib
import secrets
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
from fastapi import FastAPI

from wazuh_mcp_server import auth
from wazuh_mcp_server.oauth import OAuthManager, create_oauth_router

REDIRECT = "https://claude.ai/api/mcp/auth_callback"


@pytest.fixture
def env(monkeypatch):
    mgr = OAuthManager(
        SimpleNamespace(
            AUTH_SECRET_KEY="test-secret-key-at-least-32-characters-long",
            OAUTH_ENABLE_DCR=True,
            OAUTH_ACCESS_TOKEN_TTL=3600,
            OAUTH_REFRESH_TOKEN_TTL=86400,
            OAUTH_AUTHORIZATION_CODE_TTL=600,
            OAUTH_ISSUER_URL="https://mcp.example",
        )
    )
    keys = auth.AuthManager()
    keys.api_keys = {}  # only the two keys below
    monkeypatch.setattr(auth, "auth_manager", keys)
    reader = keys.create_api_key("reader", scopes=["wazuh:read"])
    writer = keys.create_api_key("writer", scopes=["wazuh:read", "wazuh:write"])
    app = FastAPI()
    app.include_router(create_oauth_router(mgr))
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="https://mcp.example")
    return SimpleNamespace(mgr=mgr, client=client, reader=reader, writer=writer, keys=keys)


def _pkce():
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def _params(challenge, scope="wazuh:read wazuh:write"):
    return {
        "response_type": "code",
        "client_id": "claude-desktop",
        "redirect_uri": REDIRECT,
        "scope": scope,
        "state": "s1",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }


async def _login(env, api_key, scope="wazuh:read wazuh:write"):
    verifier, challenge = _pkce()
    r = await env.client.post("/oauth/authorize", data={**_params(challenge, scope), "api_key": api_key})
    if r.status_code != 303:
        return r, None
    code = parse_qs(urlparse(r.headers["location"]).query)["code"][0]
    tokens = (
        await env.client.post(
            "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": "claude-desktop",
                "redirect_uri": REDIRECT,
                "code_verifier": verifier,
            },
        )
    ).json()
    return r, tokens


class TestNoAnonymousGrant:
    @pytest.mark.asyncio
    async def test_authorize_shows_login_instead_of_issuing_a_code(self, env):
        _, challenge = _pkce()
        r = await env.client.get("/oauth/authorize", params=_params(challenge))
        assert r.status_code == 200
        assert "location" not in r.headers
        assert 'name="api_key"' in r.text
        assert r.headers["x-frame-options"] == "DENY"
        assert "no-store" in r.headers["cache-control"]
        assert not env.mgr.authorization_codes

    @pytest.mark.asyncio
    async def test_bad_key_gets_no_code(self, env):
        r, tokens = await _login(env, "wazuh_" + "x" * 43)
        assert r.status_code == 401 and tokens is None
        assert not env.mgr.authorization_codes

    @pytest.mark.asyncio
    async def test_unregistered_redirect_is_not_followed(self, env):
        _, challenge = _pkce()
        params = {**_params(challenge), "redirect_uri": "https://evil.example/cb", "api_key": env.writer}
        r = await env.client.post("/oauth/authorize", data=params)
        assert r.status_code == 400 and "location" not in r.headers

    @pytest.mark.asyncio
    async def test_login_form_escapes_reflected_input(self, env):
        _, challenge = _pkce()
        r = await env.client.get("/oauth/authorize", params={**_params(challenge), "state": '"><script>x</script>'})
        assert "<script>x" not in r.text


class TestKeyBoundScopes:
    @pytest.mark.asyncio
    async def test_read_key_cannot_obtain_write(self, env):
        r, tokens = await _login(env, env.reader, scope="wazuh:read wazuh:write")
        assert r.status_code == 303
        assert tokens["scope"] == "wazuh:read"

    @pytest.mark.asyncio
    async def test_write_key_gets_write_and_its_identity(self, env):
        _, tokens = await _login(env, env.writer)
        assert tokens["scope"] == "wazuh:read wazuh:write"
        token = env.mgr.validate_access_token(tokens["access_token"])
        writer_id = env.keys.validate_api_key(env.writer).id
        assert token.subject == writer_id

    @pytest.mark.asyncio
    async def test_identity_survives_refresh(self, env):
        _, tokens = await _login(env, env.writer)
        refreshed = env.mgr.refresh_access_token(tokens["refresh_token"], "claude-desktop")
        token = env.mgr.validate_access_token(refreshed["access_token"])
        assert token.subject == env.keys.validate_api_key(env.writer).id


class TestReplayRevokesOneGrant:
    @pytest.mark.asyncio
    async def test_one_users_replay_does_not_log_out_others(self, env):
        _, alice = await _login(env, env.reader)
        _, bob = await _login(env, env.writer)
        bob_rotated = env.mgr.refresh_access_token(bob["refresh_token"], "claude-desktop")
        with pytest.raises(ValueError, match="invalid_grant"):
            env.mgr.refresh_access_token(bob["refresh_token"], "claude-desktop")  # replay

        # Bob's grant is burned...
        assert env.mgr.validate_access_token(bob_rotated["access_token"]) is None
        with pytest.raises(ValueError):
            env.mgr.refresh_access_token(bob_rotated["refresh_token"], "claude-desktop")
        # ...Alice, on the same shared public client, is untouched
        assert env.mgr.validate_access_token(alice["access_token"]) is not None
        assert env.mgr.refresh_access_token(alice["refresh_token"], "claude-desktop")["access_token"]


class TestDcrInputs:
    @pytest.mark.parametrize(
        "extra",
        [{"grant_types": ["password"]}, {"grant_types": ["client_credentials"]}, {"token_endpoint_auth_method": "x"}],
    )
    def test_unsupported_dcr_inputs_rejected(self, env, extra):
        with pytest.raises(ValueError):
            env.mgr.register_client({"redirect_uris": [REDIRECT], **extra})
