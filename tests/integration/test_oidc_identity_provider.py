"""
External OpenID Connect identity provider (OAUTH_IDP_ISSUER) tests.

Covers the broker flow end-to-end against a mocked IdP: /oauth/authorize parks the
MCP client's request and redirects to the IdP with its own PKCE + nonce;
/oauth/callback verifies the ID token (signature, iss, aud, nonce, exp), applies
the admission policy (tenant / domain / user allow-lists, group -> scope mapping),
issues a code bound to the authenticated subject, and that subject survives the
token exchange and refresh rotation. Also pins the legacy behaviour when no IdP is
configured.
"""

import base64
import hashlib
import json
import secrets
import time
from types import SimpleNamespace
from urllib.parse import parse_qs, parse_qsl, urlparse

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from jwt.algorithms import RSAAlgorithm

from wazuh_mcp_server.oauth import OAuthManager, create_oauth_router
from wazuh_mcp_server.oidc import IdentityDenied, IdPError, OIDCProvider

ISSUER = "https://idp.example.test"
IDP_CLIENT_ID = "idp-client-123"
SERVER_ISSUER = "https://mcp.example.test"
CLAUDE_REDIRECT = "https://claude.ai/api/mcp/auth_callback"
CALLBACK = f"{SERVER_ISSUER}/oauth/callback"


# ---------------------------------------------------------------------- fixtures
@pytest.fixture(scope="module")
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def rogue_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="module")
def jwks(rsa_key):
    jwk = json.loads(RSAAlgorithm.to_jwk(rsa_key.public_key()))
    jwk.update({"kid": "kid-1", "alg": "RS256", "use": "sig"})
    return {"keys": [jwk]}


class FakeIdP:
    """Records what the server sends and answers discovery / JWKS / token requests."""

    def __init__(self, jwks, issuer=ISSUER, base=ISSUER):
        """Serve discovery at `base`; advertise `issuer` (may differ, to test mismatch handling)."""
        self.jwks = jwks
        self.issuer = issuer  # value advertised in the discovery document
        self.base = base  # where discovery / jwks / token actually live
        self.token_requests = []
        self.next_id_token = None
        self.token_status = 200

    def transport(self):
        """httpx.MockTransport answering the three IdP endpoints."""

        async def handler(request: httpx.Request) -> httpx.Response:
            """Route discovery / JWKS / token requests to canned responses."""
            url = str(request.url)
            if url == f"{self.base}/.well-known/openid-configuration":
                return httpx.Response(
                    200,
                    json={
                        "issuer": self.issuer,
                        "authorization_endpoint": f"{self.base}/authorize",
                        "token_endpoint": f"{self.base}/token",
                        "jwks_uri": f"{self.base}/jwks",
                        "code_challenge_methods_supported": ["S256"],
                    },
                )
            if url == f"{self.base}/jwks":
                return httpx.Response(200, json=self.jwks)
            if url == f"{self.base}/token":
                self.token_requests.append(request)
                if self.token_status != 200:
                    return httpx.Response(self.token_status, json={"error": "invalid_grant"})
                return httpx.Response(
                    200, json={"access_token": "idp-at", "token_type": "Bearer", "id_token": self.next_id_token}
                )
            return httpx.Response(404)

        return httpx.MockTransport(handler)


def _config(**over):
    """Minimal config namespace with IdP settings; keyword overrides per test."""
    base = dict(
        AUTH_SECRET_KEY="test-secret-key-at-least-32-characters-long",
        OAUTH_ENABLE_DCR=False,
        OAUTH_ACCESS_TOKEN_TTL=3600,
        OAUTH_REFRESH_TOKEN_TTL=86400,
        OAUTH_AUTHORIZATION_CODE_TTL=600,
        OAUTH_ISSUER_URL=SERVER_ISSUER,
        OAUTH_IDP_ISSUER=ISSUER,
        OAUTH_IDP_CLIENT_ID=IDP_CLIENT_ID,
        OAUTH_IDP_CLIENT_SECRET="",
        OAUTH_IDP_SCOPES="openid email profile",
        OAUTH_IDP_ALLOWED_DOMAINS="",
        OAUTH_IDP_ALLOWED_TENANTS="",
        OAUTH_IDP_ALLOWED_USERS="",
        OAUTH_IDP_GROUP_CLAIM="groups",
        OAUTH_IDP_GROUP_SCOPE_MAP=json.dumps({"soc-admins": "wazuh:read wazuh:write", "soc-analysts": "wazuh:read"}),
        OAUTH_IDP_DEFAULT_SCOPE="wazuh:read",
        OAUTH_IDP_SUBJECT_CLAIM="email",
        OAUTH_IDP_LOGIN_TTL=600,
    )
    base.update(over)
    return SimpleNamespace(**base)


def _id_token(key, *, nonce, kid="kid-1", iss=ISSUER, aud=IDP_CLIENT_ID, exp_delta=3600, **extra):
    """Sign an ID token for alice@corp.example with the given key and claim overrides."""
    now = int(time.time())
    claims = {
        "iss": iss,
        "aud": aud,
        "sub": "idp-sub-42",
        "email": "alice@corp.example",
        "email_verified": True,
        "nonce": nonce,
        "iat": now,
        "exp": now + exp_delta,
    }
    claims.update(extra)
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return jwt.encode(claims, pem, algorithm="RS256", headers={"kid": kid})


def _pkce():
    """Fresh PKCE verifier/challenge pair."""
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


@pytest.fixture
def idp(jwks):
    """A fresh fake IdP per test."""
    return FakeIdP(jwks)


def _mgr(idp, **over):
    """OAuthManager wired to the fake IdP."""
    cfg = _config(**over)
    return OAuthManager(cfg, idp=OIDCProvider(cfg, transport=idp.transport()))


@pytest.fixture
def mgr(idp):
    """Default OAuthManager fixture."""
    return _mgr(idp)


@pytest.fixture
async def client(mgr):
    """ASGI client for the OAuth router mounted on a bare FastAPI app."""
    app = FastAPI()
    app.include_router(create_oauth_router(mgr))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=SERVER_ISSUER) as c:
        yield c


def _authorize_params(challenge, **over):
    """Query parameters Claude would send to /oauth/authorize."""
    params = {
        "response_type": "code",
        "client_id": "claude-desktop",
        "redirect_uri": CLAUDE_REDIRECT,
        "scope": "wazuh:read wazuh:write",
        "state": "client-state-xyz",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    params.update(over)
    return params


async def _start_login(client, **over):
    """Run /authorize and return (idp_state, nonce, idp_code_challenge)."""
    _, challenge = _pkce()
    r = await client.get("/oauth/authorize", params=_authorize_params(challenge, **over))
    assert r.status_code in (302, 307), r.text
    loc = urlparse(r.headers["location"])
    assert f"{loc.scheme}://{loc.netloc}{loc.path}" == f"{ISSUER}/authorize"
    q = parse_qs(loc.query)
    return q["state"][0], q["nonce"][0], q


# ---------------------------------------------------------------------- authorize leg
class TestAuthorizeDelegatesToIdP:
    """Tests: authorize delegates to id p."""

    async def test_redirects_to_idp_with_pkce_nonce_and_state(self, client, mgr):
        """Redirects to idp with pkce nonce and state."""
        idp_state, nonce, q = await _start_login(client)
        assert q["client_id"] == [IDP_CLIENT_ID]
        assert q["redirect_uri"] == [CALLBACK]
        assert q["code_challenge_method"] == ["S256"]
        assert q["scope"] == ["openid email profile"]
        assert len(q["code_challenge"][0]) >= 43 and len(nonce) >= 32
        # The IdP state is opaque and unrelated to the client's state.
        assert idp_state != "client-state-xyz"
        pending = mgr.pending_logins[idp_state]
        assert pending.client_id == "claude-desktop" and pending.state == "client-state-xyz"
        assert pending.scope == "wazuh:read wazuh:write"

    async def test_no_code_is_issued_before_login(self, client, mgr):
        """No code is issued before login."""
        await _start_login(client)
        assert mgr.authorization_codes == {}

    async def test_still_validates_client_redirect_and_pkce_first(self, client, mgr):
        """Still validates client redirect and pkce first."""
        _, challenge = _pkce()
        r = await client.get(
            "/oauth/authorize", params=_authorize_params(challenge, redirect_uri="https://evil.example/cb")
        )
        assert r.status_code == 400
        r = await client.get("/oauth/authorize", params=_authorize_params(challenge, code_challenge_method="plain"))
        assert r.status_code in (302, 307)
        assert parse_qs(urlparse(r.headers["location"]).query)["error"] == ["invalid_request"]
        assert mgr.pending_logins == {}

    async def test_google_hosted_domain_hint(self, jwks):
        """Google hosted domain hint."""
        google = "https://accounts.google.com"
        idp = FakeIdP(jwks, issuer=google, base=google)
        provider = OIDCProvider(
            _config(OAUTH_IDP_ISSUER=google, OAUTH_IDP_ALLOWED_DOMAINS="corp.example"), transport=idp.transport()
        )
        url = await provider.build_authorization_url(redirect_uri=CALLBACK, state="s", nonce="n", code_challenge="c")
        assert parse_qs(urlparse(url).query)["hd"] == ["corp.example"]

    async def test_multitenant_issuer_without_tenant_allow_list_is_refused(self, jwks):
        """Multitenant issuer without tenant allow list is refused."""
        idp = FakeIdP(jwks, issuer="https://login.microsoftonline.com/{tenantid}/v2.0")
        provider = OIDCProvider(_config(), transport=idp.transport())
        with pytest.raises(IdPError, match="OAUTH_IDP_ALLOWED_TENANTS"):
            await provider.metadata()

    async def test_malformed_jwks_entry_is_skipped(self, jwks, rsa_key):
        """Malformed jwks entry is skipped."""
        broken = {"keys": [{"kty": "RSA", "use": "sig", "kid": "kid-bad", "n": "!!", "e": "AQAB"}] + jwks["keys"]}
        provider = OIDCProvider(_config(), transport=FakeIdP(broken).transport())
        claims = await provider.verify_id_token(_id_token(rsa_key, nonce="n"), nonce="n")
        assert claims["email"] == "alice@corp.example"

    async def test_multiple_audiences_require_azp(self, idp, rsa_key):
        """Multiple audiences require azp."""
        provider = OIDCProvider(_config(), transport=idp.transport())
        ok = _id_token(rsa_key, nonce="n", aud=["other-app", IDP_CLIENT_ID], azp=IDP_CLIENT_ID)
        assert (await provider.verify_id_token(ok, nonce="n"))["sub"] == "idp-sub-42"
        bad = _id_token(rsa_key, nonce="n", aud=["other-app", IDP_CLIENT_ID], azp="other-app")
        with pytest.raises(IdPError, match="azp"):
            await provider.verify_id_token(bad, nonce="n")

    async def test_discovery_issuer_mismatch_is_fatal(self, jwks):
        """Discovery issuer mismatch is fatal."""
        idp = FakeIdP(jwks, issuer="https://impostor.example")
        provider = OIDCProvider(_config(), transport=idp.transport())
        with pytest.raises(IdPError, match="issuer"):
            await provider.metadata()

    async def test_entra_multitenant_template_binds_iss_to_tid(self, jwks, rsa_key):
        """Entra multitenant template binds iss to tid."""
        idp = FakeIdP(jwks, issuer="https://login.microsoftonline.com/{tenantid}/v2.0")
        provider = OIDCProvider(_config(OAUTH_IDP_ALLOWED_TENANTS="tenant-a"), transport=idp.transport())
        ok = _id_token(rsa_key, nonce="n", iss="https://login.microsoftonline.com/tenant-a/v2.0", tid="tenant-a")
        claims = await provider.verify_id_token(ok, nonce="n")
        assert provider.authorize(claims).subject == "alice@corp.example"
        forged = _id_token(rsa_key, nonce="n", iss="https://login.microsoftonline.com/tenant-a/v2.0", tid="tenant-b")
        with pytest.raises(IdPError, match="tenant"):
            await provider.verify_id_token(forged, nonce="n")


# ---------------------------------------------------------------------- callback leg
class TestCallback:
    """Tests: callback."""

    async def test_full_flow_issues_code_bound_to_subject(self, client, mgr, idp, rsa_key):
        """Full flow issues code bound to subject."""
        verifier, challenge = _pkce()
        r = await client.get("/oauth/authorize", params=_authorize_params(challenge))
        q = parse_qs(urlparse(r.headers["location"]).query)
        idp_state, nonce, idp_challenge = q["state"][0], q["nonce"][0], q["code_challenge"][0]

        idp.next_id_token = _id_token(rsa_key, nonce=nonce, groups=["soc-admins"])
        r = await client.get("/oauth/callback", params={"state": idp_state, "code": "idp-code"})
        assert r.status_code in (302, 307)
        loc = urlparse(r.headers["location"])
        assert f"{loc.scheme}://{loc.netloc}{loc.path}" == CLAUDE_REDIRECT
        back = parse_qs(loc.query)
        assert back["state"] == ["client-state-xyz"]
        assert back["iss"] == [SERVER_ISSUER]
        assert "error" not in back
        assert r.headers["cache-control"] == "no-store"

        # The IdP leg used its own PKCE verifier matching the challenge we sent.
        sent = dict(parse_qsl(idp.token_requests[-1].content.decode()))
        computed = base64.urlsafe_b64encode(hashlib.sha256(sent["code_verifier"].encode()).digest()).rstrip(b"=")
        assert computed.decode() == idp_challenge
        assert sent["redirect_uri"] == CALLBACK and sent["code"] == "idp-code"

        # Code -> tokens: subject and group-derived scope travel with the grant.
        tokens = mgr.exchange_code_for_tokens(back["code"][0], "claude-desktop", CLAUDE_REDIRECT, verifier)
        assert tokens["scope"] == "wazuh:read wazuh:write"
        access = mgr.validate_access_token(tokens["access_token"])
        assert access.subject == "alice@corp.example"
        assert jwt.decode(tokens["access_token"], mgr.secret_key, algorithms=["HS256"])["sub"] == "alice@corp.example"

        # ...and survive refresh rotation, including the stateless (post-restart) decode path.
        refreshed = mgr.refresh_access_token(tokens["refresh_token"], "claude-desktop")
        assert mgr.validate_access_token(refreshed["access_token"]).subject == "alice@corp.example"
        mgr.access_tokens.clear()
        assert mgr.validate_access_token(refreshed["access_token"]).subject == "alice@corp.example"

    async def test_state_is_single_use(self, client, idp, rsa_key):
        """State is single use."""
        idp_state, nonce, _ = await _start_login(client)
        idp.next_id_token = _id_token(rsa_key, nonce=nonce)
        first = await client.get("/oauth/callback", params={"state": idp_state, "code": "c"})
        assert "code=" in first.headers["location"]
        replay = await client.get("/oauth/callback", params={"state": idp_state, "code": "c"})
        assert replay.status_code == 400
        assert "location" not in replay.headers

    async def test_unknown_state_is_answered_directly_not_redirected(self, client):
        """Unknown state is answered directly not redirected."""
        r = await client.get("/oauth/callback", params={"state": "nope", "code": "c"})
        assert r.status_code == 400 and "location" not in r.headers

    async def test_idp_error_becomes_access_denied_for_client(self, client, idp):
        """Idp error becomes access denied for client."""
        idp_state, _, _ = await _start_login(client)
        r = await client.get(
            "/oauth/callback",
            params={"state": idp_state, "error": "login_required", "error_description": "secret internals"},
        )
        back = parse_qs(urlparse(r.headers["location"]).query)
        assert back["error"] == ["access_denied"] and back["state"] == ["client-state-xyz"]
        assert "secret internals" not in r.headers["location"]
        assert idp.token_requests == []

    async def test_idp_token_rejection(self, client, idp):
        """Idp token rejection."""
        idp_state, _, _ = await _start_login(client)
        idp.token_status = 400
        r = await client.get("/oauth/callback", params={"state": idp_state, "code": "bad"})
        assert parse_qs(urlparse(r.headers["location"]).query)["error"] == ["access_denied"]

    @pytest.mark.parametrize(
        "mutate",
        [
            lambda k, r, n: _id_token(k, nonce="other-nonce"),
            lambda k, r, n: _id_token(k, nonce=n, aud="someone-else"),
            lambda k, r, n: _id_token(k, nonce=n, iss="https://evil.example"),
            lambda k, r, n: _id_token(k, nonce=n, exp_delta=-600),
            lambda k, r, n: _id_token(r, nonce=n),  # signed by a rogue key, known kid
            lambda k, r, n: _id_token(k, nonce=n, kid="kid-unknown"),
        ],
        ids=["nonce", "aud", "iss", "expired", "rogue-key", "unknown-kid"],
    )
    async def test_invalid_id_tokens_are_rejected(self, client, mgr, idp, rsa_key, rogue_key, mutate):
        """Invalid id tokens are rejected."""
        idp_state, nonce, _ = await _start_login(client)
        idp.next_id_token = mutate(rsa_key, rogue_key, nonce)
        r = await client.get("/oauth/callback", params={"state": idp_state, "code": "c"})
        assert parse_qs(urlparse(r.headers["location"]).query)["error"] == ["access_denied"]
        assert mgr.authorization_codes == {}

    async def test_hs256_id_token_rejected(self, client, mgr, idp):
        """Hs256 id token rejected."""
        idp_state, nonce, _ = await _start_login(client)
        idp.next_id_token = jwt.encode(
            {"iss": ISSUER, "aud": IDP_CLIENT_ID, "sub": "x", "nonce": nonce, "iat": 1, "exp": time.time() + 60},
            "x" * 32,
            algorithm="HS256",
            headers={"kid": "kid-1"},
        )
        r = await client.get("/oauth/callback", params={"state": idp_state, "code": "c"})
        assert parse_qs(urlparse(r.headers["location"]).query)["error"] == ["access_denied"]
        assert mgr.authorization_codes == {}


# ---------------------------------------------------------------------- admission policy
class TestAdmissionPolicy:
    """Tests: admission policy."""

    def _provider(self, idp, **over):
        """OIDCProvider wired to the fake IdP with config overrides."""
        return OIDCProvider(_config(**over), transport=idp.transport())

    def _claims(self, **extra):
        """Verified-claims stand-in for authorize() policy tests."""
        c = {"sub": "s", "email": "bob@corp.example", "email_verified": True}
        c.update(extra)
        return c

    def test_groups_map_to_scopes_read_before_write(self, idp):
        """Groups map to scopes read before write."""
        p = self._provider(idp)
        assert p.authorize(self._claims(groups=["soc-admins"])).scope == "wazuh:read wazuh:write"
        assert p.authorize(self._claims(groups=["soc-analysts", "unrelated"])).scope == "wazuh:read"

    def test_default_scope_for_unmapped_user_and_deny_when_empty(self, idp):
        """Default scope for unmapped user and deny when empty."""
        assert self._provider(idp).authorize(self._claims(groups=[])).scope == "wazuh:read"
        with pytest.raises(IdentityDenied):
            self._provider(idp, OAUTH_IDP_DEFAULT_SCOPE="").authorize(self._claims(groups=[]))

    def test_domain_allow_list(self, idp):
        """Domain allow list."""
        p = self._provider(idp, OAUTH_IDP_ALLOWED_DOMAINS="corp.example")
        assert p.authorize(self._claims()).subject == "bob@corp.example"
        assert p.authorize(self._claims(email="x@other.example", hd="corp.example")).subject == "x@other.example"
        with pytest.raises(IdentityDenied):
            p.authorize(self._claims(email="mallory@other.example"))
        with pytest.raises(IdentityDenied):
            p.authorize(self._claims(email_verified=False))
        # Entra never sends email_verified and the claim is user-editable in foreign
        # tenants: a bare e-mail domain is not proof unless the tenant itself is allowed.
        bare = self._claims()
        del bare["email_verified"]
        with pytest.raises(IdentityDenied, match="verifiable"):
            p.authorize(bare)
        p2 = self._provider(idp, OAUTH_IDP_ALLOWED_DOMAINS="corp.example", OAUTH_IDP_ALLOWED_TENANTS="tenant-a")
        assert p2.authorize(dict(bare, tid="tenant-a")).subject == "bob@corp.example"

    def test_subject_fallback_and_normalisation(self, idp):
        """Subject fallback and normalisation."""
        p = self._provider(idp)
        assert p.authorize({"sub": "raw-sub", "preferred_username": "Bob@Corp.Example"}).subject == "bob@corp.example"
        assert p.authorize({"sub": "raw-sub"}).subject == "raw-sub"
        with pytest.raises(IdentityDenied):
            p.authorize({"sub": ""})
        with pytest.raises(IdentityDenied):
            p.authorize({"sub": "evil\nINJECTED"})
        with pytest.raises(IdentityDenied):
            p.authorize({"sub": "x" * 300})

    def test_tenant_allow_list(self, idp):
        """Tenant allow list."""
        p = self._provider(idp, OAUTH_IDP_ALLOWED_TENANTS="tenant-a")
        assert p.authorize(self._claims(tid="tenant-a")).subject
        with pytest.raises(IdentityDenied):
            p.authorize(self._claims(tid="tenant-b"))
        with pytest.raises(IdentityDenied):
            p.authorize(self._claims())

    def test_user_allow_list(self, idp):
        """User allow list."""
        p = self._provider(idp, OAUTH_IDP_ALLOWED_USERS="bob@corp.example")
        assert p.authorize(self._claims()).subject
        with pytest.raises(IdentityDenied):
            p.authorize(self._claims(email="carol@corp.example"))

    def test_roles_claim_and_subject_claim(self, idp):
        """Roles claim and subject claim."""
        p = self._provider(
            idp,
            OAUTH_IDP_GROUP_CLAIM="roles",
            OAUTH_IDP_GROUP_SCOPE_MAP=json.dumps({"Wazuh.Admin": "wazuh:write wazuh:read"}),
            OAUTH_IDP_SUBJECT_CLAIM="preferred_username",
        )
        ident = p.authorize(self._claims(roles="Wazuh.Admin", preferred_username="bob@corp.example"))
        assert ident.scope == "wazuh:read wazuh:write" and ident.subject == "bob@corp.example"

    def test_bad_group_map_rejected_at_startup(self, idp):
        """Bad group map rejected at startup."""
        with pytest.raises(ValueError):
            self._provider(idp, OAUTH_IDP_GROUP_SCOPE_MAP='{"g": "wazuh:admin"}')
        with pytest.raises(ValueError):
            self._provider(idp, OAUTH_IDP_ISSUER="http://insecure.example")

    async def test_scope_is_bounded_by_client_registration(self, client, mgr, idp, rsa_key):
        """Scope is bounded by client registration."""
        # Client registered read-only, user is an admin: the code must be read-only.
        mgr.clients["claude-desktop"].scope = "wazuh:read"
        idp_state, nonce, _ = await _start_login(client, scope="wazuh:read wazuh:write")
        idp.next_id_token = _id_token(rsa_key, nonce=nonce, groups=["soc-admins"])
        r = await client.get("/oauth/callback", params={"state": idp_state, "code": "c"})
        code = parse_qs(urlparse(r.headers["location"]).query)["code"][0]
        assert mgr.authorization_codes[code].scope == "wazuh:read"


# ---------------------------------------------------------------------- lifecycle / limits
class TestPendingLogins:
    """Tests: pending logins."""

    def test_expired_pending_login_is_rejected(self, mgr):
        """Expired pending login is rejected."""
        mgr._login_ttl = -1
        idp_state, _ = mgr.create_pending_login(
            "claude-desktop", CLAUDE_REDIRECT, "wazuh:read", "s", "c" * 43, "S256", CALLBACK
        )
        assert mgr.consume_pending_login(idp_state) is None

    def test_pending_logins_are_bounded_by_evicting_oldest(self, mgr):
        """Pending logins are bounded by evicting oldest."""
        first, _ = mgr.create_pending_login(
            "claude-desktop", CLAUDE_REDIRECT, "wazuh:read", "s", "c" * 43, "S256", CALLBACK
        )
        for _ in range(1100):
            mgr.create_pending_login("claude-desktop", CLAUDE_REDIRECT, "wazuh:read", "s", "c" * 43, "S256", CALLBACK)
        assert len(mgr.pending_logins) <= 1000
        assert first not in mgr.pending_logins  # a flood evicts the oldest, it never locks new logins out

    def test_cleanup_drops_expired(self, mgr):
        """Cleanup drops expired."""
        mgr._login_ttl = -1
        mgr.create_pending_login("claude-desktop", CLAUDE_REDIRECT, "wazuh:read", "s", "c" * 43, "S256", CALLBACK)
        mgr.cleanup_expired()
        assert mgr.pending_logins == {}


class TestLegacyWithoutIdP:
    """Tests: legacy without id p."""

    async def test_authorize_auto_approves_and_callback_is_404(self):
        """Authorize auto approves and callback is 404."""
        mgr = OAuthManager(_config(OAUTH_IDP_ISSUER=""))
        assert not mgr.requires_idp and mgr.idp is None
        app = FastAPI()
        app.include_router(create_oauth_router(mgr))
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=SERVER_ISSUER) as c:
            verifier, challenge = _pkce()
            r = await c.get("/oauth/authorize", params=_authorize_params(challenge))
            back = parse_qs(urlparse(r.headers["location"]).query)
            assert "code" in back and back["state"] == ["client-state-xyz"]
            tokens = mgr.exchange_code_for_tokens(back["code"][0], "claude-desktop", CLAUDE_REDIRECT, verifier)
            assert mgr.validate_access_token(tokens["access_token"]).subject is None
            assert (await c.get("/oauth/callback", params={"state": "x", "code": "y"})).status_code == 404


class TestConfigParsing:
    """Tests: config parsing."""

    def test_from_env_rejects_unusable_idp_settings(self, monkeypatch):
        """From env rejects unusable idp settings."""
        from wazuh_mcp_server.config import ConfigurationError, ServerConfig

        monkeypatch.setenv("WAZUH_HOST", "wazuh.internal")
        monkeypatch.setenv("WAZUH_USER", "u")
        monkeypatch.setenv("WAZUH_PASS", "p")
        monkeypatch.setenv("AUTH_MODE", "oauth")
        monkeypatch.setenv("OAUTH_IDP_ISSUER", ISSUER)
        monkeypatch.delenv("OAUTH_IDP_CLIENT_ID", raising=False)
        with pytest.raises(ConfigurationError, match="OAUTH_IDP_CLIENT_ID"):
            ServerConfig.from_env()

        monkeypatch.setenv("OAUTH_IDP_CLIENT_ID", "cid")
        monkeypatch.setenv("OAUTH_IDP_GROUP_SCOPE_MAP", '{"g": "wazuh:admin"}')
        with pytest.raises(ConfigurationError, match="GROUP_SCOPE_MAP"):
            ServerConfig.from_env()

        monkeypatch.setenv("OAUTH_IDP_GROUP_SCOPE_MAP", '{"g": "wazuh:read"}')
        monkeypatch.setenv("OAUTH_IDP_DEFAULT_SCOPE", "wazuh:admin")
        with pytest.raises(ConfigurationError, match="DEFAULT_SCOPE"):
            ServerConfig.from_env()

        monkeypatch.setenv("OAUTH_IDP_DEFAULT_SCOPE", "")
        monkeypatch.setenv("OAUTH_IDP_ISSUER", "https://login.microsoftonline.com/common/v2.0")
        with pytest.raises(ConfigurationError, match="ALLOWED_TENANTS"):
            ServerConfig.from_env()

        monkeypatch.setenv("OAUTH_IDP_ALLOWED_TENANTS", "tenant-a")
        cfg = ServerConfig.from_env()
        assert cfg.OAUTH_IDP_ISSUER == "https://login.microsoftonline.com/common/v2.0"
        assert cfg.OAUTH_IDP_DEFAULT_SCOPE == "" and cfg.OAUTH_IDP_LOGIN_TTL == 600


class TestJWKSRobustness:
    """Tests: j w k s robustness."""

    async def test_wrong_typed_key_material_is_skipped_not_fatal(self, jwks, rsa_key):
        """A JWKS entry whose `n` is null/int raises TypeError from PyJWK; it must be skipped."""
        broken = {
            "keys": [
                {"kty": "RSA", "use": "sig", "kid": "kid-null", "n": None, "e": "AQAB"},
                {"kty": "RSA", "use": "sig", "kid": "kid-int", "n": 12345, "e": "AQAB"},
                "not-a-dict",
            ]
            + jwks["keys"]
        }
        provider = OIDCProvider(_config(), transport=FakeIdP(broken).transport())
        claims = await provider.verify_id_token(_id_token(rsa_key, nonce="n"), nonce="n")
        assert claims["sub"] == "idp-sub-42"
