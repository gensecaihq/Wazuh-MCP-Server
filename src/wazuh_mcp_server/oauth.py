#!/usr/bin/env python3
"""
OAuth 2.0 implementation with Dynamic Client Registration (DCR) support.
Implements MCP 2026-07-28 authentication specification for Claude Desktop integration.
"""

import hashlib
import html
import logging
import os
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode, urlparse

import jwt
from fastapi import APIRouter, Form, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from jwt.exceptions import PyJWTError as JWTError

from wazuh_mcp_server.oidc import IdentityDenied, IdPError, OIDCProvider

logger = logging.getLogger(__name__)

# OAuth 2.0 Error Codes (RFC 6749)
OAUTH_ERRORS = {
    "invalid_request": "The request is missing a required parameter or is malformed",
    "unauthorized_client": "The client is not authorized to use this method",
    "access_denied": "The resource owner denied the request",
    "unsupported_response_type": "The response type is not supported",
    "invalid_scope": "The requested scope is invalid or unknown",
    "server_error": "The server encountered an unexpected error",
    "temporarily_unavailable": "The server is temporarily unavailable",
    "invalid_client": "Client authentication failed",
    "invalid_grant": "The authorization grant is invalid or expired",
    "unsupported_grant_type": "The grant type is not supported",
}


@dataclass
class OAuthClient:
    """Registered OAuth client."""

    client_id: str
    client_secret: str
    client_name: str
    redirect_uris: List[str]
    grant_types: List[str] = field(default_factory=lambda: ["authorization_code", "refresh_token"])
    response_types: List[str] = field(default_factory=lambda: ["code"])
    scope: str = "wazuh:read wazuh:write"
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    token_endpoint_auth_method: str = "client_secret_post"

    def to_registration_response(self) -> Dict[str, Any]:
        """Convert to DCR registration response."""
        return {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "client_name": self.client_name,
            "redirect_uris": self.redirect_uris,
            "grant_types": self.grant_types,
            "response_types": self.response_types,
            "scope": self.scope,
            "token_endpoint_auth_method": self.token_endpoint_auth_method,
            "client_id_issued_at": int(self.created_at.timestamp()),
        }


@dataclass
class AuthorizationCode:
    """OAuth authorization code."""

    code: str
    client_id: str
    redirect_uri: str
    scope: str
    created_at: datetime
    expires_at: datetime
    code_challenge: Optional[str] = None
    code_challenge_method: Optional[str] = None
    # Who approved it: an API key id (sign-in page) or an IdP user (OIDC login)
    subject: Optional[str] = None
    subject_kind: Optional[str] = None  # "api_key" | "idp_user"

    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) > self.expires_at


@dataclass
class OAuthToken:
    """OAuth access/refresh token."""

    token: str
    token_type: str  # "access" or "refresh"
    client_id: str
    scope: str
    created_at: datetime
    expires_at: datetime
    subject: Optional[str] = None
    # "api_key": subject is the API key id (tokens die with the key); "idp_user": subject is
    # the person the external IdP authenticated
    subject_kind: Optional[str] = None
    # Grant family: every token minted from one authorization shares it, so a refresh
    # replay revokes that grant only, not every user of a shared public client.
    family: Optional[str] = None

    def is_expired(self) -> bool:
        return datetime.now(timezone.utc) > self.expires_at


@dataclass
class PendingLogin:
    """An /oauth/authorize request parked while the user authenticates at the IdP."""

    client_id: str
    redirect_uri: str
    scope: str
    state: Optional[str]
    code_challenge: str
    code_challenge_method: str
    idp_nonce: str
    idp_code_verifier: str
    callback_uri: str
    expires_at: datetime

    def is_expired(self) -> bool:
        """True once the user took longer than OAUTH_IDP_LOGIN_TTL to come back from the IdP."""
        return datetime.now(timezone.utc) > self.expires_at


# DCR input the server supports; anything else is rejected rather than echoed back
_DCR_GRANT_TYPES = {"authorization_code", "refresh_token"}
_DCR_AUTH_METHODS = {"none", "client_secret_post", "client_secret_basic"}


class OAuthManager:
    """Manage OAuth 2.0 authentication with DCR support."""

    def __init__(self, config, idp: Optional[OIDCProvider] = None):
        """Build the authorization server; `idp` overrides the provider built from config (tests)."""
        self.config = config
        self.secret_key = config.AUTH_SECRET_KEY
        self.clients: Dict[str, OAuthClient] = {}
        self.authorization_codes: Dict[str, AuthorizationCode] = {}
        self.access_tokens: Dict[str, OAuthToken] = {}
        self.refresh_tokens: Dict[str, OAuthToken] = {}
        # Revocation denylist (token -> expiry) so revoked-but-unexpired tokens cannot
        # slip back in via the stateless JWT fallback. Cleaned up alongside expired tokens.
        self.revoked_tokens: Dict[str, datetime] = {}
        # Revocation denylist keyed on the token's canonical identity (jti -> expiry).
        # A signed JWT has many valid string spellings (base64url padding / non-canonical
        # trailing bits) that PyJWT all accepts, so a raw-string denylist alone can be
        # bypassed by re-spelling a revoked token. The jti is spelling-independent.
        self.revoked_jtis: Dict[str, datetime] = {}
        # Proxies whose x-forwarded-* headers we trust when deriving the issuer URL.
        self._trusted_proxies = {p.strip() for p in os.getenv("TRUSTED_PROXIES", "").split(",") if p.strip()} | {
            "127.0.0.1",
            "::1",
        }

        # External OpenID Connect provider (Entra ID, Google Workspace, Okta, ...). When
        # configured, /oauth/authorize authenticates the user there instead of the API-key
        # sign-in page. Parked requests are keyed by the opaque `state` sent to the IdP.
        self.idp: Optional[OIDCProvider] = idp
        if self.idp is None and getattr(config, "OAUTH_IDP_ISSUER", ""):
            self.idp = OIDCProvider(config)
        self.pending_logins: Dict[str, PendingLogin] = {}
        self._login_ttl = int(getattr(config, "OAUTH_IDP_LOGIN_TTL", 600) or 600)

        # Pre-register Claude as a known client
        self._register_claude_client()

    def _register_claude_client(self):
        """Pre-register Claude Desktop as a known OAuth client.

        Registered as a PUBLIC client (no secret, token_endpoint_auth_method="none"):
        a confidential secret would never be disclosed to the client, so requiring it at
        the token endpoint (client_requires_secret) would make the pre-registered client
        unusable. Security is provided by the mandatory PKCE S256 exchange, which is the
        correct posture for a public client.
        """
        claude_client = OAuthClient(
            client_id="claude-desktop",
            client_secret="",
            client_name="Claude",
            redirect_uris=[
                "https://claude.ai/api/mcp/auth_callback",
                "https://claude.com/api/mcp/auth_callback",
            ],
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            scope="wazuh:read wazuh:write",
            token_endpoint_auth_method="none",
        )
        self.clients[claude_client.client_id] = claude_client
        logger.info("Pre-registered Claude Desktop OAuth client (public / PKCE)")

    def get_issuer_url(self, request: Request) -> str:
        """Get the OAuth issuer URL.

        Prefer the explicitly configured ``OAUTH_ISSUER_URL``. When deriving from the
        request, only honor ``x-forwarded-*`` headers if the direct peer is a trusted
        proxy — otherwise an attacker can poison authorization-server discovery (both
        well-known documents echo this issuer) by spoofing ``x-forwarded-host``.
        """
        if self.config.OAUTH_ISSUER_URL:
            return self.config.OAUTH_ISSUER_URL.rstrip("/")
        scheme = request.url.scheme
        host = request.url.netloc
        peer = request.client.host if request.client else ""
        if peer in self._trusted_proxies:
            scheme = request.headers.get("x-forwarded-proto", scheme)
            host = request.headers.get("x-forwarded-host", host)
        # Reviewed false positive: FastAPI (not Flask), returned into a JSON metadata
        # document (not HTML), and host is trusted-proxy-gated above. Suppress inline.
        return f"{scheme}://{host}"  # nosemgrep

    def get_metadata(self, request: Request) -> Dict[str, Any]:
        """Get OAuth 2.0 Authorization Server Metadata (RFC 8414)."""
        issuer = self.get_issuer_url(request)

        metadata = {
            "issuer": issuer,
            "authorization_endpoint": f"{issuer}/oauth/authorize",
            "token_endpoint": f"{issuer}/oauth/token",
            "revocation_endpoint": f"{issuer}/oauth/revoke",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            # "none" is advertised because the pre-registered Claude client is a public,
            # PKCE-secured client that presents no secret at the token endpoint.
            "token_endpoint_auth_methods_supported": ["none", "client_secret_post", "client_secret_basic"],
            "scopes_supported": ["wazuh:read", "wazuh:write"],
            "code_challenge_methods_supported": ["S256"],
            "authorization_response_iss_parameter_supported": True,
            "service_documentation": f"{issuer}/docs",
        }
        # RFC 8414: omit registration_endpoint entirely when DCR is disabled, rather than
        # advertising it as null (a null endpoint is not a valid metadata value).
        if self.config.OAUTH_ENABLE_DCR:
            metadata["registration_endpoint"] = f"{issuer}/oauth/register"
        return metadata

    @staticmethod
    def _validate_redirect_uri(uri: str) -> None:
        """Reject redirect URIs that aren't https (loopback http allowed) or contain a fragment."""
        try:
            parsed = urlparse(uri)
        except Exception:
            raise ValueError(f"invalid redirect_uri: {uri}")
        if parsed.fragment:
            raise ValueError(f"redirect_uri must not contain a fragment: {uri}")
        host = (parsed.hostname or "").lower()
        is_loopback = host in ("localhost", "127.0.0.1", "::1")
        if parsed.scheme == "https":
            return
        if parsed.scheme == "http" and is_loopback:
            return
        raise ValueError(f"redirect_uri must use https (http allowed only for loopback): {uri}")

    def register_client(self, request_data: Dict[str, Any]) -> OAuthClient:
        """Dynamic Client Registration (RFC 7591)."""
        if not self.config.OAUTH_ENABLE_DCR:
            raise ValueError("Dynamic client registration is disabled")

        client_name = request_data.get("client_name", "Unknown Client")
        redirect_uris = request_data.get("redirect_uris", [])

        if not redirect_uris:
            raise ValueError("redirect_uris is required")

        # Validate redirect URIs: https only (http allowed for loopback dev), no fragments.
        for uri in redirect_uris:
            self._validate_redirect_uri(uri)

        # Generate client credentials
        client_id = f"client_{secrets.token_urlsafe(16)}"
        client_secret = secrets.token_urlsafe(32)

        grant_types = request_data.get("grant_types", ["authorization_code", "refresh_token"])
        if not isinstance(grant_types, list) or not set(grant_types) <= _DCR_GRANT_TYPES:
            raise ValueError(f"grant_types must be a subset of {sorted(_DCR_GRANT_TYPES)}")
        auth_method = request_data.get("token_endpoint_auth_method", "client_secret_post")
        if auth_method not in _DCR_AUTH_METHODS:
            raise ValueError(f"token_endpoint_auth_method must be one of {sorted(_DCR_AUTH_METHODS)}")

        # A registered client's scope is only a ceiling: what a user actually gets is further
        # capped by the scopes of the API key they log in with on /oauth/authorize.
        client = OAuthClient(
            client_id=client_id,
            client_secret=client_secret,
            client_name=client_name,
            redirect_uris=redirect_uris,
            grant_types=grant_types,
            response_types=request_data.get("response_types", ["code"]),
            scope=request_data.get("scope", "wazuh:read wazuh:write"),
            token_endpoint_auth_method=auth_method,
        )

        # Bound number of registered clients
        if len(self.clients) > 1000:
            raise ValueError("Maximum number of registered clients reached")
        self.clients[client_id] = client
        logger.info(f"Registered new OAuth client: {client_name} ({client_id})")

        return client

    def validate_client(self, client_id: str, client_secret: Optional[str] = None) -> Optional[OAuthClient]:
        """Resolve a client, rejecting a *wrong* secret if one is presented.

        Used by the authorization endpoint (which does not authenticate the client) and,
        with a secret, by the token endpoint. A *missing* secret is not rejected here —
        confidential-client authentication is enforced separately via
        client_requires_secret() at the token endpoint, because the auth-code flow
        legitimately resolves the client with no secret.
        """
        client = self.clients.get(client_id)
        if not client:
            return None

        if client_secret and not secrets.compare_digest(client.client_secret, client_secret):
            return None

        return client

    @staticmethod
    def client_requires_secret(client: OAuthClient) -> bool:
        """A confidential client (has a secret and doesn't use auth method 'none') must
        authenticate with that secret at the token endpoint."""
        return bool(client.client_secret) and client.token_endpoint_auth_method != "none"

    @staticmethod
    def bound_scope(requested: Optional[str], client: OAuthClient) -> str:
        """Down-scope the requested scope to what the client is registered for.

        Prevents a read-only client from self-granting `wazuh:write`. Grants only scopes
        that are both registered for the client and valid; falls back to the client's
        registered read scope."""
        valid = {"wazuh:read", "wazuh:write"}
        registered = set((client.scope or "").split()) & valid
        asked = set((requested or "").split()) & valid
        granted = (asked & registered) if asked else registered
        if not granted:
            granted = registered or {"wazuh:read"}
        # Stable, canonical order.
        return " ".join(s for s in ("wazuh:read", "wazuh:write") if s in granted)

    @property
    def requires_idp(self) -> bool:
        """True when users authenticate at the external IdP rather than with an API key."""
        return self.idp is not None

    def create_pending_login(
        self,
        client_id: str,
        redirect_uri: str,
        scope: str,
        state: Optional[str],
        code_challenge: str,
        code_challenge_method: str,
        callback_uri: str,
    ) -> Tuple[str, PendingLogin]:
        """Park an authorization request while the user authenticates at the IdP.

        Returns the opaque IdP `state` (the lookup key) and the record. The record carries its
        own PKCE verifier and nonce for the IdP leg; the MCP client's PKCE challenge is kept
        for the code issued afterwards.
        """
        if code_challenge_method != "S256" or not code_challenge:
            raise ValueError("invalid_request: PKCE S256 is required")
        # Bounded store: an unauthenticated flood must not lock real users out, so the oldest
        # parked requests are evicted (the attacker only hurts its own logins).
        if len(self.pending_logins) >= 1000:
            self.cleanup_expired()
        if len(self.pending_logins) >= 1000:
            for stale in sorted(self.pending_logins, key=lambda k: self.pending_logins[k].expires_at)[:100]:
                del self.pending_logins[stale]
        idp_state = secrets.token_urlsafe(32)
        record = PendingLogin(
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            state=state,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            idp_nonce=secrets.token_urlsafe(24),
            idp_code_verifier=secrets.token_urlsafe(48),
            callback_uri=callback_uri,
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=self._login_ttl),
        )
        self.pending_logins[idp_state] = record
        return idp_state, record

    def consume_pending_login(self, idp_state: str) -> Optional[PendingLogin]:
        """Single-use lookup of a parked authorization request."""
        if not idp_state:
            return None
        record = self.pending_logins.pop(idp_state, None)
        if record is None or record.is_expired():
            return None
        return record

    @staticmethod
    def intersect_scope(identity_scope: str, client_scope: str) -> str:
        """Scope granted to a code = what the person may do AND what the client registered for."""
        granted = set(identity_scope.split()) & set(client_scope.split())
        return " ".join(s for s in ("wazuh:read", "wazuh:write") if s in granted)

    def create_authorization_code(
        self,
        client_id: str,
        redirect_uri: str,
        scope: str,
        code_challenge: Optional[str] = None,
        code_challenge_method: Optional[str] = None,
        subject: Optional[str] = None,
        subject_kind: Optional[str] = None,
    ) -> str:
        """Create authorization code for OAuth flow. PKCE with S256 is mandatory."""
        if not code_challenge:
            raise ValueError("invalid_request: code_challenge is required (PKCE)")
        if code_challenge_method != "S256":
            raise ValueError("invalid_request: code_challenge_method must be S256")
        code = secrets.token_urlsafe(32)

        auth_code = AuthorizationCode(
            code=code,
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            created_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=self.config.OAUTH_AUTHORIZATION_CODE_TTL),
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            subject=subject,
            subject_kind=subject_kind if subject else None,
        )

        # Cleanup expired entries periodically to bound memory
        if len(self.authorization_codes) > 1000:
            self.cleanup_expired()
        self.authorization_codes[code] = auth_code
        return code

    def exchange_code_for_tokens(
        self, code: str, client_id: str, redirect_uri: str, code_verifier: Optional[str] = None
    ) -> Dict[str, Any]:
        """Exchange authorization code for access/refresh tokens."""
        # Atomically consume the code so a concurrent second exchange can't reuse it.
        auth_code = self.authorization_codes.pop(code, None)

        if not auth_code:
            raise ValueError("invalid_grant")

        if auth_code.is_expired():
            raise ValueError("invalid_grant")

        if auth_code.client_id != client_id:
            raise ValueError("invalid_grant")

        if auth_code.redirect_uri != redirect_uri:
            raise ValueError("invalid_grant")

        # PKCE is mandatory and S256-only (enforced at code creation; verify here).
        if not auth_code.code_challenge or auth_code.code_challenge_method != "S256":
            raise ValueError("invalid_grant")
        if not code_verifier:
            raise ValueError("invalid_grant")
        import base64

        computed = hashlib.sha256(code_verifier.encode()).digest()
        computed_challenge = base64.urlsafe_b64encode(computed).rstrip(b"=").decode()
        if not secrets.compare_digest(auth_code.code_challenge, computed_challenge):
            raise ValueError("invalid_grant")

        # Generate tokens
        family = secrets.token_urlsafe(12)
        subject, kind = auth_code.subject, auth_code.subject_kind
        access_token = self._create_jwt_token(client_id, auth_code.scope, "access", subject, family, kind)
        refresh_token = self._create_jwt_token(client_id, auth_code.scope, "refresh", subject, family, kind)

        # Cleanup expired tokens periodically to bound memory
        if len(self.access_tokens) > 5000 or len(self.refresh_tokens) > 5000:
            self.cleanup_expired()
        # Store tokens
        self.access_tokens[access_token] = OAuthToken(
            token=access_token,
            token_type="access",
            client_id=client_id,
            scope=auth_code.scope,
            created_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=self.config.OAUTH_ACCESS_TOKEN_TTL),
            subject=subject,
            subject_kind=kind,
            family=family,
        )

        self.refresh_tokens[refresh_token] = OAuthToken(
            token=refresh_token,
            token_type="refresh",
            client_id=client_id,
            scope=auth_code.scope,
            created_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=self.config.OAUTH_REFRESH_TOKEN_TTL),
            subject=subject,
            subject_kind=kind,
            family=family,
        )

        # Authorization code was already consumed via pop() above (single-use).
        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": self.config.OAUTH_ACCESS_TOKEN_TTL,
            "refresh_token": refresh_token,
            "scope": auth_code.scope,
        }

    def refresh_access_token(self, refresh_token: str, client_id: str) -> Dict[str, Any]:
        """Refresh access token, rotating the refresh token and detecting replay."""
        # Atomically consume the presented refresh token (rotation = one-time use).
        token_obj = self.refresh_tokens.pop(refresh_token, None)

        if not token_obj:
            # Replay: a syntactically-valid refresh token that's no longer in the store
            # (already rotated/revoked). Revoke the whole grant for safety, per OAuth BCP.
            # Match on jti so a re-spelled (padded) replay is still detected.
            replay_jti = replay_family = None
            replay_payload = self._safe_decode(refresh_token)
            if replay_payload is not None:
                replay_jti = replay_payload.get("jti")
                replay_family = replay_payload.get("fam")
            is_replay = refresh_token in self.revoked_tokens or (replay_jti and replay_jti in self.revoked_jtis)
            if is_replay and replay_family:
                # Only the grant the replayed token came from. Revoking by client_id logged out
                # every user of the shared public client, so one replay was a global logout.
                self._revoke_family(replay_family)
            raise ValueError("invalid_grant")

        # Validate the grant BEFORE recording the token as consumed/revoked. A mismatched
        # client_id or an expired token is a failed refresh, not a rotation — burning the
        # token here would let a wrong-client_id request (a buggy client, or an attacker
        # holding a stolen refresh token) permanently revoke a legitimate grant.
        if token_obj.is_expired():
            raise ValueError("invalid_grant")

        if token_obj.client_id != client_id:
            # Put the (still-valid) token back so a correct retry can rotate it.
            self.refresh_tokens[refresh_token] = token_obj
            raise ValueError("invalid_grant")

        # Mark the consumed token as revoked (by string AND jti) so a later replay is
        # detected above regardless of how the token is re-spelled.
        self.revoked_tokens[refresh_token] = token_obj.expires_at
        consumed_payload = self._safe_decode(refresh_token)
        if consumed_payload is not None and consumed_payload.get("jti"):
            self.revoked_jtis[consumed_payload["jti"]] = token_obj.expires_at

        # Bound access_tokens to prevent unbounded memory growth
        if len(self.access_tokens) > 5000:
            expired = [k for k, v in self.access_tokens.items() if v.is_expired()]
            for k in expired:
                del self.access_tokens[k]
            # If still too many, evict oldest
            if len(self.access_tokens) > 5000:
                oldest_keys = sorted(self.access_tokens, key=lambda k: self.access_tokens[k].created_at)
                for k in oldest_keys[: len(oldest_keys) - 2500]:
                    del self.access_tokens[k]

        # Generate new access token AND a new refresh token (rotation), same grant family.
        subject, family, kind = token_obj.subject, token_obj.family, token_obj.subject_kind
        access_token = self._create_jwt_token(client_id, token_obj.scope, "access", subject, family, kind)
        new_refresh_token = self._create_jwt_token(client_id, token_obj.scope, "refresh", subject, family, kind)

        self.access_tokens[access_token] = OAuthToken(
            token=access_token,
            token_type="access",
            client_id=client_id,
            scope=token_obj.scope,
            created_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=self.config.OAUTH_ACCESS_TOKEN_TTL),
            subject=subject,
            subject_kind=kind,
            family=family,
        )
        self.refresh_tokens[new_refresh_token] = OAuthToken(
            token=new_refresh_token,
            token_type="refresh",
            client_id=client_id,
            scope=token_obj.scope,
            created_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=self.config.OAUTH_REFRESH_TOKEN_TTL),
            subject=subject,
            subject_kind=kind,
            family=family,
        )

        return {
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": self.config.OAUTH_ACCESS_TOKEN_TTL,
            "refresh_token": new_refresh_token,
            "scope": token_obj.scope,
        }

    def _safe_decode(self, token: str) -> Optional[Dict[str, Any]]:
        """Decode+verify a token's signature, ignoring expiry. Returns claims or None.

        Expiry is ignored so revocation can still record a canonical identity (jti) for a
        token that is about to expire; validate_access_token enforces expiry separately.
        """
        try:
            return jwt.decode(token, self.secret_key, algorithms=["HS256"], options={"verify_exp": False})
        except JWTError:
            return None

    def validate_access_token(self, token: str) -> Optional[OAuthToken]:
        """Validate access token."""
        # Fast path: exact-string denylist.
        if token in self.revoked_tokens:
            return None

        # Verify the signature (and expiry) up front. Revocation must be checked against
        # the token's CANONICAL identity (jti), not its raw string: PyJWT accepts many
        # valid spellings of the same signed token (base64url padding / trailing bits), so
        # an attacker could otherwise re-spell a revoked token to slip past the denylist.
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=["HS256"])
        except JWTError:
            return None

        jti = payload.get("jti")
        if jti and jti in self.revoked_jtis:
            return None

        # Prefer the in-memory record (exact-string match); else rebuild from the verified claims.
        token_obj = self.access_tokens.get(token)
        if token_obj and not token_obj.is_expired():
            return token_obj

        if payload.get("type") == "access":
            return OAuthToken(
                token=token,
                token_type="access",
                client_id=payload.get("client_id", ""),
                scope=payload.get("scope", ""),
                created_at=datetime.fromtimestamp(payload.get("iat", 0), timezone.utc),
                expires_at=datetime.fromtimestamp(payload.get("exp", 0), timezone.utc),
                subject=payload.get("usr") or payload.get("idp_sub"),
                subject_kind="api_key" if payload.get("usr") else ("idp_user" if payload.get("idp_sub") else None),
                family=payload.get("fam"),
            )

        return None

    def revoke_token(self, token: str) -> bool:
        """Revoke an access or refresh token and add it to the denylist."""
        revoked = False
        for store in (self.access_tokens, self.refresh_tokens):
            token_obj = store.pop(token, None)
            if token_obj is not None:
                self.revoked_tokens[token] = token_obj.expires_at
                revoked = True
        # Always denylist by canonical identity (jti) too, so NO alternate spelling of this
        # signed token survives revocation — not just the exact string presented here.
        payload = self._safe_decode(token)
        if payload is not None:
            exp = datetime.fromtimestamp(payload.get("exp", 0), timezone.utc)
            self.revoked_tokens[token] = exp
            jti = payload.get("jti")
            if jti:
                self.revoked_jtis[jti] = exp
            revoked = True
        return revoked

    def _revoke_family(self, family: str) -> None:
        """Revoke every live token of one grant (refresh-replay response, OAuth BCP)."""
        for store in (self.access_tokens, self.refresh_tokens):
            for tok, obj in list(store.items()):
                if obj.family == family:
                    self.revoked_tokens[tok] = obj.expires_at
                    payload = self._safe_decode(tok)
                    if payload is not None and payload.get("jti"):
                        self.revoked_jtis[payload["jti"]] = obj.expires_at
                    del store[tok]

    def delete_client(self, client_id: str) -> bool:
        """Delete a registered client and all its tokens."""
        if client_id not in self.clients:
            return False

        # Remove all tokens for this client
        self.access_tokens = {k: v for k, v in self.access_tokens.items() if v.client_id != client_id}
        self.refresh_tokens = {k: v for k, v in self.refresh_tokens.items() if v.client_id != client_id}

        del self.clients[client_id]
        logger.info(f"Deleted OAuth client: {client_id}")
        return True

    def _create_jwt_token(
        self,
        client_id: str,
        scope: str,
        token_type: str,
        subject: Optional[str] = None,
        family: Optional[str] = None,
        subject_kind: Optional[str] = None,
    ) -> str:
        """Create JWT token. `usr` carries an API-key subject, `idp_sub` an IdP-authenticated user."""
        ttl = self.config.OAUTH_ACCESS_TOKEN_TTL if token_type == "access" else self.config.OAUTH_REFRESH_TOKEN_TTL

        payload = {
            "sub": subject or client_id,
            "client_id": client_id,
            "scope": scope,
            "type": token_type,
            "iat": datetime.now(timezone.utc).timestamp(),
            "exp": (datetime.now(timezone.utc) + timedelta(seconds=ttl)).timestamp(),
            "jti": secrets.token_urlsafe(16),
        }
        if subject and subject_kind == "idp_user":
            payload["idp_sub"] = subject
        elif subject:
            payload["usr"] = subject
        if family:
            payload["fam"] = family

        return jwt.encode(payload, self.secret_key, algorithm="HS256")

    def cleanup_expired(self):
        """Clean up expired tokens and codes."""
        now = datetime.now(timezone.utc)
        self.authorization_codes = {k: v for k, v in self.authorization_codes.items() if not v.is_expired()}
        self.access_tokens = {k: v for k, v in self.access_tokens.items() if not v.is_expired()}
        self.refresh_tokens = {k: v for k, v in self.refresh_tokens.items() if not v.is_expired()}
        # A revoked token only needs to stay on the denylist until it would have expired.
        self.revoked_tokens = {k: exp for k, exp in self.revoked_tokens.items() if exp and exp > now}
        self.revoked_jtis = {k: exp for k, exp in self.revoked_jtis.items() if exp and exp > now}
        self.pending_logins = {k: v for k, v in self.pending_logins.items() if not v.is_expired()}


_NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}


def _s256(verifier: str) -> str:
    """PKCE S256 challenge for the IdP leg (base64url, unpadded)."""
    import base64

    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()


def create_oauth_router(oauth_manager: OAuthManager) -> APIRouter:
    """Create FastAPI router for OAuth endpoints."""
    router = APIRouter(prefix="/oauth", tags=["OAuth"])

    def _login_page(client, redirect_uri, scope, state, code_challenge, error: Optional[str] = None, status=200):
        """Consent/login form. The user proves who they are with their wazuh_ API key; the
        grant then carries that key's identity and is capped at that key's scopes."""
        esc = html.escape
        hidden = "".join(
            f'<input type="hidden" name="{esc(k)}" value="{esc(v or "")}">'
            for k, v in (
                ("response_type", "code"),
                ("client_id", client.client_id),
                ("redirect_uri", redirect_uri),
                ("scope", scope),
                ("state", state),
                ("code_challenge", code_challenge),
                ("code_challenge_method", "S256"),
            )
        )
        err = f'<p class="err">{esc(error)}</p>' if error else ""
        body = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Authorize access to Wazuh</title>
<style>body{{font:15px system-ui,sans-serif;max-width:26rem;margin:4rem auto;padding:0 1rem;color:#1a1a1a}}
input[type=password]{{width:100%;padding:.55rem;font:inherit;box-sizing:border-box}}
button{{margin-top:1rem;padding:.55rem 1.1rem;font:inherit}}.err{{color:#b00020}}code{{font-size:.9em}}</style>
</head><body><h1>Authorize {esc(client.client_name)}</h1>
<p><strong>{esc(client.client_name)}</strong> is requesting access to this Wazuh MCP server
(<code>{esc(scope)}</code>). Access is limited to what your API key allows.</p>{err}
<form method="post" action="authorize">{hidden}
<label for="api_key">Your Wazuh MCP API key</label>
<input id="api_key" name="api_key" type="password" autocomplete="current-password" required placeholder="wazuh_…">
<button type="submit">Authorize</button></form></body></html>"""
        return HTMLResponse(
            body,
            status_code=status,
            headers={
                "Cache-Control": "no-store",
                "X-Frame-Options": "DENY",
                "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; "
                "frame-ancestors 'none'",
                "Referrer-Policy": "no-referrer",
            },
        )

    def _check_request(client_id, redirect_uri, response_type, state, code_challenge, code_challenge_method):
        """Validate an authorization request. Returns (client, error_response)."""
        client = oauth_manager.validate_client(client_id)
        if not client:
            return None, JSONResponse(
                {"error": "invalid_client", "error_description": "Unknown client"}, status_code=401
            )
        # Never redirect to an unregistered URI; report it directly instead
        if redirect_uri not in client.redirect_uris:
            return None, JSONResponse(
                {"error": "invalid_request", "error_description": "Invalid redirect_uri"}, status_code=400
            )
        if response_type != "code":
            params = urlencode({"error": "unsupported_response_type", "state": state or ""})
            return None, RedirectResponse(f"{redirect_uri}?{params}")
        # PKCE (S256) is mandatory
        if not code_challenge or code_challenge_method != "S256":
            params = urlencode(
                {
                    "error": "invalid_request",
                    "error_description": "PKCE required: send code_challenge with code_challenge_method=S256",
                    "state": state or "",
                }
            )
            return None, RedirectResponse(f"{redirect_uri}?{params}")
        return client, None

    async def _start_idp_login(request, client, redirect_uri, scope, state, code_challenge):
        """Park the MCP client's request and send the user to the IdP (resumed on /oauth/callback)."""
        granted_scope = oauth_manager.bound_scope(scope, client)
        callback_uri = f"{oauth_manager.get_issuer_url(request)}/oauth/callback"
        try:
            idp_state, pending = oauth_manager.create_pending_login(
                client_id=client.client_id,
                redirect_uri=redirect_uri,
                scope=granted_scope,
                state=state,
                code_challenge=code_challenge,
                code_challenge_method="S256",
                callback_uri=callback_uri,
            )
            location = await oauth_manager.idp.build_authorization_url(
                redirect_uri=callback_uri,
                state=idp_state,
                nonce=pending.idp_nonce,
                code_challenge=_s256(pending.idp_code_verifier),
            )
        except ValueError as e:
            params = urlencode({"error": str(e).split(":")[0], "state": state or ""})
            return RedirectResponse(f"{redirect_uri}?{params}", headers=_NO_STORE)
        except IdPError as e:
            logger.error(f"IdP unavailable during authorize: {e}")
            params = urlencode({"error": "temporarily_unavailable", "state": state or ""})
            return RedirectResponse(f"{redirect_uri}?{params}", headers=_NO_STORE)
        return RedirectResponse(location, headers=_NO_STORE)

    @router.get("/callback")
    async def callback(
        request: Request,
        state: Optional[str] = Query(default=None),
        code: Optional[str] = Query(default=None),
        error: Optional[str] = Query(default=None),
        error_description: Optional[str] = Query(default=None),
    ):
        """Return leg of the IdP login: verify the ID token, then issue the MCP code."""
        if not oauth_manager.requires_idp:
            return JSONResponse(
                {"error": "invalid_request", "error_description": "No identity provider configured"}, status_code=404
            )
        # The IdP `state` is our single-use lookup key; an unknown/expired/replayed one cannot
        # be tied to a client redirect, so it is answered directly (no redirect).
        pending = oauth_manager.consume_pending_login(state or "")
        if pending is None:
            return JSONResponse(
                {"error": "invalid_request", "error_description": "Unknown or expired login state"},
                status_code=400,
                headers=_NO_STORE,
            )

        def _deny(err: str, description: str) -> RedirectResponse:
            """Send the MCP client an OAuth error redirect (with its own state), never IdP text."""
            params = {"error": err, "error_description": description}
            if pending.state:
                params["state"] = pending.state
            return RedirectResponse(f"{pending.redirect_uri}?{urlencode(params)}", headers=_NO_STORE)

        if error:
            # Never echo the IdP's free-text description to the client (nor log it verbatim).
            logger.info(f"IdP returned error={error[:64]!r} for client {pending.client_id}")
            return _deny("access_denied", "The identity provider did not authorize the login")
        if not code:
            return _deny("invalid_request", "Missing authorization code from the identity provider")

        try:
            tokens = await oauth_manager.idp.exchange_code(
                code=code, redirect_uri=pending.callback_uri, code_verifier=pending.idp_code_verifier
            )
            claims = await oauth_manager.idp.verify_id_token(tokens["id_token"], nonce=pending.idp_nonce)
            identity = oauth_manager.idp.authorize(claims)
        except IdPError as e:
            logger.warning(f"IdP login failed for client {pending.client_id}: {e}")
            return _deny("access_denied", "Login could not be verified with the identity provider")
        except IdentityDenied as e:
            logger.warning(f"IdP login denied by policy ({e.reason}) for client {pending.client_id}")
            return _deny("access_denied", "This account is not authorized to use this server")
        except Exception as e:  # the state is already consumed; fail closed, never 500
            logger.error(f"Unexpected error completing IdP login: {type(e).__name__}")
            return _deny("server_error", "Login could not be completed")

        granted_scope = oauth_manager.intersect_scope(identity.scope, pending.scope)
        if not granted_scope:
            return _deny("access_denied", "This account has no permitted scope for this client")

        logger.info(
            f"IdP login: subject={identity.subject} client={pending.client_id} scope={granted_scope!r} "
            f"groups={len(identity.groups)}"
        )
        try:
            mcp_code = oauth_manager.create_authorization_code(
                client_id=pending.client_id,
                redirect_uri=pending.redirect_uri,
                scope=granted_scope,
                code_challenge=pending.code_challenge,
                code_challenge_method=pending.code_challenge_method,
                subject=identity.subject,
                subject_kind="idp_user",
            )
        except ValueError as e:
            return _deny("invalid_request", str(e))
        params = {"code": mcp_code, "iss": oauth_manager.get_issuer_url(request)}
        if pending.state:
            params["state"] = pending.state
        return RedirectResponse(f"{pending.redirect_uri}?{urlencode(params)}", headers=_NO_STORE)

    @router.get("/authorize")
    async def authorize(
        request: Request,
        response_type: str = Query(...),
        client_id: str = Query(...),
        redirect_uri: str = Query(...),
        scope: str = Query(default="wazuh:read wazuh:write"),
        state: Optional[str] = Query(default=None),
        code_challenge: Optional[str] = Query(default=None),
        code_challenge_method: Optional[str] = Query(default=None),
    ):
        """OAuth 2.0 Authorization Endpoint: validate the request, then ask the user to log in.

        This used to auto-approve every request, which handed a read+write token to anyone who
        could reach the server."""
        client, error = _check_request(
            client_id, redirect_uri, response_type, state, code_challenge, code_challenge_method
        )
        if error:
            return error
        if oauth_manager.requires_idp:
            return await _start_idp_login(request, client, redirect_uri, scope, state, code_challenge)
        return _login_page(client, redirect_uri, scope, state, code_challenge)

    @router.post("/authorize")
    async def authorize_submit(
        request: Request,
        response_type: str = Form(...),
        client_id: str = Form(...),
        redirect_uri: str = Form(...),
        api_key: str = Form(...),
        scope: str = Form(default="wazuh:read wazuh:write"),
        state: Optional[str] = Form(default=None),
        code_challenge: Optional[str] = Form(default=None),
        code_challenge_method: Optional[str] = Form(default=None),
    ):
        """Login form submission: authenticate the API key and issue the authorization code."""
        client, error = _check_request(
            client_id, redirect_uri, response_type, state, code_challenge, code_challenge_method
        )
        if error:
            return error
        if oauth_manager.requires_idp:
            # With an IdP configured, users authenticate there; the API-key form is off.
            return JSONResponse(
                {"error": "invalid_request", "error_description": "Sign in through the identity provider"},
                status_code=400,
            )

        from wazuh_mcp_server.auth import auth_manager

        key = auth_manager.validate_api_key(api_key.strip())
        if key is None:
            logger.warning(f"OAuth login failed for client {client_id}: invalid API key")
            return _login_page(
                client, redirect_uri, scope, state, code_challenge, error="That API key isn't valid.", status=401
            )

        # Requested ∩ what the client is registered for ∩ what this user's key allows
        client_scope = set(oauth_manager.bound_scope(scope, client).split())
        granted = client_scope & set(key.scopes or ["wazuh:read"])
        if not granted:
            return _login_page(
                client,
                redirect_uri,
                scope,
                state,
                code_challenge,
                error="Your API key has none of the requested scopes.",
                status=403,
            )
        granted_scope = " ".join(sc for sc in ("wazuh:read", "wazuh:write") if sc in granted)

        try:
            code = oauth_manager.create_authorization_code(
                client_id=client_id,
                redirect_uri=redirect_uri,
                scope=granted_scope,
                code_challenge=code_challenge,
                code_challenge_method=code_challenge_method,
                subject=key.id,
                subject_kind="api_key",
            )
        except ValueError as e:
            params = urlencode({"error": "invalid_request", "error_description": str(e), "state": state or ""})
            return RedirectResponse(f"{redirect_uri}?{params}", status_code=303)

        logger.info(f"OAuth grant approved: client={client_id} key={key.id} scope={granted_scope}")
        # Redirect back with code and the issuer identifier (RFC 9207) so the client can
        # defend against authorization-server mix-up attacks. 303: the browser must GET it.
        params = {"code": code, "iss": oauth_manager.get_issuer_url(request)}
        if state:
            params["state"] = state
        return RedirectResponse(f"{redirect_uri}?{urlencode(params)}", status_code=303)

    @router.post("/token")
    async def token(
        request: Request,
        grant_type: str = Form(...),
        code: Optional[str] = Form(default=None),
        redirect_uri: Optional[str] = Form(default=None),
        client_id: Optional[str] = Form(default=None),
        client_secret: Optional[str] = Form(default=None),
        refresh_token: Optional[str] = Form(default=None),
        code_verifier: Optional[str] = Form(default=None),
    ):
        """OAuth 2.0 Token Endpoint."""
        # Extract client credentials from Authorization header if not in body
        if not client_id:
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("Basic "):
                import base64

                try:
                    decoded = base64.b64decode(auth_header[6:]).decode()
                    client_id, client_secret = decoded.split(":", 1)
                except (ValueError, UnicodeDecodeError) as e:
                    logger.debug(f"Failed to decode Basic auth header: {e}")

        if not client_id:
            return JSONResponse(
                {"error": "invalid_client", "error_description": "Client authentication required"}, status_code=401
            )

        # Validate client
        client = oauth_manager.validate_client(client_id, client_secret)
        if not client:
            # Per MCP spec: Return 401 with invalid_client to signal client deletion
            return JSONResponse(
                {"error": "invalid_client", "error_description": "Client authentication failed"}, status_code=401
            )

        # A confidential client MUST present its secret at the token endpoint — otherwise
        # anyone knowing the client_id could redeem a stolen refresh token by omitting it.
        if oauth_manager.client_requires_secret(client) and not client_secret:
            return JSONResponse(
                {"error": "invalid_client", "error_description": "Client authentication required"}, status_code=401
            )

        try:
            if grant_type == "authorization_code":
                if not code or not redirect_uri:
                    return JSONResponse(
                        {"error": "invalid_request", "error_description": "code and redirect_uri required"},
                        status_code=400,
                    )

                tokens = oauth_manager.exchange_code_for_tokens(
                    code=code,
                    client_id=client_id,
                    redirect_uri=redirect_uri,
                    code_verifier=code_verifier,
                )
                return JSONResponse(tokens)

            elif grant_type == "refresh_token":
                if not refresh_token:
                    return JSONResponse(
                        {"error": "invalid_request", "error_description": "refresh_token required"}, status_code=400
                    )

                tokens = oauth_manager.refresh_access_token(refresh_token, client_id)
                return JSONResponse(tokens)

            else:
                return JSONResponse(
                    {
                        "error": "unsupported_grant_type",
                        "error_description": f"Grant type '{grant_type}' not supported",
                    },
                    status_code=400,
                )

        except ValueError as e:
            error_code = str(e)
            return JSONResponse(
                {"error": error_code, "error_description": OAUTH_ERRORS.get(error_code, str(e))}, status_code=400
            )

    @router.post("/register")
    async def register(request: Request):
        """Dynamic Client Registration Endpoint (RFC 7591)."""
        if not oauth_manager.config.OAUTH_ENABLE_DCR:
            return JSONResponse(
                {"error": "invalid_request", "error_description": "Dynamic client registration is disabled"},
                status_code=400,
            )

        try:
            body = await request.json()
            client = oauth_manager.register_client(body)
            return JSONResponse(client.to_registration_response(), status_code=201)
        except ValueError as e:
            return JSONResponse({"error": "invalid_request", "error_description": str(e)}, status_code=400)
        except Exception as e:
            logger.error(f"Client registration error: {e}")
            return JSONResponse({"error": "server_error", "error_description": "Registration failed"}, status_code=500)

    @router.post("/revoke")
    async def revoke(
        request: Request,
        token: str = Form(...),
        token_type_hint: Optional[str] = Form(default=None),
        client_id: Optional[str] = Form(default=None),
        client_secret: Optional[str] = Form(default=None),
    ):
        """Token Revocation Endpoint (RFC 7009)."""
        # Extract client credentials from Authorization header if not in body
        if not client_id:
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("Basic "):
                import base64

                try:
                    decoded = base64.b64decode(auth_header[6:]).decode()
                    client_id, client_secret = decoded.split(":", 1)
                except Exception:
                    pass

        # Validate client credentials per RFC 7009
        if client_id:
            client = oauth_manager.clients.get(client_id)
            if not client or (
                client.client_secret and not secrets.compare_digest(client.client_secret, client_secret or "")
            ):
                return JSONResponse({"error": "invalid_client"}, status_code=401)

        oauth_manager.revoke_token(token)
        # Always return 200 OK per RFC 7009
        return JSONResponse({})

    return router


# Global OAuth manager instance (initialized in server.py)
_oauth_manager: Optional[OAuthManager] = None


def get_oauth_manager() -> Optional[OAuthManager]:
    """Get OAuth manager instance."""
    return _oauth_manager


def init_oauth_manager(config) -> OAuthManager:
    """Initialize OAuth manager."""
    global _oauth_manager
    _oauth_manager = OAuthManager(config)
    if getattr(config, "ENVIRONMENT", "") == "production" and not getattr(config, "OAUTH_ISSUER_URL", ""):
        logger.warning(
            "OAUTH_ISSUER_URL is not set in production. The issuer is derived from the "
            "request and only trusts x-forwarded-* from TRUSTED_PROXIES; set OAUTH_ISSUER_URL "
            "explicitly to make authorization-server discovery deterministic."
        )
    return _oauth_manager
