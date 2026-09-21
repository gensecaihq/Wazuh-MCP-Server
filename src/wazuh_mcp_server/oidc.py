#!/usr/bin/env python3
"""
OpenID Connect identity-provider integration for the OAuth authorization server.

When ``OAUTH_IDP_ISSUER`` is configured, ``/oauth/authorize`` no longer auto-approves:
the resource owner is sent to the external IdP (Microsoft Entra ID, Google Workspace,
Okta, Keycloak, Cognito — anything that publishes OpenID Connect discovery), and the
MCP authorization code is only issued after a verified ID token comes back on
``/oauth/callback``. Group / role claims are mapped to Wazuh scopes so that write
access is a property of the person, not of the OAuth client.

Security properties enforced here:
- ID token: RS256 only (``alg`` from the token header is never trusted), ``iss``,
  ``aud == client_id``, ``exp``/``iat``, and the per-login ``nonce``.
- JWKS: cached, with at most one refresh per ``min_refresh_seconds`` on an unknown
  ``kid`` so a flood of bogus tokens cannot turn into a JWKS DoS.
- Optional tenant (Entra ``tid``), hosted-domain (Google ``hd`` / e-mail domain) and
  explicit user allow-lists; a user that matches no scope mapping and no default
  scope is denied.
"""

import asyncio
import json
import logging
import secrets
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode

import httpx
import jwt
from jwt import PyJWK
from jwt.exceptions import PyJWTError

logger = logging.getLogger(__name__)

VALID_SCOPES = ("wazuh:read", "wazuh:write")
MULTI_TENANT_ISSUER_MARKERS = ("/common/", "/organizations/", "/consumers/", "{tenantid}")
_MAX_SUBJECT_LEN = 256


class IdentityDenied(Exception):
    """The IdP authenticated the user, but this server's policy does not admit them."""

    def __init__(self, reason: str) -> None:
        """Record the (log-only) policy reason; it is never sent back to the client."""
        super().__init__(reason)
        self.reason = reason


class IdPError(Exception):
    """The IdP leg of the flow failed (network, discovery, token exchange, ID token)."""


@dataclass(frozen=True)
class Identity:
    """The authenticated resource owner, as this server will refer to them."""

    subject: str
    scope: str
    groups: Tuple[str, ...]


class _JWKSCache:
    """Cache of the IdP's RSA signing keys, refreshed at most once per `min_refresh_seconds`."""

    def __init__(
        self,
        client: httpx.AsyncClient,
        *,
        cache_seconds: int = 3600,
        min_refresh_seconds: int = 60,
    ) -> None:
        """Bind the cache to the shared HTTP client; the JWKS URL arrives after discovery."""
        self._client = client
        self._url: Optional[str] = None
        self._cache_seconds = cache_seconds
        self._min_refresh = min_refresh_seconds
        self._keys: Dict[str, PyJWK] = {}
        self._fetched_at = 0.0
        self._last_attempt = 0.0
        self._lock = asyncio.Lock()

    def set_url(self, url: str) -> None:
        """Set the `jwks_uri` learned from OpenID discovery."""
        self._url = url

    async def _refresh(self, force: bool) -> None:
        """Fetch the JWKS document (throttled) and replace the cached key set."""
        async with self._lock:
            now = time.monotonic()
            if self._keys and not force and (now - self._fetched_at) < self._cache_seconds:
                return
            if self._keys and (now - self._last_attempt) < self._min_refresh:
                return
            if not self._url:
                raise IdPError("jwks_uri not discovered")
            self._last_attempt = now
            resp = await self._client.get(self._url, timeout=httpx.Timeout(5.0))
            resp.raise_for_status()
            keys: Dict[str, PyJWK] = {}
            for entry in resp.json().get("keys", []):
                if not isinstance(entry, dict):
                    continue
                if entry.get("kty") != "RSA" or entry.get("use", "sig") != "sig" or not entry.get("kid"):
                    continue
                try:
                    keys[entry["kid"]] = PyJWK(entry, algorithm="RS256")
                except (PyJWTError, ValueError, TypeError) as e:
                    # PyJWK raises InvalidKeyError for bad base64/shape, but a wrong type in
                    # `n`/`e` surfaces as TypeError/ValueError. One malformed entry must not
                    # take every login down: skip it and keep the good keys.
                    logger.warning(f"Skipping malformed JWKS entry kid={entry.get('kid')!r}: {type(e).__name__}")
            if not keys:
                raise IdPError("JWKS document contained no usable RSA signing keys")
            self._keys = keys
            self._fetched_at = time.monotonic()

    async def get_key(self, kid: str) -> Optional[PyJWK]:
        """Return the key for `kid`, refreshing on a miss; serves stale keys if the IdP is down."""
        try:
            if not self._keys or (time.monotonic() - self._fetched_at) >= self._cache_seconds:
                await self._refresh(force=False)
            key = self._keys.get(kid)
            if key is None:
                await self._refresh(force=True)  # possible key rotation (throttled)
                key = self._keys.get(kid)
            return key
        except (httpx.HTTPError, ValueError) as e:
            if self._keys:
                logger.warning(f"JWKS refresh failed, serving cached keys: {type(e).__name__}")
                return self._keys.get(kid)
            raise IdPError(f"JWKS fetch failed: {type(e).__name__}") from e


class OIDCProvider:
    """Thin OpenID Connect relying-party client used by the authorization endpoint."""

    def __init__(self, config, transport: Optional[httpx.AsyncBaseTransport] = None) -> None:
        """Read the OAUTH_IDP_* settings; `transport` is a test seam for httpx.MockTransport."""
        self.issuer: str = config.OAUTH_IDP_ISSUER.rstrip("/")
        self.client_id: str = config.OAUTH_IDP_CLIENT_ID
        self.client_secret: str = getattr(config, "OAUTH_IDP_CLIENT_SECRET", "") or ""
        self.scopes: List[str] = [
            s for s in (getattr(config, "OAUTH_IDP_SCOPES", "") or "openid email profile").split() if s
        ]
        if "openid" not in self.scopes:
            self.scopes.insert(0, "openid")
        self.allowed_domains = _csv(getattr(config, "OAUTH_IDP_ALLOWED_DOMAINS", ""), lower=True)
        self.allowed_tenants = _csv(getattr(config, "OAUTH_IDP_ALLOWED_TENANTS", ""))
        self.allowed_users = _csv(getattr(config, "OAUTH_IDP_ALLOWED_USERS", ""), lower=True)
        self.group_claim: str = getattr(config, "OAUTH_IDP_GROUP_CLAIM", "") or "groups"
        self.group_scope_map: Dict[str, str] = _parse_group_scope_map(getattr(config, "OAUTH_IDP_GROUP_SCOPE_MAP", ""))
        self.default_scope: str = _canonical_scope(getattr(config, "OAUTH_IDP_DEFAULT_SCOPE", "wazuh:read"))
        self.subject_claim: str = getattr(config, "OAUTH_IDP_SUBJECT_CLAIM", "") or "email"

        if not self.issuer.startswith("https://"):
            raise ValueError("OAUTH_IDP_ISSUER must be an https:// URL")
        if not self.client_id:
            raise ValueError("OAUTH_IDP_CLIENT_ID is required when OAUTH_IDP_ISSUER is set")

        self._http = httpx.AsyncClient(
            timeout=httpx.Timeout(8.0),
            follow_redirects=False,
            headers={"User-Agent": "wazuh-mcp-server-oidc/1.0"},
            transport=transport,
        )
        self._jwks = _JWKSCache(self._http)
        self._metadata: Optional[Dict[str, Any]] = None
        self._metadata_lock = asyncio.Lock()

    # ------------------------------------------------------------------ discovery
    async def metadata(self) -> Dict[str, Any]:
        """Return the IdP's OpenID discovery document (fetched once, validated, cached)."""
        if self._metadata is not None:
            return self._metadata
        async with self._metadata_lock:
            if self._metadata is not None:
                return self._metadata
            url = f"{self.issuer}/.well-known/openid-configuration"
            try:
                resp = await self._http.get(url)
                resp.raise_for_status()
                md = resp.json()
            except (httpx.HTTPError, ValueError) as e:
                raise IdPError(f"OIDC discovery failed: {type(e).__name__}") from e
            for key in ("authorization_endpoint", "token_endpoint", "jwks_uri", "issuer"):
                if not isinstance(md.get(key), str) or not md[key].startswith("https://"):
                    raise IdPError(f"OIDC discovery document lacks a valid {key}")
            # Entra's multi-tenant documents advertise a templated issuer; anything else
            # must match the configured issuer exactly (RFC 8414 §3.3).
            templated = "{tenantid}" in md["issuer"]
            if not templated and md["issuer"].rstrip("/") != self.issuer:
                raise IdPError("OIDC discovery issuer does not match OAUTH_IDP_ISSUER")
            if templated and not self.allowed_tenants:
                # A multi-tenant Entra issuer accepts tokens from ANY tenant; without a
                # tenant allow-list every Microsoft account in the world could log in.
                raise IdPError("multi-tenant issuer requires OAUTH_IDP_ALLOWED_TENANTS")
            self._jwks.set_url(md["jwks_uri"])
            self._metadata = md
            return md

    # ------------------------------------------------------------------ authorize leg
    async def build_authorization_url(self, *, redirect_uri: str, state: str, nonce: str, code_challenge: str) -> str:
        """Build the IdP authorization URL for one login (PKCE S256, nonce, opaque state)."""
        md = await self.metadata()
        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": redirect_uri,
            "scope": " ".join(self.scopes),
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        # Google: pre-select the Workspace domain when exactly one is allowed.
        if len(self.allowed_domains) == 1 and "google" in md["issuer"]:
            params["hd"] = self.allowed_domains[0]
        sep = "&" if "?" in md["authorization_endpoint"] else "?"
        return f"{md['authorization_endpoint']}{sep}{urlencode(params)}"

    # ------------------------------------------------------------------ token leg
    async def exchange_code(self, *, code: str, redirect_uri: str, code_verifier: str) -> Dict[str, Any]:
        """Redeem the IdP authorization code; returns the token response (must carry id_token)."""
        md = await self.metadata()
        body = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
            "client_id": self.client_id,
        }
        if self.client_secret:
            body["client_secret"] = self.client_secret  # client_secret_post; safe for any secret charset
        headers = {"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"}
        try:
            resp = await self._http.post(md["token_endpoint"], content=urlencode(body), headers=headers)
        except httpx.HTTPError as e:
            raise IdPError(f"IdP token endpoint unreachable: {type(e).__name__}") from e
        if resp.status_code != 200:
            err = "unknown"
            try:
                err = str(resp.json().get("error", err))
            except ValueError:
                pass
            raise IdPError(f"IdP token exchange rejected: {err}")
        try:
            payload = resp.json()
        except ValueError as e:
            raise IdPError("IdP token response is not JSON") from e
        if not isinstance(payload.get("id_token"), str):
            raise IdPError("IdP token response lacks id_token")
        return payload

    async def verify_id_token(self, id_token: str, *, nonce: str) -> Dict[str, Any]:
        """Verify signature (RS256/JWKS), iss, aud/azp, exp/iat and nonce; return the claims."""
        if len(id_token) > 16384:
            raise IdPError("id_token too large")
        try:
            header = jwt.get_unverified_header(id_token)
        except PyJWTError as e:
            raise IdPError("malformed id_token") from e
        if header.get("alg") != "RS256" or not isinstance(header.get("kid"), str):
            raise IdPError("unsupported id_token algorithm")

        md = await self.metadata()
        key = await self._jwks.get_key(header["kid"])
        if key is None:
            raise IdPError("unknown id_token signing key")

        # Multi-tenant Entra: the discovery issuer is a template, the token carries the
        # concrete tenant. Verify the shape here and the tenant allow-list in authorize().
        templated = "{tenantid}" in md["issuer"]
        try:
            claims = jwt.decode(
                id_token,
                key.key,
                algorithms=["RS256"],
                audience=self.client_id,
                issuer=None if templated else md["issuer"],
                leeway=60,
                options={"require": ["exp", "iat", "sub", "iss", "aud"]},
            )
        except PyJWTError as e:
            raise IdPError(f"id_token rejected: {type(e).__name__}") from e

        if templated:
            tid = claims.get("tid")
            if not isinstance(tid, str) or claims.get("iss") != md["issuer"].replace("{tenantid}", tid):
                raise IdPError("id_token issuer does not match its tenant")
        # OIDC Core §3.1.3.7: with several audiences the authorized party must be us.
        aud = claims.get("aud")
        if isinstance(aud, list) and len(aud) > 1 and claims.get("azp") != self.client_id:
            raise IdPError("id_token azp does not match client_id")
        presented = str(claims.get("nonce", "")).encode("utf-8", "replace")
        if not nonce or not secrets.compare_digest(presented, nonce.encode("utf-8")):
            raise IdPError("id_token nonce mismatch")
        return claims

    # ------------------------------------------------------------------ policy
    def authorize(self, claims: Dict[str, Any]) -> Identity:
        """Apply this server's admission policy to verified ID-token claims."""
        email = str(claims.get("email") or "").lower()
        domain = email.rsplit("@", 1)[-1] if "@" in email else ""
        hosted_domain = str(claims.get("hd") or "").lower()

        tid = str(claims.get("tid") or "")
        if self.allowed_tenants and tid not in self.allowed_tenants:
            raise IdentityDenied("tenant not allowed")
        if self.allowed_domains:
            if hosted_domain not in self.allowed_domains and domain not in self.allowed_domains:
                raise IdentityDenied("domain not allowed")
            # An e-mail domain only proves membership when someone vouched for it: Google
            # via `hd`, a generic OIDC provider via `email_verified: true`, or an Entra
            # tenant that is itself on the allow-list. Entra never sends `email_verified`
            # and the claim is user-editable in foreign tenants, so absence is a denial.
            vouched = (
                hosted_domain in self.allowed_domains
                or claims.get("email_verified") is True
                or (bool(tid) and tid in self.allowed_tenants)
            )
            if not vouched:
                raise IdentityDenied("e-mail domain not verifiable")

        subject, claim_used = "", ""
        for claim in (self.subject_claim, "preferred_username", "sub"):
            value = claims.get(claim)
            if isinstance(value, str) and value.strip():
                subject, claim_used = value.strip(), claim
                break
        if not subject:
            raise IdentityDenied("no usable subject claim")
        if len(subject) > _MAX_SUBJECT_LEN or not subject.isprintable() or any(c.isspace() for c in subject):
            raise IdentityDenied("subject claim is not a printable single token")
        if "@" in subject:
            subject = subject.lower()  # e-mail-shaped identities are case-insensitive
        if claim_used != self.subject_claim:
            logger.debug(f"subject claim {self.subject_claim!r} absent; using {claim_used!r}")

        if self.allowed_users and subject.lower() not in self.allowed_users and email not in self.allowed_users:
            raise IdentityDenied("user not allowed")

        groups_raw = claims.get(self.group_claim, [])
        if isinstance(groups_raw, str):
            groups_raw = [groups_raw]
        groups = tuple(str(g) for g in groups_raw) if isinstance(groups_raw, list) else ()

        granted: set = set()
        for g in groups:
            granted.update(self.group_scope_map.get(g, "").split())
        scope = _canonical_scope(" ".join(granted)) if granted else self.default_scope
        if not scope:
            raise IdentityDenied("user matches no scope mapping")
        return Identity(subject=subject, scope=scope, groups=groups)

    async def aclose(self) -> None:
        """Release the HTTP client (called from the server's shutdown hook)."""
        await self._http.aclose()


# ---------------------------------------------------------------------- helpers
def validate_idp_settings(config) -> None:
    """Fail fast on an unusable OAUTH_IDP_* configuration (called from config.from_env).

    Raises ValueError with an operator-readable message.
    """
    issuer = (getattr(config, "OAUTH_IDP_ISSUER", "") or "").rstrip("/")
    if not issuer:
        return
    if not issuer.startswith("https://"):
        raise ValueError("OAUTH_IDP_ISSUER must be an https:// URL")
    if not getattr(config, "OAUTH_IDP_CLIENT_ID", ""):
        raise ValueError("OAUTH_IDP_CLIENT_ID is required when OAUTH_IDP_ISSUER is set")
    if any(m in issuer.lower() for m in MULTI_TENANT_ISSUER_MARKERS) and not _csv(
        getattr(config, "OAUTH_IDP_ALLOWED_TENANTS", "")
    ):
        raise ValueError(
            "OAUTH_IDP_ISSUER is a multi-tenant issuer; set OAUTH_IDP_ALLOWED_TENANTS "
            "or use the tenant-specific issuer URL"
        )
    _parse_group_scope_map(getattr(config, "OAUTH_IDP_GROUP_SCOPE_MAP", ""))
    default_scope = getattr(config, "OAUTH_IDP_DEFAULT_SCOPE", "") or ""
    unknown = set(default_scope.split()) - set(VALID_SCOPES)
    if unknown:
        raise ValueError(f"OAUTH_IDP_DEFAULT_SCOPE contains unknown scope(s): {' '.join(sorted(unknown))}")


def _csv(raw: str, lower: bool = False) -> List[str]:
    """Split a comma-separated setting into stripped, non-empty items."""
    items = [x.strip() for x in (raw or "").split(",") if x.strip()]
    return [x.lower() for x in items] if lower else items


def _canonical_scope(raw: str) -> str:
    """Keep only known Wazuh scopes, in canonical (read, write) order."""
    wanted = set((raw or "").split())
    return " ".join(s for s in VALID_SCOPES if s in wanted)


def _parse_group_scope_map(raw: str) -> Dict[str, str]:
    """Parse OAUTH_IDP_GROUP_SCOPE_MAP (JSON object of group -> scopes); raise on bad input."""
    if not raw or not raw.strip():
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError("OAUTH_IDP_GROUP_SCOPE_MAP must be a JSON object") from e
    if not isinstance(parsed, dict):
        raise ValueError("OAUTH_IDP_GROUP_SCOPE_MAP must be a JSON object")
    result: Dict[str, str] = {}
    for group, scope in parsed.items():
        if not isinstance(group, str) or not isinstance(scope, str):
            raise ValueError("OAUTH_IDP_GROUP_SCOPE_MAP keys and values must be strings")
        canonical = _canonical_scope(scope)
        if not canonical:
            raise ValueError(f"OAUTH_IDP_GROUP_SCOPE_MAP[{group!r}] grants no known scope")
        result[group] = canonical
    return result
