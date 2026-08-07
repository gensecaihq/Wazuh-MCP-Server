"""
Regression tests for the OAuth revocation-bypass-via-JWT-padding disclosure.

A signed JWT has many valid string spellings — PyJWT adds base64url padding and accepts
non-canonical trailing bits — so a revocation denylist keyed on the raw token string can
be bypassed by re-spelling a revoked token. Revocation must key on the token's canonical
identity (the jti claim) instead. Reported by Corban Villa, Sohee Kim, and Austin Chu
(UC Berkeley security research).
"""

from types import SimpleNamespace

import pytest

from wazuh_mcp_server.oauth import OAuthManager

_SECRET = "test-secret-key-at-least-32-characters-long"


def _mgr():
    return OAuthManager(
        SimpleNamespace(
            AUTH_SECRET_KEY=_SECRET,
            OAUTH_ENABLE_DCR=False,
            OAUTH_ACCESS_TOKEN_TTL=3600,
            OAUTH_REFRESH_TOKEN_TTL=86400,
            OAUTH_AUTHORIZATION_CODE_TTL=600,
            OAUTH_ISSUER_URL="",
        )
    )


class TestRevocationPaddingBypass:
    def test_padded_respelling_is_rejected_after_revoke(self):
        mgr = _mgr()
        token = mgr._create_jwt_token("claude-desktop", "wazuh:read", "access")
        header, payload, signature = token.split(".")

        assert mgr.validate_access_token(token) is not None
        assert mgr.revoke_token(token) is True

        # Exact token is denied...
        assert mgr.validate_access_token(token) is None
        # ...and so is every padded respelling that PyJWT still decodes to the same token.
        assert mgr.validate_access_token(f"{header}.{payload}.{signature}=") is None
        assert mgr.validate_access_token(f"{header}.{payload}.{signature}==") is None

    def test_tampered_signature_still_rejected(self):
        mgr = _mgr()
        token = mgr._create_jwt_token("claude-desktop", "wazuh:read", "access")
        header, payload, signature = token.split(".")
        replacement = "A" if signature[0] != "A" else "B"
        tampered = f"{header}.{payload}.{replacement}{signature[1:]}"
        # A genuinely different signature is invalid regardless of revocation.
        assert mgr.validate_access_token(tampered) is None

    def test_unrevoked_token_still_valid(self):
        mgr = _mgr()
        keep = mgr._create_jwt_token("claude-desktop", "wazuh:read", "access")
        drop = mgr._create_jwt_token("claude-desktop", "wazuh:read", "access")
        mgr.revoke_token(drop)
        # Revoking one token must not affect an unrelated one.
        assert mgr.validate_access_token(keep) is not None
        assert mgr.validate_access_token(drop) is None

    def test_revocation_recorded_by_jti(self):
        mgr = _mgr()
        import jwt

        token = mgr._create_jwt_token("claude-desktop", "wazuh:read", "access")
        jti = jwt.decode(token, _SECRET, algorithms=["HS256"])["jti"]
        mgr.revoke_token(token)
        assert jti in mgr.revoked_jtis


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
