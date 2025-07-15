"""Comprehensive tests for v3.0.0 OAuth 2.0 authentication system."""

import pytest
import asyncio
import time
import secrets
from unittest.mock import Mock, AsyncMock, patch
from typing import List, Dict, Any

import jwt
from passlib.context import CryptContext

from wazuh_mcp_server.auth.oauth2 import OAuth2Server, TokenManager, OAuth2Client
from wazuh_mcp_server.auth.models import (
    User, Client, Token, AuthorizationCode, AuthScope, GrantType, TokenType,
    TokenRequest, TokenResponse, ErrorResponse
)
from wazuh_mcp_server.auth.middleware import AuthMiddleware, AuthContext
from wazuh_mcp_server.utils.exceptions import (
    AuthenticationError, AuthorizationError, ValidationError
)


class TestTokenManager:
    """Test TokenManager functionality."""
    
    def test_token_manager_initialization(self):
        """Test token manager initialization."""
        token_manager = TokenManager()
        
        assert token_manager.secret_key is not None
        assert token_manager.algorithm == "HS256"
        assert hasattr(token_manager, '_private_key')
        assert hasattr(token_manager, '_public_key')
    
    def test_token_manager_with_custom_secret(self):
        """Test token manager with custom secret key."""
        custom_secret = "test-secret-key"
        token_manager = TokenManager(secret_key=custom_secret)
        
        assert token_manager.secret_key == custom_secret
    
    def test_create_access_token(self):
        """Test access token creation."""
        token_manager = TokenManager()
        
        user_id = "user123"
        client_id = "client456"
        scopes = [AuthScope.READ_ALERTS, AuthScope.READ_AGENTS]
        
        token = token_manager.create_access_token(user_id, client_id, scopes)
        
        assert isinstance(token, str)
        assert len(token) > 0
        
        # Verify token can be decoded
        payload = jwt.decode(token, token_manager.secret_key, algorithms=[token_manager.algorithm])
        assert payload["sub"] == user_id
        assert payload["client_id"] == client_id
        assert payload["token_type"] == "access_token"
        assert set(payload["scopes"]) == {scope.value for scope in scopes}
    
    def test_create_refresh_token(self):
        """Test refresh token creation."""
        token_manager = TokenManager()
        
        user_id = "user123"
        client_id = "client456"
        
        token = token_manager.create_refresh_token(user_id, client_id)
        
        assert isinstance(token, str)
        assert len(token) > 0
        
        # Verify token can be decoded
        payload = jwt.decode(token, token_manager.secret_key, algorithms=[token_manager.algorithm])
        assert payload["sub"] == user_id
        assert payload["client_id"] == client_id
        assert payload["token_type"] == "refresh_token"
    
    def test_verify_valid_token(self):
        """Test verification of valid token."""
        token_manager = TokenManager()
        
        user_id = "user123"
        client_id = "client456"
        scopes = [AuthScope.READ_ALERTS]
        
        token = token_manager.create_access_token(user_id, client_id, scopes)
        payload = token_manager.verify_token(token)
        
        assert payload["sub"] == user_id
        assert payload["client_id"] == client_id
        assert payload["scopes"] == [AuthScope.READ_ALERTS.value]
    
    def test_verify_expired_token(self):
        """Test verification of expired token."""
        token_manager = TokenManager()
        
        # Create token that expires immediately
        user_id = "user123"
        client_id = "client456"
        scopes = [AuthScope.READ_ALERTS]
        
        # Create token with very short expiry
        token = token_manager.create_access_token(user_id, client_id, scopes, expires_in=-1)
        
        with pytest.raises(AuthenticationError, match="Token has expired"):
            token_manager.verify_token(token)
    
    def test_verify_invalid_token(self):
        """Test verification of invalid token."""
        token_manager = TokenManager()
        
        invalid_token = "invalid.token.here"
        
        with pytest.raises(AuthenticationError, match="Invalid token"):
            token_manager.verify_token(invalid_token)
    
    def test_revoke_token(self):
        """Test token revocation."""
        token_manager = TokenManager()
        
        user_id = "user123"
        client_id = "client456"
        scopes = [AuthScope.READ_ALERTS]
        
        token = token_manager.create_access_token(user_id, client_id, scopes)
        
        # Token should be valid before revocation
        payload = token_manager.verify_token(token)
        assert payload is not None
        
        # Revoke token
        result = token_manager.revoke_token(token)
        assert result is True


class TestAuthModels:
    """Test authentication model classes."""
    
    def test_user_model_creation(self):
        """Test User model creation and methods."""
        user = User(
            username="testuser",
            email="test@example.com",
            scopes=[AuthScope.READ_ALERTS, AuthScope.READ_AGENTS]
        )
        
        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert user.is_active is True
        assert user.is_admin is False
        assert AuthScope.READ_ALERTS in user.scopes
        
        # Test scope checking
        assert user.has_scope(AuthScope.READ_ALERTS) is True
        assert user.has_scope(AuthScope.ADMIN_CONFIG) is False
        assert user.has_any_scope([AuthScope.READ_ALERTS, AuthScope.ADMIN_CONFIG]) is True
    
    def test_admin_user_scope_checking(self):
        """Test admin user has all scopes."""
        admin_user = User(
            username="admin",
            email="admin@example.com",
            is_admin=True
        )
        
        # Admin should have all scopes even if not explicitly set
        assert admin_user.has_scope(AuthScope.ADMIN_CONFIG) is True
        assert admin_user.has_scope(AuthScope.READ_ALERTS) is True
        assert admin_user.has_any_scope([AuthScope.WRITE_CONFIG]) is True
    
    def test_client_model_creation(self):
        """Test Client model creation and methods."""
        client = Client(
            name="Test Client",
            description="A test OAuth2 client",
            redirect_uris=["http://localhost:8080/callback"],
            grant_types=[GrantType.AUTHORIZATION_CODE],
            scopes=[AuthScope.READ_ALERTS]
        )
        
        assert client.name == "Test Client"
        assert client.validate_redirect_uri("http://localhost:8080/callback") is True
        assert client.validate_redirect_uri("http://malicious.com/callback") is False
        assert client.supports_grant_type(GrantType.AUTHORIZATION_CODE) is True
        assert client.supports_grant_type(GrantType.CLIENT_CREDENTIALS) is False
        assert client.has_scope(AuthScope.READ_ALERTS) is True
    
    def test_authorization_code_model(self):
        """Test AuthorizationCode model."""
        auth_code = AuthorizationCode(
            client_id="client123",
            user_id="user456",
            redirect_uri="http://localhost:8080/callback",
            scopes=[AuthScope.READ_ALERTS]
        )
        
        assert auth_code.is_valid is True
        assert auth_code.is_expired is False
        assert auth_code.used is False
        
        # Use the code
        auth_code.use()
        assert auth_code.used is True
        assert auth_code.is_valid is False
    
    def test_token_model(self):
        """Test Token model."""
        token = Token(
            token="test_token",
            token_type=TokenType.ACCESS_TOKEN,
            client_id="client123",
            user_id="user456",
            scopes=[AuthScope.READ_ALERTS],
            expires_at=time.time() + 3600  # 1 hour from now
        )
        
        assert token.is_valid is True
        assert token.is_expired is False
        assert token.revoked is False
        
        # Revoke token
        token.revoke()
        assert token.revoked is True
        assert token.is_valid is False


@pytest.mark.asyncio
class TestOAuth2Server:
    """Test OAuth2Server functionality."""
    
    async def test_oauth2_server_initialization(self):
        """Test OAuth2 server initialization."""
        token_manager = TokenManager()
        oauth2_server = OAuth2Server(token_manager)
        
        assert oauth2_server.token_manager == token_manager
        assert isinstance(oauth2_server.password_context, CryptContext)
        assert oauth2_server.users == {}
        assert oauth2_server.clients == {}
    
    async def test_create_user(self):
        """Test user creation."""
        token_manager = TokenManager()
        oauth2_server = OAuth2Server(token_manager)
        
        username = "testuser"
        email = "test@example.com"
        password = "secure_password123"
        scopes = [AuthScope.READ_ALERTS]
        
        user = await oauth2_server.create_user(username, email, password, scopes)
        
        assert user.username == username
        assert user.email == email
        assert user.scopes == scopes
        assert "password_hash" in user.metadata
        assert user.id in oauth2_server.users
    
    async def test_create_duplicate_user(self):
        """Test creation of duplicate user fails."""
        token_manager = TokenManager()
        oauth2_server = OAuth2Server(token_manager)
        
        username = "testuser"
        
        # Create first user
        await oauth2_server.create_user(username, "test1@example.com", "password1")
        
        # Attempt to create duplicate
        with pytest.raises(ValidationError, match="Username already exists"):
            await oauth2_server.create_user(username, "test2@example.com", "password2")
    
    async def test_create_client(self):
        """Test OAuth2 client creation."""
        token_manager = TokenManager()
        oauth2_server = OAuth2Server(token_manager)
        
        name = "Test Client"
        description = "A test client"
        redirect_uris = ["http://localhost:8080/callback"]
        scopes = [AuthScope.READ_ALERTS]
        
        client = await oauth2_server.create_client(name, description, redirect_uris, scopes=scopes)
        
        assert client.name == name
        assert client.description == description
        assert client.redirect_uris == redirect_uris
        assert client.scopes == scopes
        assert client.client_id in oauth2_server.clients
    
    async def test_authenticate_user_valid(self):
        """Test user authentication with valid credentials."""
        token_manager = TokenManager()
        oauth2_server = OAuth2Server(token_manager)
        
        username = "testuser"
        password = "secure_password123"
        
        # Create user
        await oauth2_server.create_user(username, "test@example.com", password)
        
        # Authenticate
        user = await oauth2_server.authenticate_user(username, password)
        
        assert user is not None
        assert user.username == username
        assert user.last_login is not None
    
    async def test_authenticate_user_invalid(self):
        """Test user authentication with invalid credentials."""
        token_manager = TokenManager()
        oauth2_server = OAuth2Server(token_manager)
        
        username = "testuser"
        password = "secure_password123"
        
        # Create user
        await oauth2_server.create_user(username, "test@example.com", password)
        
        # Try invalid password
        user = await oauth2_server.authenticate_user(username, "wrong_password")
        assert user is None
        
        # Try non-existent user
        user = await oauth2_server.authenticate_user("nonexistent", password)
        assert user is None
    
    async def test_validate_client(self):
        """Test client validation."""
        token_manager = TokenManager()
        oauth2_server = OAuth2Server(token_manager)
        
        # Create client
        client = await oauth2_server.create_client("Test Client")
        
        # Valid client
        validated_client = await oauth2_server.validate_client(client.client_id, client.client_secret)
        assert validated_client is not None
        assert validated_client.client_id == client.client_id
        
        # Invalid secret
        invalid_client = await oauth2_server.validate_client(client.client_id, "wrong_secret")
        assert invalid_client is None
        
        # Non-existent client
        invalid_client = await oauth2_server.validate_client("nonexistent", "secret")
        assert invalid_client is None
    
    async def test_authorization_code_flow(self):
        """Test complete authorization code flow."""
        token_manager = TokenManager()
        oauth2_server = OAuth2Server(token_manager)
        
        # Create user and client
        user = await oauth2_server.create_user("testuser", "test@example.com", "password")
        client = await oauth2_server.create_client(
            "Test Client",
            redirect_uris=["http://localhost:8080/callback"]
        )
        
        # Create authorization code
        redirect_uri = "http://localhost:8080/callback"
        scopes = [AuthScope.READ_ALERTS]
        
        code = await oauth2_server.create_authorization_code(
            client.client_id, user.id, redirect_uri, scopes
        )
        
        assert code is not None
        assert code in oauth2_server.authorization_codes
        
        # Exchange code for tokens
        access_token, refresh_token = await oauth2_server.exchange_code_for_tokens(
            code, client.client_id, redirect_uri
        )
        
        assert access_token is not None
        assert refresh_token is not None
        
        # Verify tokens
        access_payload = token_manager.verify_token(access_token)
        assert access_payload["sub"] == user.id
        assert access_payload["client_id"] == client.client_id
        
        refresh_payload = token_manager.verify_token(refresh_token)
        assert refresh_payload["sub"] == user.id
        assert refresh_payload["client_id"] == client.client_id
    
    async def test_refresh_token_flow(self):
        """Test refresh token flow."""
        token_manager = TokenManager()
        oauth2_server = OAuth2Server(token_manager)
        
        # Create user
        user = await oauth2_server.create_user("testuser", "test@example.com", "password")
        client_id = "test_client"
        
        # Create refresh token
        refresh_token = token_manager.create_refresh_token(user.id, client_id)
        
        # Use refresh token to get new access token
        new_access_token = await oauth2_server.refresh_access_token(refresh_token, client_id)
        
        assert new_access_token is not None
        
        # Verify new access token
        payload = token_manager.verify_token(new_access_token)
        assert payload["sub"] == user.id
        assert payload["client_id"] == client_id
    
    async def test_validate_token(self):
        """Test token validation."""
        token_manager = TokenManager()
        oauth2_server = OAuth2Server(token_manager)
        
        # Create user
        user = await oauth2_server.create_user("testuser", "test@example.com", "password")
        client_id = "test_client"
        scopes = [AuthScope.READ_ALERTS]
        
        # Create access token
        access_token = token_manager.create_access_token(user.id, client_id, scopes)
        
        # Validate token
        payload = await oauth2_server.validate_token(access_token)
        
        assert payload is not None
        assert payload["sub"] == user.id
        assert payload["client_id"] == client_id
    
    async def test_cleanup_expired_codes(self):
        """Test cleanup of expired authorization codes."""
        token_manager = TokenManager()
        oauth2_server = OAuth2Server(token_manager)
        
        # Create expired authorization code
        expired_code = AuthorizationCode(
            code="expired_code",
            client_id="client123",
            user_id="user456",
            redirect_uri="http://localhost",
            scopes=[AuthScope.READ_ALERTS],
            expires_at=time.time() - 1  # Already expired
        )
        
        oauth2_server.authorization_codes["expired_code"] = expired_code
        
        # Add valid code
        valid_code = AuthorizationCode(
            code="valid_code",
            client_id="client123",
            user_id="user456",
            redirect_uri="http://localhost",
            scopes=[AuthScope.READ_ALERTS]
        )
        
        oauth2_server.authorization_codes["valid_code"] = valid_code
        
        # Run cleanup
        await oauth2_server.cleanup_expired_codes()
        
        # Expired code should be removed, valid code should remain
        assert "expired_code" not in oauth2_server.authorization_codes
        assert "valid_code" in oauth2_server.authorization_codes


class TestAuthContext:
    """Test AuthContext functionality."""
    
    def test_auth_context_creation(self):
        """Test auth context creation."""
        user_id = "user123"
        client_id = "client456"
        scopes = [AuthScope.READ_ALERTS, AuthScope.READ_AGENTS]
        token_payload = {"sub": user_id, "client_id": client_id}
        
        context = AuthContext(user_id, client_id, scopes, token_payload)
        
        assert context.user_id == user_id
        assert context.client_id == client_id
        assert context.scopes == scopes
        assert context.token_payload == token_payload
        assert isinstance(context.authenticated_at, float)
    
    def test_scope_checking(self):
        """Test scope checking methods."""
        scopes = [AuthScope.READ_ALERTS, AuthScope.READ_AGENTS]
        context = AuthContext("user123", "client456", scopes, {})
        
        # Test has_scope
        assert context.has_scope(AuthScope.READ_ALERTS) is True
        assert context.has_scope(AuthScope.ADMIN_CONFIG) is False
        
        # Test has_any_scope
        assert context.has_any_scope([AuthScope.READ_ALERTS, AuthScope.ADMIN_CONFIG]) is True
        assert context.has_any_scope([AuthScope.ADMIN_CONFIG, AuthScope.WRITE_CONFIG]) is False
        
        # Test has_all_scopes
        assert context.has_all_scopes([AuthScope.READ_ALERTS, AuthScope.READ_AGENTS]) is True
        assert context.has_all_scopes([AuthScope.READ_ALERTS, AuthScope.ADMIN_CONFIG]) is False


@pytest.mark.asyncio
class TestAuthMiddleware:
    """Test AuthMiddleware functionality."""
    
    async def test_middleware_initialization(self):
        """Test middleware initialization."""
        token_manager = TokenManager()
        oauth2_server = OAuth2Server(token_manager)
        middleware = AuthMiddleware(oauth2_server)
        
        assert middleware.oauth2_server == oauth2_server
        assert "/health" in middleware.exclude_paths
        assert "/metrics" in middleware.exclude_paths
    
    async def test_skip_auth_for_excluded_paths(self):
        """Test authentication skip for excluded paths."""
        token_manager = TokenManager()
        oauth2_server = OAuth2Server(token_manager)
        middleware = AuthMiddleware(oauth2_server, exclude_paths=["/health", "/public"])
        
        # Mock request
        mock_request = Mock()
        mock_request.path = "/health"
        
        assert middleware._should_skip_auth(mock_request) is True
        
        mock_request.path = "/api/protected"
        assert middleware._should_skip_auth(mock_request) is False
    
    async def test_extract_bearer_token(self):
        """Test Bearer token extraction."""
        token_manager = TokenManager()
        oauth2_server = OAuth2Server(token_manager)
        middleware = AuthMiddleware(oauth2_server)
        
        # Create valid token
        user = await oauth2_server.create_user("testuser", "test@example.com", "password")
        access_token = token_manager.create_access_token(
            user.id, "client123", [AuthScope.READ_ALERTS]
        )
        
        # Mock request with valid token
        mock_request = Mock()
        mock_request.headers = {"Authorization": f"Bearer {access_token}"}
        
        auth_context = await middleware._authenticate_request(mock_request)
        
        assert auth_context is not None
        assert auth_context.user_id == user.id
        assert AuthScope.READ_ALERTS in auth_context.scopes
    
    async def test_invalid_authorization_header(self):
        """Test handling of invalid authorization headers."""
        token_manager = TokenManager()
        oauth2_server = OAuth2Server(token_manager)
        middleware = AuthMiddleware(oauth2_server)
        
        # Test missing header
        mock_request = Mock()
        mock_request.headers = {}
        
        auth_context = await middleware._authenticate_request(mock_request)
        assert auth_context is None
        
        # Test invalid format
        mock_request.headers = {"Authorization": "Invalid token"}
        auth_context = await middleware._authenticate_request(mock_request)
        assert auth_context is None
        
        # Test invalid token
        mock_request.headers = {"Authorization": "Bearer invalid.token.here"}
        auth_context = await middleware._authenticate_request(mock_request)
        assert auth_context is None


class TestOAuth2Client:
    """Test OAuth2Client functionality."""
    
    def test_client_initialization(self):
        """Test OAuth2 client initialization."""
        client_id = "test_client"
        client_secret = "test_secret"
        server_url = "https://auth.example.com"
        
        client = OAuth2Client(client_id, client_secret, server_url)
        
        assert client.client_id == client_id
        assert client.client_secret == client_secret
        assert client.server_url == "https://auth.example.com"
        assert client.access_token is None
    
    def test_authorization_url_generation(self):
        """Test authorization URL generation."""
        client = OAuth2Client("client123", "secret456", "https://auth.example.com")
        
        redirect_uri = "http://localhost:8080/callback"
        scopes = ["read:alerts", "read:agents"]
        state = "random_state_value"
        
        auth_url = client.get_authorization_url(redirect_uri, scopes, state)
        
        assert "https://auth.example.com/oauth/authorize" in auth_url
        assert "client_id=client123" in auth_url
        assert "redirect_uri=http%3A//localhost%3A8080/callback" in auth_url
        assert "scope=read%3Aalerts+read%3Aagents" in auth_url
        assert "state=random_state_value" in auth_url
    
    def test_token_validity_checking(self):
        """Test token validity checking."""
        client = OAuth2Client("client123", "secret456", "https://auth.example.com")
        
        # No token
        assert client.is_token_valid() is False
        
        # Token without expiry
        client.access_token = "some_token"
        assert client.is_token_valid() is False
        
        # Valid token
        client.token_expires_at = time.time() + 3600  # 1 hour from now
        assert client.is_token_valid() is True
        
        # Expired token
        client.token_expires_at = time.time() - 1  # 1 second ago
        assert client.is_token_valid() is False