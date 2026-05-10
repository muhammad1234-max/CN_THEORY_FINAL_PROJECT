#!/usr/bin/env python3
"""
Pytest test suite for Authentication Server
Tests credential hashing, token generation, lockout logic, and protocol parsing.
"""

import sys
import json
import time
import pytest
from pathlib import Path
from datetime import datetime, timedelta

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from auth_server import (
    AuthManager, DataStore, User, Session,
    PBKDF2_ITERATIONS, MAX_FAILED_ATTEMPTS, LOCKOUT_DURATION_MINUTES, SESSION_TTL_MINUTES
)


class TestPasswordHashing:
    """Test password hashing functionality."""
    
    def test_hash_password_consistency(self):
        """Test that same password and salt produce same hash."""
        password = "testpassword123"
        salt = AuthManager.generate_salt()
        
        hash1 = AuthManager.hash_password(password, salt)
        hash2 = AuthManager.hash_password(password, salt)
        
        assert hash1 == hash2, "Hash should be consistent for same password and salt"
    
    def test_hash_password_different_salts(self):
        """Test that different salts produce different hashes."""
        password = "testpassword123"
        salt1 = AuthManager.generate_salt()
        salt2 = AuthManager.generate_salt()
        
        hash1 = AuthManager.hash_password(password, salt1)
        hash2 = AuthManager.hash_password(password, salt2)
        
        assert hash1 != hash2, "Different salts should produce different hashes"
    
    def test_hash_password_different_passwords(self):
        """Test that different passwords produce different hashes."""
        password1 = "testpassword123"
        password2 = "differentpassword456"
        salt = AuthManager.generate_salt()
        
        hash1 = AuthManager.hash_password(password1, salt)
        hash2 = AuthManager.hash_password(password2, salt)
        
        assert hash1 != hash2, "Different passwords should produce different hashes"
    
    def test_salt_generation_unique(self):
        """Test that generated salts are unique."""
        salts = [AuthManager.generate_salt() for _ in range(100)]
        assert len(set(salts)) == 100, "Generated salts should be unique"
    
    def test_salt_length(self):
        """Test that generated salt has correct length (32 hex chars = 16 bytes)."""
        salt = AuthManager.generate_salt()
        assert len(salt) == 32, "Salt should be 32 hex characters"


class TestTokenGeneration:
    """Test session token generation."""
    
    def test_token_length(self):
        """Test that generated token has correct length (64 hex chars = 32 bytes)."""
        token = AuthManager.generate_token()
        assert len(token) == 64, "Token should be 64 hex characters"
    
    def test_token_unique(self):
        """Test that generated tokens are unique."""
        tokens = [AuthManager.generate_token() for _ in range(100)]
        assert len(set(tokens)) == 100, "Generated tokens should be unique"
    
    def test_token_format(self):
        """Test that token contains only hex characters."""
        token = AuthManager.generate_token()
        assert all(c in '0123456789abcdef' for c in token), "Token should only contain hex characters"


class TestRegistration:
    """Test user registration functionality."""
    
    @pytest.fixture
    def temp_data_dir(self, tmp_path):
        """Create temporary data directory for testing."""
        import auth_server
        original_data_dir = auth_server.DATA_DIR
        auth_server.DATA_DIR = tmp_path
        auth_server.USERS_FILE = tmp_path / 'users.json'
        auth_server.SESSIONS_FILE = tmp_path / 'sessions.json'
        auth_server.LOG_FILE = tmp_path / 'auth.log'
        yield tmp_path
        auth_server.DATA_DIR = original_data_dir
    
    def test_successful_registration(self, temp_data_dir):
        """Test successful user registration."""
        store = DataStore()
        auth_manager = AuthManager(store)
        
        success, message = auth_manager.register("testuser", "testpassword123")
        
        assert success is True, f"Registration should succeed: {message}"
        assert message == "OK"
        
        # Verify user was created
        user = store.get_user("testuser")
        assert user is not None, "User should exist after registration"
        assert user.username == "testuser"
        assert user.salt is not None
        assert user.password_hash is not None
    
    def test_registration_duplicate_username(self, temp_data_dir):
        """Test registration with duplicate username fails."""
        store = DataStore()
        auth_manager = AuthManager(store)
        
        # Register first user
        auth_manager.register("testuser", "password123")
        
        # Try to register again with same username
        success, message = auth_manager.register("testuser", "differentpassword")
        
        assert success is False, "Registration with duplicate username should fail"
        assert "USERNAME_EXISTS" in message
    
    def test_registration_empty_username(self, temp_data_dir):
        """Test registration with empty username fails."""
        store = DataStore()
        auth_manager = AuthManager(store)
        
        success, message = auth_manager.register("", "password123")
        
        assert success is False, "Registration with empty username should fail"
    
    def test_registration_empty_password(self, temp_data_dir):
        """Test registration with empty password fails."""
        store = DataStore()
        auth_manager = AuthManager(store)
        
        success, message = auth_manager.register("testuser", "")
        
        assert success is False, "Registration with empty password should fail"


class TestLogin:
    """Test login functionality."""
    
    @pytest.fixture
    def temp_data_dir(self, tmp_path):
        """Create temporary data directory with a registered user."""
        import auth_server
        original_data_dir = auth_server.DATA_DIR
        auth_server.DATA_DIR = tmp_path
        auth_server.USERS_FILE = tmp_path / 'users.json'
        auth_server.SESSIONS_FILE = tmp_path / 'sessions.json'
        auth_server.LOG_FILE = tmp_path / 'auth.log'
        
        # Create a user
        store = DataStore()
        auth_manager = AuthManager(store)
        auth_manager.register("testuser", "correctpassword")
        
        yield tmp_path
        auth_server.DATA_DIR = original_data_dir
    
    def test_successful_login(self, temp_data_dir):
        """Test successful login returns token."""
        store = DataStore()
        auth_manager = AuthManager(store)
        
        success, message = auth_manager.login("testuser", "correctpassword", "127.0.0.1")
        
        assert success is True, f"Login should succeed: {message}"
        assert message.startswith("TOKEN:"), "Message should contain session token"
        
        token = message[6:]  # Remove "TOKEN:" prefix
        assert len(token) == 64, "Token should be 64 characters"
    
    def test_login_wrong_password(self, temp_data_dir):
        """Test login with wrong password fails."""
        store = DataStore()
        auth_manager = AuthManager(store)
        
        success, message = auth_manager.login("testuser", "wrongpassword", "127.0.0.1")
        
        assert success is False, "Login with wrong password should fail"
        assert "INVALID_CREDENTIALS" in message
    
    def test_login_nonexistent_user(self, temp_data_dir):
        """Test login with non-existent user fails."""
        store = DataStore()
        auth_manager = AuthManager(store)
        
        success, message = auth_manager.login("nonexistent", "password", "127.0.0.1")
        
        assert success is False, "Login for non-existent user should fail"
        assert "INVALID_CREDENTIALS" in message


class TestAccountLockout:
    """Test account lockout functionality."""
    
    @pytest.fixture
    def temp_data_dir(self, tmp_path):
        """Create temporary data directory with a registered user."""
        import auth_server
        original_data_dir = auth_server.DATA_DIR
        auth_server.DATA_DIR = tmp_path
        auth_server.USERS_FILE = tmp_path / 'users.json'
        auth_server.SESSIONS_FILE = tmp_path / 'sessions.json'
        auth_server.LOG_FILE = tmp_path / 'auth.log'
        
        # Create a user
        store = DataStore()
        auth_manager = AuthManager(store)
        auth_manager.register("locktestuser", "correctpassword")
        
        yield tmp_path
        auth_server.DATA_DIR = original_data_dir
    
    def test_account_lockout_after_max_attempts(self, temp_data_dir):
        """Test account locks after max failed attempts."""
        store = DataStore()
        auth_manager = AuthManager(store)
        
        # Make MAX_FAILED_ATTEMPTS failed login attempts
        for i in range(MAX_FAILED_ATTEMPTS):
            success, message = auth_manager.login("locktestuser", "wrongpassword", "127.0.0.1")
            assert success is False, f"Attempt {i+1} should fail"
            assert "INVALID_CREDENTIALS" in message or "LOCKED" in message
        
        # Next attempt should indicate account is locked
        success, message = auth_manager.login("locktestuser", "correctpassword", "127.0.0.1")
        assert success is False, "Login should fail when account is locked"
        assert "LOCKED" in message, f"Message should indicate lockout: {message}"
    
    def test_account_lockout_resets_on_success(self, temp_data_dir):
        """Test that failed attempts reset on successful login."""
        store = DataStore()
        auth_manager = AuthManager(store)
        
        # Make some failed attempts
        for _ in range(3):
            auth_manager.login("locktestuser", "wrongpassword", "127.0.0.1")
        
        user = store.get_user("locktestuser")
        assert user.failed_attempts == 3, "Failed attempts should be 3"
        
        # Successful login should reset counter
        auth_manager.login("locktestuser", "correctpassword", "127.0.0.1")
        
        user = store.get_user("locktestuser")
        assert user.failed_attempts == 0, "Failed attempts should reset after successful login"
    
    def test_manual_account_unlock(self, temp_data_dir):
        """Test manual account unlock via data store."""
        store = DataStore()
        auth_manager = AuthManager(store)
        
        # Lock the account
        for _ in range(MAX_FAILED_ATTEMPTS):
            auth_manager.login("locktestuser", "wrongpassword", "127.0.0.1")
        
        # Verify account is locked
        success, message = auth_manager.login("locktestuser", "correctpassword", "127.0.0.1")
        assert "LOCKED" in message
        
        # Manually unlock
        unlock_success = store.unlock_account("locktestuser")
        assert unlock_success is True, "Unlock should succeed"
        
        # Login should work now
        success, message = auth_manager.login("locktestuser", "correctpassword", "127.0.0.1")
        assert success is True, f"Login should succeed after unlock: {message}"


class TestSessionManagement:
    """Test session token lifecycle."""
    
    @pytest.fixture
    def temp_data_dir(self, tmp_path):
        """Create temporary data directory with logged in user."""
        import auth_server
        original_data_dir = auth_server.DATA_DIR
        auth_server.DATA_DIR = tmp_path
        auth_server.USERS_FILE = tmp_path / 'users.json'
        auth_server.SESSIONS_FILE = tmp_path / 'sessions.json'
        auth_server.LOG_FILE = tmp_path / 'auth.log'
        
        # Create a user and login
        store = DataStore()
        auth_manager = AuthManager(store)
        auth_manager.register("sessionuser", "password123")
        success, message = auth_manager.login("sessionuser", "password123", "127.0.0.1")
        token = message[6:]  # Remove "TOKEN:" prefix
        
        yield tmp_path, auth_manager, token
        auth_server.DATA_DIR = original_data_dir
    
    def test_valid_token_access(self, temp_data_dir):
        """Test that valid token allows resource access."""
        tmp_path, auth_manager, token = temp_data_dir
        
        success, message = auth_manager.access_resource(token, "resource1")
        
        assert success is True, f"Access should be granted: {message}"
        assert "DATA:" in message
        assert "resource1" in message
    
    def test_invalid_token_rejected(self, temp_data_dir):
        """Test that invalid token is rejected."""
        tmp_path, auth_manager, token = temp_data_dir
        
        success, message = auth_manager.access_resource("invalidtoken123", "resource1")
        
        assert success is False, "Access should be denied with invalid token"
        assert "INVALID_TOKEN" in message
    
    def test_logout_invalidates_token(self, temp_data_dir):
        """Test that logout invalidates the token."""
        tmp_path, auth_manager, token = temp_data_dir
        
        # Logout
        success, message = auth_manager.logout(token)
        assert success is True, "Logout should succeed"
        
        # Try to access resource with invalidated token
        success, message = auth_manager.access_resource(token, "resource1")
        assert success is False, "Access should be denied after logout"
        assert "INVALID_TOKEN" in message
    
    def test_session_status_check(self, temp_data_dir):
        """Test session status check."""
        tmp_path, auth_manager, token = temp_data_dir
        
        success, message = auth_manager.status(token)
        
        assert success is True, f"Status check should succeed: {message}"
        assert "ACTIVE:" in message
        assert "sessionuser" in message


class TestDataStore:
    """Test DataStore functionality."""
    
    @pytest.fixture
    def temp_data_dir(self, tmp_path):
        """Create temporary data directory."""
        import auth_server
        original_data_dir = auth_server.DATA_DIR
        auth_server.DATA_DIR = tmp_path
        auth_server.USERS_FILE = tmp_path / 'users.json'
        auth_server.SESSIONS_FILE = tmp_path / 'sessions.json'
        auth_server.LOG_FILE = tmp_path / 'auth.log'
        
        yield tmp_path
        auth_server.DATA_DIR = original_data_dir
    
    def test_user_persistence(self, temp_data_dir):
        """Test that users are persisted to disk."""
        store1 = DataStore()
        user = User(
            username="persistuser",
            salt="testsalt123",
            password_hash="testhash456"
        )
        store1.save_user(user)
        
        # Create new DataStore instance (simulating server restart)
        store2 = DataStore()
        loaded_user = store2.get_user("persistuser")
        
        assert loaded_user is not None, "User should be persisted"
        assert loaded_user.username == "persistuser"
        assert loaded_user.salt == "testsalt123"
    
    def test_session_persistence(self, temp_data_dir):
        """Test that sessions are persisted to disk."""
        store1 = DataStore()
        session = Session(
            token="testtoken123",
            username="testuser",
            issued_at=datetime.now().isoformat(),
            expires_at=(datetime.now() + timedelta(hours=1)).isoformat(),
            client_ip="127.0.0.1"
        )
        store1.save_session(session)
        
        # Create new DataStore instance
        store2 = DataStore()
        loaded_session = store2.get_session("testtoken123")
        
        assert loaded_session is not None, "Session should be persisted"
        assert loaded_session.username == "testuser"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
