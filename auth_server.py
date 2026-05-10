#!/usr/bin/env python3
"""
User Authentication Server
A multi-threaded TCP server for secure user authentication using socket programming.
"""

import socket
import threading
import json
import hashlib
import secrets
import logging
import os
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum

# Configuration
HOST = '0.0.0.0'
PORT = 9000
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 5
SESSION_TTL_MINUTES = 30
PBKDF2_ITERATIONS = 100000
DATA_DIR = Path(__file__).parent / 'data'

# Ensure data directory exists
DATA_DIR.mkdir(exist_ok=True)

# File paths
USERS_FILE = DATA_DIR / 'users.json'
SESSIONS_FILE = DATA_DIR / 'sessions.json'
LOG_FILE = DATA_DIR / 'auth.log'

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class AuthEvent(Enum):
    REGISTER = "REGISTER"
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILURE = "LOGIN_FAILURE"
    LOGOUT = "LOGOUT"
    ACCESS_GRANTED = "ACCESS_GRANTED"
    ACCESS_DENIED = "ACCESS_DENIED"
    ACCOUNT_LOCKED = "ACCOUNT_LOCKED"
    ACCOUNT_UNLOCKED = "ACCOUNT_UNLOCKED"


@dataclass
class User:
    username: str
    salt: str
    password_hash: str
    failed_attempts: int = 0
    locked_until: Optional[str] = None
    created_at: str = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now().isoformat()


@dataclass
class Session:
    token: str
    username: str
    issued_at: str
    expires_at: str
    client_ip: str


class DataStore:
    """Thread-safe data store for users and sessions."""
    
    def __init__(self):
        self.lock = threading.Lock()
        self.users: Dict[str, User] = {}
        self.sessions: Dict[str, Session] = {}
        self._users_mtime = 0
        self._sessions_mtime = 0
        self._load()
    
    def _load(self):
        """Load data from JSON files."""
        if USERS_FILE.exists():
            try:
                with open(USERS_FILE, 'r') as f:
                    users_data = json.load(f)
                    self.users = {k: User(**v) for k, v in users_data.items()}
                self._users_mtime = USERS_FILE.stat().st_mtime
            except Exception as e:
                logger.error(f"Error loading users: {e}")
        
        if SESSIONS_FILE.exists():
            try:
                with open(SESSIONS_FILE, 'r') as f:
                    sessions_data = json.load(f)
                    self.sessions = {k: Session(**v) for k, v in sessions_data.items()}
                    # Clean expired sessions on load
                    self._cleanup_expired_sessions()
                self._sessions_mtime = SESSIONS_FILE.stat().st_mtime
            except Exception as e:
                logger.error(f"Error loading sessions: {e}")
    
    def _check_and_reload(self):
        """Check if files were modified externally and reload if needed."""
        try:
            if USERS_FILE.exists():
                current_mtime = USERS_FILE.stat().st_mtime
                if current_mtime != self._users_mtime:
                    self._load()
                    logger.info("Reloaded users from disk (external modification detected)")
            
            if SESSIONS_FILE.exists():
                current_mtime = SESSIONS_FILE.stat().st_mtime
                if current_mtime != self._sessions_mtime:
                    self._load()
                    logger.info("Reloaded sessions from disk (external modification detected)")
        except Exception as e:
            logger.error(f"Error checking file modifications: {e}")
    
    def _save(self):
        """Save data to JSON files."""
        try:
            with open(USERS_FILE, 'w') as f:
                users_data = {k: asdict(v) for k, v in self.users.items()}
                json.dump(users_data, f, indent=2)
            
            with open(SESSIONS_FILE, 'w') as f:
                sessions_data = {k: asdict(v) for k, v in self.sessions.items()}
                json.dump(sessions_data, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving data: {e}")
    
    def _cleanup_expired_sessions(self):
        """Remove expired sessions."""
        now = datetime.now()
        expired = [
            token for token, session in self.sessions.items()
            if datetime.fromisoformat(session.expires_at) < now
        ]
        for token in expired:
            del self.sessions[token]
    
    def get_user(self, username: str) -> Optional[User]:
        with self.lock:
            self._check_and_reload()
            return self.users.get(username)
    
    def save_user(self, user: User):
        with self.lock:
            self.users[user.username] = user
            self._save()
    
    def get_session(self, token: str) -> Optional[Session]:
        with self.lock:
            self._check_and_reload()
            session = self.sessions.get(token)
            if session:
                if datetime.fromisoformat(session.expires_at) < datetime.now():
                    del self.sessions[token]
                    self._save()
                    return None
            return session
    
    def save_session(self, session: Session):
        with self.lock:
            self.sessions[session.token] = session
            self._save()
    
    def delete_session(self, token: str):
        with self.lock:
            if token in self.sessions:
                del self.sessions[token]
                self._save()
    
    def get_all_users(self) -> Dict[str, User]:
        with self.lock:
            self._check_and_reload()
            return dict(self.users)
    
    def get_all_sessions(self) -> Dict[str, Session]:
        with self.lock:
            self._check_and_reload()
            self._cleanup_expired_sessions()
            return dict(self.sessions)
    
    def unlock_account(self, username: str) -> bool:
        with self.lock:
            self._check_and_reload()
            user = self.users.get(username)
            if user and user.locked_until:
                user.locked_until = None
                user.failed_attempts = 0
                self._save()
                return True
            return False


class AuthManager:
    """Handles authentication logic."""
    
    def __init__(self, store: DataStore):
        self.store = store
    
    @staticmethod
    def hash_password(password: str, salt: str) -> str:
        """Hash password using PBKDF2-HMAC-SHA256."""
        return hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            PBKDF2_ITERATIONS
        ).hex()
    
    @staticmethod
    def generate_salt() -> str:
        """Generate random 16-byte salt."""
        return secrets.token_hex(16)
    
    @staticmethod
    def generate_token() -> str:
        """Generate 64-character session token."""
        return secrets.token_hex(32)
    
    def is_account_locked(self, user: User) -> bool:
        """Check if account is currently locked."""
        if user.locked_until:
            locked_until = datetime.fromisoformat(user.locked_until)
            if datetime.now() < locked_until:
                return True
            else:
                # Auto-unlock if lockout period has passed
                user.locked_until = None
                user.failed_attempts = 0
                self.store.save_user(user)
        return False
    
    def register(self, username: str, password: str) -> Tuple[bool, str]:
        """Register a new user."""
        if not username or not password:
            return False, "ERR:USERNAME_OR_PASSWORD_EMPTY"
        
        if self.store.get_user(username):
            return False, "ERR:USERNAME_EXISTS"
        
        salt = self.generate_salt()
        password_hash = self.hash_password(password, salt)
        
        user = User(
            username=username,
            salt=salt,
            password_hash=password_hash
        )
        self.store.save_user(user)
        logger.info(f"User registered: {username}")
        return True, "OK"
    
    def login(self, username: str, password: str, client_ip: str) -> Tuple[bool, str]:
        """Authenticate user and return session token."""
        user = self.store.get_user(username)
        
        if not user:
            logger.warning(f"Login attempt for non-existent user: {username} from {client_ip}")
            return False, "ERR:INVALID_CREDENTIALS"
        
        # Check if account is locked
        if self.is_account_locked(user):
            locked_until = datetime.fromisoformat(user.locked_until)
            remaining = (locked_until - datetime.now()).seconds // 60
            logger.warning(f"Login attempt on locked account: {username} from {client_ip}")
            return False, f"ERR:LOCKED:{remaining}"
        
        # Verify password
        attempted_hash = self.hash_password(password, user.salt)
        if attempted_hash != user.password_hash:
            # Increment failed attempts
            user.failed_attempts += 1
            
            if user.failed_attempts >= MAX_FAILED_ATTEMPTS:
                locked_until = datetime.now() + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
                user.locked_until = locked_until.isoformat()
                logger.warning(f"Account locked: {username} from {client_ip}")
                self.store.save_user(user)
                return False, f"ERR:LOCKED:{LOCKOUT_DURATION_MINUTES}"
            
            self.store.save_user(user)
            remaining_attempts = MAX_FAILED_ATTEMPTS - user.failed_attempts
            logger.warning(f"Failed login: {username} from {client_ip} ({user.failed_attempts} attempts)")
            return False, f"ERR:INVALID_CREDENTIALS:{remaining_attempts}"
        
        # Successful login - reset failed attempts and create session
        user.failed_attempts = 0
        user.locked_until = None
        self.store.save_user(user)
        
        # Generate session token
        token = self.generate_token()
        issued_at = datetime.now()
        expires_at = issued_at + timedelta(minutes=SESSION_TTL_MINUTES)
        
        session = Session(
            token=token,
            username=username,
            issued_at=issued_at.isoformat(),
            expires_at=expires_at.isoformat(),
            client_ip=client_ip
        )
        self.store.save_session(session)
        
        logger.info(f"Login successful: {username} from {client_ip}, token issued")
        return True, f"TOKEN:{token}"
    
    def validate_token(self, token: str) -> Tuple[bool, Optional[str]]:
        """Validate session token and return username if valid."""
        session = self.store.get_session(token)
        if not session:
            return False, None
        return True, session.username
    
    def access_resource(self, token: str, resource_id: str) -> Tuple[bool, str]:
        """Access a protected resource with token."""
        valid, username = self.validate_token(token)
        if not valid:
            return False, "ERR:INVALID_TOKEN"
        
        logger.info(f"Resource access: {resource_id} by {username}")
        return True, f"DATA:Access granted to {resource_id} for user {username}"
    
    def logout(self, token: str) -> Tuple[bool, str]:
        """Invalidate session token."""
        valid, username = self.validate_token(token)
        if not valid:
            return False, "ERR:INVALID_TOKEN"
        
        self.store.delete_session(token)
        logger.info(f"Logout: {username}")
        return True, "OK"
    
    def status(self, token: str) -> Tuple[bool, str]:
        """Check session status."""
        valid, username = self.validate_token(token)
        if not valid:
            return False, "ERR:INVALID_TOKEN"
        
        session = self.store.get_session(token)
        expires_at = datetime.fromisoformat(session.expires_at)
        remaining = (expires_at - datetime.now()).seconds // 60
        
        return True, f"ACTIVE:{username}:{remaining}"


class ClientHandler(threading.Thread):
    """Handle individual client connections."""
    
    def __init__(self, client_socket: socket.socket, client_address: Tuple[str, int], auth_manager: AuthManager):
        super().__init__(daemon=True)
        self.client_socket = client_socket
        self.client_address = client_address
        self.auth_manager = auth_manager
        self.running = True
    
    def send(self, message: str):
        """Send message to client."""
        try:
            self.client_socket.sendall((message + '\n').encode('utf-8'))
        except Exception as e:
            logger.error(f"Error sending to {self.client_address}: {e}")
    
    def run(self):
        """Main client handling loop."""
        client_ip = self.client_address[0]
        logger.info(f"Client connected: {self.client_address}")
        
        try:
            while self.running:
                # Receive data
                data = self.client_socket.recv(4096).decode('utf-8').strip()
                if not data:
                    break
                
                logger.debug(f"Received from {self.client_address}: {data}")
                
                # Parse command
                parts = data.split(maxsplit=2)
                if not parts:
                    self.send("ERR:COMMAND_EMPTY")
                    continue
                
                command = parts[0].upper()
                
                if command == "REGISTER":
                    if len(parts) != 3:
                        self.send("ERR:INVALID_FORMAT (REGISTER username password)")
                        continue
                    _, username, password = parts
                    success, message = self.auth_manager.register(username, password)
                    self.send(message)
                
                elif command == "LOGIN":
                    if len(parts) != 3:
                        self.send("ERR:INVALID_FORMAT (LOGIN username password)")
                        continue
                    _, username, password = parts
                    success, message = self.auth_manager.login(username, password, client_ip)
                    self.send(message)
                
                elif command == "ACCESS":
                    if len(parts) != 3:
                        self.send("ERR:INVALID_FORMAT (ACCESS token resource_id)")
                        continue
                    _, token, resource_id = parts
                    success, message = self.auth_manager.access_resource(token, resource_id)
                    self.send(message)
                
                elif command == "LOGOUT":
                    if len(parts) != 2:
                        self.send("ERR:INVALID_FORMAT (LOGOUT token)")
                        continue
                    _, token = parts
                    success, message = self.auth_manager.logout(token)
                    self.send(message)
                
                elif command == "STATUS":
                    if len(parts) != 2:
                        self.send("ERR:INVALID_FORMAT (STATUS token)")
                        continue
                    _, token = parts
                    success, message = self.auth_manager.status(token)
                    self.send(message)
                
                elif command == "QUIT":
                    self.send("OK:DISCONNECTING")
                    break
                
                else:
                    self.send("ERR:UNKNOWN_COMMAND")
        
        except Exception as e:
            logger.error(f"Error handling client {self.client_address}: {e}")
        
        finally:
            self.client_socket.close()
            logger.info(f"Client disconnected: {self.client_address}")


class AuthServer:
    """Main authentication server."""
    
    def __init__(self, host: str = HOST, port: int = PORT):
        self.host = host
        self.port = port
        self.store = DataStore()
        self.auth_manager = AuthManager(self.store)
        self.server_socket = None
        self.running = False
    
    def start(self):
        """Start the authentication server."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True
            
            logger.info(f"Auth Server started on {self.host}:{self.port}")
            
            while self.running:
                try:
                    self.server_socket.settimeout(1.0)
                    client_socket, client_address = self.server_socket.accept()
                    
                    # Create and start client handler
                    handler = ClientHandler(client_socket, client_address, self.auth_manager)
                    handler.start()
                
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        logger.error(f"Error accepting connection: {e}")
        
        except KeyboardInterrupt:
            logger.info("Server shutting down...")
        
        finally:
            self.stop()
    
    def stop(self):
        """Stop the server."""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        logger.info("Server stopped")


def main():
    server = AuthServer()
    server.start()


if __name__ == "__main__":
    main()
