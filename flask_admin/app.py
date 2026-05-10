#!/usr/bin/env python3
"""
Flask Admin Interface for Auth Server
Web-based administration dashboard for managing users, sessions, and viewing audit logs.
"""

import os
import sys
import json
from datetime import datetime
from pathlib import Path
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session as flask_session

# Add parent directory to path to import auth_server
sys.path.insert(0, str(Path(__file__).parent.parent))

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')

# Custom Jinja Filters
@app.template_filter('hash')
def hash_filter(s):
    import hashlib
    return hashlib.md5(str(s).encode()).hexdigest()

# Configuration
DATA_DIR = Path(__file__).parent.parent / 'data'
USERS_FILE = DATA_DIR / 'users.json'
SESSIONS_FILE = DATA_DIR / 'sessions.json'
LOG_FILE = DATA_DIR / 'auth.log'
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'admin123')  # Change in production!


def login_required(f):
    """Decorator to require admin login."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not flask_session.get('admin_logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def load_users():
    """Load users from JSON file."""
    if USERS_FILE.exists():
        try:
            with open(USERS_FILE, 'r') as f:
                return json.load(f)
        except Exception as e:
            app.logger.error(f"Error loading users: {e}")
    return {}


def load_sessions():
    """Load active sessions from JSON file."""
    if SESSIONS_FILE.exists():
        try:
            with open(SESSIONS_FILE, 'r') as f:
                sessions = json.load(f)
                # Filter out expired sessions
                now = datetime.now()
                valid_sessions = {}
                for token, sess in sessions.items():
                    expires_at = datetime.fromisoformat(sess['expires_at'])
                    if expires_at > now:
                        valid_sessions[token] = sess
                return valid_sessions
        except Exception as e:
            app.logger.error(f"Error loading sessions: {e}")
    return {}


def load_audit_log(limit=100):
    """Load recent audit log entries."""
    if LOG_FILE.exists():
        try:
            with open(LOG_FILE, 'r') as f:
                lines = f.readlines()
                return lines[-limit:] if len(lines) > limit else lines
        except Exception as e:
            app.logger.error(f"Error loading audit log: {e}")
    return []


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Admin login page."""
    if request.method == 'POST':
        password = request.form.get('password', '')
        if password == ADMIN_PASSWORD:
            flask_session['admin_logged_in'] = True
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid password', 'error')
    return render_template('login.html')


@app.route('/logout')
def logout():
    """Admin logout."""
    flask_session.pop('admin_logged_in', None)
    flash('Logged out successfully', 'info')
    return redirect(url_for('login'))


@app.route('/')
@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard with summary."""
    users = load_users()
    sessions = load_sessions()
    log_entries = load_audit_log(10)
    
    # Calculate statistics
    total_users = len(users)
    active_sessions = len(sessions)
    locked_accounts = sum(1 for u in users.values() if u.get('locked_until'))
    
    # Count recent failed logins from log
    recent_failures = 0
    for entry in log_entries:
        if 'LOGIN_FAILURE' in entry or 'ACCOUNT_LOCKED' in entry:
            recent_failures += 1
    
    stats = {
        'total_users': total_users,
        'active_sessions': active_sessions,
        'locked_accounts': locked_accounts,
        'recent_failures': recent_failures
    }
    
    return render_template('dashboard.html', stats=stats, log_entries=log_entries)


@app.route('/users')
@login_required
def users():
    """List all users."""
    users_data = load_users()
    now = datetime.now()
    
    user_list = []
    for username, data in users_data.items():
        locked_until = data.get('locked_until')
        is_locked = False
        if locked_until:
            locked_time = datetime.fromisoformat(locked_until)
            is_locked = locked_time > now
        
        status = 'Locked' if is_locked else 'Active'
        if data.get('failed_attempts', 0) > 0 and not is_locked:
            status = f"Warning ({data['failed_attempts']} fails)"
        
        user_list.append({
            'username': username,
            'created_at': data.get('created_at', 'Unknown'),
            'status': status,
            'failed_attempts': data.get('failed_attempts', 0),
            'locked_until': locked_until if is_locked else None
        })
    
    return render_template('users.html', users=user_list)


@app.route('/users/register', methods=['POST'])
@login_required
def register_user():
    """Register a new user via admin interface."""
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '').strip()
    
    if not username or not password:
        flash('Username and password are required', 'error')
        return redirect(url_for('users'))
    
    # Import auth_server to use the same logic
    import auth_server
    
    store = auth_server.DataStore()
    auth_manager = auth_server.AuthManager(store)
    
    success, message = auth_manager.register(username, password)
    
    if success:
        flash(f'User {username} registered successfully', 'success')
    else:
        flash(f'Registration failed: {message}', 'error')
    
    return redirect(url_for('users'))


@app.route('/users/<username>/unlock', methods=['POST'])
@login_required
def unlock_user(username):
    """Manually unlock a locked account."""
    import auth_server
    
    store = auth_server.DataStore()
    success = store.unlock_account(username)
    
    if success:
        flash(f'Account {username} unlocked successfully', 'success')
    else:
        flash(f'Failed to unlock account {username} (may not be locked)', 'error')
    
    return redirect(url_for('users'))


@app.route('/sessions')
@login_required
def sessions():
    """List all active sessions."""
    sessions_data = load_sessions()
    now = datetime.now()
    
    session_list = []
    for token, data in sessions_data.items():
        expires_at = datetime.fromisoformat(data['expires_at'])
        minutes_remaining = (expires_at - now).seconds // 60
        
        session_list.append({
            'token': token[:16] + '...',  # Show only first 16 chars
            'full_token': token,
            'username': data.get('username', 'Unknown'),
            'client_ip': data.get('client_ip', 'Unknown'),
            'issued_at': data.get('issued_at', 'Unknown'),
            'expires_at': data.get('expires_at', 'Unknown'),
            'minutes_remaining': minutes_remaining
        })
    
    return render_template('sessions.html', sessions=session_list)


@app.route('/sessions/<token>/revoke', methods=['POST'])
@login_required
def revoke_session(token):
    """Revoke (invalidate) a specific session."""
    import auth_server
    
    store = auth_server.DataStore()
    store.delete_session(token)
    
    flash('Session revoked successfully', 'success')
    return redirect(url_for('sessions'))


@app.route('/audit')
@login_required
def audit():
    """View audit log."""
    page = request.args.get('page', 1, type=int)
    per_page = 50
    
    all_entries = load_audit_log(1000)  # Load more for pagination
    total_entries = len(all_entries)
    
    # Simple pagination
    start = (page - 1) * per_page
    end = start + per_page
    entries = all_entries[start:end]
    
    total_pages = (total_entries + per_page - 1) // per_page
    
    # Parse entries for display
    parsed_entries = []
    for entry in entries:
        parsed_entries.append({
            'raw': entry.strip()
        })
    
    return render_template('audit.html', 
                          entries=parsed_entries, 
                          page=page, 
                          total_pages=total_pages,
                          has_prev=page > 1,
                          has_next=page < total_pages)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
