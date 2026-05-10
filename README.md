# ShieldAuth - Enterprise Authentication System

A secure, multi-client authentication system with a premium, redesigned administrative interface.

**Team:** Hamza (23k-0060) | Muhammad Abbas (23k-0068)

## Project Overview

ShieldAuth implements a complete client-server authentication system with the following features:
- **Redesigned Admin UI**: Modern, SaaS-quality dashboard built with Tailwind CSS and Chart.js.
- **Multi-threaded TCP Server**: High-performance Python server handling concurrent socket connections.
- **Python TCP Client**: Interactive CLI with session persistence.
- **Enterprise Security**: PBKDF2-HMAC-SHA256 hashing (100k iterations) and secure session management.
- **Account Protection**: Automated lockout policy and real-time security auditing.

## Architecture

```
┌─────────────────┐         TCP Port 9000         ┌──────────────────┐
│  Python Client  │  ◄───────────────────────────►  │  Python Server   │
│   (CLI App)     │      Custom Text Protocol      │  (auth_server.py)│
└─────────────────┘                                └──────────────────┘
                                                             │
                                                             │ File-based
                                                             │ Shared State
                                                             ▼
                                                   ┌──────────────────┐
                                                   │  Data Store      │
                                                   │  (JSON/SQLite)   │
                                                   └──────────────────┘
                                                             │
                                                   ┌─────────┴─────────┐
                                                   ▼                   ▼
                                          ┌──────────┐        ┌──────────┐
                                          │  Users   │        │ Sessions │
                                          └──────────┘        └──────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                           Flask Admin UI (Port 5000)                       │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌──────────────────┐  │
│  │  Dashboard  │  │    Users    │  │  Sessions   │  │   Audit Log      │  │
│  │  (Summary)  │  │ (Register,  │  │  (View,     │  │  (View Events)   │  │
│  │             │  │   Unlock)   │  │   Revoke)   │  │                  │  │
│  └─────────────┘  └─────────────┘  └─────────────┘  └──────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Project Structure

```
cn project/
├── auth_server.py              # Python TCP authentication server
├── auth_client.py            # Python TCP client
├── flask_admin/
│   ├── app.py                  # Flask admin application (with custom filters)
│   ├── static/                 # Modern UI assets
│   │   ├── css/style.css       # Custom glassmorphism & dark theme styles
│   │   ├── js/main.js          # Interactive UI logic & notifications
│   │   └── img/                # UI images and icons
│   └── templates/              # Redesigned Jinja2 templates
│       ├── base.html           # Modern sidebar-based layout
│       ├── login.html          # Sleek security sign-in
│       ├── dashboard.html      # Analytics & activity graphs
│       ├── users.html          # Searchable user records
│       ├── sessions.html       # Real-time session monitor
│       └── audit.html          # Immutable timeline logs
├── tests/
│   └── test_auth.py           # pytest test suite
├── data/                       # Runtime data files (created automatically)
│   ├── users.json
│   ├── sessions.json
│   └── auth.log
├── requirements.txt            # Python dependencies
├── README.md                   # This file
└── cn proposal.txt            # Original project proposal
```

## Quick Start

### Prerequisites

- Python 3.11 or higher
- pip (Python package manager)

### 1. Install Python Dependencies

```bash
pip install -r requirements.txt
```

### 2. Start the Authentication Server

```bash
python auth_server.py
```

The server will start on port 9000. You'll see:
```
Auth Server started on 0.0.0.0:9000
```

### 3. Start the Flask Admin Interface

In a new terminal:

```bash
cd flask_admin
python app.py
```

The admin UI will be available at `http://localhost:5000`

Default password: `admin123` (change in production!)

### 4. Run the Python Client

In a new terminal:
```powershell
# Set encoding to UTF-8 for modern UI symbols
$env:PYTHONIOENCODING="utf-8"
python auth_client.py
```

Or with custom server address:
```powershell
$env:PYTHONIOENCODING="utf-8"
python auth_client.py --host localhost --port 9000
```

## Protocol Specification

The client and server communicate using a simple text-based protocol over TCP.

### Commands

| Command | Format | Response |
|---------|--------|----------|
| REGISTER | `REGISTER username password` | `OK` or `ERR:USERNAME_EXISTS` |
| LOGIN | `LOGIN username password` | `TOKEN:<token>` or `ERR:INVALID_CREDENTIALS` or `ERR:LOCKED:<minutes>` |
| ACCESS | `ACCESS token resource_id` | `DATA:<message>` or `ERR:INVALID_TOKEN` |
| STATUS | `STATUS token` | `ACTIVE:<username>:<minutes>` or `ERR:INVALID_TOKEN` |
| LOGOUT | `LOGOUT token` | `OK` or `ERR:INVALID_TOKEN` |
| QUIT | `QUIT` | `OK:DISCONNECTING` |

## Security Features

### Password Hashing
- Algorithm: PBKDF2-HMAC-SHA256
- Iterations: 100,000
- Salt: 16-byte random per user
- No plain-text password storage

### Session Management
- Tokens: 32-byte cryptographically random (64 hex characters)
- Session TTL: 30 minutes
- Automatic expiry cleanup
- Manual revocation support via admin UI

### Account Lockout
- Max failed attempts: 5
- Lockout duration: 5 minutes
- Automatic unlock after timeout
- Manual unlock via ShieldAuth Admin UI

## ShieldAuth Admin Interface (New)

The admin interface has been completely redesigned for a premium, enterprise experience:
- **Dark Mode Architecture**: Deep navy palette (`#0f172a`) optimized for long-term monitoring.
- **Glassmorphism UI**: Backdrop blur effects and translucent borders for a high-fidelity feel.
- **Real-time Analytics**: Interactive activity charts powered by **Chart.js**.
- **System Health Indicators**: Live server status pulses and synchronized system clock.
- **Identity Avatars**: Automatically generated identity markers for all users.
- **Toast Notifications**: Instant feedback for administrative actions.
- **Responsive Design**: Seamless experience across mobile, tablet, and desktop.

## Testing

Run the test suite:

```bash
pytest tests/test_auth.py -v
```

The tests cover:
- Password hashing (consistency, uniqueness)
- Token generation
- User registration
- Login/authentication
- Account lockout policy
- Session management
- Data persistence

## API Reference

### AuthManager Class

```python
from auth_server import AuthManager, DataStore

store = DataStore()
auth = AuthManager(store)

# Register a user
success, message = auth.register("username", "password")

# Login
success, message = auth.login("username", "password", "client_ip")
# Returns: (True, "TOKEN:<token>") or (False, "ERR:...")

# Validate token
is_valid, username = auth.validate_token(token)

# Access resource
success, message = auth.access_resource(token, "resource_id")

# Logout
success, message = auth.logout(token)
```

### DataStore Class

```python
from auth_server import DataStore

store = DataStore()

# Get user
user = store.get_user("username")

# Get session
session = store.get_session("token")

# Get all users/sessions
users = store.get_all_users()
sessions = store.get_all_sessions()

# Unlock account
success = store.unlock_account("username")
```

## Configuration

Configuration is done via environment variables or constants in `auth_server.py`:

| Variable | Default | Description |
|----------|---------|-------------|
| `HOST` | `0.0.0.0` | Server bind address |
| `PORT` | `9000` | Server port |
| `MAX_FAILED_ATTEMPTS` | `5` | Failed logins before lockout |
| `LOCKOUT_DURATION_MINUTES` | `5` | Account lockout duration |
| `SESSION_TTL_MINUTES` | `30` | Session token lifetime |
| `PBKDF2_ITERATIONS` | `100000` | Password hashing iterations |
| `ADMIN_PASSWORD` | `admin123` | Flask admin password |

## Running the Complete System

1. **Terminal 1** - Start the auth server:
   ```bash
   python auth_server.py
   ```

2. **Terminal 2** - Start the admin UI:
   ```bash
   cd flask_admin
   python app.py
   ```

3. **Terminal 3** - Run Python client:
   ```bash
   python auth_client.py
   ```

4. **Browser** - Access admin dashboard:
   - URL: `http://localhost:5000`
   - Password: `admin123`

## Troubleshooting

### Port Already in Use
```bash
# Find and kill process using port 9000 (Windows)
netstat -ano | findstr :9000
taskkill /PID <PID> /F

# For port 5000
netstat -ano | findstr :5000
taskkill /PID <PID> /F
```

### Python Dependencies
```bash
pip install --upgrade -r requirements.txt
```

## Team Responsibilities

- **Hamza (23k-0060)**: Python TCP server, security layer, unit tests, documentation
- **Muhammad Abbas (23k-0068)**: Python TCP client, Flask admin interface, integration testing

## Deliverables

✅ `auth_server.py` - Python TCP authentication server
✅ `auth_client.py` - Python TCP client
✅ `flask_admin/app.py` - Flask admin with custom Jinja filters
✅ `flask_admin/static/` - Redesigned CSS/JS and UI assets
✅ `flask_admin/templates/` - Modernized glassmorphism templates
✅ `tests/` - pytest test suite
✅ `README.md` - This documentation
✅ `requirements.txt` - Python dependencies
✅ `cn proposal.txt` - Project proposal

## License

This project is for educational purposes (Networks Programming course).
