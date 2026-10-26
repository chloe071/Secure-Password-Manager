# Secure Password Manager

![tests](https://github.com/chloe071/Secure-Password-Manager/actions/workflows/tests.yml/badge.svg)

A Flask password vault that encrypts every saved password with AES-256-GCM using a key derived from the user's master password. It includes optional TOTP two-factor authentication, rate limiting, CSRF protection, a secure password generator, and audit logging.

## Features

- **Encrypted vault**: add, edit, delete, search, and filter saved logins by category
- **Show / copy** passwords on demand; copied passwords are cleared from the clipboard after 30 seconds
- **Password generator** (8–64 characters, optional symbols) using Python's `secrets` module
- **Strength meter** while typing a password
- **Two-factor authentication** (TOTP) with QR-code setup for apps like Google Authenticator
- **Encrypted export** to CSV (ciphertext only)
- **Audit log** of logins, failed logins, MFA events, and vault changes

## How the Encryption Works

```text
master password ──► PBKDF2-HMAC-SHA256 (600,000 iterations, per-user salt) ──► 256-bit key
                                                                                    │
saved password ──► AES-256-GCM (random 96-bit nonce per item, owner ID as AAD) ◄─────┘
                                     │
                                     ▼
                     ciphertext + nonce stored in SQLite
```

- The master password is checked against a salted hash (Werkzeug) and **never stored**.
- After login, the derived key is held **only in server memory**, referenced by a random token in the session. Logging out or restarting the server erases it.
- Each item gets a new random nonce, and ciphertext is bound to its owner (AAD), so encrypted rows can't be swapped between accounts.

## Security Controls

| Threat | Control |
|---|---|
| Stolen database | Passwords are AES-GCM ciphertext; master passwords are salted hashes |
| Brute-force login | 5 login attempts per minute per IP; 6 MFA attempts per minute |
| Stolen password | Optional TOTP MFA; MFA is enabled only after the user confirms a valid code |
| Accessing other users' items | Every item route checks ownership and returns 404 otherwise |
| CSRF | Flask-WTF CSRF tokens on all forms and AJAX requests |
| XSS / clickjacking | Jinja auto-escaping, strict Content-Security-Policy (no inline scripts), `X-Frame-Options: DENY` |
| Session theft | `HttpOnly` and `SameSite=Lax` cookies; `Secure` flag available via env var |
| Cached secrets | `Cache-Control: no-store` on every response |
| Weak generated passwords | `secrets` module (cryptographically secure), guaranteed character variety |

## Setup

```bash
git clone https://github.com/chloe071/Secure-Password-Manager.git
cd Secure-Password-Manager
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
export FLASK_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
python app.py
```

Open http://127.0.0.1:5000, create an account (master password must be 12+ characters), and start adding items. Enable MFA from the navigation bar.

### Optional environment variables

| Variable | Purpose | Default |
|---|---|---|
| `FLASK_SECRET_KEY` | Signs session cookies | Random per start |
| `DATABASE_URL` | Database location | `sqlite:///vault.db` |
| `SESSION_COOKIE_SECURE` | Set to `1` when serving over HTTPS | Off |
| `RATELIMIT_STORAGE_URI` | e.g. `redis://localhost:6379/0` for shared rate limits | In memory |
| `FLASK_DEBUG` | Set to `1` for local debugging only | Off |

## Running Tests

```bash
pip install pytest
pytest -q
```

14 tests cover encryption at rest, unique nonces, cross-user access, MFA enforcement, CSRF, rate limiting, security headers, the generator, and export. They run automatically on every push.

## Limitations

- **Server-side decryption**: the server decrypts items when you click Show/Copy. A zero-knowledge design would encrypt and decrypt in the browser (see `prototypes/ClientSideEncryption.js`).
- **In-memory keys**: vault keys are lost on restart (you'll need to log in again), and the app should run as a single process.
- **No master-password change or recovery**: changing it would require re-encrypting every item.
- **Import** of exported CSVs isn't implemented yet.
- Intended as a portfolio project; use an audited password manager for real credentials.

## Project Structure

```text
Secure-Password-Manager/
├── app.py              # Flask app: models, crypto, routes
├── templates/          # Jinja2 pages
├── static/             # app.js (reveal/copy/strength/generator), styles.css
├── tests/test_app.py   # Security and feature tests
├── prototypes/         # Original feature snippets this app was built from
└── requirements.txt
```

## Development History

This project began as separate prototype snippets for each feature (now in `prototypes/`). They were consolidated into one working app, fixing these issues along the way:

- **Undecryptable items**: a new random salt was generated per item but never stored, so saved passwords couldn't be decrypted. Now each user has one stored salt.
- **Master password in the session cookie**: Flask's default session is signed, not encrypted, so the master password was readable by anyone with the cookie. Now only a random token is stored.
- **Missing ownership check on edit**: any user could edit another user's item. All item routes now check ownership.
- **Insecure generator**: `random` was replaced with `secrets`.
- **MFA enabled without confirmation**: users could lock themselves out. MFA now activates only after a valid code.
- Typos that stopped the code from running (`cryptogrpahy`, `FLask`, `Login_user`, `os.random`, `sqlite://` paths), and filenames containing `:` that can't be checked out on Windows.
