import os
import re
import sys
import tempfile

os.environ["DATABASE_URL"] = "sqlite:///" + os.path.join(tempfile.mkdtemp(), "test.db")
os.environ["KDF_ITERATIONS"] = "1000"  # fast for tests only
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pyotp
import pytest
from app import app, db, limiter, User, VaultItem, generate_password, SYMBOLS

PW = "correct horse battery"


@pytest.fixture
def client():
    app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    limiter.enabled = False
    with app.app_context():
        db.drop_all()
        db.create_all()
    with app.test_client() as c:
        yield c


def register_and_login(c, username="alice", password=PW):
    c.post("/register", data={"username": username, "password": password})
    return c.post("/login", data={"username": username, "password": password})


def add(c, site="example.com", pw="s3cret-Value!"):
    return c.post("/add", data={"site": site, "vault_username": "me", "password": pw})


def test_vault_requires_login(client):
    rv = client.get("/vault")
    assert rv.status_code == 302 and "/login" in rv.headers["Location"]


def test_short_master_password_rejected(client):
    client.post("/register", data={"username": "bob", "password": "short"})
    with app.app_context():
        assert User.query.filter_by(username="bob").first() is None


def test_password_is_hashed_not_stored(client):
    register_and_login(client)
    with app.app_context():
        u = User.query.filter_by(username="alice").first()
        assert PW not in u.password_hash


def test_items_encrypted_at_rest_and_decryptable(client):
    register_and_login(client)
    add(client, pw="plain-text-pw")
    with app.app_context():
        item = VaultItem.query.first()
        assert b"plain-text-pw" not in item.password_encrypted
        item_id = item.id
    rv = client.post(f"/vault/{item_id}/reveal")
    assert rv.get_json()["password"] == "plain-text-pw"


def test_nonce_unique_per_item(client):
    register_and_login(client)
    add(client, "a.com", "same")
    add(client, "b.com", "same")
    with app.app_context():
        a, b = VaultItem.query.all()
        assert a.nonce != b.nonce and a.password_encrypted != b.password_encrypted


def test_user_cannot_access_another_users_item(client):
    register_and_login(client, "alice")
    add(client)
    with app.app_context():
        item_id = VaultItem.query.first().id
    client.post("/logout")
    register_and_login(client, "mallory")
    assert client.post(f"/vault/{item_id}/reveal").status_code == 404
    assert client.get(f"/edit/{item_id}").status_code == 404
    assert client.post(f"/delete/{item_id}").status_code == 404
    with app.app_context():
        assert db.session.get(VaultItem, item_id) is not None


def test_master_password_not_in_session_cookie(client):
    rv = register_and_login(client)
    cookies = " ".join(rv.headers.getlist("Set-Cookie"))
    assert "correct" not in cookies


def test_logout_locks_vault(client):
    register_and_login(client)
    add(client)
    client.post("/logout")
    assert client.get("/vault").status_code == 302


def test_mfa_required_after_enabling(client):
    register_and_login(client)
    client.get("/setup_mfa")
    with client.session_transaction() as s:
        secret = s["pending_mfa_secret"]
    client.post("/setup_mfa", data={"token": pyotp.TOTP(secret).now()})
    client.post("/logout")
    rv = client.post("/login", data={"username": "alice", "password": PW})
    assert "/verify_mfa" in rv.headers["Location"]
    assert client.get("/vault").status_code == 302  # not logged in yet
    client.post("/verify_mfa", data={"token": "000000"})
    assert client.get("/vault").status_code == 302
    client.post("/verify_mfa", data={"token": pyotp.TOTP(secret).now()})
    assert client.get("/vault").status_code == 200


def test_generator_strength():
    for _ in range(50):
        p = generate_password(16, True)
        assert len(p) == 16
        assert re.search(r"[a-z]", p) and re.search(r"[A-Z]", p) and re.search(r"\d", p)
        assert any(c in SYMBOLS for c in p)
    assert len(generate_password(500)) == 64 and len(generate_password(1)) == 8


def test_security_headers(client):
    rv = client.get("/login")
    assert rv.headers["X-Frame-Options"] == "DENY"
    assert "script-src 'self'" in rv.headers["Content-Security-Policy"]


def test_csrf_enforced():
    app.config.update(TESTING=True, WTF_CSRF_ENABLED=True)
    try:
        with app.test_client() as c:
            assert c.post("/login", data={"username": "x", "password": "y"}).status_code == 400
    finally:
        app.config["WTF_CSRF_ENABLED"] = False


def test_export_contains_only_ciphertext(client):
    register_and_login(client)
    add(client, pw="do-not-leak")
    rv = client.get("/export")
    assert rv.status_code == 200 and b"do-not-leak" not in rv.data


def test_login_rate_limited(client):
    limiter.enabled = True
    limiter.reset()
    try:
        codes = [client.post("/login", data={"username": "x", "password": "wrong"}).status_code for _ in range(7)]
        assert 429 in codes
    finally:
        limiter.enabled = False
