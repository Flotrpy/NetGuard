from netguard.config import get_settings


def test_first_user_is_admin_and_later_users_are_members(client, make_client):
    r = client.register("first@example.com")
    assert r.status_code == 201 and r.json()["user"]["role"] == "admin"
    other = make_client("second@example.com")
    assert other.get("/api/auth/me").json()["user"]["role"] == "member"


def test_session_cookie_is_httponly_and_no_password_in_response(client):
    r = client.register()
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=lax" in cookie
    assert "password" not in r.text.lower()


def test_me_requires_authentication(client):
    assert client.get("/api/auth/me").status_code == 401


def test_weak_password_and_duplicate_email_rejected(client):
    assert client.register(password="short").status_code == 422
    assert client.register().status_code == 201
    dup = client.register()
    assert dup.status_code == 409


def test_login_wrong_password_is_generic_and_correct_password_works(client):
    client.register("u@example.com", "Sup3r-secret-pass")
    bad = client.login("u@example.com", "nope-nope-nope")
    unknown = client.login("ghost@example.com", "nope-nope-nope")
    assert bad.status_code == unknown.status_code == 401
    assert bad.json() == unknown.json()  # no user enumeration
    assert client.login("u@example.com", "Sup3r-secret-pass").status_code == 200


def test_account_locks_after_repeated_failures(client, monkeypatch):
    monkeypatch.setenv("NETGUARD_AUTH_RATE_LIMIT_PER_MINUTE", "1000")
    get_settings.cache_clear()
    client.register("lock@example.com")
    for _ in range(5):
        client.login("lock@example.com", "wrong-wrong-wrong")
    r = client.login("lock@example.com", "Sup3r-secret-pass")
    assert r.status_code == 429


def test_csrf_required_for_state_changing_cookie_requests(client):
    client.register()
    good_csrf = client.csrf
    client.csrf = None
    assert client.post("/api/auth/logout").status_code == 403  # no header
    client.csrf = "wrong-token"
    assert client.post("/api/auth/logout").status_code == 403  # bad header
    client.csrf = good_csrf
    assert client.post("/api/auth/logout").status_code == 204


def test_cross_origin_state_change_rejected(client):
    client.register()
    r = client.post("/api/auth/logout", headers={"Origin": "https://evil.example"})
    assert r.status_code == 403


def test_logout_revokes_session(client):
    client.register()
    assert client.post("/api/auth/logout").status_code == 204
    assert client.get("/api/auth/me").status_code == 401


def test_login_endpoint_is_rate_limited(client):
    codes = [client.login("a@example.com", "whatever-pass-1").status_code for _ in range(12)]
    assert 429 in codes


def test_registration_can_be_disabled_after_bootstrap(client, monkeypatch):
    client.register("boot@example.com")
    monkeypatch.setenv("NETGUARD_ALLOW_REGISTRATION", "false")
    get_settings.cache_clear()
    from fastapi.testclient import TestClient

    other = TestClient(client.http.app)
    payload = {"email": "x@example.com", "password": "Sup3r-secret-pass"}
    r = other.post("/api/auth/register", json=payload)
    assert r.status_code == 403
