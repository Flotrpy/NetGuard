from fastapi.testclient import TestClient

from netguard.core.ratelimit import RateLimiter
from netguard.main import create_app


def test_rate_limiter_window_and_retry_after():
    rl = RateLimiter(limit=2, window_seconds=10)
    assert rl.check("a", now=0) == (True, 0)
    assert rl.check("a", now=1)[0] is True
    allowed, retry = rl.check("a", now=2)
    assert not allowed and 1 <= retry <= 10
    assert rl.check("b", now=2)[0] is True  # independent keys
    assert rl.check("a", now=11)[0] is True  # window slid


def test_security_headers_present():
    client = TestClient(create_app())
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert "default-src 'none'" in r.headers["content-security-policy"]
    assert r.headers["cache-control"] == "no-store"
    assert r.headers["x-request-id"]


def test_request_id_is_propagated():
    client = TestClient(create_app())
    r = client.get("/api/health", headers={"X-Request-ID": "abc123"})
    assert r.headers["x-request-id"] == "abc123"


def test_global_rate_limit_returns_429(monkeypatch):
    monkeypatch.setenv("NETGUARD_RATE_LIMIT_PER_MINUTE", "3")
    from netguard import config

    config.get_settings.cache_clear()
    client = TestClient(create_app())
    codes = [client.get("/api/health").status_code for _ in range(5)]
    assert codes[:3] == [200, 200, 200] and codes[3] == 429
    assert client.get("/api/health").headers["retry-after"]
