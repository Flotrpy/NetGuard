"""Shared pytest fixtures: isolated settings, in-memory DB and an API test client."""

from __future__ import annotations

import pytest

from netguard import config as config_module
from netguard.config import Settings


@pytest.fixture(autouse=True)
def _settings(tmp_path, monkeypatch):
    """Every test gets its own data dir, a fixed secret and cheap password hashing."""
    monkeypatch.setenv("NETGUARD_ENV", "test")
    monkeypatch.setenv("NETGUARD_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("NETGUARD_SECRET_KEY", "test-secret-key-that-is-long-enough-0123456789")
    for key in ("ANTHROPIC_API_KEY", "GROQ_API_KEY", "GEMINI_API_KEY"):
        monkeypatch.delenv(key, raising=False)  # tests must never hit a real AI provider
    monkeypatch.setenv("NETGUARD_LOG_LEVEL", "WARNING")
    monkeypatch.setenv("NETGUARD_OSV_OFFLINE", "true")
    monkeypatch.setenv("NETGUARD_SCAN_ISOLATION", "inline")  # sandbox has its own tests
    monkeypatch.setenv("NETGUARD_EMBEDDED_WORKER", "false")  # tests drive the worker
    config_module.get_settings.cache_clear()
    from netguard.core import security

    monkeypatch.setattr(security, "_SCRYPT_N", 2**10)
    yield Settings()
    config_module.get_settings.cache_clear()


@pytest.fixture
def app(_settings):
    from netguard.db import Base, get_engine, init_db
    from netguard.main import create_app

    application = create_app()
    init_db(database_url="sqlite://")  # isolated in-memory DB
    Base.metadata.create_all(get_engine())
    return application


class ApiClient:
    """TestClient wrapper that behaves like the SPA: keeps cookies and echoes the CSRF token."""

    def __init__(self, app):
        from fastapi.testclient import TestClient

        self.http = TestClient(app)
        self.csrf: str | None = None

    def register(self, email="admin@example.com", password="Sup3r-secret-pass", name="Admin"):
        payload = {"email": email, "password": password, "name": name}
        r = self.http.post("/api/auth/register", json=payload)
        if r.status_code == 201:
            self.csrf = r.json()["csrf_token"]
        return r

    def login(self, email, password):
        r = self.http.post("/api/auth/login", json={"email": email, "password": password})
        if r.status_code == 200:
            self.csrf = r.json()["csrf_token"]
        return r

    def _h(self, extra=None):
        h = {"X-CSRF-Token": self.csrf} if self.csrf else {}
        h.update(extra or {})
        return h

    def get(self, url, **kw):
        return self.http.get(url, headers=self._h(kw.pop("headers", None)), **kw)

    def post(self, url, **kw):
        return self.http.post(url, headers=self._h(kw.pop("headers", None)), **kw)

    def put(self, url, **kw):
        return self.http.put(url, headers=self._h(kw.pop("headers", None)), **kw)

    def patch(self, url, **kw):
        return self.http.patch(url, headers=self._h(kw.pop("headers", None)), **kw)

    def delete(self, url, **kw):
        return self.http.delete(url, headers=self._h(kw.pop("headers", None)), **kw)


@pytest.fixture
def client(app):
    return ApiClient(app)


@pytest.fixture
def make_client(app):
    def _make(email, password="Sup3r-secret-pass"):
        c = ApiClient(app)
        c.register(email, password)
        return c

    return _make


@pytest.fixture
def fake_scanner():
    """Register a deterministic scanner that flags every line containing 'BAD'."""
    from netguard.core.files import iter_files, read_text
    from netguard.enums import Confidence, Severity
    from netguard.enums import Scanner as Name
    from netguard.scanners import registry
    from netguard.scanners.base import RawFinding, Scanner, ScanResult

    class FakeSast(Scanner):
        name = Name.SAST
        display_name = "Fake SAST"

        def scan(self, ctx):
            findings = []
            files = list(iter_files(ctx.root, only_paths=ctx.only_paths))
            for i, f in enumerate(files):
                ctx.progress(100 * i / max(1, len(files)), f.rel_path)
                for n, line in enumerate((read_text(f.abs_path) or "").splitlines(), 1):
                    if "BAD" in line:
                        findings.append(
                            RawFinding(
                                rule_id="fake.bad",
                                title="Bad thing",
                                severity=Severity.HIGH,
                                confidence=Confidence.HIGH,
                                file_path=f.rel_path,
                                line=n,
                                code_context=line,
                            )
                        )
            return ScanResult(findings=findings, metadata={"files": len(files)})

    registry.all_scanners()  # ensure registry is loaded
    original = registry._REGISTRY["sast"]
    registry._REGISTRY["sast"] = FakeSast()
    yield
    registry._REGISTRY["sast"] = original


@pytest.fixture
def planned_api():
    """Temporarily make the API scanner a 'planned' stub, to test how unavailable scanners behave.

    Every real scanner is implemented now, so the honesty rules for planned scanners (never shown
    as OK, cannot be started, produce no findings) need a stand-in to stay covered.
    """
    from netguard.enums import Scanner as Name
    from netguard.scanners import registry
    from netguard.scanners.base import PlannedScanner

    class PlannedApi(PlannedScanner):
        name = Name.API
        display_name = "API Scanner"
        description = "Authorized web API checks."
        supported_inputs = ("api_target",)

    registry.all_scanners()
    original = registry._REGISTRY["api"]
    registry._REGISTRY["api"] = PlannedApi()
    yield
    registry._REGISTRY["api"] = original
