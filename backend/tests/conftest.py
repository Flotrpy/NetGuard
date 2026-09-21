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
    monkeypatch.setenv("NETGUARD_LOG_LEVEL", "WARNING")
    monkeypatch.setenv("NETGUARD_OSV_OFFLINE", "true")
    config_module.get_settings.cache_clear()
    from netguard.core import security

    monkeypatch.setattr(security, "_SCRYPT_N", 2**10)
    yield Settings()
    config_module.get_settings.cache_clear()
