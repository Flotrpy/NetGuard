"""Application configuration, loaded from environment variables (prefix ``NETGUARD_``)."""

from __future__ import annotations

import secrets
from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="NETGUARD_", env_file=".env", extra="ignore")

    env: str = "development"  # development | production | test
    database_url: str = "sqlite:///./data/netguard.db"
    data_dir: Path = Path("./data")
    secret_key: str = ""  # required in production; used to derive the token-encryption key
    log_level: str = "INFO"
    log_json: bool = True

    # Sessions / cookies
    session_ttl_minutes: int = 60 * 12
    cookie_secure: bool = False
    cookie_name: str = "ng_session"
    csrf_cookie_name: str = "ng_csrf"
    allow_registration: bool = True
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:3000"])

    # Upload / scan resource limits
    max_upload_mb: int = 50
    max_extracted_mb: int = 500
    max_archive_files: int = 20000
    max_file_scan_kb: int = 1024  # files larger than this are skipped by content scanners
    scan_timeout_seconds: int = 600
    scan_memory_mb: int = 1024

    # Rate limiting (per client, per minute)
    rate_limit_per_minute: int = 300
    auth_rate_limit_per_minute: int = 10

    # Network/API scanning policy
    allow_public_targets: bool = False  # public IPs need an explicit opt-in by the operator
    max_scan_hosts: int = 1024
    max_scan_ports: int = 1024

    # External services
    osv_api_url: str = "https://api.osv.dev"
    osv_timeout_seconds: float = 20.0
    osv_offline: bool = False
    anthropic_model: str = "claude-sonnet-5"
    github_api_url: str = "https://api.github.com"
    gitlab_api_url: str = "https://gitlab.com/api/v4"
    webhook_secret: str = ""

    @property
    def is_production(self) -> bool:
        return self.env == "production"

    @property
    def snapshots_dir(self) -> Path:
        return self.data_dir / "snapshots"

    @property
    def uploads_dir(self) -> Path:
        return self.data_dir / "uploads"

    @property
    def reports_dir(self) -> Path:
        return self.data_dir / "reports"

    def ensure_dirs(self) -> None:
        for d in (self.data_dir, self.snapshots_dir, self.uploads_dir, self.reports_dir):
            d.mkdir(parents=True, exist_ok=True)

    def resolved_secret_key(self) -> str:
        """Return the configured secret, or (dev/test only) a generated one persisted on disk."""
        if self.secret_key:
            if self.is_production and len(self.secret_key) < 32:
                raise RuntimeError("NETGUARD_SECRET_KEY must be at least 32 characters in production")
            return self.secret_key
        if self.is_production:
            raise RuntimeError("NETGUARD_SECRET_KEY must be set in production")
        self.ensure_dirs()
        key_file = self.data_dir / ".dev_secret_key"
        if not key_file.exists():
            key_file.write_text(secrets.token_urlsafe(48), encoding="utf-8")
        return key_file.read_text(encoding="utf-8").strip()


@lru_cache
def get_settings() -> Settings:
    return Settings()
