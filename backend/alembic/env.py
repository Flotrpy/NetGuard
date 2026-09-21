"""Alembic environment: uses NetGuard settings and model metadata."""

from alembic import context

from netguard import models  # noqa: F401  (register tables on Base.metadata)
from netguard.config import get_settings
from netguard.db import Base, make_engine

config = context.config
target_metadata = Base.metadata


def _url() -> str:
    return config.get_main_option("sqlalchemy.url") or get_settings().database_url


def run_migrations_offline() -> None:
    context.configure(url=_url(), target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    url = _url()
    if url.startswith("sqlite:///") and ":memory:" not in url:
        get_settings().ensure_dirs()
    engine = make_engine(url)
    with engine.connect() as connection:
        context.configure(
            connection=connection, target_metadata=target_metadata, render_as_batch=True
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
