"""Test helpers shared by service-level tests."""

from __future__ import annotations

from netguard.db import Base, get_engine, get_session_factory, init_db
from netguard.enums import Confidence, Severity
from netguard.models import Project, Scan, User
from netguard.scanners.base import RawFinding


def fresh_db():
    init_db(database_url="sqlite://")
    Base.metadata.create_all(get_engine())
    return get_session_factory()()


def make_project(db) -> Project:
    user = User(email="u@example.com", password_hash="x")
    db.add(user)
    db.flush()
    project = Project(name="P", owner_id=user.id)
    db.add(project)
    db.flush()
    return project


def make_scan(db, project) -> Scan:
    scan = Scan(project_id=project.id, scanners=["sast"])
    db.add(scan)
    db.flush()
    return scan


def raw(rule="r1", file="a.py", line=1, code="x = 1", sev=Severity.HIGH, **kw) -> RawFinding:
    return RawFinding(
        rule_id=rule,
        title=kw.pop("title", "Issue"),
        severity=sev,
        confidence=kw.pop("confidence", Confidence.HIGH),
        file_path=file,
        line=line,
        code_context=code,
        **kw,
    )
