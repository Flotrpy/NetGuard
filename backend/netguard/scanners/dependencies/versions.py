"""Best-effort version comparison per ecosystem.

Used only to pick which *fixed* version applies to an installed one. Whether a package is
vulnerable at all is decided by OSV, not by this module.
"""

from __future__ import annotations

import re
from functools import cmp_to_key

from packaging.version import InvalidVersion, Version

_PRE = (
    "alpha", "beta", "rc", "pre", "preview", "snapshot", "dev", "milestone", "m", "a", "b", "cr",
)
_SPLIT = re.compile(r"[.\-+_]")


def _generic_key(version: str) -> tuple:
    v = version.strip().lstrip("vV")
    v = v.split("+", 1)[0]  # build metadata does not affect precedence
    parts = [p for p in _SPLIT.split(v) if p != ""]
    numbers: list[int] = []
    prerelease: list[str] = []
    in_pre = False
    for p in parts:
        m = re.fullmatch(r"(\d+)([a-zA-Z]*)(\d*)", p)
        if not in_pre and p.isdigit():
            numbers.append(int(p))
            continue
        if not in_pre and m and m.group(1) and m.group(2):
            numbers.append(int(m.group(1)))
            in_pre = m.group(2).lower() in _PRE or in_pre
            if in_pre:
                prerelease.append(m.group(2).lower() + (m.group(3) or ""))
            continue
        if p.lower() in _PRE or (prerelease and not in_pre):
            in_pre = True
        if in_pre:
            prerelease.append(p.lower())
        # other qualifiers (RELEASE, Final, jre, ...) are treated as the plain release
    while numbers and numbers[-1] == 0:
        numbers.pop()
    # A release sorts after any prerelease with the same numbers.
    return (tuple(numbers), 0 if prerelease else 1, tuple(prerelease))


def compare(ecosystem: str, a: str, b: str) -> int:
    if ecosystem == "PyPI":
        try:
            va, vb = Version(a), Version(b)
            return (va > vb) - (va < vb)
        except InvalidVersion:
            pass
    ka, kb = _generic_key(a), _generic_key(b)
    return (ka > kb) - (ka < kb)


def sort_versions(ecosystem: str, versions: list[str]) -> list[str]:
    return sorted(versions, key=cmp_to_key(lambda x, y: compare(ecosystem, x, y)))
