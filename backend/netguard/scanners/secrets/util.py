"""Entropy, placeholder detection and redaction helpers for the secret scanner."""

from __future__ import annotations

import math
import re
from collections import Counter

_PLACEHOLDER_WORDS = (
    "example", "changeme", "change_me", "change-me", "your_", "your-", "yourkey", "<", ">",
    "xxxx", "****", "....", "dummy", "sample", "placeholder", "redacted", "todo", "fixme",
    "insert", "replace", "not-a-real", "notreal", "fake", "mysecret", "password123",
    "secret123", "lorem", "foobar", "12345678", "abcdefgh", "undefined", "null", "none",
)
_VARIABLE_REFS = re.compile(
    r"^\$\{?[\w.]+\}?$|\{\{.*\}\}|%\(.*\)s|^\$\(|process\.env|os\.environ|getenv|ENV\[|"
    r"System\.getenv|config\.|settings\.|secrets\.|vault|\$\{"
)


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def char_classes(value: str) -> int:
    return sum(
        bool(re.search(p, value)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]")
    )


def is_placeholder(value: str) -> bool:
    """True for values that are obviously templates, examples or references to a variable."""
    low = value.lower()
    if _VARIABLE_REFS.search(value):
        return True
    if any(w in low for w in _PLACEHOLDER_WORDS):
        return True
    return len(set(value)) <= 2 or bool(re.fullmatch(r"(.)\1{5,}", value))


def redact(value: str, known_prefix: str = "") -> str:
    """Mask a secret for display, e.g. ``sk_live_********************92``.

    Only a recognisable, non-secret prefix and the last two characters are kept, and nothing at
    all for short values, so the redacted form can never be used to reconstruct the secret.
    """
    n = len(value)
    if n < 12:
        return "*" * max(n, 6)
    prefix = known_prefix if known_prefix and value.startswith(known_prefix) else ""
    prefix = prefix[:10]
    keep_tail = 2
    stars = max(n - len(prefix) - keep_tail, 4)
    return f"{prefix}{'*' * stars}{value[-keep_tail:]}"
