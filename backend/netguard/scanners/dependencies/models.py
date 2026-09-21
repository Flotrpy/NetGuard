"""Shared dependency data model."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

# Ecosystem names follow OSV.dev's naming so they can be sent to the API unchanged.
NPM = "npm"
PYPI = "PyPI"
MAVEN = "Maven"
NUGET = "NuGet"


@dataclass
class Package:
    ecosystem: str
    name: str
    version: str
    manifest: str  # repo-relative path of the file it was read from
    direct: bool = True
    dev: bool = False
    # Chain from a direct dependency down to this package, e.g. ["express", "qs"].
    path: list[str] = field(default_factory=list)
    line: int = 0

    @property
    def coordinate(self) -> tuple[str, str, str]:
        return (self.ecosystem, self.name, self.version)

    @property
    def path_text(self) -> str:
        return " > ".join(self.path or [self.name])


@dataclass
class ParseResult:
    packages: list[Package] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def shortest_paths(
    roots: list[str], edges: dict[str, list[str]]
) -> dict[str, list[str]]:
    """Breadth-first shortest dependency chain from any root to every reachable node."""
    paths: dict[str, list[str]] = {}
    queue: deque[str] = deque()
    for r in roots:
        if r not in paths:
            paths[r] = [r]
            queue.append(r)
    while queue:
        node = queue.popleft()
        for child in edges.get(node, []):
            if child not in paths:
                paths[child] = [*paths[node], child]
                queue.append(child)
    return paths


def find_line(text: str, needle: str) -> int:
    """1-based line number of the first occurrence of ``needle`` in ``text`` (0 if absent)."""
    idx = text.find(needle)
    return text.count("\n", 0, idx) + 1 if idx >= 0 else 0
