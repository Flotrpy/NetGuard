"""OSV.dev client (https://google.github.io/osv.dev/api/).

OSV aggregates GitHub Security Advisories, PyPA, RustSec, the Go vulnerability DB and others.
Everything reported by the dependency scanner comes from these records; NetGuard adds no
vulnerability knowledge of its own. Responses are cached on disk to keep rescans fast.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from netguard.enums import Severity
from netguard.scanners.dependencies import cvss
from netguard.scanners.dependencies.versions import compare, sort_versions

QUERY_TTL = 6 * 3600
VULN_TTL = 24 * 3600
BATCH = 500
MAX_PAGES = 5

Coordinate = tuple[str, str, str]  # (ecosystem, name, version)


class OsvUnavailable(Exception):
    """Vulnerability data could not be retrieved (offline mode or network failure)."""


@dataclass
class Vuln:
    id: str
    aliases: list[str]
    summary: str
    details: str
    severity: Severity
    severity_source: str  # ghsa | cvss3 | unknown
    cvss_score: float | None
    cwes: list[str]
    references: list[str]
    fixed_versions: list[str]
    published: str = ""
    raw_ids: list[str] = field(default_factory=list)

    @property
    def cve(self) -> str:
        return next((a for a in self.aliases if a.startswith("CVE-")), "")


_GHSA_SEVERITY = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}


def _ecosystem_matches(affected_eco: str, ecosystem: str) -> bool:
    return affected_eco.split(":", 1)[0].lower() == ecosystem.lower()


def _norm(ecosystem: str, name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower() if ecosystem == "PyPI" else name.lower()


def fixed_versions_for(record: dict, ecosystem: str, name: str, installed: str) -> list[str]:
    """Fixed versions from OSV ``affected`` ranges for this package.

    Returns the earliest fix strictly above the installed version (the upgrade target for the
    affected range), or every published fix if none is newer.
    """
    fixes: list[str] = []
    for aff in record.get("affected", []):
        pkg = aff.get("package", {})
        if not _ecosystem_matches(pkg.get("ecosystem", ""), ecosystem):
            continue
        if _norm(ecosystem, pkg.get("name", "")) != _norm(ecosystem, name):
            continue
        for rng in aff.get("ranges", []):
            if rng.get("type") not in ("SEMVER", "ECOSYSTEM"):
                continue
            for event in rng.get("events", []):
                if "fixed" in event:
                    fixes.append(event["fixed"])
    unique = sort_versions(ecosystem, sorted(set(fixes)))
    newer = [f for f in unique if compare(ecosystem, f, installed) > 0]
    return newer[:1] if newer else unique[-1:] if unique else []


def to_vuln(record: dict, ecosystem: str, name: str, installed: str) -> Vuln:
    db = record.get("database_specific") or {}
    severity, source, score = Severity.MEDIUM, "unknown", None
    ghsa = str(db.get("severity", "")).upper()
    for sev in record.get("severity", []) or []:
        if str(sev.get("type", "")).startswith("CVSS_V3"):
            score = cvss.base_score(sev.get("score", ""))
            if score is not None:
                break
    if ghsa in _GHSA_SEVERITY:
        severity, source = _GHSA_SEVERITY[ghsa], "ghsa"
    elif score is not None:
        severity, source = Severity(cvss.severity_from_score(score)), "cvss3"
    refs = [r["url"] for r in record.get("references", []) if r.get("url")][:8]
    return Vuln(
        id=record["id"],
        aliases=list(record.get("aliases", [])),
        summary=record.get("summary") or (record.get("details", "").split("\n")[0][:200]),
        details=record.get("details", ""),
        severity=severity,
        severity_source=source,
        cvss_score=score,
        cwes=list(db.get("cwe_ids", []) or []),
        references=refs,
        fixed_versions=fixed_versions_for(record, ecosystem, name, installed),
        published=record.get("published", ""),
    )


class OsvClient:
    def __init__(
        self,
        base_url: str = "https://api.osv.dev",
        *,
        timeout: float = 20.0,
        cache_dir: Path | None = None,
        offline: bool = False,
        client: httpx.Client | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.offline = offline
        self.cache_dir = Path(cache_dir) / "osv" if cache_dir else None
        self._client = client or httpx.Client(timeout=timeout, headers={"User-Agent": "NetGuard"})
        self.stats = {"queries": 0, "cache_hits": 0, "http_requests": 0}

    # -- cache ---------------------------------------------------------------------------
    def _cache_path(self, kind: str, key: str) -> Path | None:
        if self.cache_dir is None:
            return None
        digest = hashlib.sha256(key.encode()).hexdigest()
        return self.cache_dir / kind / f"{digest}.json"

    def _cache_get(self, kind: str, key: str, ttl: int) -> Any | None:
        path = self._cache_path(kind, key)
        if path is None or not path.exists():
            return None
        try:
            if time.time() - path.stat().st_mtime > ttl:
                return None
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

    def _cache_put(self, kind: str, key: str, value: Any) -> None:
        path = self._cache_path(kind, key)
        if path is None:
            return
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(value), encoding="utf-8")
        except OSError:
            pass  # cache is an optimisation only

    # -- HTTP ----------------------------------------------------------------------------
    def _post(self, path: str, payload: dict) -> dict:
        self.stats["http_requests"] += 1
        try:
            resp = self._client.post(f"{self.base_url}{path}", json=payload)
            resp.raise_for_status()
            return resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise OsvUnavailable(f"OSV request failed: {exc}") from exc

    def _get(self, path: str) -> dict:
        self.stats["http_requests"] += 1
        try:
            resp = self._client.get(f"{self.base_url}{path}")
            resp.raise_for_status()
            return resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise OsvUnavailable(f"OSV request failed: {exc}") from exc

    # -- API -----------------------------------------------------------------------------
    def query(self, coords: list[Coordinate]) -> dict[Coordinate, list[str]]:
        """Return vulnerability ids that affect each exact (ecosystem, name, version)."""
        results: dict[Coordinate, list[str]] = {}
        pending: list[Coordinate] = []
        for c in coords:
            cached = self._cache_get("query", "|".join(c), QUERY_TTL)
            if cached is not None:
                results[c] = cached
                self.stats["cache_hits"] += 1
            else:
                pending.append(c)
        if pending and self.offline:
            raise OsvUnavailable("OSV lookups are disabled (offline mode)")
        for i in range(0, len(pending), BATCH):
            chunk = pending[i : i + BATCH]
            self.stats["queries"] += len(chunk)
            queries = [
                {"package": {"name": name, "ecosystem": eco}, "version": ver}
                for eco, name, ver in chunk
            ]
            data = self._post("/v1/querybatch", {"queries": queries})
            answers = data.get("results", [])
            if len(answers) != len(chunk):
                raise OsvUnavailable("OSV returned an unexpected number of results")
            for coord, query, answer in zip(chunk, queries, answers, strict=True):
                ids = [v["id"] for v in answer.get("vulns", [])]
                token = answer.get("next_page_token")
                pages = 1
                while token and pages < MAX_PAGES:
                    paged = {"queries": [{**query, "page_token": token}]}
                    more = self._post("/v1/querybatch", paged)
                    first = (more.get("results") or [{}])[0]
                    ids += [v["id"] for v in first.get("vulns", [])]
                    token = first.get("next_page_token")
                    pages += 1
                results[coord] = sorted(set(ids))
                self._cache_put("query", "|".join(coord), results[coord])
        return results

    def get_vuln(self, vuln_id: str) -> dict:
        cached = self._cache_get("vuln", vuln_id, VULN_TTL)
        if cached is not None:
            self.stats["cache_hits"] += 1
            return cached
        if self.offline:
            raise OsvUnavailable("OSV lookups are disabled (offline mode)")
        record = self._get(f"/v1/vulns/{vuln_id}")
        self._cache_put("vuln", vuln_id, record)
        return record
