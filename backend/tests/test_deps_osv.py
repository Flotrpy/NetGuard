import httpx
import pytest

from netguard.enums import Severity
from netguard.scanners.dependencies import cvss
from netguard.scanners.dependencies.osv import (
    OsvClient,
    OsvUnavailable,
    fixed_versions_for,
    to_vuln,
)
from netguard.scanners.dependencies.versions import compare, sort_versions

# Vectors with published scores (FIRST CVSS 3.1 examples / NVD).
KNOWN = [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5),
    ("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N", 4.3),
    ("CVSS:3.1/AV:P/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0.0),
]


@pytest.mark.parametrize("vector,score", KNOWN)
def test_cvss_base_scores_match_published_values(vector, score):
    assert cvss.base_score(vector) == score


def test_cvss_rejects_unsupported_or_malformed_vectors():
    assert cvss.base_score("CVSS:4.0/AV:N/AC:L") is None
    assert cvss.base_score("CVSS:3.1/AV:N") is None
    assert cvss.base_score("garbage") is None


def test_severity_bands():
    assert [cvss.severity_from_score(s) for s in (9.8, 7.0, 4.0, 0.1, 0.0)] == [
        "critical", "high", "medium", "low", "info"]


def test_version_ordering():
    assert compare("npm", "1.10.0", "1.9.0") == 1
    assert compare("npm", "1.0.0", "1.0.0-beta.1") == 1  # release > prerelease
    assert compare("npm", "1.0", "1.0.0") == 0
    assert compare("PyPI", "2.0rc1", "2.0") == -1
    assert compare("Maven", "30.0-jre", "29.9-jre") == 1
    assert compare("Maven", "2.14.1", "2.15.0") == -1
    assert sort_versions("npm", ["1.10.0", "1.2.0", "1.9.9"]) == ["1.2.0", "1.9.9", "1.10.0"]


def record(**kw):
    base = {
        "id": "GHSA-xxxx-yyyy-zzzz",
        "aliases": ["CVE-2021-0001"],
        "summary": "Prototype pollution in lodash",
        "details": "long text",
        "database_specific": {"severity": "HIGH", "cwe_ids": ["CWE-1321"]},
        "references": [{"url": "https://example.com/advisory"}],
        "affected": [{
            "package": {"ecosystem": "npm", "name": "lodash"},
            "ranges": [{"type": "SEMVER", "events": [
                {"introduced": "0"}, {"fixed": "4.17.12"}, {"introduced": "5.0.0"}, {"fixed": "5.1.0"}]}],
        }],
    }
    base.update(kw)
    return base


def test_to_vuln_uses_ghsa_severity_and_picks_applicable_fix():
    v = to_vuln(record(), "npm", "lodash", "4.17.4")
    assert (v.severity, v.severity_source, v.cve) == (Severity.HIGH, "ghsa", "CVE-2021-0001")
    assert v.fixed_versions == ["4.17.12"] and v.cwes == ["CWE-1321"]
    # Installed version in the second range -> the second fix applies.
    assert to_vuln(record(), "npm", "lodash", "5.0.1").fixed_versions == ["5.1.0"]


def test_severity_falls_back_to_cvss_then_marks_unknown():
    rec = record(database_specific={}, severity=[
        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}])
    v = to_vuln(rec, "npm", "lodash", "1.0.0")
    assert (v.severity, v.severity_source, v.cvss_score) == (Severity.CRITICAL, "cvss3", 9.8)
    unknown = to_vuln(record(database_specific={}), "npm", "lodash", "1.0.0")
    assert unknown.severity_source == "unknown"  # never presented as a real rating


def test_fixed_versions_only_from_matching_package_and_ecosystem():
    rec = record()
    rec["affected"].append({"package": {"ecosystem": "PyPI", "name": "lodash"},
                            "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "9.9.9"}]}]})
    assert fixed_versions_for(rec, "npm", "lodash", "4.0.0") == ["4.17.12"]
    assert fixed_versions_for(rec, "npm", "other", "4.0.0") == []
    assert fixed_versions_for(record(affected=[]), "npm", "lodash", "1.0.0") == []


def make_client(handler, tmp_path=None, **kw):
    transport = httpx.MockTransport(handler)
    return OsvClient("https://osv.test", cache_dir=tmp_path, client=httpx.Client(transport=transport), **kw)


def test_querybatch_maps_results_and_caches(tmp_path):
    calls = []

    def handler(request):
        calls.append(request)
        body = __import__("json").loads(request.content)
        answers = [{"vulns": [{"id": "GHSA-1"}]} if q["package"]["name"] == "lodash" else {}
                   for q in body["queries"]]
        return httpx.Response(200, json={"results": answers})

    client = make_client(handler, tmp_path)
    coords = [("npm", "lodash", "4.17.4"), ("npm", "safe", "1.0.0")]
    assert client.query(coords) == {coords[0]: ["GHSA-1"], coords[1]: []}
    assert len(calls) == 1
    again = make_client(handler, tmp_path)
    assert again.query(coords)[coords[0]] == ["GHSA-1"]
    assert len(calls) == 1 and again.stats["cache_hits"] == 2  # served from disk cache


def test_pagination_tokens_are_followed():
    pages = iter([
        {"results": [{"vulns": [{"id": "A"}], "next_page_token": "t1"}]},
        {"results": [{"vulns": [{"id": "B"}]}]},
    ])
    client = make_client(lambda r: httpx.Response(200, json=next(pages)))
    assert client.query([("npm", "x", "1")])[("npm", "x", "1")] == ["A", "B"]


def test_offline_mode_raises_instead_of_reporting_clean(tmp_path):
    client = make_client(lambda r: httpx.Response(500), tmp_path, offline=True)
    with pytest.raises(OsvUnavailable, match="offline"):
        client.query([("npm", "x", "1")])
    with pytest.raises(OsvUnavailable):
        client.get_vuln("GHSA-1")


def test_http_errors_and_malformed_responses_raise():
    with pytest.raises(OsvUnavailable):
        make_client(lambda r: httpx.Response(503)).query([("npm", "x", "1")])
    with pytest.raises(OsvUnavailable):
        make_client(lambda r: httpx.Response(200, json={"results": []})).query([("npm", "x", "1")])
    with pytest.raises(OsvUnavailable):
        make_client(lambda r: httpx.Response(200, content=b"<html>")).get_vuln("X")


def test_get_vuln_is_cached(tmp_path):
    n = []

    def handler(r):
        n.append(1)
        return httpx.Response(200, json=record())

    client = make_client(handler, tmp_path)
    assert client.get_vuln("GHSA-1")["id"] == "GHSA-xxxx-yyyy-zzzz"
    client.get_vuln("GHSA-1")
    assert len(n) == 1
