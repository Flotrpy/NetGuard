import json

import pytest

from netguard.services.ai import explain as explain_module
from netguard.services.ai import llm
from tests.helpers import raw
from tests.test_findings_api import seed


@pytest.fixture(autouse=True)
def _no_real_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)


def _seed_finding(client):
    p = seed(client, {"sast": [raw(
        rule="py.sql-injection", file="db/users.py", line=42, code="cur.execute('..' + uid)",
        title="SQL query built with string formatting", cwe="CWE-89",
        description="A SQL statement is built with concatenation.",
        impact="An attacker can change the query logic.",
        remediation="Use parameterized queries. Never concatenate user input.")]})
    return client.get("/api/findings", params={"project_id": p["id"]}).json()["items"][0]["id"]


def stub_llm(monkeypatch, payload, model="claude-opus-5"):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    from netguard import config
    config.get_settings.cache_clear()
    calls = []

    def fake_complete(system, user, **kw):
        calls.append((system, user, kw))
        return llm.LlmResult(text=payload if isinstance(payload, str) else json.dumps(payload), model=model)

    monkeypatch.setattr(llm, "complete", fake_complete)
    return calls


GOOD = {
    "what_happened": "User input is placed straight into a database query.",
    "why_it_matters": "An attacker may be able to alter the query (CWE-89).",
    "inferred": ["The value probably comes from a request parameter."],
    "recommended": ["Use parameterized queries."],
}


def test_without_ai_key_returns_rule_based_explanation_and_says_so(client):
    fid = _seed_finding(client)
    r = client.post(f"/api/findings/{fid}/explain", json={}).json()
    assert r["source"] == "rule" and r["model"] is None
    assert "not configured" in r["notice"]
    assert r["what_happened"] == "A SQL statement is built with concatenation."
    assert r["inferred"] == []  # the baseline never guesses
    assert r["recommended"] == ["Use parameterized queries.", "Never concatenate user input."]
    labels = {d["label"]: d["value"] for d in r["detected"]}
    assert labels["Location"] == "db/users.py:42" and labels["CWE"] == "CWE-89"


def test_ai_explanation_is_used_labelled_and_cached(client, monkeypatch):
    fid = _seed_finding(client)
    calls = stub_llm(monkeypatch, GOOD)
    r = client.post(f"/api/findings/{fid}/explain", json={"audience": "advanced"}).json()
    assert r["source"] == "ai" and r["model"] == "claude-opus-5" and r["cached"] is False
    assert r["inferred"] == ["The value probably comes from a request parameter."]
    assert "review before acting" in r["notice"]
    assert "Audience: advanced" in calls[0][0] and "db/users.py:42" in calls[0][1]
    again = client.post(f"/api/findings/{fid}/explain", json={"audience": "advanced"}).json()
    assert again["cached"] is True and len(calls) == 1
    refreshed = client.post(f"/api/findings/{fid}/explain", json={"audience": "advanced", "refresh": True}).json()
    assert refreshed["cached"] is False and len(calls) == 2
    kinds = [e["kind"] for e in client.get(f"/api/findings/{fid}").json()["events"]]
    assert "explained" in kinds


def test_fabricated_cve_discards_ai_text(client, monkeypatch):
    fid = _seed_finding(client)
    bad = {**GOOD, "why_it_matters": "This is exactly CVE-2099-12345, a known RCE."}
    stub_llm(monkeypatch, bad)
    r = client.post(f"/api/findings/{fid}/explain", json={}).json()
    assert r["source"] == "rule" and "CVE-2099-12345" in r["notice"]
    assert "CVE-2099" not in r["why_it_matters"]


def test_fabricated_cwe_is_rejected_but_the_findings_own_cwe_is_allowed(client, monkeypatch):
    fid = _seed_finding(client)
    stub_llm(monkeypatch, {**GOOD, "what_happened": "Related to CWE-79."})
    assert client.post(f"/api/findings/{fid}/explain", json={}).json()["source"] == "rule"
    stub_llm(monkeypatch, GOOD)  # mentions CWE-89, which is in the finding
    assert client.post(f"/api/findings/{fid}/explain", json={"refresh": True}).json()["source"] == "ai"


@pytest.mark.parametrize("payload", ["not json at all", '{"what_happened": "x"}', '["a"]',
                                     {"what_happened": "", "why_it_matters": "y", "recommended": []}])
def test_malformed_ai_output_falls_back_safely(client, monkeypatch, payload):
    fid = _seed_finding(client)
    stub_llm(monkeypatch, payload)
    r = client.post(f"/api/findings/{fid}/explain", json={}).json()
    assert r["source"] == "rule" and "unavailable" in r["notice"]


def test_service_failures_and_refusals_fall_back(client, monkeypatch):
    fid = _seed_finding(client)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    from netguard import config
    config.get_settings.cache_clear()

    def boom(*a, **k):
        raise llm.LlmUnavailable("The AI service declined this request")

    monkeypatch.setattr(llm, "complete", boom)
    r = client.post(f"/api/findings/{fid}/explain", json={}).json()
    assert r["source"] == "rule" and "declined" in r["notice"]


def test_json_extraction_handles_code_fences():
    assert llm.extract_json('```json\n{"a": 1}\n```') == {"a": 1}
    assert llm.extract_json('Sure! {"a": 1} hope it helps') == {"a": 1}


def test_explain_requires_access(client, make_client):
    fid = _seed_finding(client)
    other = make_client("other@example.com")
    assert other.post(f"/api/findings/{fid}/explain", json={}).status_code == 404


def test_dependency_facts_use_scanner_data_only():
    from netguard.models import Finding

    f = Finding(id="1", project_id="p", scanner="dependencies", rule_id="dep.osv", fingerprint="x",
                title="t", severity="high", confidence="high", description="d", impact="i",
                remediation="Upgrade x to 2.0.", cwe="", references=[],
                extra={"package": "qs", "version": "6.11.0", "cve": "CVE-2099-0001",
                       "fixed_versions": ["6.11.1"]})
    labels = {d["label"]: d["value"] for d in explain_module.facts(f)}
    assert labels["Package"] == "qs" and labels["Fixed in"] == "6.11.1" and labels["CVE"] == "CVE-2099-0001"
