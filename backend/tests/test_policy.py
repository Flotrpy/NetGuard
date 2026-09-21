import pytest
from pydantic import ValidationError

from netguard.services.policy import Policy, PolicyFinding, evaluate


def F(sev, scanner="sast", new=False, **kw):
    return PolicyFinding(severity=sev, scanner=scanner, is_new=new, **kw)


def test_default_policy_passes_when_only_low_and_medium_findings():
    res = evaluate([F("low"), F("low"), F("medium"), F("info")])
    assert res.passed and res.violations == [] and res.counts["low"] == 2


def test_default_policy_fails_on_any_critical():
    res = evaluate([F("critical")])
    assert not res.passed and res.violations[0].rule == "max_critical"


def test_new_high_fails_but_preexisting_high_does_not():
    assert evaluate([F("high", new=False)]).passed
    res = evaluate([F("high", new=True), F("high", new=False)])
    assert not res.passed and res.violations[0].rule == "max_new_high" and res.new_counts["high"] == 1


def test_secrets_fail_by_default_and_can_be_disabled():
    assert not evaluate([F("low", scanner="secrets")]).passed
    assert evaluate([F("low", scanner="secrets")], Policy(fail_on_secrets=False)).passed


def test_thresholds_are_configurable():
    p = Policy(max_critical=None, max_new_high=None, max_high=2, fail_on_secrets=False)
    assert evaluate([F("high"), F("high")], p).passed
    assert not evaluate([F("high")] * 3, p).violations == []
    strict = Policy(fail_on_severity="medium", max_critical=None, max_new_high=None)
    assert not evaluate([F("medium")], strict).passed and evaluate([F("low")], strict).passed


def test_triaged_and_low_confidence_findings_are_ignored():
    findings = [F("critical", status="false_positive"), F("critical", status="fixed"),
                F("critical", status="accepted_risk")]
    assert evaluate(findings).passed
    assert evaluate([F("critical", confidence="low")], Policy(min_confidence="medium")).passed
    assert not evaluate([F("critical", confidence="high")], Policy(min_confidence="medium")).passed


def test_ignored_scanners():
    assert evaluate([F("critical", scanner="dependencies")], Policy(ignore_scanners=["dependencies"])).passed


def test_low_severity_never_fails_default_policy_even_in_bulk():
    assert evaluate([F("low")] * 500).passed


def test_policy_validation_rejects_bad_values():
    with pytest.raises(ValidationError):
        Policy(max_critical=-1)
    with pytest.raises(ValidationError):
        Policy(fail_on_severity="catastrophic")
    with pytest.raises(ValidationError):
        Policy(min_confidence="certain")
