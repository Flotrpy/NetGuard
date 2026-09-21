import pytest

from netguard.enums import Confidence, Severity
from netguard.services.risk import METHODOLOGY, compute_risk, severity_counts


def test_max_score_is_ten_for_critical_certain_internet_facing():
    assert compute_risk("critical", "high", "high", "internet") == 10.0


def test_score_monotonic_in_each_dimension():
    base = compute_risk("medium", "medium", "medium", "unknown")
    assert compute_risk("high", "medium", "medium", "unknown") > base
    assert compute_risk("medium", "high", "medium", "unknown") > base
    assert compute_risk("medium", "medium", "high", "unknown") > base
    assert compute_risk("medium", "medium", "medium", "internet") > base
    assert compute_risk("medium", "low", "medium", "unknown") < base


def test_severity_ordering_dominates_for_equal_context():
    scores = [compute_risk(s, "medium") for s in ("info", "low", "medium", "high", "critical")]
    assert scores == sorted(scores) and len(set(scores)) == 5


def test_accepts_enums_and_unknown_context_falls_back():
    assert compute_risk(Severity.HIGH, Confidence.HIGH, "weird", "weird") == compute_risk(
        "high", "high", "medium", "unknown"
    )


def test_invalid_severity_rejected():
    with pytest.raises(ValueError):
        compute_risk("catastrophic", "high")


def test_methodology_documents_every_factor_used():
    assert set(METHODOLOGY["severity_base"]) == {s.value for s in Severity}
    assert "never" in " ".join(METHODOLOGY["notes"]).lower()


def test_severity_counts_includes_zero_buckets():
    counts = severity_counts(["high", "high", "low"])
    assert counts == {"critical": 0, "high": 2, "medium": 0, "low": 1, "info": 0}
