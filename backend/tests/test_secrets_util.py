import pytest

from netguard.scanners.secrets.patterns import RULES, guidance_for
from netguard.scanners.secrets.util import (
    char_classes,
    is_placeholder,
    redact,
    shannon_entropy,
)


def test_redaction_keeps_prefix_and_last_two_only():
    secret = "sk_live_" + "a1B2c3D4e5F6g7H8i9J0" + "92"
    red = redact(secret, "sk_live_")
    assert red.startswith("sk_live_") and red.endswith("92")
    assert set(red[8:-2]) == {"*"} and len(red) == len(secret)
    assert secret[8:-2] not in red


def test_short_values_are_fully_masked_and_unknown_prefixes_not_kept():
    assert set(redact("hunter22")) == {"*"}
    long = "correcthorsebatterystaple"
    assert redact(long, "zzz").startswith("*")  # prefix that isn't actually there is ignored
    assert redact(long)[-2:] == long[-2:]


def test_entropy_orders_random_above_words():
    assert shannon_entropy("aaaaaaaa") == 0
    assert shannon_entropy("Xk9$pQ2vLm7ZrT4w") > 3.5 > shannon_entropy("passwordpassword")
    assert shannon_entropy("") == 0
    assert char_classes("Abc123!") == 4 and char_classes("abc") == 1


@pytest.mark.parametrize("value", [
    "changeme", "your_api_key_here", "<YOUR-TOKEN>", "${DB_PASSWORD}", "process.env.API_KEY",
    "os.environ['X']", "xxxxxxxxxxxx", "aaaaaaaaaaaa", "{{ secret }}", "EXAMPLEKEYVALUE12",
    "dummy-secret-value",
])
def test_placeholders_detected(value):
    assert is_placeholder(value)


@pytest.mark.parametrize("value", ["Xk9$pQ2vLm7ZrT4w", "q8Zr2LpTn5VbHc7WdXyK"])
def test_real_looking_values_are_not_placeholders(value):
    assert not is_placeholder(value)


def test_rule_ids_unique_and_groups_valid():
    ids = [r.id for r in RULES]
    assert len(ids) == len(set(ids))
    for r in RULES:
        assert r.group <= r.pattern.groups
        assert r.cwe.startswith("CWE-")


def test_guidance_mentions_rotation_and_history_and_provider():
    rule = next(r for r in RULES if r.id == "github-token")
    text = guidance_for(rule)
    assert "revoke or rotate" in text.lower() and "git history" in text and "github.com/settings/tokens" in text
    assert "password" in guidance_for(next(r for r in RULES if r.id == "database-url")).lower()
