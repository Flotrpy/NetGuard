import pytest

from netguard.core import security


def test_password_hash_roundtrip_and_salting():
    h1 = security.hash_password("correct horse battery")
    h2 = security.hash_password("correct horse battery")
    assert h1 != h2  # unique salts
    assert security.verify_password("correct horse battery", h1)
    assert not security.verify_password("wrong password!!", h1)


def test_verify_rejects_malformed_hash():
    assert not security.verify_password("x", "not-a-hash")
    assert not security.verify_password("x", "bcrypt$1$2$3$4$5")


def test_hash_embeds_parameters_so_they_can_be_upgraded():
    h = security.hash_password("another-long-password", n=2**11)
    assert h.split("$")[1] == str(2**11)
    assert security.verify_password("another-long-password", h)


@pytest.mark.parametrize(
    "password,email",
    [("short", ""), ("a" * 200, ""), ("aaaaaaaaaaaa", ""), ("affanshaik-pass1", "affanshaik@x.io")],
)
def test_password_policy_rejects_weak(password, email):
    with pytest.raises(security.PasswordPolicyError):
        security.validate_password_strength(password, email)


def test_password_policy_accepts_reasonable_password():
    security.validate_password_strength("Tr1cky-passphrase-here", "someone@example.com")


def test_tokens_are_random_and_hashed_deterministically():
    a, b = security.generate_token(), security.generate_token()
    assert a != b and len(a) >= 40
    assert security.hash_token(a) == security.hash_token(a)
    assert security.hash_token(a) != a


def test_secret_encryption_roundtrip_and_empty_passthrough():
    ct = security.encrypt_secret("ghp_exampletoken")
    assert "ghp_" not in ct
    assert security.decrypt_secret(ct) == "ghp_exampletoken"
    assert security.encrypt_secret("") == "" and security.decrypt_secret("") == ""


def test_decrypt_with_wrong_key_fails_cleanly(monkeypatch):
    from netguard import config

    ct = security.encrypt_secret("value")
    monkeypatch.setenv("NETGUARD_SECRET_KEY", "a-completely-different-secret-key-9999999")
    config.get_settings.cache_clear()
    with pytest.raises(ValueError):
        security.decrypt_secret(ct)


def test_constant_time_equals():
    assert security.constant_time_equals("abc", "abc")
    assert not security.constant_time_equals("abc", "abd")
