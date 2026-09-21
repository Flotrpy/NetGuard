import dataclasses
import io
import json
import random
import string
import zipfile

import pytest

from netguard.scanners.base import ScanContext
from netguard.scanners.registry import get_scanner
from netguard.scanners.secrets.scanner import scan_text
from netguard.worker import process_one

ALNUM = string.ascii_letters + string.digits


def fake(n: int, seed: int = 1, alphabet: str = ALNUM) -> str:
    """Deterministic random-looking value. Built at runtime so no token-shaped string is
    ever committed to the repository."""
    rng = random.Random(seed)
    return "".join(rng.choice(alphabet) for _ in range(n))


SALT = "test-salt"


def scan(text, path="src/app.py", salt=SALT):
    return scan_text(path, text, salt)


def everything(finding) -> str:
    return json.dumps(dataclasses.asdict(finding), default=str)


# (rule id, line containing a fake secret, the secret itself)
def cases():
    aws = "AKIA" + fake(16, 2, string.ascii_uppercase + string.digits)
    gh = "ghp_" + fake(36, 3)
    gh_pat = "github_pat_" + fake(40, 4)
    gl = "glpat-" + fake(20, 5)
    slack = "xoxb-" + fake(12, 6, string.digits) + "-" + fake(24, 6)
    hook = "https://hooks.slack.com/services/T" + fake(8, 7, string.ascii_uppercase + string.digits) + \
        "/B" + fake(8, 8, string.ascii_uppercase + string.digits) + "/" + fake(24, 9)
    stripe = "sk_live_" + fake(24, 10)
    google = "AIza" + fake(35, 11, string.ascii_letters + string.digits + "_-")
    sendgrid = "SG." + fake(22, 12) + "." + fake(43, 13)
    npm_tok = "npm_" + fake(36, 14)
    ant = "sk-ant-" + fake(40, 15, string.ascii_letters + string.digits + "-_")
    dburl_pw = fake(16, 16)
    return [
        ("aws-access-key-id", f'AWS_KEY = "{aws}"', aws),
        ("github-token", f"token: {gh}", gh),
        ("github-fine-grained-token", f"export T={gh_pat}", gh_pat),
        ("gitlab-token", f"GITLAB={gl}", gl),
        ("slack-token", f"slack = '{slack}'", slack),
        ("slack-webhook", f"url = '{hook}'", hook),
        ("stripe-live-key", f'stripe.api_key = "{stripe}"', stripe),
        ("google-api-key", f'key = "{google}"', google),
        ("sendgrid-key", f"SENDGRID={sendgrid}", sendgrid),
        ("npm-token", f"//registry.npmjs.org/:_authToken={npm_tok}", npm_tok),
        ("anthropic-key", f"KEY={ant}", ant),
        ("database-url", f'DATABASE_URL = "postgres://app:{dburl_pw}@db.internal:5432/app"', dburl_pw),
    ]


@pytest.mark.parametrize("rule,line,secret", cases(), ids=[c[0] for c in cases()])
def test_provider_secret_detected_and_never_exposed(rule, line, secret):
    findings = scan(f"# config\n{line}\nprint('done')\n")
    hit = [f for f in findings if f.rule_id == f"secret.{rule}"]
    assert len(hit) == 1, [f.rule_id for f in findings]
    f = hit[0]
    assert f.line == 2 and f.category == "Exposed Secret" and f.cwe.startswith("CWE-")
    assert secret not in everything(f), "full secret leaked into a finding field"
    assert secret[:-2] not in f.code_context
    assert "*" in f.extra["redacted"] and f.extra["redacted"].endswith(secret[-2:])
    assert "rotate" in f.remediation.lower() and "git history" in f.remediation


def test_severity_reflects_credential_type():
    stripe = "sk_live_" + fake(24, 10)
    test_key = "sk_test_" + fake(24, 11)
    by = {f.rule_id: f for f in scan(f"a = '{stripe}'\nb = '{test_key}'\n")}
    assert by["secret.stripe-live-key"].severity.value == "critical"
    assert by["secret.stripe-test-key"].severity.value == "low"


def test_private_key_never_shows_key_body():
    body = fake(64, 20)
    text = f"-----BEGIN RSA PRIVATE KEY-----\n{body}\n{fake(64, 21)}\n-----END RSA PRIVATE KEY-----\n"
    (f,) = scan(text, "deploy/id_rsa")
    assert f.rule_id == "secret.private-key" and f.severity.value == "critical" and f.line == 1
    assert body not in everything(f) and "MII" not in f.code_context
    assert f.code_context.count("\n") == 0  # header line only


def test_gcp_service_account_key_body_is_omitted_even_on_same_line():
    body = fake(80, 22)
    text = '{"type": "service_account", "private_key": "-----BEGIN PRIVATE KEY-----\\n' + body + '\\n-----END PRIVATE KEY-----\\n"}'
    findings = scan(text, "sa.json")
    assert [f.rule_id for f in findings] == ["secret.gcp-service-account"]
    assert body not in everything(findings[0])


def test_generic_assignment_requires_entropy_and_ignores_placeholders():
    real = fake(32, 30)
    assert [f.rule_id for f in scan(f'api_key = "{real}"')] == ["secret.generic-secret-assignment"]
    for benign in [
        'api_key = "changeme"',
        'password = "your_password_here"',
        'secret = "${SECRET_VALUE}"',
        'token = os.environ["API_TOKEN"]',
        'password_field = "user_password_input"',
        'password = "aaaaaaaaaaaa"',
        'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"',
    ]:
        assert scan(benign) == [], benign


def test_generic_confidence_scales_with_entropy():
    strong = scan(f'client_secret = "{fake(40, 31)}"')[0]
    weak = scan('client_secret = "Welcome2024x"')
    assert strong.confidence.value == "medium"
    assert all(f.confidence.value == "low" for f in weak)


def test_database_url_placeholder_and_no_double_reporting():
    assert scan('u = "postgres://user:password@localhost/db"') == []
    findings = scan(f'u = "mysql://root:{fake(14, 32)}@db/app"')
    assert [f.rule_id for f in findings] == ["secret.database-url"]  # not also basic-auth/generic


def test_dotenv_rule_only_applies_to_env_files():
    line = f"STRIPE_WEBHOOK_SECRET={fake(30, 33)}\n"
    assert scan(line, ".env.production")[0].rule_id == "secret.dotenv-secret"
    assert scan(line, "notes.txt") == []


def test_low_trust_paths_reduce_confidence():
    line = f'api_key = "{fake(32, 34)}"'
    normal = scan(line, "src/a.py")[0]
    test = scan(line, "tests/fixtures/a.py")[0]
    assert normal.confidence.value == "medium" and test.confidence.value == "low"
    assert "test/example path" in test.description


def test_inline_suppression():
    gh = "ghp_" + fake(36, 3)
    assert scan(f"t = '{gh}'  # netguard:ignore secret.github-token") == []
    assert scan(f"t = '{gh}'  # netguard:ignore") == []


def test_context_redacts_neighbouring_secrets_too():
    a, b = "ghp_" + fake(36, 40), "sk_live_" + fake(24, 41)
    (fa, fb) = sorted(scan(f"a = '{a}'\nb = '{b}'\n"), key=lambda f: f.line)
    assert b not in fa.code_context and a not in fb.code_context


def test_fingerprint_key_is_salted_hmac_and_stable_across_line_shifts():
    gh = "ghp_" + fake(36, 3)
    f1 = scan(f"x = '{gh}'")[0]
    f2 = scan(f"\n\n\nx = '{gh}'")[0]
    other = scan(f"x = '{'ghp_' + fake(36, 4)}'")[0]
    assert f1.key == f2.key and f1.key != other.key
    assert scan(f"x = '{gh}'", salt="another-salt")[0].key != f1.key
    assert gh not in f1.key and len(f1.key) == 32


def test_scanner_skips_lockfiles_binaries_and_reports_history_limit(tmp_path):
    gh = "ghp_" + fake(36, 3)
    (tmp_path / "package-lock.json").write_text(f'{{"x": "{gh}"}}')
    (tmp_path / "blob.bin").write_bytes(b"\x00\x01" + gh.encode())
    (tmp_path / "config.py").write_text(f"T = '{gh}'\n")
    res = get_scanner("secrets").scan(ScanContext(root=tmp_path, runtime={"fingerprint_salt": SALT}))
    assert [f.file_path for f in res.findings] == ["config.py"]
    assert res.metadata["history_scanned"] is False and "history" in res.warnings[0]


# ---- end to end through the API: findings never expose the secret ------------------------------
def make_zip(files):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for n, c in files.items():
            zf.writestr(n, c)
    return buf.getvalue()


def test_api_never_returns_the_secret_and_dedupes_across_rescans(client):
    gh = "ghp_" + fake(36, 3)
    db_pw = fake(16, 50)
    files = {"src/config.py": f"TOKEN = '{gh}'\nDB = 'postgres://u:{db_pw}@h/d'\n"}
    client.register()
    p = client.post("/api/projects", json={"name": "P"}).json()
    repo = client.post(f"/api/projects/{p['id']}/repositories", json={"name": "r"}).json()
    client.post(f"/api/repositories/{repo['id']}/upload",
                files={"file": ("a.zip", make_zip(files), "application/zip")})

    def scan_once():
        r = client.post(f"/api/projects/{p['id']}/scans",
                        json={"scanners": ["secrets"], "repository_id": repo["id"]})
        assert r.status_code == 202, r.text
        process_one("w")
        return client.get(f"/api/scans/{r.json()['id']}").json()

    first = scan_once()
    assert first["status"] == "completed" and first["summary"]["scanners"]["secrets"]["findings"] == 2
    second = scan_once()
    assert second["summary"]["scanners"]["secrets"]["ingest"]["new"] == 0

    listing = client.get("/api/findings", params={"project_id": p["id"]})
    detail_texts = [listing.text]
    for item in listing.json()["items"]:
        detail_texts.append(client.get(f"/api/findings/{item['id']}").text)
    blob = "\n".join(detail_texts)
    assert gh not in blob and db_pw not in blob
    assert "ghp_" in blob  # the redacted prefix is still shown
    assert all(i["detection_source"] == "Secret Scanner" for i in listing.json()["items"])
