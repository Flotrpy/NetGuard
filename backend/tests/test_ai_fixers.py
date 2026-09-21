import ast

import pytest

from netguard.models import Finding
from netguard.services.ai.fixers import FIXERS, get_fixer


def finding(rule, line, file="app.py", language="python", extra=None):
    return Finding(id="f", project_id="p", scanner="sast", rule_id=rule, fingerprint="x", title="t",
                   severity="high", confidence="high", file_path=file, line=line, language=language,
                   extra=extra or {})


def apply(rule, text, line, **kw):
    fixer = get_fixer(rule)
    assert fixer, rule
    return fixer(finding(rule, line, **kw), text)


def test_python_weak_hash():
    src = "import hashlib\nh = hashlib.md5(pw.encode()).hexdigest()\n"
    res = apply("py.weak-hash", src, 2)
    assert "hashlib.sha256(pw.encode())" in res.new_text and "md5" not in res.new_text
    assert any("64 hex" in c for c in res.caveats)
    ast.parse(res.new_text)


def test_js_weak_hash_and_tls_and_innerhtml():
    assert "createHash('sha256')" in apply("js.weak-hash", "c.createHash('md5').update(x)", 1, file="a.js").new_text
    assert "rejectUnauthorized: true" in apply("js.tls-verification-disabled", "{ rejectUnauthorized: false }", 1, file="a.js").new_text
    assert "el.textContent = x" in apply("js.innerhtml", "el.innerHTML = x;", 1, file="a.js").new_text


def test_python_tls_and_debug():
    assert "verify=True" in apply("py.tls-verification-disabled", "r = requests.get(u, verify=False)", 1).new_text
    assert "debug=False" in apply("py.debug-enabled", "app.run(debug=True)", 1).new_text
    assert apply("py.debug-enabled", "DEBUG = True", 1).new_text == "DEBUG=False"


def test_yaml_load_fixed_but_pickle_is_not():
    res = apply("py.unsafe-deserialization", "cfg = yaml.load(s, Loader=yaml.Loader)", 1)
    assert res.new_text == "cfg = yaml.safe_load(s)"
    assert apply("py.unsafe-deserialization", "obj = pickle.loads(b)", 1) is None


def test_insecure_random_uses_secrets_and_adds_import():
    src = "import os\n\ntoken = random.choice(ALPHABET)\n"
    res = apply("py.insecure-random", src, 3)
    assert "secrets.choice(ALPHABET)" in res.new_text and "import secrets" in res.new_text
    ast.parse(res.new_text)
    res2 = apply("py.insecure-random", "import x\notp = random.randint(100000, 999999)\n", 2)
    assert "secrets.randbelow(999999 - 100000 + 1) + 100000" in res2.new_text


def test_no_change_means_no_fix():
    assert apply("py.weak-hash", "x = 1\n", 1) is None
    assert apply("py.weak-hash", "hashlib.md5(x)", 99) is None  # bad line number


def test_secret_python_becomes_env_lookup_with_rotation_caveat():
    src = 'import sys\n\nAPI_TOKEN = "abcdefghijklmnop1234"  # prod\n'
    res = apply("secret.generic-secret-assignment", src, 3)
    assert 'API_TOKEN = os.environ["API_TOKEN"]  # prod' in res.new_text and "import os" in res.new_text
    assert "abcdefghij" not in res.new_text
    assert any("ROTATE" in c for c in res.caveats)
    ast.parse(res.new_text)


def test_secret_js_and_dotenv():
    js = apply("secret.github-token", "const apiKey = 'abcdefghijklmnop1234';", 1, file="c.js")
    assert "process.env.API_KEY" in js.new_text and "abcdefgh" not in js.new_text
    env = apply("secret.dotenv-secret", "DB_PASSWORD=supersecretvalue1\nOTHER=1\n", 1, file=".env")
    assert env.new_text == "DB_PASSWORD=\nOTHER=1\n" and any("gitignore" in c for c in env.caveats)


DEP_EXTRA = {"package": "django", "version": "3.2.0", "fixed_versions": ["3.2.5"], "vulnerability": "PYSEC-1"}


def dep(text, file, extra=None, pkg=None):
    e = dict(DEP_EXTRA, **(extra or {}))
    return apply("dep.osv", text, 1, file=file, extra=e)


def test_dependency_bump_in_requirements_package_json_pom_csproj():
    r = dep("Django==3.2.0\nrequests==2.0\n", "requirements.txt")
    assert r.new_text == "Django==3.2.5\nrequests==2.0\n" and "PYSEC-1" in r.explanation
    p = dep('{"dependencies": {"lodash": "4.17.4"}}', "package.json",
            {"package": "lodash", "version": "4.17.4", "fixed_versions": ["4.17.21"]})
    assert '"lodash": "4.17.21"' in p.new_text
    pom = dep("<dependency><artifactId>snakeyaml</artifactId><version>1.30</version></dependency>", "pom.xml",
              {"package": "org.yaml:snakeyaml", "version": "1.30", "fixed_versions": ["1.33"]})
    assert "<version>1.33</version>" in pom.new_text
    cs = dep('<PackageReference Include="Newtonsoft.Json" Version="9.0.1" />', "a.csproj",
             {"package": "Newtonsoft.Json", "version": "9.0.1", "fixed_versions": ["13.0.1"]})
    assert 'Version="13.0.1"' in cs.new_text


def test_dependency_in_lockfile_or_without_fix_version_is_not_mechanically_fixable():
    assert dep('{"packages": {}}', "package-lock.json") is None
    assert dep("Django==3.2.0", "requirements.txt", {"fixed_versions": []}) is None


@pytest.mark.parametrize("rule", sorted(FIXERS))
def test_every_registered_fixer_declines_unrelated_text(rule):
    fixer = FIXERS[rule]
    assert fixer(finding(rule, 1, extra={}), "print('hello')\n") is None
