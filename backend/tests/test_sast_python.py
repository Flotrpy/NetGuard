import textwrap

import pytest

from netguard.scanners.sast import python_analyzer
from netguard.scanners.sast.python_rules import PY_RULES


def rules_hit(src: str) -> set[str]:
    return {f.rule_id for f in python_analyzer.analyze("app.py", textwrap.dedent(src))}


def findings(src: str):
    return python_analyzer.analyze("app.py", textwrap.dedent(src))


# (rule id, vulnerable source, safe source)
CASES = [
    ("py.sql-injection",
     "def f(cur, uid):\n    cur.execute(f\"SELECT * FROM users WHERE id = {uid}\")",
     "def f(cur, uid):\n    cur.execute('SELECT * FROM users WHERE id = %s', (uid,))"),
    ("py.sql-injection",
     "def f(cur, n):\n    q = \"SELECT * FROM t WHERE n = '\" + n + \"'\"\n    cur.execute(q)",
     "def f(cur):\n    q = 'SELECT 1'\n    cur.execute(q)"),
    ("py.command-injection",
     "import os\ndef f(host):\n    os.system('ping ' + host)",
     "import os\nos.system('ls')"),
    ("py.command-injection",
     "import subprocess\ndef f(d):\n    subprocess.run(f'ls {d}', shell=True)",
     "import subprocess\ndef f(d):\n    subprocess.run(['ls', d])"),
    ("py.subprocess-shell-true",
     "import subprocess\nsubprocess.run('ls -la', shell=True)",
     "import subprocess\nsubprocess.run(['ls', '-la'])"),
    ("py.code-injection", "def f(x):\n    return eval(x)", "eval('1 + 1')"),
    ("py.unsafe-deserialization", "import pickle\ndef f(b):\n    return pickle.loads(b)", "import json\njson.loads('{}')"),
    ("py.unsafe-deserialization", "import yaml\nyaml.load(open('c.yml'))", "import yaml\nyaml.safe_load(open('c.yml'))"),
    ("py.unsafe-deserialization", "import yaml\nyaml.load(s, Loader=yaml.Loader)", "import yaml\nyaml.load(s, Loader=yaml.SafeLoader)"),
    ("py.weak-hash", "import hashlib\nhashlib.md5(b'x')", "import hashlib\nhashlib.sha256(b'x')"),
    ("py.weak-hash", "import hashlib\nhashlib.sha1(b'x')", "import hashlib\nhashlib.md5(b'x', usedforsecurity=False)"),
    ("py.weak-cipher", "from Crypto.Cipher import DES\nDES.new(k)", "from Crypto.Cipher import AES\nAES.new(k, AES.MODE_GCM)"),
    ("py.weak-cipher", "from Crypto.Cipher import AES\nAES.new(k, AES.MODE_ECB)", "x = 1"),
    ("py.insecure-random", "import random\nsession_token = random.randint(0, 10**9)", "import random\nroll = random.randint(1, 6)"),
    ("py.insecure-random", "import random\ndef make_password():\n    return random.choice('abc')", "import random\ndef pick_color():\n    return random.choice('abc')"),
    ("py.tls-verification-disabled", "import requests\nrequests.get(u, verify=False)", "import requests\nrequests.get(u, verify=True)"),
    ("py.tls-verification-disabled", "import ssl\nctx = ssl._create_unverified_context()", "import ssl\nctx = ssl.create_default_context()"),
    ("py.debug-enabled", "app.run(debug=True)", "app.run(debug=False)"),
    ("py.debug-enabled", "DEBUG = True", "DEBUG = False"),
    ("py.path-traversal", "from flask import request\ndef f():\n    return open(request.args['f']).read()", "def f():\n    return open('/etc/app.conf').read()"),
    ("py.archive-extraction", "import tarfile\nt = tarfile.open('a.tar')\nt.extractall('/tmp/x')", "import tarfile\nt = tarfile.open('a.tar')\nt.extractall('/tmp/x', filter='data')"),
    ("py.ssrf", "import requests\nfrom flask import request\nrequests.get(request.args['url'])", "import requests\nrequests.get('https://api.example.com')"),
    ("py.template-injection", "from flask import request, render_template_string\nrender_template_string(request.args['t'])", "from flask import render_template_string\nrender_template_string('<p>hi</p>')"),
    ("py.reflected-xss", "from flask import request\nfrom markupsafe import Markup\nMarkup(request.args['n'])", "from markupsafe import Markup\nMarkup('<b>ok</b>')"),
    ("py.open-redirect", "from flask import request, redirect\ndef f():\n    return redirect(request.args['next'])", "from flask import redirect\nredirect('/home')"),
    ("py.insecure-tempfile", "import tempfile\ntempfile.mktemp()", "import tempfile\ntempfile.mkstemp()"),
    ("py.xxe", "import xml.etree.ElementTree as ET\nfrom flask import request\nET.fromstring(request.data)", "import xml.etree.ElementTree as ET\nET.fromstring('<a/>')"),
    ("py.hardcoded-credential-check", "def login(password):\n    if password == 'hunter2':\n        return True", "def login(password, stored):\n    if password == stored:\n        return True"),
    ("py.jwt-insecure", "import jwt\njwt.decode(t, key, algorithms=['none'])", "import jwt\njwt.decode(t, key, algorithms=['HS256'])"),
    ("py.jwt-insecure", "import jwt\njwt.decode(t, options={'verify_signature': False})", "import jwt\njwt.decode(t, key, algorithms=['HS256'])"),
    ("py.csrf-exempt", "@csrf_exempt\ndef view(request):\n    pass", "def view(request):\n    pass"),
    ("py.permission-allow-any", "@permission_classes([AllowAny])\ndef v(request):\n    pass", "@permission_classes([IsAuthenticated])\ndef v(request):\n    pass"),
    ("py.insecure-cookie", "resp.set_cookie('s', v, httponly=False)", "resp.set_cookie('s', v, httponly=True, secure=True)"),
    ("py.insecure-cookie", "SESSION_COOKIE_SECURE = False", "SESSION_COOKIE_SECURE = True"),
    ("py.file-permissions", "import os\nos.chmod(p, 0o777)", "import os\nos.chmod(p, 0o600)"),
]


@pytest.mark.parametrize("rule_id,bad,good", CASES, ids=[f"{c[0]}:{i}" for i, c in enumerate(CASES)])
def test_rule_detects_vulnerable_and_ignores_safe(rule_id, bad, good):
    assert rule_id in rules_hit(bad), f"{rule_id} missed:\n{bad}"
    assert rule_id not in rules_hit(good), f"{rule_id} false positive:\n{good}"


def test_every_python_rule_has_a_test_case():
    assert {c[0] for c in CASES} == set(PY_RULES)


def test_tainted_flow_raises_confidence_and_says_so():
    tainted = findings(
        """
        from flask import request
        def view():
            name = request.args["name"]
            os.system("echo " + name)
        """
    )[0]
    assert tainted.confidence.value == "high" and tainted.extra["tainted"] is True
    assert "request-controlled" in tainted.description

    untainted = findings("import os\ndef f(x):\n    os.system('echo ' + x)")[0]
    assert untainted.confidence.value == "medium" and untainted.extra["tainted"] is False


def test_taint_propagates_through_assignments_and_fstrings():
    hits = rules_hit(
        """
        from flask import request
        def v(cur):
            a = request.form["x"]
            b = a.strip()
            q = f"SELECT * FROM t WHERE c = '{b}'"
            cur.execute(q)
        """
    )
    assert "py.sql-injection" in hits


def test_sanitizers_stop_taint():
    # The command string is still dynamic (so it is reported), but no longer traced to the request.
    findings_ = findings(
        """
        import os
        from flask import request
        def v():
            n = int(request.args["n"])
            os.system("sleep " + str(n))
        """
    )
    assert all(not f.extra["tainted"] for f in findings_)


def test_route_parameters_are_treated_as_user_input():
    fs = findings(
        """
        @app.route('/files/<name>')
        def get(name):
            return open(name).read()
        """
    )
    assert [f.rule_id for f in fs] == ["py.path-traversal"]


def test_typed_int_route_params_are_not_tainted():
    assert findings(
        """
        @app.get('/u/{uid}')
        def get(uid: int):
            return open(uid)
        """
    ) == []


def test_findings_have_location_context_and_metadata():
    f = findings("import os\n\n\ndef f(x):\n    os.system('a' + x)\n")[0]
    assert (f.file_path, f.line, f.language, f.cwe) == ("app.py", 5, "python", "CWE-78")
    assert "5:     os.system('a' + x)" in f.code_context
    assert f.remediation and f.impact and f.references


def test_inline_suppression_and_same_line_deduplication():
    src = "import hashlib\nhashlib.md5(b'x')  # netguard:ignore py.weak-hash\n"
    assert rules_hit(src) == set()
    src2 = "eval(a); eval(b)\n"
    assert len(findings(src2)) == 1  # one finding per rule per line


def test_syntax_errors_raise_for_the_engine_to_report():
    with pytest.raises(SyntaxError):
        python_analyzer.analyze("bad.py", "def (:")
