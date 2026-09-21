import pytest

from netguard.scanners.sast.catalog import all_rules
from netguard.scanners.sast.engine import scan_text_with_rules

# (rule id, vulnerable snippet, safe snippet that must NOT trigger that rule)
CASES = [
    ("js.eval", "const r = eval(req.body.code);", "const r = JSON.parse(x);"),
    ("js.command-injection", "exec(`ls ${req.query.dir}`);", "execFile('ls', [dir]);"),
    ("js.command-injection", "child_process.exec('ping ' + host);", "re.exec(text);"),
    ("js.sql-injection", "db.query(`SELECT * FROM users WHERE id = ${id}`);",
     "db.query('SELECT * FROM users WHERE id = $1', [id]);"),
    ("js.sql-injection", "db.query(\"DELETE FROM t WHERE a='\" + a + \"'\");",
     "db.query('SELECT 1');"),
    ("js.nosql-injection", "User.findOne(req.body);", "User.findOne({ name: String(req.body.name) });"),
    ("js.innerhtml", "el.innerHTML = userComment;", "el.innerHTML = '<b>static</b>';"),
    ("js.document-write", "document.write(location.hash);", "document.write('<p>hi</p>');"),
    ("js.react-dangerously-set-html", "<div dangerouslySetInnerHTML={{__html: html}} />", "<div>{text}</div>"),
    ("js.reflected-xss", "res.send('<h1>' + req.query.name + '</h1>');", "res.json({ ok: true });"),
    ("js.path-traversal", "fs.readFile(path.join(root, req.params.file), cb);", "fs.readFile('/etc/app.conf', cb);"),
    ("js.ssrf", "axios.get(req.query.url);", "axios.get('https://api.example.com/x');"),
    ("js.open-redirect", "res.redirect(req.query.next);", "res.redirect('/home');"),
    ("js.weak-hash", "crypto.createHash('md5').update(p)", "crypto.createHash('sha256').update(p)"),
    ("js.insecure-random", "const sessionToken = Math.random().toString(36);", "const x = Math.random() * 10;"),
    ("js.tls-verification-disabled", "https.request({ rejectUnauthorized: false })", "https.request({ rejectUnauthorized: true })"),
    ("js.jwt-insecure", "jwt.verify(t, k, { algorithms: ['none'] })", "jwt.verify(t, k, { algorithms: ['HS256'] })"),
    ("js.hardcoded-credential-check", "if (password === 'hunter2') login();", "if (password === stored) login();"),
    ("js.insecure-cookie", "cookie: { httpOnly: false }", "cookie: { httpOnly: true }"),
    ("js.cors-permissive", "app.use(cors({ origin: '*' }));", "app.use(cors({ origin: 'https://a.example' }));"),
    ("js.unsafe-deserialization", "const s = require('node-serialize');", "const s = JSON.parse(x);"),
    ("js.vm-context", "vm.runInNewContext(code, sandbox);", "vm.isContext(x);"),
    ("js.prototype-pollution", "obj['__proto__'].x = 1;", "obj.proto = 1;"),
    ("js.file-permissions", "fs.chmodSync(p, 0o777);", "fs.chmodSync(p, 0o600);"),
]


@pytest.mark.parametrize("rule_id,bad,good", CASES, ids=[f"{c[0]}:{i}" for i, c in enumerate(CASES)])
def test_rule_detects_vulnerable_and_ignores_safe(rule_id, bad, good):
    rules = all_rules()
    hit = [f.rule_id for f in scan_text_with_rules(rules, "a.js", "javascript", bad)]
    assert rule_id in hit, f"{rule_id} missed: {bad}"
    miss = [f.rule_id for f in scan_text_with_rules(rules, "a.js", "javascript", good)]
    assert rule_id not in miss, f"{rule_id} false positive: {good}"


def test_typescript_files_use_the_same_rules():
    rules = all_rules()
    assert scan_text_with_rules(rules, "a.ts", "typescript", "el.innerHTML = x;")


def test_js_rules_do_not_fire_on_other_languages():
    assert scan_text_with_rules(all_rules(), "a.py", "python", "el.innerHTML = x") == []


def test_every_js_rule_is_exercised_by_a_test_case():
    from netguard.scanners.sast.rules_js import RULES

    tested = {c[0] for c in CASES}
    assert {r.id for r in RULES} == tested
