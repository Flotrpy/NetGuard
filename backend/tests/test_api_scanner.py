import base64
import json

import pytest

from netguard.scanners.api.rules import RULES
from netguard.scanners.api.scanner import _Run
from netguard.scanners.api.spec import SpecError, fill_path, parse_spec
from netguard.scanners.base import ScanContext
from netguard.scanners.registry import get_scanner
from tests.api_servers import SPEC, Api, GoodHandler, WeakHandler
from tests.test_network_scanner import make_cert


@pytest.fixture
def api():
    made = []

    def make(handler, cert=None):
        GoodHandler.hits = 0
        s = Api(handler, cert)
        made.append(s)
        return s

    yield make
    for s in made:
        s.close()


def scan(server, **cfg):
    config = {"base_url": server.url, "ip": "127.0.0.1", **cfg}
    return get_scanner("api").scan(ScanContext(config=config, runtime={"allow_public_targets": False}))


def rules(result):
    return sorted({f.rule_id for f in result.findings})


def by_rule(result, rule):
    return [f for f in result.findings if f.rule_id == rule]


# ---- spec parsing ------------------------------------------------------------------------------
def test_spec_parsing_json_and_yaml_and_security_inheritance():
    spec = parse_spec(json.dumps(SPEC))
    ops = {(o.method, o.path): o for o in spec.operations}
    assert set(ops) == {("GET", "/users/me"), ("GET", "/public/info"), ("GET", "/search"), ("POST", "/items"), ("DELETE", "/items/{id}")}
    assert ops[("GET", "/users/me")].requires_auth and not ops[("GET", "/public/info")].requires_auth
    assert ops[("POST", "/items")].security is None and ops[("POST", "/items")].has_request_body
    assert [p.name for p in ops[("GET", "/search")].params] == ["q", "api_key"]
    assert set(spec.security_schemes) == {"bearer", "basic", "key"} and spec.title == "Test API"
    yaml_spec = "openapi: 3.0.0\ninfo: {title: Y}\nsecurity: [{k: []}]\npaths:\n  /a:\n    get: {}\n"
    assert parse_spec(yaml_spec).operations[0].requires_auth  # global security is inherited


def test_swagger2_and_refs_and_invalid_specs():
    sw = {"swagger": "2.0", "host": "h.example", "schemes": ["https"], "basePath": "/v1",
          "securityDefinitions": {"k": {"type": "apiKey", "in": "header", "name": "X"}},
          "parameters": {"lim": {"name": "limit", "in": "query", "type": "integer"}},
          "paths": {"/a": {"get": {"parameters": [{"$ref": "#/parameters/lim"}]}}}}
    s = parse_spec(json.dumps(sw))
    assert s.servers == ["https://h.example/v1"] and s.operations[0].params[0].name == "limit"
    for bad in ("not a spec", "{}", "[]", '{"openapi": "3", "paths": 5}', "a: [", "x" * 6_000_000):
        with pytest.raises(SpecError):
            parse_spec(bad)
    assert fill_path("/u/{id}/x/{name}", []) == "/u/1/x/1"


# ---- weak API ----------------------------------------------------------------------------------
def test_weak_api_findings_cover_headers_cors_auth_and_errors(api):
    s = api(WeakHandler)
    res = scan(s, max_requests=200)
    got = set(rules(res))
    assert {"api.plaintext-http", "api.version-disclosure", "api.missing-nosniff",
            "api.cors-reflects-origin-credentials", "api.trace-enabled", "api.insecure-cookie",
            "api.verbose-errors", "api.no-rate-limiting", "api.auth-not-enforced",
            "api.server-error-on-bad-input", "api.spec-no-security", "api.spec-weak-scheme",
            "api.spec-sensitive-query-param", "api.spec-plaintext-server"} <= got
    unauth_all = by_rule(res, "api.auth-not-enforced")
    assert {f.extra["where"] for f in unauth_all} == {"GET /users/me", "GET /search"}  # both declare security
    unauth = next(f for f in unauth_all if f.extra["where"] == "GET /users/me")
    assert unauth.title == "Protected endpoint accessible without credentials: GET /users/me"
    assert unauth.severity.value == "high" and unauth.asset.type == "api" and unauth.asset.identifier == s.url
    assert unauth.exposure == "internal" and unauth.cwe == "CWE-306"
    assert "GET /public/info" not in unauth.title  # public endpoint is not a violation
    assert {f.extra["where"] for f in by_rule(res, "api.spec-no-security")} == {"POST /items", "DELETE /items/{id}"}
    assert res.metadata["spec"]["operations"] == 5 and res.metadata["requests_made"] > 30


def test_scanner_is_non_destructive_only_safe_methods_are_ever_sent(api):
    s = api(WeakHandler)
    scan(s, max_requests=200)
    assert s.methods <= {"GET", "OPTIONS", "HEAD"}, s.methods
    assert not any(p in ("/items",) or p.startswith("/items/") for _, p in s.handler.log_calls)  # write endpoints never called


def test_request_guard_blocks_unsafe_methods_even_if_called_directly(api):
    s = api(WeakHandler)
    run = _Run(ScanContext(config={"base_url": s.url, "ip": "127.0.0.1"}, runtime={}))
    with pytest.raises(AssertionError):
        run.request("POST", "/items")
    run.client.close()
    assert "POST" not in s.methods


def test_request_budget_is_enforced_and_reported(api):
    s = api(WeakHandler)
    res = scan(s, max_requests=10)
    assert res.metadata["requests_made"] == 10 and res.complete is False
    assert any("budget" in w for w in res.warnings)
    assert any("skipped" in c["status"] for c in res.metadata["checks"])
    assert len(s.handler.log_calls) <= 10


def test_no_spec_is_reported_honestly(api):
    s = api(WeakHandler)
    discovered = scan(s, max_requests=200)  # no spec supplied: found at /openapi.json
    assert discovered.metadata["spec"]["title"] == "Test API"
    bad = scan(s, spec_text="not a spec", max_requests=200)
    assert bad.metadata["spec"] is None
    assert any(c["name"] == "specification parsing" and "skipped" in c["status"] for c in bad.metadata["checks"])
    assert any("No OpenAPI specification" in w for w in bad.warnings)
    assert "api.auth-not-enforced" not in rules(bad)  # endpoint-level checks need a spec


# ---- well-configured API ---------------------------------------------------------------------------
def test_good_api_has_no_serious_findings_and_authentication_is_enforced(api):
    s = api(GoodHandler)
    res = scan(s, auth_value="Bearer good-token", max_requests=200)
    severe = [f for f in res.findings if f.severity.value in ("critical", "high")]
    assert severe == []
    assert "api.auth-not-enforced" not in rules(res) and "api.invalid-credentials-accepted" not in rules(res)
    assert "api.no-rate-limiting" not in rules(res)  # 429 + headers observed
    assert "api.cors-wildcard" not in rules(res) and "api.missing-nosniff" not in rules(res)
    assert "api.spec-plaintext-server" not in rules(res)


def test_invalid_credentials_accepted_detected(api):
    class Lenient(WeakHandler):
        log_calls: list = []

        def do_GET(self):
            self._record()
            if self.path.split("?")[0] == "/openapi.json":
                return self._json(200, {"openapi": "3.0.0", "paths": {"/me": {"get": {"security": [{"b": []}]}}}})
            return self._json(200, {"ok": True})  # accepts anything, with or without a token

    s = api(Lenient)
    res = scan(s, auth_value="Bearer whatever", max_requests=100)
    assert "api.auth-not-enforced" in rules(res)


def test_jwt_static_checks_on_supplied_token(api):
    def jwt(header, payload):
        b = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()  # noqa: E731
        return f"{b(header)}.{b(payload)}.SIGNATUREVALUE123"

    s = api(GoodHandler)
    res = scan(s, auth_value="Bearer " + jwt({"alg": "none"}, {"sub": "1"}), max_requests=60)
    assert {"api.jwt-none", "api.jwt-no-expiry"} <= set(rules(res))
    ok = scan(api(GoodHandler), auth_value="Bearer " + jwt({"alg": "HS256"}, {"exp": 4102444800}), max_requests=60)
    assert "api.jwt-none" not in rules(ok) and "api.jwt-no-expiry" not in rules(ok)
    dump = repr([(f.title, f.description, f.extra) for f in res.findings])
    assert "SIGNATUREVALUE123" not in dump and "Bearer" not in dump  # token material is never echoed


def test_public_endpoint_listing_only_when_credentials_are_supplied(api):
    s = api(WeakHandler)
    with_auth = scan(s, auth_value="Bearer x", max_requests=200)
    assert by_rule(with_auth, "api.public-endpoints")
    without = scan(api(WeakHandler), max_requests=200)
    assert not by_rule(without, "api.public-endpoints")


# ---- TLS -----------------------------------------------------------------------------------------------
def test_tls_certificate_problems_are_reported(api, tmp_path):
    expired = api(GoodHandler, cert=make_cert(tmp_path, expired=True))
    res = scan(expired, max_requests=60)
    assert "api.tls-certificate" in rules(res) and "api.plaintext-http" not in rules(res)
    self_signed = api(GoodHandler, cert=make_cert(tmp_path, days=365))
    assert "api.tls-certificate" in rules(scan(self_signed, max_requests=60))  # untrusted issuer


def test_tls_expiring_soon_warning(api, tmp_path):
    soon = api(GoodHandler, cert=make_cert(tmp_path, days=5))
    assert "api.tls-cert-expiring" in rules(scan(soon, max_requests=60))


# ---- target safety ------------------------------------------------------------------------------------------
@pytest.mark.parametrize("ip", ["169.254.169.254", "8.8.8.8", "224.0.0.1"])
def test_scanner_rechecks_the_pinned_address(ip):
    with pytest.raises(ValueError, match="not permitted"):
        get_scanner("api").scan(ScanContext(config={"base_url": "http://x.example", "ip": ip}, runtime={}))


@pytest.mark.parametrize("url", ["ftp://x", "http://user:pw@host/", "file:///etc/passwd", "http://"])
def test_scanner_rejects_bad_urls(url):
    with pytest.raises(ValueError):
        get_scanner("api").scan(ScanContext(config={"base_url": url, "ip": "127.0.0.1"}, runtime={}))


def test_redirects_are_never_followed(api):
    class Redirector(WeakHandler):
        log_calls: list = []

        def do_GET(self):
            self._record()
            self._send(302, b"", {"Location": "http://169.254.169.254/latest/meta-data/"})

    s = api(Redirector)
    res = scan(s, max_requests=60)
    assert all(host_path != "/latest/meta-data/" for _, host_path in s.handler.log_calls)
    assert res.metadata["requests_made"] > 0


def test_rules_metadata_is_complete():
    for rule in RULES.values():
        assert rule.remediation and rule.impact and rule.cwe.startswith("CWE-")
    assert len(RULES) >= 20
