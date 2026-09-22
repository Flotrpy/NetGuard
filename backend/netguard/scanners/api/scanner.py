"""Authorized, non-destructive web API security scanner.

Only GET, HEAD and OPTIONS requests are ever sent; write operations found in an OpenAPI spec are
analysed statically and never invoked. Requests are capped, redirects are not followed, the
target address is pinned to the IP that passed the target policy, and credentials only exist in
memory for the duration of the scan.
"""

from __future__ import annotations

import base64
import json
import re
import socket
import ssl
import time
from datetime import UTC, datetime
from urllib.parse import urlsplit

import httpx
from cryptography import x509

from netguard.core.targets import TargetError, check_address
from netguard.enums import Scanner as ScannerName
from netguard.scanners.api.rules import RULES
from netguard.scanners.api.spec import (
    SENSITIVE_PARAMS,
    ApiSpec,
    Operation,
    SpecError,
    fill_path,
    parse_spec,
)
from netguard.scanners.base import AssetRef, RawFinding, ScanContext, Scanner, ScanResult
from netguard.scanners.sast.rules import cwe_url

SPEC_PATHS = ("/openapi.json", "/swagger.json", "/v3/api-docs", "/api/openapi.json", "/openapi.yaml")
ERROR_PATTERNS = [re.compile(p, re.I) for p in (
    r"Traceback \(most recent call last\)", r"\bat [\w.$]+\([\w.]+:\d+\)", r"SQLSTATE\[",
    r"You have an error in your SQL syntax", r"\bORA-\d{5}\b", r"System\.\w+Exception",
    r"<b>Warning</b>:.*on line", r"Whitelabel Error Page", r"django\.core\.exceptions",
    r"werkzeug\.exceptions|Werkzeug Debugger", r"node_modules/.*\.js:\d+",
)]
RATE_HEADERS = ("x-ratelimit-limit", "x-ratelimit-remaining", "ratelimit-limit", "ratelimit-remaining",
                "ratelimit-policy", "retry-after", "x-rate-limit-limit")
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


class _BudgetExceeded(Exception):
    pass


class ApiScanner(Scanner):
    name = ScannerName.API
    display_name = "API Scanner"
    version = "1.0.0"
    description = (
        "Authorized, non-destructive checks of a web API: TLS, security headers, CORS, "
        "authentication behaviour, input handling, rate limiting and OpenAPI specification review. "
        "Only GET/HEAD/OPTIONS requests are sent."
    )
    supported_inputs = ("api_target",)

    def scan(self, ctx: ScanContext) -> ScanResult:
        return _Run(ctx).run()


class _Run:
    def __init__(self, ctx: ScanContext) -> None:
        cfg, rt = ctx.config, ctx.runtime
        self.ctx = ctx
        self.base_url = str(cfg["base_url"]).rstrip("/")
        parts = urlsplit(self.base_url)
        if parts.scheme not in ("http", "https") or not parts.hostname or parts.username:
            raise ValueError("Target not permitted: invalid URL")
        self.scheme, self.host = parts.scheme, parts.hostname
        self.port = parts.port or (443 if self.scheme == "https" else 80)
        self.prefix = parts.path.rstrip("/")
        self.ip = str(cfg["ip"])
        import ipaddress

        try:  # defence in depth: the sandbox re-checks the pinned address
            check_address(ipaddress.ip_address(self.ip), allow_public=bool(rt.get("allow_public_targets")))
        except (TargetError, ValueError) as exc:
            raise ValueError(f"Target not permitted: {exc}") from exc
        self.max_requests = min(int(cfg.get("max_requests", 120)), 300)
        self.auth_name = str(cfg.get("auth_header_name") or "Authorization")
        self.auth_value = str(cfg.get("auth_value") or "")
        self.extra_paths = [p for p in cfg.get("paths", []) if isinstance(p, str) and p.startswith("/")][:50]
        self.spec_text = cfg.get("spec_text") or ""
        self.requests = 0
        self.errors = 0
        self.findings: list[RawFinding] = []
        self.checks: list[dict[str, str]] = []
        self.client = httpx.Client(
            base_url=f"{self.scheme}://{self.ip}:{self.port}", timeout=5.0, follow_redirects=False,
            verify=False,  # certificate validity is assessed explicitly in the TLS check
            headers={"User-Agent": "NetGuard-API-Scanner", "Host": self._host_header()},
        )
        self.asset = AssetRef("api", self.base_url, self.base_url)
        self.public_gets: list[str] = []

    def _host_header(self) -> str:
        default = 443 if self.scheme == "https" else 80
        return self.host if self.port == default else f"{self.host}:{self.port}"

    # ---- plumbing -----------------------------------------------------------------------------
    def request(self, method: str, path: str, *, headers: dict | None = None, params: dict | None = None,
                auth: bool = False) -> httpx.Response | None:
        if method.upper() not in SAFE_METHODS:  # hard guarantee: never send state-changing requests
            raise AssertionError("non-safe method blocked")
        if self.requests >= self.max_requests:
            raise _BudgetExceeded()
        self.ctx.check_cancelled()
        self.requests += 1
        h = dict(headers or {})
        if auth and self.auth_value:
            h[self.auth_name] = self.auth_value
        try:
            return self.client.request(method, self.prefix + path, headers=h, params=params,
                                       extensions={"sni_hostname": self.host})
        except httpx.HTTPError:
            self.errors += 1
            return None

    def emit(self, rule_id: str, *, note: str = "", where: str = "", key: str = "", extra: dict | None = None) -> None:
        rule = RULES[rule_id]
        self.findings.append(RawFinding(
            rule_id=rule_id, title=f"{rule.title}: {where}" if where else rule.title,
            category=rule.category, severity=rule.severity, confidence=rule.confidence, cwe=rule.cwe,
            description=f"{rule.description} {note}".strip(), impact=rule.impact,
            remediation=rule.remediation, references=[cwe_url(rule.cwe)],
            exploitability=rule.exploitability, asset=self.asset,
            exposure="internal" if _is_private(self.ip) else "internet",
            extra={"base_url": self.base_url, "where": where, **(extra or {})},
            key=f"{rule_id}:{key or where}",
        ))

    def check(self, name: str, fn) -> None:  # noqa: ANN001
        try:
            fn()
            self.checks.append({"name": name, "status": "done"})
        except _BudgetExceeded:
            self.checks.append({"name": name, "status": "skipped: request budget exhausted"})
            raise
        except SpecError as exc:
            self.checks.append({"name": name, "status": f"skipped: {exc}"})

    # ---- run ----------------------------------------------------------------------------------
    def run(self) -> ScanResult:
        spec: ApiSpec | None = None
        budget_hit = False
        started = time.monotonic()
        try:
            self.ctx.progress(5, "TLS and transport")
            self.check("transport & TLS", self.check_transport)
            self.ctx.progress(15, "baseline response")
            self.check("security headers", self.check_headers)
            self.check("CORS", self.check_cors)
            self.check("HTTP methods", self.check_methods)
            self.check("error handling", self.check_errors)
            self.check("rate limiting", self.check_rate_limit)
            self.check("token analysis", self.check_token)
            self.ctx.progress(50, "API specification")
            spec = self.load_spec()
            if spec:
                self.check("specification review", lambda: self.check_spec(spec))
                self.ctx.progress(65, "authentication behaviour")
                self.check("authentication", lambda: self.check_auth(spec))
                self.ctx.progress(85, "input handling")
                self.check("input handling", lambda: self.check_input(spec))
            else:
                self.checks.append({"name": "specification review", "status": "skipped: no OpenAPI spec provided or found"})
        except _BudgetExceeded:
            budget_hit = True
        finally:
            self.client.close()
        self.ctx.progress(100, "done")
        warnings = []
        if budget_hit:
            warnings.append(f"Request budget ({self.max_requests}) exhausted; some checks were skipped.")
        if self.errors:
            warnings.append(f"{self.errors} request(s) failed (timeouts/connection errors); results may be incomplete.")
        if spec is None:
            warnings.append("No OpenAPI specification: endpoint-level authentication and input checks "
                            "were skipped. Provide a spec for deeper coverage.")
        warnings.append("Authorization (object-level access) needs two identities and is not tested; "
                        "only authentication behaviour is checked.")
        return ScanResult(
            findings=self.findings, warnings=warnings, complete=not budget_hit and self.errors == 0,
            metadata={"base_url": self.base_url, "requests_made": self.requests, "checks": self.checks,
                      "spec": ({"title": spec.title, "version": spec.version, "operations": len(spec.operations)}
                               if spec else None),
                      "duration_seconds": round(time.monotonic() - started, 2), "rules": len(RULES)},
        )

    # ---- checks ---------------------------------------------------------------------------------
    def check_transport(self) -> None:
        if self.scheme == "http":
            self.emit("api.plaintext-http", note=f"Target: {self.base_url}.", where=self.host)
            return
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((self.ip, self.port), timeout=5) as raw, \
                    ctx.wrap_socket(raw, server_hostname=self.host) as tls:
                der = tls.getpeercert(binary_form=True)
        except ssl.SSLCertVerificationError as exc:
            self.emit("api.tls-certificate", note=f"Validation failed: {exc.verify_message}.", where=self.host)
            der = self._peer_cert_unverified()
        except (OSError, ssl.SSLError):
            self.errors += 1
            return
        if der:
            left = (x509.load_der_x509_certificate(der).not_valid_after_utc - datetime.now(UTC)).days
            if 0 <= left <= 14:
                self.emit("api.tls-cert-expiring", note=f"{left} days left.", where=self.host)
        # Does the server still complete a handshake at TLS 1.0/1.1?
        legacy = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        legacy.check_hostname, legacy.verify_mode = False, ssl.CERT_NONE
        try:
            legacy.minimum_version, legacy.maximum_version = ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1
            legacy.set_ciphers("ALL:@SECLEVEL=0")
            with socket.create_connection((self.ip, self.port), timeout=5) as raw, \
                    legacy.wrap_socket(raw, server_hostname=self.host) as tls:
                self.emit("api.tls-legacy-protocol", note=f"Negotiated {tls.version()}.", where=self.host)
        except (OSError, ssl.SSLError, ValueError):
            pass  # refusing legacy protocols is the good outcome (or this OpenSSL cannot try)

    def _peer_cert_unverified(self) -> bytes | None:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        try:
            with socket.create_connection((self.ip, self.port), timeout=5) as raw, \
                    ctx.wrap_socket(raw, server_hostname=self.host) as tls:
                return tls.getpeercert(binary_form=True)
        except (OSError, ssl.SSLError):
            return None

    def check_headers(self) -> None:
        r = self.request("GET", "/", auth=True)
        if r is None:
            return
        h = {k.lower(): v for k, v in r.headers.items()}
        if self.scheme == "https" and "strict-transport-security" not in h:
            self.emit("api.missing-hsts", where=self.host)
        if h.get("x-content-type-options", "").lower() != "nosniff":
            self.emit("api.missing-nosniff", where=self.host)
        for name in ("server", "x-powered-by", "x-aspnet-version"):
            if re.search(r"\d+\.\d+", h.get(name, "")):
                self.emit("api.version-disclosure", note=f"{name}: {h[name][:80]}", where=name, key=name)
        for cookie in r.headers.get_list("set-cookie"):
            low = cookie.lower()
            missing = [a for a, ok in (("Secure", "secure" in low or self.scheme == "http"),
                                       ("HttpOnly", "httponly" in low)) if not ok]
            if missing:
                self.emit("api.insecure-cookie", note=f"Missing: {', '.join(missing)}.",
                          where=cookie.split("=", 1)[0][:60])

    def check_cors(self) -> None:
        origin = "https://netguard-cors-probe.invalid"
        r = self.request("GET", "/", headers={"Origin": origin}, auth=True)
        if r is None:
            return
        allow = r.headers.get("access-control-allow-origin", "")
        creds = r.headers.get("access-control-allow-credentials", "").lower() == "true"
        if allow == origin and creds:
            self.emit("api.cors-reflects-origin-credentials", where=self.host)
        elif allow == "*" and creds:
            self.emit("api.cors-reflects-origin-credentials", note="Wildcard origin with credentials.", where=self.host)
        elif allow == "*":
            self.emit("api.cors-wildcard", where=self.host)
        elif allow == origin:
            self.emit("api.cors-wildcard", note="Arbitrary origins are reflected (no credentials).", where=self.host)

    def check_methods(self) -> None:
        r = self.request("OPTIONS", "/")
        if r is not None and "TRACE" in r.headers.get("allow", "").upper():
            self.emit("api.trace-enabled", where=self.host)

    def check_errors(self) -> None:
        r = self.request("GET", f"/netguard-{int(time.time())}-not-found")
        if r is not None:
            self._verbose(r, "GET (unknown path)")

    def _verbose(self, r: httpx.Response, where: str) -> bool:
        body = r.text[:6000] if r.status_code >= 400 else ""
        if any(p.search(body) for p in ERROR_PATTERNS):
            self.emit("api.verbose-errors", note=f"HTTP {r.status_code}.", where=where)
            return True
        return False

    def check_rate_limit(self) -> None:
        limited, seen_header = False, False
        for _ in range(25):
            r = self.request("GET", "/", auth=True)
            if r is None:
                return
            limited = limited or r.status_code == 429
            seen_header = seen_header or any(k in r.headers for k in RATE_HEADERS)
            if limited:
                break
        if not limited and not seen_header:
            self.emit("api.no-rate-limiting", note="25 sequential requests were all accepted.", where=self.host)

    def check_token(self) -> None:
        token = self.auth_value.split(" ", 1)[-1]
        parts = token.split(".")
        if len(parts) != 3:
            return
        try:
            def dec(seg: str) -> dict:
                return json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))

            header, payload = dec(parts[0]), dec(parts[1])
        except (ValueError, UnicodeDecodeError):
            return
        if str(header.get("alg", "")).lower() == "none":
            self.emit("api.jwt-none", where="supplied token")
        if "exp" not in payload:
            self.emit("api.jwt-no-expiry", where="supplied token")

    # ---- specification -----------------------------------------------------------------------------
    def load_spec(self) -> ApiSpec | None:
        if self.spec_text:
            try:
                return parse_spec(self.spec_text)
            except SpecError as exc:
                self.checks.append({"name": "specification parsing", "status": f"skipped: {exc}"})
                return None
        for path in SPEC_PATHS:
            r = self.request("GET", path)
            if r is not None and r.status_code == 200 and len(r.content) < 5_000_000:
                try:
                    return parse_spec(r.text)
                except SpecError:
                    continue
        return None

    def check_spec(self, spec: ApiSpec) -> None:
        for url in spec.servers:
            if url.startswith("http://") and not _is_private(urlsplit(url).hostname or ""):
                self.emit("api.spec-plaintext-server", note=url, where=url[:100])
        for name, scheme in spec.security_schemes.items():
            stype, sname = str(scheme.get("type", "")).lower(), str(scheme.get("scheme", "")).lower()
            if stype == "basic" or (stype == "http" and sname == "basic"):
                self.emit("api.spec-weak-scheme", note="HTTP Basic authentication.", where=name)
            elif stype == "apikey" and scheme.get("in") == "query":
                self.emit("api.spec-weak-scheme", note="API key passed in the query string.", where=name)
        for op in spec.operations:
            if op.method in ("POST", "PUT", "PATCH", "DELETE") and op.security is None and spec.security_schemes:
                self.emit("api.spec-no-security", where=f"{op.method} {op.path}")
            for p in op.params:
                if p.location == "query" and any(s in p.name.lower() for s in SENSITIVE_PARAMS):
                    self.emit("api.spec-sensitive-query-param", note=f"Parameter '{p.name}'.",
                              where=f"{op.method} {op.path}", key=f"{op.method} {op.path}:{p.name}")

    def _safe_gets(self, spec: ApiSpec) -> list[Operation]:
        ops = [o for o in spec.operations if o.method == "GET"]
        for p in self.extra_paths:
            ops.append(Operation("GET", p))
        return ops[:40]

    def check_auth(self, spec: ApiSpec) -> None:
        for op in self._safe_gets(spec):
            path = fill_path(op.path, op.params)
            where = f"GET {op.path}"
            r = self.request("GET", path)  # no credentials at all
            if r is None:
                continue
            ok = 200 <= r.status_code < 300
            if ok and op.requires_auth:
                self.emit("api.auth-not-enforced", note=f"HTTP {r.status_code} without credentials.", where=where)
            elif ok and (self.auth_value or op.security is None):
                self.public_gets.append(op.path)
            if op.requires_auth or self.auth_value:
                bad = self.request("GET", path, headers={self.auth_name: "Bearer netguard-invalid-token"})
                if bad is not None and 200 <= bad.status_code < 300 and not ok:
                    self.emit("api.invalid-credentials-accepted", where=where)
        if self.public_gets and self.auth_value:
            self.emit("api.public-endpoints", note="Endpoints: " + ", ".join(self.public_gets[:15]) + ".",
                      where=f"{len(self.public_gets)} endpoint(s)")

    def check_input(self, spec: ApiSpec) -> None:
        tested = 0
        for op in self._safe_gets(spec):
            queries = [p for p in op.params if p.location == "query"]
            if not queries or tested >= 10:
                continue
            tested += 1
            path, where = fill_path(op.path, op.params), f"GET {op.path}"
            for payload in ("x" * 2000, "'\"<>%00", "-1" if queries[0].type in ("integer", "number") else "NaN"):
                r = self.request("GET", path, params={queries[0].name: payload}, auth=True)
                if r is None:
                    break
                failed = r.status_code >= 500
                if failed:
                    self.emit("api.server-error-on-bad-input", note=f"HTTP {r.status_code} for parameter "
                              f"'{queries[0].name}'.", where=where)
                if self._verbose(r, where) or failed:
                    break


def _is_private(host: str) -> bool:
    import ipaddress

    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback
    except ValueError:
        return host in ("localhost",)
