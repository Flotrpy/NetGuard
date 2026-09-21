"""Python AST analyzer with lightweight intra-function taint tracking.

Approach (documented so results can be interpreted correctly):

* *Sources* of untrusted data: ``request.*`` (Flask/Django/FastAPI/Bottle), ``input()``,
  ``sys.argv`` and parameters of functions decorated as web routes.
* *Propagation*: assignments, f-strings, concatenation, ``%``/``.format`` and calls whose
  arguments are tainted (except known sanitizers such as ``int()`` or ``shlex.quote``).
* *Sinks*: the calls in the rule catalog. A tainted flow raises confidence to HIGH; a merely
  dynamic (non-constant) value keeps the rule's default confidence.

This is intentionally simple and local to one function (or module body): it does not follow data
across function calls or files, so absence of a finding is not proof of safety.
"""

from __future__ import annotations

import ast

from netguard.core.files import context_lines
from netguard.enums import Confidence
from netguard.scanners.base import RawFinding
from netguard.scanners.sast.engine import suppressed
from netguard.scanners.sast.python_rules import PY_RULES
from netguard.scanners.sast.rules import cwe_url

RULE_COUNT = len(PY_RULES)

_SOURCE_ROOTS = {"request", "req", "flask", "bottle"}
_ROUTE_DECORATORS = {"route", "get", "post", "put", "delete", "patch", "api_view", "websocket"}
_SAFE_PARAM_ANNOTATIONS = {"int", "float", "bool", "UUID", "Depends", "Session", "Request"}
_SANITIZERS = {
    "int",
    "float",
    "bool",
    "len",
    "abs",
    "round",
    "UUID",
    "quote",
    "quote_plus",
    "escape",
    "secure_filename",
    "basename",
    "clean",
    "literal_eval",
    "sha256",
    "hexdigest",
}
_SQL_EXECUTE = {"execute", "executemany", "executescript", "read_sql", "read_sql_query"}
_SQL_CALLS = _SQL_EXECUTE | {"raw", "extra", "text"}
_SQL_WORDS = ("select ", "insert ", "update ", "delete ", "drop ", "create ", " where ", " from ")
_SECRET_NAMES = (
    "token",
    "secret",
    "password",
    "passwd",
    "apikey",
    "api_key",
    "salt",
    "nonce",
    "session",
    "otp",
    "csrf",
    "key",
)
_PATH_SINKS = {
    "open",
    "send_file",
    "send_from_directory",
    "remove",
    "unlink",
    "rmtree",
    "copyfile",
    "copy",
    "move",
    "listdir",
    "Path",
    "makedirs",
    "mkdir",
    "rename",
}
_HTTP_VERBS = {"get", "post", "put", "delete", "patch", "head", "request", "urlopen"}
_HTTP_ROOTS = {"requests", "httpx", "urllib", "aiohttp", "session", "client", "urlopen"}
_XML_FUNCS = {"parse", "fromstring", "parseString", "XML", "iterparse"}
_XML_ROOTS = {"etree", "ElementTree", "minidom", "sax", "ET", "lxml"}
_SUBPROCESS = {"run", "call", "check_call", "check_output", "Popen", "getoutput", "getstatusoutput"}
_PICKLES = {
    ("pickle", "load"),
    ("pickle", "loads"),
    ("cPickle", "load"),
    ("cPickle", "loads"),
    ("marshal", "load"),
    ("marshal", "loads"),
    ("dill", "load"),
    ("dill", "loads"),
    ("shelve", "open"),
    ("jsonpickle", "decode"),
    ("yaml", "unsafe_load"),
    ("yaml", "unsafe_load_all"),
}
_UNSAFE_YAML_LOADERS = {"Loader", "UnsafeLoader", "FullLoader", "CLoader", "CUnsafeLoader"}


def dotted(node: ast.AST) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    elif isinstance(node, ast.Call):
        inner = dotted(node.func)
        if inner:
            parts.append(inner + "()")
    return ".".join(reversed(parts))


def _root(node: ast.AST) -> str:
    while True:
        if isinstance(node, ast.Attribute | ast.Subscript):
            node = node.value
        elif isinstance(node, ast.Call):
            node = node.func
        else:
            break
    return node.id if isinstance(node, ast.Name) else ""


def _const_text(node: ast.AST) -> str:
    return " ".join(
        n.value.lower()
        for n in ast.walk(node)
        if isinstance(n, ast.Constant) and isinstance(n.value, str)
    )


def _is_str_const(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _stringy(node: ast.AST) -> bool:
    """Is this expression a string being built (literal, f-string, or +/% of one)?"""
    if _is_str_const(node) or isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add | ast.Mod):
        return _stringy(node.left) or _stringy(node.right)
    return False


def _all_const(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.BinOp):
        return _all_const(node.left) and _all_const(node.right)
    return False


def _kw(call: ast.Call, name: str) -> ast.expr | None:
    for k in call.keywords:
        if k.arg == name:
            return k.value
    return None


def _is_const(node: ast.AST | None, value: object) -> bool:
    return isinstance(node, ast.Constant) and node.value is value


class _Scope:
    def __init__(self) -> None:
        self.tainted: set[str] = set()
        self.dynamic_sql: set[str] = set()


class Analyzer(ast.NodeVisitor):
    def __init__(self, rel_path: str, source: str) -> None:
        self.rel_path = rel_path
        self.lines = source.splitlines()
        self.findings: list[RawFinding] = []
        self.scopes: list[_Scope] = [_Scope()]
        self.func_names: list[str] = []
        self._seen: set[tuple[str, int]] = set()

    # -- infrastructure --------------------------------------------------------------------
    @property
    def scope(self) -> _Scope:
        return self.scopes[-1]

    def emit(self, rule_id: str, node: ast.AST, *, tainted: bool = False, note: str = "") -> None:
        line = getattr(node, "lineno", 0)
        if (rule_id, line) in self._seen:
            return
        src_line = self.lines[line - 1] if 0 < line <= len(self.lines) else ""
        if suppressed(src_line, rule_id):
            return
        self._seen.add((rule_id, line))
        rule = PY_RULES[rule_id]
        desc = rule.description
        if tainted:
            desc += (
                " NetGuard traced request-controlled data into this call "
                "(inferred, intra-function)."
            )
        if note:
            desc += f" {note}"
        self.findings.append(
            RawFinding(
                rule_id=rule.id,
                title=rule.title,
                category=rule.category,
                severity=rule.severity,
                confidence=Confidence.HIGH if tainted else rule.confidence,
                cwe=rule.cwe,
                description=desc,
                impact=rule.impact,
                remediation=rule.remediation,
                file_path=self.rel_path,
                line=line,
                end_line=getattr(node, "end_lineno", line) or line,
                language="python",
                code_context=context_lines(self.lines, line, 2),
                references=list(rule.references) or [cwe_url(rule.cwe)],
                exploitability="high" if tainted else rule.exploitability,
                extra={"fixer": rule.fixer, "tainted": tainted},
                key=src_line.strip(),
            )
        )

    # -- taint -----------------------------------------------------------------------------
    def is_tainted(self, node: ast.AST | None) -> bool:
        if node is None:
            return False
        if isinstance(node, ast.Name):
            return node.id in self.scope.tainted or node.id in _SOURCE_ROOTS
        if isinstance(node, ast.Constant):
            return False
        if isinstance(node, ast.Call):
            name = dotted(node.func).split(".")[-1]
            if name in _SANITIZERS:
                return False
            if name in ("input", "raw_input") or _root(node.func) in _SOURCE_ROOTS:
                return True
            if self.is_tainted(node.func) and isinstance(node.func, ast.Attribute):
                return True  # method call on a tainted object, e.g. tainted.strip()
            return any(self.is_tainted(a) for a in node.args) or any(
                self.is_tainted(k.value) for k in node.keywords
            )
        if isinstance(node, ast.Attribute | ast.Subscript):
            if dotted(node).startswith("sys.argv") or _root(node) in _SOURCE_ROOTS:
                return True
            return self.is_tainted(node.value)
        return any(self.is_tainted(c) for c in ast.iter_child_nodes(node))

    def is_dynamic_str(self, node: ast.AST | None) -> bool:
        if node is None:
            return False
        if isinstance(node, ast.JoinedStr):
            return any(isinstance(v, ast.FormattedValue) for v in node.values)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add | ast.Mod):
            return _stringy(node) and not _all_const(node)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "format" and _is_str_const(node.func.value):
                return bool(node.args or node.keywords)
        if isinstance(node, ast.Name):
            return node.id in self.scope.dynamic_sql
        return False

    # -- scopes ----------------------------------------------------------------------------
    def _function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        scope = _Scope()
        is_route = any(
            dotted(d.func if isinstance(d, ast.Call) else d).split(".")[-1] in _ROUTE_DECORATORS
            for d in node.decorator_list
        )
        args = node.args
        for a in [*args.posonlyargs, *args.args, *args.kwonlyargs]:
            ann = dotted(a.annotation) if a.annotation is not None else ""
            if a.arg in _SOURCE_ROOTS:
                scope.tainted.add(a.arg)
            elif (
                is_route
                and a.arg not in ("self", "cls", "db", "session", "current_user")
                and ann.split(".")[-1] not in _SAFE_PARAM_ANNOTATIONS
            ):
                scope.tainted.add(a.arg)
        for d in node.decorator_list:
            self._check_decorator(d)
        self.scopes.append(scope)
        self.func_names.append(node.name)
        self.generic_visit(node)
        self.func_names.pop()
        self.scopes.pop()

    visit_FunctionDef = _function
    visit_AsyncFunctionDef = _function

    def _check_decorator(self, deco: ast.expr) -> None:
        name = dotted(deco.func if isinstance(deco, ast.Call) else deco)
        if name.split(".")[-1] == "csrf_exempt":
            self.emit("py.csrf-exempt", deco)
        if name.split(".")[-1] == "permission_classes" and isinstance(deco, ast.Call):
            if any(dotted(a).endswith("AllowAny") for n in deco.args for a in ast.walk(n)):
                self.emit("py.permission-allow-any", deco)

    # -- assignments -----------------------------------------------------------------------
    def _bind(self, target: ast.AST, value: ast.AST | None) -> None:
        tainted = self.is_tainted(value)
        dyn = self.is_dynamic_str(value) and any(w in _const_text(value) for w in _SQL_WORDS)
        for t in ast.walk(target):
            if isinstance(t, ast.Name):
                (self.scope.tainted.add if tainted else self.scope.tainted.discard)(t.id)
                (self.scope.dynamic_sql.add if dyn else self.scope.dynamic_sql.discard)(t.id)

    def visit_Assign(self, node: ast.Assign) -> None:
        for t in node.targets:
            self._bind(t, node.value)
            self._check_assign(t, node.value, node)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self._bind(node.target, node.value)
            self._check_assign(node.target, node.value, node)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        if self.is_tainted(node.value) and isinstance(node.target, ast.Name):
            self.scope.tainted.add(node.target.id)
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        self._bind(node.target, node.iter)
        self.generic_visit(node)

    def visit_With(self, node: ast.With) -> None:
        for item in node.items:
            if item.optional_vars is not None:
                self._bind(item.optional_vars, item.context_expr)
        self.generic_visit(node)

    def _check_assign(self, target: ast.AST, value: ast.AST, node: ast.AST) -> None:
        name = dotted(target).split(".")[-1]
        low = name.lower()
        if name == "DEBUG" and _is_const(value, True):
            self.emit("py.debug-enabled", node, note="Django DEBUG = True.")
        if low in (
            "session_cookie_secure",
            "session_cookie_httponly",
            "csrf_cookie_secure",
        ) and _is_const(value, False):
            self.emit("py.insecure-cookie", node)
        if low == "check_hostname" and _is_const(value, False):
            self.emit("py.tls-verification-disabled", node)
        # random for secrets, by assigned variable name
        if any(s in low for s in _SECRET_NAMES) and self._uses_random(value):
            self.emit("py.insecure-random", node)

    def _uses_random(self, node: ast.AST) -> bool:
        for n in ast.walk(node):
            if isinstance(n, ast.Call):
                d = dotted(n.func)
                if d.startswith("random.") and d.split(".")[-1] in {
                    "random",
                    "randint",
                    "choice",
                    "choices",
                    "randrange",
                    "getrandbits",
                    "sample",
                }:
                    return True
        return False

    # -- comparisons: hard-coded credentials ------------------------------------------------
    def visit_Compare(self, node: ast.Compare) -> None:
        if len(node.ops) == 1 and isinstance(node.ops[0], ast.Eq | ast.NotEq):
            left, right = node.left, node.comparators[0]
            for var, lit in ((left, right), (right, left)):
                if (
                    _is_str_const(lit)
                    and len(lit.value) >= 3  # type: ignore[attr-defined]
                    and any(
                        s in dotted(var).split(".")[-1].lower()
                        for s in ("password", "passwd", "pwd", "secret", "token", "api_key")
                    )
                    and not isinstance(var, ast.Constant)
                ):
                    self.emit("py.hardcoded-credential-check", node)
        self.generic_visit(node)

    # -- calls: the sinks --------------------------------------------------------------------
    def visit_Call(self, node: ast.Call) -> None:
        self._check_call(node)
        self.generic_visit(node)

    def _first_arg(self, node: ast.Call) -> ast.expr | None:
        return node.args[0] if node.args else None

    def _check_call(self, node: ast.Call) -> None:
        full = dotted(node.func)
        parts = full.split(".")
        last = parts[-1]
        first = self._first_arg(node)
        root = parts[0]

        # SQL injection
        if last in _SQL_CALLS and first is not None:
            tainted = self.is_tainted(first)
            named_sql = isinstance(first, ast.Name) and first.id in self.scope.dynamic_sql
            sql_like = named_sql or any(w in _const_text(first) for w in _SQL_WORDS)
            if self.is_dynamic_str(first) and (sql_like or tainted):
                self.emit("py.sql-injection", node, tainted=tainted)
            elif tainted and last in _SQL_EXECUTE and not _is_str_const(first):
                self.emit("py.sql-injection", node, tainted=True)

        # Command injection / subprocess
        if full in ("os.system", "os.popen", "commands.getoutput") and first is not None:
            if self.is_dynamic_str(first) or self.is_tainted(first):
                self.emit("py.command-injection", node, tainted=self.is_tainted(first))
        if root == "subprocess" and last in _SUBPROCESS:
            shell = _kw(node, "shell")
            if _is_const(shell, True):
                dynamic = first is not None and (
                    self.is_dynamic_str(first) or self.is_tainted(first) or not _is_str_const(first)
                )
                if dynamic:
                    self.emit("py.command-injection", node, tainted=self.is_tainted(first))
                else:
                    self.emit("py.subprocess-shell-true", node)

        # Code injection
        if full in ("eval", "exec", "compile") and first is not None and not _is_str_const(first):
            self.emit("py.code-injection", node, tainted=self.is_tainted(first))

        # Deserialization
        if len(parts) >= 2 and (parts[-2], last) in _PICKLES:
            self.emit("py.unsafe-deserialization", node, tainted=self.is_tainted(first))
        if len(parts) >= 2 and parts[-2] == "yaml" and last in ("load", "load_all"):
            loader = _kw(node, "Loader")
            if loader is None and len(node.args) < 2:
                self.emit(
                    "py.unsafe-deserialization",
                    node,
                    tainted=self.is_tainted(first),
                    note="yaml.load without a safe Loader.",
                )
            elif loader is not None and dotted(loader).split(".")[-1] in _UNSAFE_YAML_LOADERS:
                self.emit(
                    "py.unsafe-deserialization",
                    node,
                    tainted=self.is_tainted(first),
                    note="yaml.load with an unsafe Loader.",
                )
            elif (
                len(node.args) >= 2 and dotted(node.args[1]).split(".")[-1] in _UNSAFE_YAML_LOADERS
            ):
                self.emit("py.unsafe-deserialization", node, tainted=self.is_tainted(first))

        # Weak crypto
        if (
            root == "hashlib"
            and last in ("md5", "sha1")
            and not _is_const(_kw(node, "usedforsecurity"), False)
        ):
            self.emit("py.weak-hash", node)
        if (
            full == "hashlib.new"
            and first is not None
            and _is_str_const(first)
            and first.value.lower() in ("md5", "sha1")
        ):  # type: ignore[attr-defined]
            self.emit("py.weak-hash", node)
        if last == "new" and root in ("DES", "ARC4", "Blowfish", "ARC2", "DES3"):
            self.emit("py.weak-cipher", node)
        if (
            last == "new"
            and root == "AES"
            and any(dotted(a).endswith("MODE_ECB") for a in node.args)
        ):
            self.emit("py.weak-cipher", node, note="AES in ECB mode.")

        # Randomness in secret-named functions
        if full.startswith("random.") and last in {
            "random",
            "randint",
            "choice",
            "choices",
            "randrange",
            "getrandbits",
        }:
            fn = self.func_names[-1].lower() if self.func_names else ""
            if any(s in fn for s in _SECRET_NAMES):
                self.emit("py.insecure-random", node)

        # TLS
        if _is_const(_kw(node, "verify"), False) and root in (
            "requests",
            "httpx",
            "session",
            "client",
            "s",
            "r",
            "self",
        ):
            self.emit("py.tls-verification-disabled", node)
        if full in ("ssl._create_unverified_context",) or last == "_create_unverified_context":
            self.emit("py.tls-verification-disabled", node)
        if any(
            dotted(a).endswith("CERT_NONE") for a in ast.walk(node) if isinstance(a, ast.Attribute)
        ):
            self.emit("py.tls-verification-disabled", node)

        # Debug
        if last == "run" and _is_const(_kw(node, "debug"), True):
            self.emit("py.debug-enabled", node)

        # Path traversal
        if (
            last in _PATH_SINKS
            and (root not in ("re",))
            and first is not None
            and self.is_tainted(first)
        ):
            self.emit("py.path-traversal", node, tainted=True)
        if full in ("os.path.join", "posixpath.join") and any(
            self.is_tainted(a) for a in node.args[1:]
        ):
            self.emit("py.path-traversal", node, tainted=True)
        if last == "extractall" and _kw(node, "filter") is None:
            self.emit("py.archive-extraction", node)

        # SSRF
        if (
            (root in _HTTP_ROOTS or last == "urlopen")
            and (last in _HTTP_VERBS)
            and first is not None
            and self.is_tainted(first)
        ):
            self.emit("py.ssrf", node, tainted=True)

        # Template injection / XSS / redirect
        if (
            last in ("render_template_string", "Template", "from_string")
            and first is not None
            and self.is_tainted(first)
        ):
            self.emit("py.template-injection", node, tainted=True)
        if (
            last in ("Markup", "mark_safe", "HttpResponse", "SafeString")
            and first is not None
            and self.is_tainted(first)
        ):
            self.emit("py.reflected-xss", node, tainted=True)
        if (
            last in ("redirect", "HttpResponseRedirect")
            and first is not None
            and self.is_tainted(first)
        ):
            self.emit("py.open-redirect", node, tainted=True)

        # Temp files, permissions
        if full == "tempfile.mktemp":
            self.emit("py.insecure-tempfile", node)
        if (
            full == "os.chmod"
            and len(node.args) >= 2
            and isinstance(node.args[1], ast.Constant)
            and node.args[1].value in (0o777, 0o666, 0o776, 0o766)
        ):
            self.emit("py.file-permissions", node)
        if full == "os.umask" and isinstance(first, ast.Constant) and first.value == 0:
            self.emit("py.file-permissions", node)

        # XML
        if (
            last in _XML_FUNCS
            and root in _XML_ROOTS
            and first is not None
            and self.is_tainted(first)
        ):
            self.emit("py.xxe", node, tainted=True)

        # JWT
        if last == "decode" and root == "jwt":
            opts = _kw(node, "options")
            if _is_const(_kw(node, "verify"), False):
                self.emit("py.jwt-insecure", node)
            elif (
                opts is not None
                and "verify_signature"
                in _const_text(opts)
                + " ".join(str(k.value) for k in ast.walk(opts) if isinstance(k, ast.Constant))
                and any(_is_const(v, False) for v in ast.walk(opts) if isinstance(v, ast.Constant))
            ):
                self.emit("py.jwt-insecure", node)
            algs = _kw(node, "algorithms")
            if algs is not None and any(
                isinstance(c, ast.Constant) and str(c.value).lower() == "none"
                for c in ast.walk(algs)
            ):
                self.emit("py.jwt-insecure", node)

        # Cookies
        if last == "set_cookie":
            for flag in ("secure", "httponly"):
                if _is_const(_kw(node, flag), False):
                    self.emit("py.insecure-cookie", node)


def analyze(rel_path: str, source: str) -> list[RawFinding]:
    """Analyze one Python file. Raises SyntaxError if the file cannot be parsed."""
    tree = ast.parse(source)
    analyzer = Analyzer(rel_path, source)
    analyzer.visit(tree)
    return analyzer.findings
