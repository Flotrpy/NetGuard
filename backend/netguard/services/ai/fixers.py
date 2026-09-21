"""Deterministic (rule-based) fixers.

Each fixer makes a small, well-understood text transformation for one detection rule and reports
its caveats honestly. They never touch files themselves: the caller turns the result into a
reviewable diff. A fixer returns ``None`` when it cannot safely fix the specific occurrence.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from netguard.models import Finding


@dataclass
class FixResult:
    new_text: str
    explanation: str
    caveats: list[str] = field(default_factory=list)


Fixer = Callable[[Finding, str], FixResult | None]


def _sub_on_line(text: str, line_no: int, pattern: str, repl: str, flags: int = 0) -> str | None:
    """Apply a regex substitution to a single (1-based) line; None if nothing changed."""
    lines = text.split("\n")
    if not 1 <= line_no <= len(lines):
        return None
    new, n = re.subn(pattern, repl, lines[line_no - 1], count=1, flags=flags)
    if n == 0:
        return None
    lines[line_no - 1] = new
    return "\n".join(lines)


def _simple(pattern: str, repl: str, explanation: str, caveats: list[str], flags: int = 0) -> Fixer:
    def fixer(f: Finding, text: str) -> FixResult | None:
        new = _sub_on_line(text, f.line, pattern, repl, flags)
        return FixResult(new, explanation, list(caveats)) if new is not None else None

    return fixer


def _ensure_import(text: str, module: str) -> str:
    if re.search(rf"^\s*(?:import\s+{module}\b|from\s+{module}\s+import)", text, re.MULTILINE):
        return text
    lines = text.split("\n")
    last_import = -1
    for i, line in enumerate(lines):
        if re.match(r"^(?:import|from)\s+\w", line):
            last_import = i
        elif line.strip() and not line.startswith(("#", '"""', "'''")) and last_import >= 0:
            break
    idx = last_import + 1 if last_import >= 0 else 0
    lines.insert(idx, f"import {module}")
    return "\n".join(lines)


_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def _fix_python_random(f: Finding, text: str) -> FixResult | None:
    line = text.split("\n")[f.line - 1] if 0 < f.line <= len(text.split("\n")) else ""
    new = None
    if "random.choice(" in line:
        new = _sub_on_line(text, f.line, r"\brandom\.choice\(", "secrets.choice(")
    elif "random.getrandbits(" in line:
        new = _sub_on_line(text, f.line, r"\brandom\.getrandbits\(", "secrets.randbits(")
    else:
        m = re.search(r"\brandom\.randint\(\s*(\d+)\s*,\s*([^()]+?)\s*\)", line)
        if m:
            lo, hi = m.group(1), m.group(2)
            expr = (
                f"secrets.randbelow({hi} - {lo} + 1) + {lo}"
                if lo != "0"
                else f"secrets.randbelow({hi} + 1)"
            )
            new = _sub_on_line(text, f.line, r"\brandom\.randint\(\s*\d+\s*,\s*[^()]+?\s*\)", expr)
    if new is None:
        return None
    return FixResult(
        _ensure_import(new, "secrets"),
        "Replaced the predictable `random` call with the `secrets` module, which draws from the "
        "operating system's cryptographically secure generator.",
        [
            "Confirm the surrounding code still handles the value type (`secrets.token_*` returns "
            "strings; `secrets.randbelow` returns an int)."
        ],
    )


def _fix_yaml_load(f: Finding, text: str) -> FixResult | None:
    line = text.split("\n")[f.line - 1] if 0 < f.line <= len(text.split("\n")) else ""
    if "yaml.load" not in line:
        return None  # pickle/marshal cannot be made safe by a mechanical edit
    new = _sub_on_line(text, f.line, r"yaml\.load(_all)?\(", r"yaml.safe_load\1(")
    if new is None:
        return None
    new = _sub_on_line(new, f.line, r",\s*Loader\s*=\s*[\w.]+", "") or new
    return FixResult(
        new,
        "yaml.load can construct arbitrary Python objects. yaml.safe_load only builds plain data "
        "types (dict, list, str, numbers).",
        [
            "If your YAML relies on custom Python tags, it will now raise an error and needs an "
            "explicit, restricted loader."
        ],
    )


def _fix_secret(f: Finding, text: str) -> FixResult | None:
    lines = text.split("\n")
    if not 1 <= f.line <= len(lines):
        return None
    line = lines[f.line - 1]
    name = PurePosixPath(f.file_path).name.lower()
    caveat = [
        "ROTATE the credential. Removing it from the code does not make it safe: it remains "
        "in git history and must be treated as compromised until revoked."
    ]
    if name.startswith(".env") or name.endswith(".env"):
        new = _sub_on_line(text, f.line, r"^(\s*(?:export\s+)?[A-Za-z_][\w]*\s*=\s*).+$", r"\1")
        if new is None:
            return None
        return FixResult(
            new,
            "Emptied the committed value; real secrets belong in your secret "
            "manager or deployment environment.",
            caveat + ["Also remove this file from version control and add it to .gitignore."],
        )
    if name.endswith(".py"):
        m = re.match(r"^(\s*)([A-Za-z_]\w*)(\s*(?::\s*\w+\s*)?=\s*)(['\"])[^'\"]{8,}\4(.*)$", line)
        if not m:
            return None
        var = m.group(2)
        lines[f.line - 1] = f'{m.group(1)}{var}{m.group(3)}os.environ["{var.upper()}"]{m.group(5)}'
        return FixResult(
            _ensure_import("\n".join(lines), "os"),
            f"Replaced the hard-coded value with a lookup of the {var.upper()} environment variable.",
            caveat
            + [
                f"Set {var.upper()} in your deployment environment; the app raises KeyError if it is missing."
            ],
        )
    if name.endswith((".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs")):
        m = re.match(
            r"^(\s*(?:export\s+)?(?:const|let|var)\s+)([A-Za-z_$][\w$]*)(\s*=\s*)(['\"`])[^'\"`]{8,}\4(.*)$",
            line,
        )
        if not m:
            return None
        var = m.group(2)
        env = re.sub(r"(?<!^)(?=[A-Z])", "_", var).upper()
        lines[f.line - 1] = f"{m.group(1)}{var}{m.group(3)}process.env.{env}{m.group(5)}"
        return FixResult(
            "\n".join(lines),
            f"Replaced the hard-coded value with process.env.{env}.",
            caveat + [f"Set {env} in your environment; it is undefined if missing."],
        )
    return None


# ---- dependency upgrades ------------------------------------------------------------------------
def _fix_dependency(f: Finding, text: str) -> FixResult | None:
    extra = f.extra or {}
    pkg, old = extra.get("package"), extra.get("version")
    fixed = (extra.get("fixed_versions") or [None])[0]
    if not (pkg and old and fixed):
        return None
    name = PurePosixPath(f.file_path).name.lower()
    esc_pkg, esc_old = re.escape(pkg), re.escape(old)
    new: str | None = None
    if name.startswith("requirements") and name.endswith(".txt"):
        new = re.sub(
            rf"(?im)^({esc_pkg}(?:\[[^\]]*\])?\s*===?\s*){esc_old}\b",
            rf"\g<1>{fixed}",
            text,
            count=1,
        )
    elif name == "package.json":
        new = re.sub(
            rf'("{esc_pkg}"\s*:\s*")\^?~?{esc_old}(")', rf"\g<1>{fixed}\g<2>", text, count=1
        )
    elif name == "pom.xml" and ":" in pkg:
        artifact = re.escape(pkg.split(":", 1)[1])
        new = re.sub(
            rf"(<artifactId>{artifact}</artifactId>\s*<version>){esc_old}(</version>)",
            rf"\g<1>{fixed}\g<2>",
            text,
            count=1,
        )
    elif name.endswith((".csproj", ".fsproj", ".vbproj")):
        new = re.sub(
            rf'(Include="{esc_pkg}"[^>]*Version=")' + esc_old + '"',
            rf'\g<1>{fixed}"',
            text,
            count=1,
            flags=re.IGNORECASE,
        )
    if new is None or new == text:
        return None  # lockfiles / transitive packages: needs the package manager, not a text edit
    return FixResult(
        new,
        f"Bumped {pkg} from {old} to {fixed}, the release that fixes {extra.get('vulnerability', 'the advisory')}.",
        [
            "Review the changelog for breaking changes between the two versions.",
            "Regenerate your lockfile (npm install / pip-compile / mvn dependency:resolve) and run tests.",
        ],
    )


FIXERS: dict[str, Fixer] = {
    "py.weak-hash": _simple(
        r"hashlib\.(?:md5|sha1)\(",
        "hashlib.sha256(",
        "Replaced MD5/SHA-1 with SHA-256.",
        [
            "The digest is longer (64 hex characters): widen any database column or comparison that "
            "stores it, and re-hash stored values.",
            "For passwords, use a dedicated password hash (argon2, bcrypt or scrypt) instead of a "
            "plain SHA-256.",
        ],
    ),
    "js.weak-hash": _simple(
        r"""createHash\(\s*(['"])(?:md5|sha1)\1""",
        r"createHash(\1sha256\1",
        "Replaced MD5/SHA-1 with SHA-256.",
        [
            "The digest is longer; update anything that stores or compares it.",
            "For passwords, use bcrypt, scrypt or argon2 instead of a bare hash.",
        ],
        re.IGNORECASE,
    ),
    "py.tls-verification-disabled": _simple(
        r"\bverify\s*=\s*False",
        "verify=True",
        "Re-enabled TLS certificate verification.",
        [
            "Requests to servers with self-signed or private-CA certificates will now fail; provide "
            "the CA bundle with verify='/path/to/ca.pem' instead of disabling checks."
        ],
    ),
    "js.tls-verification-disabled": _simple(
        r"rejectUnauthorized\s*:\s*false",
        "rejectUnauthorized: true",
        "Re-enabled TLS certificate verification.",
        [
            "Connections to hosts with untrusted certificates will now fail; trust the correct CA "
            "(the `ca` option) rather than disabling verification."
        ],
    ),
    "py.debug-enabled": _simple(
        r"\b(debug|DEBUG)\s*=\s*True",
        r"\1=False",
        "Turned debug mode off.",
        [
            "Read the setting from an environment variable if you need debug locally, e.g. "
            "debug=os.environ.get('APP_DEBUG') == '1'."
        ],
    ),
    "py.unsafe-deserialization": _fix_yaml_load,
    "py.insecure-random": _fix_python_random,
    "js.innerhtml": _simple(
        r"\.innerHTML(\s*\+?=)",
        r".textContent\1",
        "Assigned to textContent so the value is treated as text, never parsed as HTML.",
        [
            "Any markup in the value will now display literally. If you truly need HTML, sanitise "
            "it with DOMPurify before assigning to innerHTML."
        ],
    ),
    "dep.osv": _fix_dependency,
}
for _rule in (
    "secret.generic-secret-assignment",
    "secret.dotenv-secret",
    "secret.github-token",
    "secret.stripe-live-key",
    "secret.stripe-test-key",
    "secret.slack-token",
    "secret.google-api-key",
    "secret.sendgrid-key",
    "secret.npm-token",
    "secret.anthropic-key",
    "secret.gitlab-token",
    "secret.aws-access-key-id",
):
    FIXERS[_rule] = _fix_secret


def get_fixer(rule_id: str) -> Fixer | None:
    return FIXERS.get(rule_id)
