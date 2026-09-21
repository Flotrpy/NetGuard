"""Secret detection patterns and rotation guidance."""

from __future__ import annotations

import re
from dataclasses import dataclass

from netguard.enums import Confidence, Severity


@dataclass(frozen=True)
class SecretRule:
    id: str
    name: str
    provider: str  # "" when not identifiable
    category: str  # cloud | vcs | payments | messaging | ai | database | crypto | generic
    pattern: re.Pattern[str]
    severity: Severity
    confidence: Confidence
    group: int = 0  # regex group holding the secret value
    prefix: str = ""  # non-secret prefix kept in the redacted preview
    generic: bool = False  # generic rules need entropy/placeholder filtering
    cwe: str = "CWE-798"
    # Mask from the match start to the end of the line (private keys can share a line with
    # their body, e.g. JSON service-account files).
    redact_to_eol: bool = False


def _r(id_, name, provider, cat, pattern, sev, conf, **kw) -> SecretRule:
    return SecretRule(id_, name, provider, cat, re.compile(pattern), sev, conf, **kw)


S, C = Severity, Confidence
_KEYWORDS = (
    r"password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|"
    r"client[_-]?secret|private[_-]?key|secret[_-]?key|token"
)

# Order matters: provider-specific rules run first and claim their text span; generic rules only
# fire on text no specific rule already matched.
RULES: list[SecretRule] = [
    _r("private-key", "Private key", "", "crypto",
       r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED |PRIVATE )?PRIVATE KEY(?: BLOCK)?-----",
       S.CRITICAL, C.HIGH, prefix="-----BEGIN", cwe="CWE-321", redact_to_eol=True),
    _r("aws-access-key-id", "AWS access key ID", "AWS", "cloud",
       r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[A-Z0-9]{16}\b", S.CRITICAL, C.HIGH,
       prefix="AKIA"),
    _r("aws-secret-access-key", "AWS secret access key", "AWS", "cloud",
       r"(?i)aws[\w\s.\-]{0,30}?(?:secret|private)[\w\s.\-]{0,20}?[:=]\s*['\"]?([A-Za-z0-9/+=]{40})\b",
       S.CRITICAL, C.MEDIUM, group=1),
    _r("github-token", "GitHub token", "GitHub", "vcs",
       r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b", S.HIGH, C.HIGH, prefix="ghp_"),
    _r("github-fine-grained-token", "GitHub fine-grained token", "GitHub", "vcs",
       r"\bgithub_pat_[A-Za-z0-9_]{22,255}\b", S.HIGH, C.HIGH, prefix="github_pat_"),
    _r("gitlab-token", "GitLab personal access token", "GitLab", "vcs",
       r"\bglpat-[A-Za-z0-9_\-]{20,}\b", S.HIGH, C.HIGH, prefix="glpat-"),
    _r("slack-token", "Slack token", "Slack", "messaging",
       r"\bxox[baprs]-[A-Za-z0-9-]{10,72}\b", S.HIGH, C.HIGH, prefix="xox"),
    _r("slack-webhook", "Slack incoming webhook URL", "Slack", "messaging",
       r"https://hooks\.slack\.com/services/T[A-Z0-9]{6,}/B[A-Z0-9]{6,}/[A-Za-z0-9]{16,}",
       S.MEDIUM, C.HIGH, prefix="https://hooks.slack.com/"),
    _r("stripe-live-key", "Stripe live secret key", "Stripe", "payments",
       r"\b[sr]k_live_[A-Za-z0-9]{16,}\b", S.CRITICAL, C.HIGH, prefix="sk_live_"),
    _r("stripe-test-key", "Stripe test secret key", "Stripe", "payments",
       r"\b[sr]k_test_[A-Za-z0-9]{16,}\b", S.LOW, C.HIGH, prefix="sk_test_"),
    _r("google-api-key", "Google API key", "Google", "cloud",
       r"\bAIza[0-9A-Za-z_\-]{35}\b", S.MEDIUM, C.HIGH, prefix="AIza"),
    _r("google-oauth-secret", "Google OAuth client secret", "Google", "cloud",
       r"\bGOCSPX-[A-Za-z0-9_\-]{28}\b", S.HIGH, C.HIGH, prefix="GOCSPX-"),
    _r("gcp-service-account", "GCP service account private key", "Google", "cloud",
       r"\"private_key\"\s*:\s*\"-----BEGIN PRIVATE KEY-----", S.CRITICAL, C.HIGH,
       cwe="CWE-321", redact_to_eol=True),
    _r("azure-storage-key", "Azure storage account key", "Microsoft Azure", "cloud",
       r"AccountKey=([A-Za-z0-9+/]{60,}={0,2})", S.CRITICAL, C.HIGH, group=1),
    _r("sendgrid-key", "SendGrid API key", "SendGrid", "messaging",
       r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b", S.HIGH, C.HIGH, prefix="SG."),
    _r("twilio-key", "Twilio API key", "Twilio", "messaging",
       r"\bSK[0-9a-fA-F]{32}\b", S.HIGH, C.MEDIUM, prefix="SK"),
    _r("mailgun-key", "Mailgun API key", "Mailgun", "messaging",
       r"\bkey-[0-9a-f]{32}\b", S.HIGH, C.MEDIUM, prefix="key-"),
    _r("npm-token", "npm access token", "npm", "vcs",
       r"\bnpm_[A-Za-z0-9]{36}\b", S.HIGH, C.HIGH, prefix="npm_"),
    _r("pypi-token", "PyPI upload token", "PyPI", "vcs",
       r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}", S.HIGH, C.HIGH, prefix="pypi-"),
    _r("anthropic-key", "Anthropic API key", "Anthropic", "ai",
       r"\bsk-ant-[A-Za-z0-9_\-]{30,}\b", S.HIGH, C.HIGH, prefix="sk-ant-"),
    _r("openai-key", "OpenAI API key", "OpenAI", "ai",
       r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,}\b|\bsk-proj-[A-Za-z0-9_\-]{40,}\b",
       S.HIGH, C.HIGH, prefix="sk-"),
    _r("database-url", "Credentials in a connection string", "", "database",
       r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql|sqlserver)"
       r"://[^\s:@/'\"]+:([^\s@/'\"]{3,})@[^\s/'\"]+", S.HIGH, C.HIGH, group=1),
    _r("basic-auth-url", "Credentials embedded in a URL", "", "generic",
       r"\bhttps?://[^\s:@/'\"]+:([^\s@/'\"]{3,})@[^\s/'\"]+", S.MEDIUM, C.MEDIUM, group=1),
    _r("jwt", "JSON Web Token", "", "generic",
       r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b", S.MEDIUM,
       C.MEDIUM, prefix="eyJ", generic=True),
    _r("generic-secret-assignment", "Hard-coded credential", "", "generic",
       rf"(?i)\b(?:\w*(?:{_KEYWORDS})\w*)\s*(?::|=|=>|:=)\s*['\"]([^'\"\s]{{8,}})['\"]",
       S.MEDIUM, C.LOW, group=1, generic=True),
    _r("dotenv-secret", "Secret in environment file", "", "generic",
       rf"(?im)^\s*(?:export\s+)?[A-Z0-9_]*(?:{_KEYWORDS.upper()})[A-Z0-9_]*\s*=\s*['\"]?([^\s'\"#]{{8,}})",
       S.MEDIUM, C.LOW, group=1, generic=True),
]

_GUIDANCE_STEPS = (
    "1. Treat the secret as compromised: revoke or rotate it NOW at the provider{where}.\n"
    "2. Create a replacement and store it in a secret manager or environment variable "
    "(never in source control).\n"
    "3. Remove it from the code AND from git history (git filter-repo or BFG), then force-push "
    "and ask collaborators to re-clone.\n"
    "4. Review the provider's audit/access logs for use of the old credential.\n"
    "5. Add secret scanning to pre-commit and CI so this cannot recur."
)

PROVIDER_LINKS = {
    "AWS": " (IAM console -> Users -> Security credentials -> Make inactive, then delete)",
    "GitHub": " (github.com/settings/tokens -> Delete)",
    "GitLab": " (User settings -> Access tokens -> Revoke)",
    "Slack": " (api.slack.com/apps -> revoke token / regenerate webhook)",
    "Stripe": " (Dashboard -> Developers -> API keys -> Roll key)",
    "Google": " (Google Cloud console -> APIs & Services -> Credentials -> delete/regenerate)",
    "Microsoft Azure": " (Storage account -> Access keys -> Rotate key)",
    "SendGrid": " (Settings -> API Keys -> Delete)",
    "npm": " (npmjs.com -> Access Tokens -> Revoke)",
    "PyPI": " (pypi.org -> Account settings -> API tokens -> Remove)",
    "Anthropic": " (console.anthropic.com -> API keys -> Disable)",
    "OpenAI": " (platform.openai.com -> API keys -> Revoke)",
}


def guidance_for(rule: SecretRule) -> str:
    where = PROVIDER_LINKS.get(rule.provider, "")
    if rule.category == "database":
        where = " (change the database user's password and update every consumer)"
    if rule.category == "crypto":
        where = " (generate a new key pair, replace the public key wherever it is trusted)"
    return _GUIDANCE_STEPS.format(where=where)
