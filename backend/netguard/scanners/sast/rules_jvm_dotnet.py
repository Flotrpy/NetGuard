"""Java / Kotlin and C# rules."""

from __future__ import annotations

import re

from netguard.enums import Confidence as C
from netguard.enums import Severity as S
from netguard.scanners.sast.rules import Rule, rx

I = re.IGNORECASE  # noqa: E741
JVM = ("java", "kotlin")
CS = ("csharp",)
_SQL = r"\b(?:select|insert\s+into|update|delete\s+from)\b"
_SECRET_WORDS = r"(?=.*(?:token|secret|password|passwd|session|nonce|apikey|api_key|csrf|salt))"


def mk(id_, title, cat, sev, conf, cwe, langs, pattern, desc, impact, fix, *, flags=0,
       unless=None, expl="medium", refs=()):
    return Rule(
        id=id_, title=title, category=cat, severity=sev, confidence=conf, cwe=cwe,
        languages=langs, pattern=rx(pattern, flags), unless=rx(unless, flags) if unless else None,
        description=desc, impact=impact, remediation=fix, exploitability=expl, references=refs,
    )


RULES: list[Rule] = [
    # ---- Java / Kotlin ------------------------------------------------------------------
    mk("java.sql-injection", "SQL statement built by concatenation", "SQL Injection", S.HIGH,
       C.MEDIUM, "CWE-89", JVM,
       rf"(?:executeQuery|executeUpdate|\.execute|prepareStatement|createQuery|createNativeQuery)"
       rf"\s*\(\s*(?:\"[^\"]*{_SQL}[^\"]*\"\s*\+|String\.format\(\s*\"[^\"]*{_SQL})",
       "A SQL string is assembled from variables and sent to the database.",
       "An attacker can alter the query to read or modify data.",
       "Use PreparedStatement with ? placeholders (or named parameters in JPA/JdbcTemplate).",
       flags=I, expl="high"),
    mk("java.command-injection", "OS command built from dynamic input", "Command Injection",
       S.HIGH, C.MEDIUM, "CWE-78", JVM,
       r"Runtime\.getRuntime\(\)\.exec\s*\(\s*(?:\"[^\"]*\"\s*\+|[a-zA-Z_]\w*\s*[,)])|"
       r"new\s+ProcessBuilder\s*\([^)]*\+",
       "A command line is built from variables and executed.",
       "Attacker input can inject additional commands.",
       "Pass arguments as a fixed String[]/List, never through a shell, and validate against "
       "an allow-list.", expl="high"),
    mk("java.unsafe-deserialization", "Java native deserialization", "Unsafe Deserialization",
       S.HIGH, C.MEDIUM, "CWE-502", JVM,
       r"new\s+ObjectInputStream\s*\(|\.readObject\s*\(\s*\)|new\s+XMLDecoder\s*\(",
       "ObjectInputStream/XMLDecoder deserialize arbitrary object graphs.",
       "Gadget chains in the classpath lead to remote code execution.",
       "Avoid Java serialization for untrusted data; use JSON with explicit types or apply an "
       "ObjectInputFilter allow-list.", expl="high"),
    mk("java.weak-hash", "Weak hash algorithm (MD5 / SHA-1)", "Insecure Cryptography", S.MEDIUM,
       C.HIGH, "CWE-327", JVM, r"MessageDigest\.getInstance\(\s*\"(?:MD5|SHA-?1)\"",
       "MD5/SHA-1 are broken and unsuitable for security purposes.",
       "Hashes can be forged; passwords cracked quickly.",
       "Use SHA-256+ for integrity and BCrypt/Argon2/PBKDF2 for passwords.", flags=I,
       expl="low"),
    mk("java.weak-cipher", "Weak cipher or ECB mode", "Insecure Cryptography", S.MEDIUM, C.HIGH,
       "CWE-327", JVM,
       r"Cipher\.getInstance\(\s*\"(?:DES|DESede|RC4|RC2|Blowfish|AES|[A-Za-z0-9]+/ECB/[^\"]*)\"",
       "DES/RC4 or ECB mode (including bare \"AES\", which defaults to ECB) is used.",
       "Ciphertext leaks patterns and can be decrypted or modified.",
       "Use AES/GCM/NoPadding with a unique IV per message.", flags=I, expl="low"),
    mk("java.insecure-random", "java.util.Random used for a secret", "Insecure Randomness",
       S.MEDIUM, C.MEDIUM, "CWE-338", JVM, rf"{_SECRET_WORDS}.*new\s+Random\s*\(|"
       rf"{_SECRET_WORDS}.*Math\.random\s*\(",
       "java.util.Random and Math.random() are predictable.",
       "Tokens/keys can be guessed.", "Use java.security.SecureRandom.", flags=I),
    mk("java.xxe", "XML parser factory without hardening", "XML External Entity", S.MEDIUM,
       C.LOW, "CWE-611", JVM,
       r"(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory)"
       r"\.newInstance\s*\(",
       "XML parser factories are used; external entities are enabled by default in many versions.",
       "Malicious XML can read local files or trigger SSRF.",
       "Set disallow-doctype-decl (or disable external entities) and enable secure processing.",
       expl="medium"),
    mk("java.trust-all-certificates", "TLS validation disabled", "Insecure Transport", S.HIGH,
       C.HIGH, "CWE-295", JVM,
       r"checkServerTrusted\s*\([^)]*\)\s*(?:throws[^{]*)?\{\s*\}|ALLOW_ALL_HOSTNAME_VERIFIER|"
       r"NoopHostnameVerifier|TrustAllStrategy|TrustSelfSignedStrategy|"
       r"setHostnameVerifier\(\s*\([^)]*\)\s*->\s*true\s*\)",
       "The application trusts every certificate or hostname.",
       "TLS connections can be intercepted (man-in-the-middle).",
       "Use the default trust store; pin or install the correct CA instead of trusting all.",
       expl="medium"),
    mk("java.path-traversal", "File path built from request parameter", "Path Traversal", S.HIGH,
       C.MEDIUM, "CWE-22", JVM,
       r"(?:new\s+File|Paths\.get|new\s+FileInputStream|new\s+FileReader)\s*\([^;]*"
       r"(?:getParameter|getHeader|@RequestParam|request\.get)",
       "A file path is derived directly from user input.",
       "Attackers can read or overwrite files outside the intended directory.",
       "Normalize and verify the path stays under an allowed base directory; use IDs, not names.",
       expl="high"),
    mk("java.reflected-xss", "Request parameter written to the response", "Cross-Site Scripting",
       S.HIGH, C.MEDIUM, "CWE-79", JVM,
       r"getWriter\(\)\.(?:print|println|write|append)\s*\([^;]*(?:getParameter|getHeader)",
       "User input is written into the HTML response without encoding.",
       "Script injection runs in victims' browsers.",
       "Encode output (OWASP Java Encoder) or use auto-escaping templates.", expl="high"),
    mk("java.open-redirect", "Redirect to a request-supplied URL", "Open Redirect", S.MEDIUM,
       C.MEDIUM, "CWE-601", JVM, r"sendRedirect\s*\([^;]*(?:getParameter|getHeader)",
       "The response redirects to a user-controlled location.",
       "Phishing via a trusted domain.", "Redirect only to allow-listed or relative targets."),
    mk("java.spring-csrf-disabled", "Spring Security CSRF protection disabled",
       "Authorization", S.MEDIUM, C.MEDIUM, "CWE-352", JVM,
       r"csrf\(\s*\)\s*\.disable\s*\(|csrf\s*\(\s*\w+\s*->\s*\w+\.disable\s*\(|"
       r"csrf\s*\(\s*(?:AbstractHttpConfigurer|\w+)::disable\s*\)",
       "CSRF protection is switched off.",
       "State-changing requests can be forged if the app uses cookie/session authentication.",
       "Keep CSRF enabled for browser clients; disable only for stateless token-authenticated APIs."),
    mk("java.spring-permit-all", "Broad permitAll() authorization rule", "Authorization",
       S.MEDIUM, C.LOW, "CWE-862", JVM,
       r"antMatchers\(\s*\"/\*\*\"\s*\)\s*\.permitAll|anyRequest\(\)\s*\.permitAll",
       "All requests are permitted without authentication.",
       "Sensitive endpoints may be reachable by anyone.",
       "Default to authenticated() and permit only specific public paths.", expl="low"),
    mk("java.hardcoded-credential-check", "Credential compared to a hard-coded value",
       "Insecure Authentication", S.HIGH, C.MEDIUM, "CWE-798", JVM,
       r"(?:password|passwd|pwd|secret|token)\w*\.equals\(\s*\"[^\"]{3,}\"\s*\)|"
       r"\"[^\"]{3,}\"\.equals\(\s*\w*(?:password|passwd|pwd|secret|token)\w*\s*\)",
       "Authentication logic compares a credential to a literal.",
       "Anyone with the source can authenticate.",
       "Verify against salted hashes in a datastore or secret manager.", flags=I, expl="high"),
    # ---- C# -----------------------------------------------------------------------------
    mk("cs.sql-injection", "SQL command built from strings", "SQL Injection", S.HIGH, C.MEDIUM,
       "CWE-89", CS,
       rf"(?:new\s+SqlCommand|FromSqlRaw|ExecuteSqlRaw|SqlQuery)\s*\(\s*"
       rf"(?:\$\"[^\"]*{{|@?\"[^\"]*{_SQL}[^\"]*\"\s*\+)",
       "A SQL command is created from an interpolated or concatenated string.",
       "An attacker can alter the query.",
       "Use SqlParameter / parameterized queries, or FromSqlInterpolated.", flags=I,
       expl="high"),
    mk("cs.command-injection", "Process started with dynamic arguments", "Command Injection",
       S.HIGH, C.MEDIUM, "CWE-78", CS,
       r"Process\.Start\s*\([^)]*\+|Arguments\s*=\s*(?:\$\"|\"[^\"]*\"\s*\+)",
       "A process is launched with arguments built from variables.",
       "Attacker input can inject additional arguments or commands.",
       "Pass validated arguments via ArgumentList and avoid shell execution.", expl="high"),
    mk("cs.unsafe-deserialization", "Unsafe .NET deserialization", "Unsafe Deserialization",
       S.HIGH, C.HIGH, "CWE-502", CS,
       r"\b(?:BinaryFormatter|SoapFormatter|NetDataContractSerializer|LosFormatter|"
       r"ObjectStateFormatter)\b|TypeNameHandling\s*=\s*TypeNameHandling\.(?:All|Auto|Objects|Arrays)",
       "Formatters that instantiate arbitrary types are used.",
       "Untrusted input can lead to remote code execution.",
       "Use System.Text.Json or DataContractSerializer with known types; avoid BinaryFormatter.",
       expl="high"),
    mk("cs.weak-hash", "Weak hash algorithm (MD5 / SHA-1)", "Insecure Cryptography", S.MEDIUM,
       C.HIGH, "CWE-327", CS,
       r"\b(?:MD5|SHA1)\.Create\s*\(|new\s+(?:MD5|SHA1)(?:CryptoServiceProvider|Managed)\b",
       "MD5/SHA-1 are broken.", "Hashes can be forged; passwords cracked.",
       "Use SHA-256+ and a password hasher (PBKDF2/Argon2/BCrypt).", expl="low"),
    mk("cs.tls-verification-disabled", "TLS validation disabled", "Insecure Transport", S.HIGH,
       C.HIGH, "CWE-295", CS,
       r"ServerCertificateValidationCallback\s*\+?=\s*[^;]*(?:true|delegate)|"
       r"ServerCertificateCustomValidationCallback\s*=\s*[^;]*(?:true|DangerousAcceptAny)",
       "Certificate validation callbacks accept every certificate.",
       "Connections can be intercepted.", "Remove the override and trust the correct CA.",
       expl="medium"),
    mk("cs.path-traversal", "File path built from request data", "Path Traversal", S.HIGH,
       C.MEDIUM, "CWE-22", CS,
       r"(?:File|Directory)\.\w+\s*\([^;]*Request\.(?:Query|Form|QueryString|Params)",
       "A file operation takes a path from request input.",
       "Attackers can access files outside the intended directory.",
       "Use Path.GetFileName and verify the resolved path is inside an allowed root.",
       expl="high"),
    mk("cs.xxe", "XML DTD/resolver enabled", "XML External Entity", S.MEDIUM, C.MEDIUM,
       "CWE-611", CS,
       r"DtdProcessing\s*=\s*DtdProcessing\.Parse|XmlResolver\s*=\s*new\s+XmlUrlResolver",
       "DTD processing / external resolution is enabled.",
       "Malicious XML can read local files or trigger SSRF.",
       "Set DtdProcessing.Prohibit and XmlResolver = null."),
    mk("cs.request-validation-disabled", "ASP.NET request validation disabled",
       "Cross-Site Scripting", S.MEDIUM, C.MEDIUM, "CWE-79", CS,
       r"\[ValidateInput\(\s*false\s*\)\]|ValidateRequest\s*=\s*\"?false|\[AllowHtml\]",
       "Built-in request validation against script injection is turned off.",
       "Unencoded HTML may reach pages, enabling XSS.",
       "Keep validation on and HTML-encode output; sanitise rich-text input explicitly."),
    mk("cs.insecure-random", "System.Random used for a secret", "Insecure Randomness", S.MEDIUM,
       C.MEDIUM, "CWE-338", CS, rf"{_SECRET_WORDS}.*new\s+Random\s*\(",
       "System.Random is predictable.", "Tokens/keys can be guessed.",
       "Use RandomNumberGenerator (System.Security.Cryptography).", flags=I),
]
