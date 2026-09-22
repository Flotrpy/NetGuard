# NetGuard

AI-powered security detection, analysis and remediation platform.

**Detect → Explain → Fix → Verify → Monitor**

> NetGuard is a *defensive* platform: only scan systems, APIs, networks or traffic you own or are
> explicitly authorized to assess. Network scans, API scans and packet-capture imports all require
> an explicit authorization attestation before they run.

## What it does

- **Source code (SAST)** — Python, JavaScript/TypeScript, Java/.NET rule-based static analysis.
- **Secrets** — pattern + entropy detection with redaction, keyed fingerprints and span claiming so
  a secret isn't also reported as a lower-confidence generic match.
- **Dependencies** — npm, PyPI, Maven/Gradle and NuGet lockfile parsing, cross-referenced against
  [OSV.dev](https://osv.dev) advisories with CVSS v3 scoring.
- **Infrastructure as Code** — Terraform (via an HCL parser), Kubernetes manifests and CloudFormation
  templates.
- **Containers** — Dockerfile/Compose analysis, plus scanning a `docker save` image tarball without
  executing it.
- **Network** — authorized discovery, port/service inventory, banner-based service identification and
  a security audit, with a host inventory and logical topology map.
- **Packet analysis** — import a `.pcap`/`.pcapng` capture, get protocol statistics and security
  observations, and search/inspect individual packets (payloads are never displayed).
- **Web API security** — non-destructive (GET/HEAD/OPTIONS only) checks driven by an OpenAPI spec
  and/or a base URL, covering the checks listed at `/api/api-scanner/options`.
- **SBOM** — CycloneDX 1.5 and SPDX 2.3 export for a repository's dependency inventory.
- **AI explain/fix/verify** — a plain-language explanation of a finding, a proposed patch (diff),
  and a rescan-based verification that the patch actually resolved it. Supports Anthropic, Groq or
  Google Gemini; nothing is invented — findings and fixes only include facts observed by scanners.
- **CI/CD** — GitHub/GitLab repository connection with webhook-triggered scans and PR gating, a
  configurable pass/fail policy, project-scoped CI tokens, and `netguard-cli` for running scans and
  enforcing the same policy outside of NetGuard's own server (SARIF output for GitHub code scanning).
- **Reports** — an exportable security assessment (HTML/PDF/JSON/CSV) covering findings, verification
  results, dependency and network detail. Secret values are scrubbed before they ever reach a report.

## Architecture

- `backend/` — FastAPI + SQLAlchemy application (`netguard/`). Scanners run as isolated child
  processes (`scan_isolation`), findings are deduplicated/fingerprinted, and everything is scoped to
  a project with owner/editor/viewer roles.
- `frontend/` — Next.js (App Router) UI. It talks to the API through a same-origin rewrite
  (`next.config.mjs`), so session cookies stay first-party and the API itself never needs permissive
  CORS.

## Access control

There's no separate "username" — accounts are identified by email. The **first account ever
registered automatically becomes admin**, regardless of the registration setting below. For a
single-operator deployment, register that one account, then set `NETGUARD_ALLOW_REGISTRATION=false`
in `.env` so no one else can create a second one — the register endpoint returns `403 Registration is
disabled` for every attempt after the first.

Bootstrap that first account directly against the API (the frontend's register page works too):

```bash
curl -X POST http://localhost:8000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"you@example.com","password":"a-strong-passphrase","name":"Your Name"}'
```

Passwords must be at least 10 characters and must not contain the part of your email before the `@`.

## Running it locally

### Backend

```bash
cd backend
python -m venv .venv
.venv/Scripts/activate        # .venv/bin/activate on macOS/Linux
pip install -e ".[ai,dev]"
uvicorn netguard.main:create_app --factory --reload
```

The API listens on `http://localhost:8000`. In development it auto-generates a secret key
(`backend/data/.dev_secret_key`) and runs an embedded background worker, so no extra setup is needed
to process scans.

Copy `backend/.env.example` to `backend/.env` and fill in real values there — `.env` is git-ignored,
so secrets never end up in version control. See `netguard/config.py` for the full list of settings.

### Frontend

```bash
cd frontend
npm install
npm run dev
```

The UI listens on `http://localhost:3000` and proxies `/api/*` to `NETGUARD_API_URL`
(defaults to `http://localhost:8000`).

### Tests

```bash
cd backend && pytest
cd frontend && npm run typecheck && npm test
```

### `netguard-cli`

Runs scanners and (optionally) enforces a policy without the server, for use in any CI system:

```bash
netguard-cli scan ./path/to/repo --format sarif -o results.sarif
netguard-cli scan ./path/to/repo --policy policy.json --strict
```

See `ci/github-actions.yml` and `ci/gitlab-ci.yml` for ready-to-use pipeline templates, and
`ci/example-policy/policy.json` for a sample gate policy.
