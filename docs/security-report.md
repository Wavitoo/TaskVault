# Security Report — TaskVault DevSecOps Pipeline

This report documents every real vulnerability and incident discovered while
building this pipeline — either intentionally introduced for tool demonstration,
or genuinely discovered through the process (build/config issues).

---

## 1. SQL Injection (Intentional Demo)

- **CWE**: CWE-89 — Improper Neutralization of SQL Command Elements
- **OWASP**: A03:2021 - Injection
- **Component**: `backend/routes/auth.js`, `GET /search` (demo branch only, never merged)
- **Severity**: Critical
- **Description**: Query built via template literal interpolation (`` `...${username}...` ``) instead of parameterization.
- **Detection**: Generic Semgrep rulesets (`auto`, `owasp-top-ten`, `security-audit`) failed to detect it — a **false negative**. Required writing a custom taint-mode Semgrep rule (`security/sast/custom-rules.yml`) tracking `req.query`/`req.body`/`req.params` to `pool.query()`'s first argument specifically (via `focus-metavariable`).
- **Proof of Concept** (test environment only): input `' OR '1'='1` on the vulnerable route would return all rows regardless of the query intent.
- **Impact**: Full database read access, potential data exfiltration.
- **Remediation**: Never merged into develop/main; production code uses parameterized queries throughout (verified: 0 findings on develop).
- **Verification**: CI run `30221998735` (red, vulnerable branch) vs `30222131119` (green, clean branch) — same pipeline, different result.

## 2. Vulnerable Dependency — lodash@4.17.4 (Intentional Demo)

- **CVE**: CVE-2019-10744 (and 9 other advisories: prototype pollution, command injection, ReDoS)
- **CVSS**: Critical
- **Component**: `backend/package.json` (demo branch only)
- **Detection**: `npm audit --audit-level=high` in CI, blocking on first run (no false negative here)
- **Remediation**: Never merged; branch closed after capturing proof (run `30222305251`)

## 3. Secret Leak (Intentional Demo, Two-Layer Defense)

- **Component**: `backend/index.js` (demo branch only)
- **Finding 1**: Stripe-formatted fake key (`sk_live_...`) — blocked by **GitHub Push Protection** before even reaching CI (platform-level defense)
- **Finding 2**: Generic high-entropy token — passed Push Protection, detected by **Gitleaks** in CI via `generic-api-key` rule (entropy 3.91)
- **Lesson**: Defense in depth matters — pattern-based detection (Stripe format) and entropy-based detection (generic secrets) catch different cases.

## 4. Docker Build Reproducibility Bug (Real, Discovered Incidentally)

- **Component**: `backend/Dockerfile`, missing `.dockerignore`
- **Severity**: Medium (build integrity, not a direct exploit)
- **Description**: Trivy flagged `lodash@4.17.4` (CRITICAL) on the `develop` branch — impossible, since `develop` never had that dependency. Root cause: local `node_modules/` (containing a stale install from the demo branch) was copied into the Docker image via `COPY . .`, silently overwriting the clean `npm ci` install, because no `.dockerignore` excluded it.
- **Impact**: Docker builds were not reproducible — the image content depended on the developer's local filesystem state, not just the git-tracked source.
- **Remediation**: Added `backend/.dockerignore` excluding `node_modules`, `.env`, `.git`.
- **Verification**: Rebuilt image showed 0 findings for `lodash` after the fix.

## 5. NPM's Own Internal Dependencies (Real Finding)

- **CVEs**: CVE-2026-13149/14257 (`brace-expansion`, HIGH), CVE-2026-59873 (`tar`, CRITICAL), CVE-2026-12151 (`undici`, HIGH)
- **Component**: `node:24-alpine` base image — npm's bundled dependencies, not TaskVault's own code
- **Detection**: Trivy container scan
- **Decision**: Rather than suppress the finding, removed `npm`/`npx`/`yarn` entirely from the runtime stage of the Dockerfile (only needed at build time), eliminating the vulnerable code from the shipped image and reducing attack surface.
- **Verification**: Post-fix Trivy scan shows 0 CRITICAL/HIGH findings.

## 6. Missing HTTP Security Headers (Real Finding, DAST)

- **Component**: `backend/index.js`
- **Findings** (OWASP ZAP baseline scan): `X-Powered-By` header leak [10037], missing CSP [10038], missing Permissions-Policy [10063], cacheable sensitive content [10049]
- **Remediation**: Integrated `helmet` middleware with explicit CSP directives (`frameAncestors: 'none'`, `objectSrc: 'none'`, etc.) and a custom `Cache-Control: no-store` middleware.
- **Verification**: Before/after ZAP scans — 4 warnings → 2 (remaining 2 documented as accepted risk, see SECURITY.md, both only affect nonexistent 404 pages).

## 7. Supply-Chain Risk — Mutable GitHub Action Tags (Real Finding)

- **Component**: `.github/workflows/ci.yml`
- **Detection**: Semgrep's own `github-actions-mutable-action-tag` rule flagged `actions/checkout@v4` etc.
- **Impact**: A compromised action maintainer account could silently repoint the `v4` tag to malicious code, executed in every future CI run.
- **Remediation**: All actions pinned to full commit SHA with a version comment.
- **Note**: This rule also caught our own later addition (`gitleaks-action`) automatically — proof the guardrail works continuously, not just once.

## 8. Broken Security Gate — Deprecated Semgrep Action (Real Finding)

- **Component**: `.github/workflows/ci.yml`, SAST job
- **Description**: `semgrep/semgrep-action@v1` silently crashed (`ValueError: invalid rule severity value: MEDIUM`) but GitHub Actions still reported the job as ✅ green — a **false-green Security Gate**, worse than a simple false negative because it hides its own failure.
- **Root cause**: Deprecated third-party wrapper with an outdated Semgrep engine bundled inside, incompatible with newer community rule severities.
- **Remediation**: Replaced with the official `semgrep/semgrep` Docker image, calling `semgrep scan` directly with `--error`, matching local testing behavior exactly.

## 9. Dependencies Drifted After the Build (Real Finding)

- **Component**: `backend/package-lock.json` (transitive dependencies of `express`)
- **Detection**: the weekly Trivy rescan of the *deployed* image in the sibling project taskvault-platform found `proxy-addr@2.0.7`
  (CVE-2026-90711, **CRITICAL**, IP spoofing via IPv4-mapped IPv6 trust subnet, fixed in 2.0.8) and `body-parser@2.3.0`
  (CVE-2026-111181, HIGH, denial of service, fixed in 2.4.0). A fresh `npm audit` then listed 6 findings (1 critical, 2 high, 3 moderate) including `qs`.
- **Why the pipeline missed it**: the dependencies were clean when the image was built; the advisories were published afterwards.
  A scan that runs only on push cannot see this class of problem.
- **Remediation**: `npm audit fix` and `npm update express pg` (express 5.2.1 to 5.3.0, no breaking change); `npm audit --audit-level=high` is now clean.
  Two MEDIUM findings remain in `nodemon`/`minimatch` (dev-only, not in the image): documented in SECURITY.md.
- **OS packages**: a full-severity Trivy scan of the rebuilt image then listed 11 MEDIUM findings in Alpine packages (OpenSSL 3.5.9-r0, zlib 1.3.2-r1),
  all with a fix available. `RUN apk upgrade --no-cache` in the runtime stage of the Dockerfile applies them: 0 fixable findings remain, all severities.
  Trade-off: the build depends on the state of the Alpine repositories when it runs; reproducibility comes from deploying the image by digest, not from rebuilding.
- **Prevention**: weekly scheduled rescan (`.github/workflows/scheduled-scan.yml`) and Dependabot.

## 10. Documented Follow-ups Implemented (v1.2)

- **Rate limiting** on `/api/auth` (10 / 15 min / IP), tested. Limit: counter is per instance.
- **JWT revocation**: `jti` on every token, `POST /api/auth/logout`, `revoked_tokens` table checked on each request. Tests include a
  mutation check: with the revocation check disabled, 2 tests fail. Limit: no refresh-token rotation.
- **DB port** published on `127.0.0.1` only in `docker-compose.yml`.

## Summary Table

| # | Finding | Severity | Type | Status |
|---|---------|----------|------|--------|
| 1 | SQL Injection | Critical | Demo | Contained, never merged |
| 2 | lodash CVEs | Critical | Demo | Contained, never merged |
| 3 | Secret leak (2 variants) | Critical | Demo | Contained, never merged |
| 4 | Docker build reproducibility | Medium | Real | Fixed |
| 5 | npm internal CVEs | High/Critical | Real | Fixed |
| 6 | Missing HTTP headers | Medium | Real | Fixed (2/4), 2 accepted |
| 7 | Mutable Action tags | Critical (supply chain) | Real | Fixed |
| 8 | False-green SAST gate | Critical (process) | Real | Fixed |
| 9 | Dependencies drifted after build (proxy-addr CRITICAL, body-parser HIGH) | Critical | Real | Fixed (2 MEDIUM dev-only accepted) |
| 10 | Follow-ups: rate limiting, JWT revocation, DB port | High | Hardening | Implemented, limits documented |
