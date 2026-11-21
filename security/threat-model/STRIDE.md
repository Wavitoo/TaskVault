# Threat Model — TaskVault (STRIDE)

## Architecture Overview

Internet --> [Backend API : Express/Node] --> [PostgreSQL DB]

Trust Boundary 1: Internet <-> API
Trust Boundary 2: API <-> DB
Trust Boundary 3: Authenticated user <-> Unauthenticated user
Trust Boundary 4: User A <-> User B (data isolation)

## Assets
- User passwords (bcrypt hashed)
- JWT tokens (identity proof)
- Task data (per-user ownership)
- JWT_SECRET (root of trust for all sessions)
- Database credentials

## Threat Actors
- Anonymous internet attacker
- Authenticated malicious user (valid account, targets other users' data)
- Supply-chain attacker (compromised dependency/action)

## STRIDE Analysis

| # | Component | Threat | Category | Impact | Likelihood | Risk | Mitigation | Status |
|---|-----------|--------|----------|--------|------------|------|------------|--------|
| 1 | Login | Attacker guesses/brute-forces password | Spoofing | High | Medium | High | bcrypt (slow hash, 12 rounds) + rate limit on /api/auth (10 requests / 15 min / IP, in-memory per instance, tested) | Mitigated |
| 2 | Login | Username enumeration via error messages | Info Disclosure | Medium | Medium | Medium | Generic "Invalid credentials" for both wrong user/password | Mitigated |
| 3 | /api/auth/register | SQL Injection via crafted username | Tampering | Critical | Low | Medium | Parameterized queries throughout | Mitigated |
| 4 | JWT | Token forged if JWT_SECRET leaks | Spoofing/Elevation | Critical | Low | High | Secret never committed (Gitleaks + Push Protection); stored in .env, git-ignored | Mitigated |
| 5 | JWT | Token replay after logout (no revocation) | Repudiation | Medium | Medium | Medium | POST /api/auth/logout revokes the token (jti stored in a revocation table, checked on every request; tested). Tokens without a jti are refused. A token stolen before logout stays valid until expiry; no refresh-token rotation | Mitigated |
| 6 | /api/tasks/:id | IDOR - user A deletes/reads user B's task | Elevation of Privilege | High | Medium | High | WHERE id = $1 AND user_id = $2 on all task queries | Mitigated |
| 7 | Dependencies | Known-CVE package silently introduced | Tampering | High | Medium | High | SCA (npm audit) blocks HIGH/CRITICAL in CI | Mitigated |
| 8 | Docker image | Vulnerable base image / bundled tools (npm) | Tampering | High | Medium | Medium | Trivy scan in CI; npm/npx/yarn stripped from runtime stage | Mitigated |
| 9 | CI/CD | Compromised GitHub Action (supply chain) | Tampering | Critical | Low | High | All actions pinned to commit SHA (found via Semgrep custom rule) | Mitigated |
| 10 | API (any route) | Denial of Service via request flooding | Denial of Service | High | Medium | High | Rate limit on /api/auth only (tested); other routes are not rate limited | Partial |
| 11 | Database | Direct DB access if port 5432 exposed publicly | Info Disclosure | Critical | Low | Medium | Compose binds 5432 to 127.0.0.1 only (not reachable from the network); never published in the Kubernetes deployment (taskvault-platform) | Mitigated |
| 12 | Secrets | .env accidentally committed | Info Disclosure | Critical | Low | Medium | .gitignore + Gitleaks CI + GitHub Push Protection (defense in depth, tested in Phase 6) | Mitigated |

## Follow-ups: status

Implemented (v1.2), with tests:
1. Rate limiting on /api/auth (threats 1 and 10, partial for 10) - `express-rate-limit`, 10 requests per 15 minutes per IP.
2. JWT revocation (threat 5) - `POST /api/auth/logout` plus a `revoked_tokens` table.
3. DB port bound to localhost (threat 11).

Still open (honest list):
- The rate-limit counter is in memory **per instance**: with N replicas the effective limit is N x 10. A shared store (Redis) would make it exact.
- No refresh-token rotation: access tokens still live 1 hour; a token stolen before logout is usable until it expires.
- Rate limiting covers /api/auth only, not the whole API.
- No account lockout and no alerting on repeated failures (see docs/monitoring.md).
