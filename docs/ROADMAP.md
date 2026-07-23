# Roadmap

## Working agreement
Build all planned modules first. Once the full set exists, run one
complete QA + pentest pass across the whole app (not per-module) --
catches integration issues between modules that isolated testing
wouldn't surface. Bugs found during that pass get reported and fixed
as their own commits/PRs, not folded into module-build commits.

## Completed
- [x] Core auth (register/login/lockout, User model)
- [x] `idor_beneficiary` — Broken Access Control / IDOR
- [x] `stored_xss_support_ticket` — Stored XSS chained with missing HttpOnly → session theft → admin takeover
- [x] `jwt_alg_confusion` — Mobile API JWT verification trusts client-controlled alg header → forge admin token using the legitimately-public RSA key
- [x] `sqli_transaction_search` — UNION-based SQLi in transaction search → extract users table password hashes (built and verified against real Postgres, not just SQLite)

## Planned
- [ ] Flag submission/tracking system (core infra, not per-module) — a
      `core.flags` table (module_name, hashed flag_value), a
      `POST /submit-flag` endpoint, and a `/progress` page. Retrofit
      into existing modules once built, since it's decoupled from any
      single vuln.
- [ ] Username enumeration / weak password reset → account takeover chain.
      Needs its own dedicated seed user with a realistic-but-discoverable
      username/password pattern — NOT the existing `attacker`/`victim`/`admin`
      dev accounts, which stay simple for local testing.
- [ ] JWT algorithm confusion / signature bypass
- [ ] SQL injection (transaction history search)
- [ ] SSRF (statement PDF fetch-from-URL feature) → pivot to internal-service
- [ ] CSRF (fund transfer)
- [ ] Business logic flaw (unauthorized fund transfer / race condition)
- [ ] File upload vulnerability (KYC document upload)
- [ ] SSTI
- [ ] Insecure deserialization
- [ ] GraphQL section (stretch goal)

See individual `modules/<name>/docs/README.md` for completed module details.
