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
- [x] `username_enum_weak_reset` — Distinguishable forgot-password responses + predictable reset token → account takeover
- [x] `fund_transfer_flaws` — CSRF (missing token + SameSite=None) and business logic (missing amount validation) on the same endpoint
- [x] `mass_assignment_role` — Profile update accepts arbitrary fields including `role` → privilege escalation
- [x] `file_upload_kyc` — Unrestricted file type + path traversal on upload → host phishing/XSS page on trusted domain
- [x] `ssrf_statement_fetch` — Statement import from URL has no allowlist → pivot into internal-service
- [x] `xxe_kyc_xml` — XML KYC submission resolves external entities → local file read
- [x] `ssti_notification` — Notification preview builds Jinja2 template source from user input → verified RCE
- [x] `race_condition_double_spend` — Non-atomic balance check on fund_transfer_flaws → concurrent double-spend (docs + PoC script, not covered by automated pytest — timing-dependent, verify live)
- [x] `insecure_deserialization_admin_import` — Admin "restore backup" feature calls pickle.loads() on client data → verified RCE
- [x] `capstone_chain` — documentation-only writeup chaining mass_assignment_role → insecure_deserialization_admin_import → fund_transfer_flaws

## Planned
- [ ] Flag submission/tracking system (core infra, not per-module) — a
      `core.flags` table (module_name, hashed flag_value), a
      `POST /submit-flag` endpoint, and a `/progress` page.
- [ ] Difficulty relabeling pass — build order didn't strictly match
      true difficulty; e.g. jwt_alg_confusion (built early) is
      genuinely Hard, while username_enum_weak_reset (built later) is
      genuinely Easy. Reorder for player-facing presentation once a
      flag/progress system exists to hang difficulty labels on.
- [ ] Theming pass (Watch Dogs-style framing for module briefings/UI
      chrome — decided to keep the bank app itself realistic, apply
      theme to surrounding presentation only, not yet started).

## Note on this batch (modules 5-13)
Built together as one batch per explicit request to move faster. All
have full pytest coverage (50/50 passing) run against SQLite, but --
unlike sqli_transaction_search and jwt_alg_confusion, which got full
live-Postgres + live-Docker verification during their own build --
this batch has NOT yet been verified against real Postgres/Docker.
Two things specifically worth checking during the QA pass:
- Any Postgres-specific type/dialect issues (same class of bug the
  SQLi module hit with LIKE case-sensitivity and datetime typing).
- race_condition_double_spend specifically needs live Docker with
  real concurrent workers — it's not meaningfully testable via the
  single-process pytest client.
