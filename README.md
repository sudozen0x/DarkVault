# DarkVault — Realistic Fintech VAPT Training Platform

Single Flask application simulating a digital banking platform.
Vulnerabilities are embedded in real business workflows (beneficiaries,
transfers, statements, support tickets) rather than exposed as labeled
challenges.

## Architecture

- `app/core/` — auth, session, dashboard. Shared infrastructure every
  module depends on. Vuln modules should override/extend this, not
  weaken it directly (keeps chained-attack modules composable).
- `modules/<name>/` — one directory per vulnerability. Each exposes a
  Flask Blueprint (`routes.py`), local models, seed data, and
  `docs/README.md` (OWASP/CWE mapping, hints, flag location,
  remediation). Use `scripts/new_module.py <name>` to scaffold.
- `internal_service/` — isolated Docker service on a Docker-internal
  network (no host port, no internet route). Target for SSRF-chain
  modules — proves real impact instead of a simulated flag.
- `config.py: ENABLED_MODULES` — curate which modules load, so you can
  ship a "beginner" build vs the full advanced set from one codebase.

## Git branching strategy

- `main` — always deployable; only merges from `develop` via reviewed PR.
- `develop` — integration branch; modules merge here once complete.
- `module/<name>` — one branch per vulnerability module, branched from
  `develop`. Keeps each vuln's dev/test cycle isolated so a broken
  SSTI module doesn't block merging a finished IDOR module.
- `release/x.y` — cut from `develop` when a difficulty pack is ready
  to ship; only bugfixes land here before merging to `main` + tag.

```
main ── merge ← release/1.0 ← develop ← module/idor_beneficiary
                                       ← module/jwt_alg_confusion
                                       ← module/ssrf_statement_fetch
```

## Running locally

```bash
docker compose up --build
```

```bash
docker compose exec app python -m scripts.init_db
```

App on :8080, internal-service unreachable from host by design.

## Adding a module

```bash
python scripts/new_module.py stored_xss_support_ticket
git checkout -b module/stored_xss_support_ticket develop
```
