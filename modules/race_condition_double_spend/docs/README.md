# race_condition_double_spend

| Field | Value |
|---|---|
| OWASP | A04:2021 Insecure Design |
| CWE | CWE-362 (Race Condition / TOCTOU) |
| Difficulty | Advanced |
| Targets | `fund_transfer_flaws` module's `POST /transfer` endpoint (no separate route of its own) |

## Vulnerable code
`modules/fund_transfer_flaws/routes.py: transfer()` reads `user.balance`,
checks it against the requested amount, then writes a new balance back —
all without a row-level lock (`SELECT ... FOR UPDATE` / SQLAlchemy's
`with_for_update()`). Two concurrent requests can both read the same
starting balance and both pass the sufficiency check before either commit
lands, allowing total transfers to exceed the actual balance.

## Player path
Run `docs/race_poc.py` (needs `pip install requests`) against the live
Docker deployment — it fires 10 concurrent transfer requests of $1,000
each against an account that starts with $5,000, and checks whether more
than one succeeded.

**Note on reliability**: race conditions are timing-dependent by nature.
This is more reliably reproduced against real Postgres under
docker-compose (with gunicorn's 4 workers genuinely running requests in
parallel) than against a single-process test client — this module is
intentionally *not* covered by the automated pytest suite for that reason.
If the first run doesn't show it, increase `CONCURRENT_REQUESTS` in the
script or just run it again.

## Hints
- Hint 1: "What happens if you send several transfer requests at the exact same moment instead of one after another?"
- Hint 2: "Between checking that you have enough balance and actually deducting it — is there a gap an attacker could land in?"

## Remediation
- Use database-level locking on the read: `User.query.with_for_update().get(user_id)` inside a transaction, ensuring concurrent requests serialize instead of interleaving.
- Alternatively, use an atomic conditional update: `UPDATE users SET balance = balance - :amount WHERE id = :id AND balance >= :amount`, checking the row count affected rather than doing a separate read-then-write.
- Idempotency keys on the client side prevent accidental duplicate submissions, though they don't fully replace server-side locking against a deliberate attacker.
