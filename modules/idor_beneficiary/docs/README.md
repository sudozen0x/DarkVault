# idor_beneficiary

| Field | Value |
|---|---|
| OWASP | A01:2021 Broken Access Control |
| API Top 10 | API1:2023 Broken Object Level Authorization |
| CWE | CWE-639 |
| Difficulty | Beginner |
| Chains into | idor_beneficiary → sensitive_data_exposure → (planned) priv_esc module |

## Vulnerable endpoint
`GET /api/beneficiaries/<id>` — no ownership check against `session["user_id"]`.

## Player path (expected recon flow)
1. Log in as attacker account, add a beneficiary via normal UI flow.
2. Observe API call in browser devtools / Burp: `GET /api/beneficiaries/101`.
3. Increment ID → `102` returns another customer's beneficiary data.

## Hints (progressive disclosure)
- Hint 1: "Watch what happens when the dashboard loads your beneficiaries."
- Hint 2: "IDs are sequential integers, not UUIDs."

## Flag location
Embedded in `account_number` field of beneficiary id=102.

## Remediation
- Enforce `Beneficiary.query.filter_by(id=id, owner_id=session['user_id'])`.
- Prefer non-sequential (UUID) primary keys for anything cross-tenant.
- Add authorization test coverage per endpoint, not just authentication checks.
