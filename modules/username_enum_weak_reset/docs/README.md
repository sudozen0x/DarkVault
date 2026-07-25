# username_enum_weak_reset

| Field | Value |
|---|---|
| OWASP | A07:2021 Identification and Authentication Failures |
| CWE | CWE-204 + CWE-640 |
| Difficulty | Easy |
| Chains into | Enumerate victim → derive reset token → account takeover |

## Vulnerable code
`modules/username_enum_weak_reset/routes.py`:
- `forgot_password()` returns 404 for unknown usernames, 200 with a masked
  email for known ones — distinguishable responses leak account existence.
- `_compute_reset_token()` derives the token purely from `username` and
  `user_id` — both discoverable, no server secret, no expiry.

## Player path
1. `POST /forgot-password {"username":"admin"}` → 200 (exists)
   `POST /forgot-password {"username":"notarealuser"}` → 404 (doesn't)
2. Compute the token yourself:
   `sha256("reset:admin:3")[:16]` (admin's user_id=3, established elsewhere
   in the app, e.g. via the idor_beneficiary or jwt_alg_confusion modules)
3. `POST /reset-password {"username":"admin","token":"<computed>","new_password":"Pwned123!"}`
4. Log in as admin with the new password.

## Hints
- Hint 1: "Does the forgot-password response look the same for every username you try?"
- Hint 2: "What does the reset token actually depend on? Is any of it secret?"

## Remediation
- Return an identical response regardless of account existence (generic "if this account exists, instructions were sent").
- Generate reset tokens with a cryptographically random value (`secrets.token_urlsafe(32)`), store it server-side with an expiry, and invalidate after first use.
- Rate-limit the forgot-password endpoint per IP/account.
