# fund_transfer_flaws

| Field | Value |
|---|---|
| OWASP | A01:2021 Broken Access Control (CSRF) + Business Logic |
| CWE | CWE-352 (CSRF) + CWE-841 (missing amount validation) |
| Difficulty | Easy |
| Chains into | Two independent findings on one endpoint |

## Finding 1: CSRF
No CSRF token exists on `POST /transfer`. Paired with
`config.py: SESSION_COOKIE_SAMESITE = "None"` (see that file's comment),
the session cookie is sent even on cross-site requests, so a malicious
page can trigger a transfer using the victim's own session with zero
interaction beyond loading the page.

**PoC**: `docs/csrf_poc.html` in this folder. Host it anywhere, get a
logged-in victim to open it — it auto-submits a transfer to beneficiary
101 for $500 the moment the page loads.

## Finding 2: Business logic — missing amount validation
`transfer()` never checks that `amount > 0`. Submitting a negative amount
does `balance -= (negative number)`, which *increases* the sender's own
balance instead of decreasing it — effectively infinite money.

**PoC**:
```
POST /transfer
{"beneficiary_id": 101, "amount": -5000}
```
Check `/account/balance` before and after — it goes up, not down.

## Hints
- Hint 1 (CSRF): "Is there anything on this form besides the session cookie proving the request came from you?"
- Hint 2 (business logic): "What happens if you send a transfer amount the developer didn't expect — like a negative one?"

## Remediation
- CSRF: implement per-session CSRF tokens (Flask-WTF's `CSRFProtect` is the standard choice), validated on every state-changing POST. Set `SESSION_COOKIE_SAMESITE = "Lax"` or `"Strict"` as defense in depth.
- Business logic: validate `amount > 0` server-side (never trust client-side validation alone), and consider a maximum transfer limit per transaction.
