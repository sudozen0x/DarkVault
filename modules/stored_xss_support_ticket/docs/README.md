# stored_xss_support_ticket

| Field | Value |
|---|---|
| OWASP | A03:2021 Injection (Cross-Site Scripting) |
| CWE | CWE-79 (Stored XSS) chained with CWE-1004 (missing HttpOnly) |
| Difficulty | Intermediate |
| Chains into | Stored XSS → session cookie theft → administrator account compromise |

## Vulnerable code
`modules/stored_xss_support_ticket/templates/support/admin_queue.html`
renders `{{ t.message | safe }}` — the admin queue trusts customer-submitted
ticket bodies as pre-sanitized HTML. The customer-facing ticket list
(`support/list.html`) does NOT do this and is not vulnerable.

This is paired with a global config decision: `SESSION_COOKIE_HTTPONLY = False`
in `config.py`. Without that, the stolen session cookie couldn't be read by
injected JavaScript at all — worth testing both independently during a
real assessment, since either one alone is a lower-severity finding.

## Player path
1. Log in as a customer (`attacker` / `Password123!`), go to `/support`.
2. Submit a ticket with a payload in the message field, e.g.:
   ```html
   <script>fetch('/api/support/collector',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({cookie:document.cookie})})</script>
   ```
3. Log in as `admin` (`ChangeMe_Admin!2024`) — ideally in a second browser
   profile / incognito window, to mirror a real assessment where you don't
   control the admin's browser directly.
4. Visit `/admin/support` as admin. The payload fires in the admin's real
   session and POSTs their cookie to the collector.
5. Back as attacker, `GET /api/support/collector` to retrieve the stolen
   session cookie.
6. Replace your own `session` cookie value with the stolen one (browser
   devtools → Application → Cookies, or Burp) and reload `/admin/support` —
   you're now browsing as admin without knowing their password.

## Hints
- Hint 1: "Two different pages render your ticket message. Do they treat it the same way?"
- Hint 2: "Check `SESSION_COOKIE_HTTPONLY` and think about what that flag actually controls."

## Remediation
- Never render user-controlled content with `|safe` unless it has passed
  through a real HTML sanitizer (e.g. `bleach`) with an explicit allowlist.
- Set `SESSION_COOKIE_HTTPONLY = True` (Flask's default) — there is almost
  never a legitimate reason for client-side JS to read the session cookie.
- Add `Content-Security-Policy` restricting `script-src` as defense in depth,
  so even a missed sanitization gap doesn't execute arbitrary script.
