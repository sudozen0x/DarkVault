# mass_assignment_role

| Field | Value |
|---|---|
| OWASP | A08:2021 Software and Data Integrity Failures |
| CWE | CWE-915 |
| Difficulty | Medium |
| Chains into | Self-service privilege escalation to admin |

## Vulnerable code
`modules/mass_assignment_role/routes.py: update_profile()` loops over every
key in the submitted JSON and calls `setattr(user, key, value)` for any
attribute that exists on the model — including `role`, which was never
meant to be client-editable.

## Player path
1. Log in as a normal customer.
2. `PATCH /profile` with body `{"role": "admin"}`.
3. **Log out and log back in** — this matters: `role` is only written to
   your session at login time (see `app/core/auth.py`), so the tampered
   DB value doesn't take effect until a fresh login re-reads it.
4. You're now an admin session — try the admin endpoints from other
   modules (e.g. `stored_xss_support_ticket`'s `/admin/support`).

## Hints
- Hint 1: "What happens if you add fields to the profile update request that aren't shown in the form?"
- Hint 2: "Changing the database value and changing what your current session believes about you aren't the same thing — when would the second one catch up?"

## Remediation
- Never mass-assign from raw client input. Explicitly pull only allowed fields: `user.username = data.get("username", user.username)`.
- If using an ORM/ marshalling library with bulk-update helpers, use an explicit allowlist/schema (e.g. marshmallow, Pydantic) rather than accepting an arbitrary dict.
- Treat `role` (and other privilege-bearing fields) as admin-only writable, checked server-side regardless of which endpoint touches the user record.
