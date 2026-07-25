# ssrf_statement_fetch

| Field | Value |
|---|---|
| OWASP | A10:2021 Server-Side Request Forgery |
| CWE | CWE-918 |
| Difficulty | Hard |
| Chains into | SSRF → internal-service (unreachable from host) → credential exposure |

## Vulnerable code
`modules/ssrf_statement_fetch/routes.py: import_statement_from_url()` makes
a server-side `requests.get(url)` to whatever URL the client provides, with
no domain allowlist and no check against internal/private address ranges.

## Why this matters here specifically
`internal_service` (see `docker-compose.yml`) runs on the Docker-internal
`backnet` network with **no host port mapping** — you cannot reach it
directly from your browser or curl on your machine. This endpoint, running
inside the same Docker network as `internal-service`, is the only path in.

## Player path
```
POST /statements/import-from-url
{"url": "http://internal-service:9000/internal/admin-creds"}
```
The response's `preview` field will contain the internal service's JSON,
including an `admin_api_key` that should never be reachable from outside
the internal network.

## Hints
- Hint 1: "This feature makes a request on the server's behalf, from inside the server's own network — where else might that reach?"
- Hint 2: "Check docker-compose.yml — is there anything else running that isn't exposed to your host?"

## Remediation
- Maintain an explicit allowlist of permitted external domains/IPs for server-side fetches; reject everything else by default.
- Resolve the hostname first and reject requests to private/reserved IP ranges (RFC 1918, loopback, link-local) and to internal service names.
- Use a dedicated egress proxy for outbound server-side requests with its own network-level restrictions, so app-level allowlist bugs aren't the only defense.
