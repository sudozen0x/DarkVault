# jwt_alg_confusion

| Field | Value |
|---|---|
| OWASP | A02:2021 Cryptographic Failures |
| CWE | CWE-347 Improper Verification of Cryptographic Signature |
| Difficulty | Advanced |
| Chains into | Forged JWT → admin API access (no password needed) |

## Vulnerable code
`modules/jwt_alg_confusion/jwt_utils.py: verify_token()` — trusts the
client-controlled `alg` header. If `alg=HS256`, it HMAC-verifies using
`PUBLIC_KEY_PEM` as the secret — the same public key that's legitimately
exposed for RS256 verification.

## Player path
1. `GET /api/mobile/public-key` — save the PEM output.
2. `POST /api/mobile/login` with any customer credentials (e.g.
   `attacker` / `Password123!`) — inspect the returned JWT, note `alg: RS256`
   in the header.
3. Forge a new token: header `{"alg":"HS256","typ":"JWT"}`, payload
   `{"user_id":3,"username":"admin","role":"admin","exp":<future unix ts>}`,
   HMAC-SHA256 signed using the exact PEM string (including `-----BEGIN...`
   header/footer and newlines) as the key.
   - `jwt_tool` automates this: `python3 jwt_tool.py <legit_token> -X k -pk public_key.pem`
   - Or manually with PyJWT locally (note: PyJWT's own `encode()` blocks this
     by design now — you have to build the token by hand, see `jwt_utils.py`
     for the exact signing logic to replicate).
4. `GET /api/mobile/admin/overview` with `Authorization: Bearer <forged token>`.

## Hints
- Hint 1: "The server issues RS256 tokens. Does it only *accept* RS256?"
- Hint 2: "What's actually secret about a key that's served over an unauthenticated GET endpoint?"

## Remediation
- Never let the token's own header dictate which algorithm/key type verification uses — pin one algorithm server-side (`jwt.decode(token, key, algorithms=["RS256"])` with no alternatives) and reject anything else outright.
- Use distinct key material for signing vs. any symmetric use cases — never let RSA public key bytes double as an HMAC secret.
- Prefer a maintained library's guarded decode path over hand-rolled verification (ironically, this module exists specifically because we bypassed that guard to demonstrate the underlying bug).
