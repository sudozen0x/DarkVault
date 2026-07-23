"""
Generates an RSA keypair once per app process for signing mobile API
tokens. In a real deployment this would be a long-lived key loaded
from a secrets manager, not regenerated on restart -- but for this
training environment, in-memory-per-run is fine since we're not
persisting mobile sessions across restarts.

PUBLIC_KEY_PEM is legitimately exposed via GET /api/mobile/public-key
(mobile clients need it to verify server-issued tokens, same as any
real JWKS endpoint) -- the vulnerability isn't that this key is
public, it's that verification code reuses it as an HMAC secret too.
"""
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

PRIVATE_KEY = _key
PUBLIC_KEY = _key.public_key()

PUBLIC_KEY_PEM = PUBLIC_KEY.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
).decode()
