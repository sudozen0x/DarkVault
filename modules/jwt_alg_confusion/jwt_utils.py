"""
Hand-rolled minimal JWT encode/verify for the mobile API.

This is deliberately NOT using a hardened library call for
verification -- modern PyJWT actually guards against exactly this
attack (it detects PEM-formatted key material and refuses to use it
as an HMAC secret). That guard is a library-level convenience check,
not a cryptographic protection, and plenty of real production
incidents come from teams writing their own JWT verification instead
of trusting the library's algorithm handling -- which is the realistic
scenario this module reproduces.
"""
import base64
import hashlib
import hmac
import json
import time

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

from .keys import PRIVATE_KEY, PUBLIC_KEY, PUBLIC_KEY_PEM


class TokenError(Exception):
    pass


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def issue_token(claims: dict, expires_in: int = 3600) -> str:
    """Server always issues RS256 tokens signed with the private key."""
    header = {"alg": "RS256", "typ": "JWT"}
    payload = dict(claims)
    payload["exp"] = int(time.time()) + expires_in

    header_b64 = _b64url(json.dumps(header).encode())
    payload_b64 = _b64url(json.dumps(payload).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()

    signature = PRIVATE_KEY.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{header_b64}.{payload_b64}.{_b64url(signature)}"


def verify_token(token: str) -> dict:
    """
    VULNERABLE: trusts the client-controlled `alg` header to decide
    HOW to verify, and reuses the same PUBLIC_KEY_PEM bytes as the
    HMAC secret for the HS256 branch. Since the public key is meant
    to be public (mobile clients fetch it to verify RS256 tokens),
    anyone who has it can forge an HS256 token the server will accept
    as valid.
    """
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
    except ValueError:
        raise TokenError("malformed token")

    header = json.loads(_b64url_decode(header_b64))
    payload = json.loads(_b64url_decode(payload_b64))
    signing_input = f"{header_b64}.{payload_b64}".encode()
    signature = _b64url_decode(sig_b64)
    alg = header.get("alg")

    if alg == "RS256":
        try:
            PUBLIC_KEY.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
        except InvalidSignature:
            raise TokenError("invalid RS256 signature")
    elif alg == "HS256":
        # THE BUG: PUBLIC_KEY_PEM should never be usable as a symmetric secret.
        expected = hmac.new(PUBLIC_KEY_PEM.encode(), signing_input, hashlib.sha256).digest()
        if not hmac.compare_digest(signature, expected):
            raise TokenError("invalid HS256 signature")
    else:
        raise TokenError(f"unsupported alg: {alg}")

    if payload.get("exp", 0) < time.time():
        raise TokenError("token expired")

    return payload
