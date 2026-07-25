import os
import tempfile
import redis


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-change-me")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", "postgresql://darkvault:darkvault@db:5432/darkvault"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SESSION_TYPE = "redis"
    # Flask-Session wants a redis.Redis client object here, not the raw
    # URL string -- passing the string silently falls back to a default
    # localhost connection, which doesn't exist inside the container.
    SESSION_REDIS = redis.from_url(
        os.environ.get("REDIS_URL", "redis://redis:6379/0")
    )

    # Intentional finding (CWE-1004: Sensitive Cookie Without HttpOnly
    # Flag) -- kept as its own documented misconfiguration rather than
    # a silent implementation detail, because it's what turns the
    # stored_xss_support_ticket module from "can deface a page" into
    # "can steal a live admin session." Real apps disable this by
    # accident (legacy JS needing cookie access) more often than by
    # deliberate design, which is why it's realistic to chain.
    SESSION_COOKIE_HTTPONLY = False

    # Intentional finding (CWE-352 support): SameSite=None means the
    # session cookie is sent on cross-site requests, including a
    # malicious page's auto-submitting form -- this is what makes
    # fund_transfer_flaws' CSRF actually exploitable. Secure=True is
    # required alongside None or browsers reject the cookie outright;
    # it still works over plain http on localhost specifically, since
    # browsers treat loopback addresses as a secure context.
    SESSION_COOKIE_SAMESITE = "None"
    SESSION_COOKIE_SECURE = True

    # Toggle which vuln modules load. Empty list = load everything in /modules.
    # Use this to ship curated packs: ["idor_beneficiary", "xss_stored_support"]
    # for a "beginner" build vs the full set for advanced.
    ENABLED_MODULES = []

    # Internal-only service used by SSRF chain challenges (not exposed
    # to host network — see docker-compose.yml internal_service).
    INTERNAL_SERVICE_URL = os.environ.get(
        "INTERNAL_SERVICE_URL", "http://internal-service:9000"
    )


class TestConfig(Config):
    """
    Used by the pytest suite. Swaps Redis-backed sessions for
    filesystem ones so `pytest` runs without a live Redis server --
    CI runners and local dev shouldn't need the full docker-compose
    stack just to run unit tests.
    """
    TESTING = True
    SESSION_TYPE = "filesystem"
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", "sqlite:///" + os.path.join(tempfile.gettempdir(), "darkvault_test.db")
    )
