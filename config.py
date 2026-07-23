import os
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
        "DATABASE_URL", "sqlite:////tmp/darkvault_test.db"
    )
