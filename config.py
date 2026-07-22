import os


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-change-me")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", "postgresql://darkvault:darkvault@db:5432/darkvault"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SESSION_TYPE = "redis"
    SESSION_REDIS = os.environ.get("REDIS_URL", "redis://redis:6379/0")

    # Toggle which vuln modules load. Empty list = load everything in /modules.
    # Use this to ship curated packs: ["idor_beneficiary", "xss_stored_support"]
    # for a "beginner" build vs the full set for advanced.
    ENABLED_MODULES = []

    # Internal-only service used by SSRF chain challenges (not exposed
    # to host network — see docker-compose.yml internal_service).
    INTERNAL_SERVICE_URL = os.environ.get(
        "INTERNAL_SERVICE_URL", "http://internal-service:9000"
    )
