"""
App factory + module loader.

Design rationale: every vuln module is a self-contained Flask Blueprint
living under /modules/<name>/. This file discovers and registers them
at startup so modules never need to know about each other, and the
core app (auth, session, db) stays the single source of truth for
state that chained vulns depend on (e.g. session cookie format, JWT
secret, user table schema).
"""
import importlib
import os
from pathlib import Path

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_session import Session

db = SQLAlchemy()
sess = Session()

MODULES_DIR = Path(__file__).resolve().parent.parent / "modules"


def create_app(config_object="config.Config"):
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_object(config_object)

    db.init_app(app)
    sess.init_app(app)

    # --- core blueprints (always loaded, other modules depend on these) ---
    from app.core.auth import auth_bp
    from app.core.dashboard import dashboard_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)

    # --- dynamic module discovery ---
    _load_vuln_modules(app)

    return app


def _load_vuln_modules(app):
    """
    Each module dir must expose modules/<name>/routes.py with a
    `bp = Blueprint(...)` object. Modules are enabled/disabled via
    MODULE_MANIFEST in config so you can toggle difficulty sets
    (e.g. ship "beginner" pack without touching module code).
    """
    enabled = set(app.config.get("ENABLED_MODULES", []))
    if not MODULES_DIR.exists():
        return

    for module_path in sorted(MODULES_DIR.iterdir()):
        if not module_path.is_dir():
            continue
        name = module_path.name
        if enabled and name not in enabled:
            continue
        routes_file = module_path / "routes.py"
        if not routes_file.exists():
            continue

        spec = importlib.import_module(f"modules.{name}.routes")
        if hasattr(spec, "bp"):
            app.register_blueprint(spec.bp)
            app.logger.info(f"[module] loaded: {name}")

        # each module can optionally register a seed/reset hook
        if hasattr(spec, "register_reset"):
            app.extensions.setdefault("reset_hooks", {})[name] = spec.register_reset
