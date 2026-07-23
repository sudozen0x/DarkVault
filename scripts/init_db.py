"""
Usage (inside the app container, or locally with DATABASE_URL set):
    python scripts/init_db.py

Creates all tables (core + every module's models, since they all
share `db` from app/__init__.py) and seeds baseline accounts, then
calls each loaded module's register_reset() hook so module-specific
data (e.g. idor_beneficiary's two beneficiaries) exists too.

This is also what your "reset environment" admin action should call
between training sessions -- drop-and-recreate keeps state honest.
"""
from werkzeug.security import generate_password_hash

from app import create_app, db
from app.core.models import User


def main():
    app = create_app()
    with app.app_context():
        db.drop_all()
        db.create_all()

        db.session.add_all([
            User(id=1, username="attacker", email="attacker@example.com",
                 password_hash=generate_password_hash("Password123!"), role="customer"),
            User(id=2, username="victim", email="victim@example.com",
                 password_hash=generate_password_hash("Password123!"), role="customer"),
            User(id=3, username="admin", email="admin@darkvault.local",
                 password_hash=generate_password_hash("ChangeMe_Admin!2024"), role="admin"),
        ])
        db.session.commit()

        reset_hooks = app.extensions.get("reset_hooks", {})
        for name, hook in reset_hooks.items():
            hook()
            print(f"[seed] ran reset hook for module: {name}")

        print("Database initialized.")


if __name__ == "__main__":
    main()
