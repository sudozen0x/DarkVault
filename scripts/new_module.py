#!/usr/bin/env python3
"""
Usage: python scripts/new_module.py stored_xss_support_ticket

Generates modules/<name>/{routes.py, models.py, seed.py, docs/README.md}
from templates so every module has the same shape: routes.py exposes
`bp` and optionally `register_reset()`, docs/README.md follows the
same table format (OWASP/CWE/difficulty/chain/hints/flag/remediation).
This is what lets the reset tool and the admin difficulty-pack config
treat every module identically regardless of what vuln it teaches.
"""
import sys
import textwrap
from pathlib import Path

TEMPLATE_ROUTES = '''"""
Module: {name}
Difficulty: TODO
OWASP: TODO

Business context: TODO - describe the legitimate feature this vuln
lives inside, and why a player would find it during normal recon
rather than because it's labeled as a challenge.
"""
from flask import Blueprint

bp = Blueprint("{name}", __name__, url_prefix="/api/{name}")


def register_reset():
    from .seed import run_seed
    from app import db
    run_seed(db)
'''

TEMPLATE_DOCS = """# {name}

| Field | Value |
|---|---|
| OWASP | TODO |
| API Top 10 | TODO |
| CWE | TODO |
| Difficulty | TODO |
| Chains into | TODO |

## Vulnerable endpoint
TODO

## Player path (expected recon flow)
TODO

## Hints (progressive disclosure)
- Hint 1: TODO
- Hint 2: TODO

## Flag location
TODO

## Remediation
TODO
"""

TEMPLATE_SEED = '''def run_seed(db):
    """Reset this module's data to its known-good starting state."""
    pass
'''


def main():
    if len(sys.argv) != 2:
        print("Usage: python scripts/new_module.py <module_name>")
        sys.exit(1)

    name = sys.argv[1]
    base = Path(__file__).resolve().parent.parent / "modules" / name
    if base.exists():
        print(f"modules/{name} already exists")
        sys.exit(1)

    (base / "templates").mkdir(parents=True)
    (base / "docs").mkdir(parents=True)

    (base / "routes.py").write_text(TEMPLATE_ROUTES.format(name=name))
    (base / "seed.py").write_text(TEMPLATE_SEED)
    (base / "docs" / "README.md").write_text(TEMPLATE_DOCS.format(name=name))
    (base / "__init__.py").touch()

    print(f"Created modules/{name}/ — remember to add '{name}' to "
          f"config.py ENABLED_MODULES if you're curating a pack.")


if __name__ == "__main__":
    main()
