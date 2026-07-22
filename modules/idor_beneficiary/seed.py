"""
Seeds two customers, each with a beneficiary. The flag/PII lives on
victim's (user_id=2) beneficiary record; attacker account is user_id=1.
Realistic values, not "FLAG{...}" placeholders in visible fields --
keep the flag in a place consistent with the vuln (e.g. a hidden
field or the account number itself for this module).
"""
from .models import Beneficiary


def run_seed(db):
    Beneficiary.query.delete()
    db.session.add_all([
        Beneficiary(id=101, owner_id=1, name="J. Perera", account_number="8001223344", bank_name="Commercial Bank"),
        Beneficiary(id=102, owner_id=2, name="A. Fernando", account_number="FLAG-ACCT-9911223", bank_name="Sampath Bank"),
    ])
    db.session.commit()
