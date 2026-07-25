"""
Central registry of every module's player-facing metadata: tier,
title, mission briefing (NULLWAVE narrative framing), and the SHA-256
hash of its canonical flag.

Deliberately code-defined rather than DB-seeded -- these are
design-time constants, and keeping them in version control means the
flag *hashes* are visible in the public repo (fine, that's how a
hash is supposed to work) while the plaintext flags themselves only
ever exist inside each module's actual vulnerable data path, never
here.

Each module embeds its own real flag in whatever its exploit reveals
(see individual modules/<name>/docs/README.md "Flag location"
sections) -- this registry only holds the hash to check submissions
against, plus the narrative wrapper. The bank app's own UI/UX never
references any of this; it only appears in the meta-layer (briefings
page, /flags/submit, /progress).
"""
import hashlib


def _h(flag: str) -> str:
    return hashlib.sha256(flag.encode()).hexdigest()


CONTRACTS = {
    "idor_beneficiary": {
        "tier": "Easy",
        "title": "Ghost Account",
        "briefing": (
            "The Grid's beneficiary lookup trusts whatever ID you hand it. "
            "NULLWAVE wants proof another customer's account is one integer away."
        ),
        "flag_hash": _h("DARKVAULT{1d0r_by_4ny_0th3r_n4m3}"),
    },
    "username_enum_weak_reset": {
        "tier": "Easy",
        "title": "Open Door Policy",
        "briefing": (
            "Their password reset flow answers every question you ask it, including "
            "the ones it shouldn't. Take the admin account without ever touching their inbox."
        ),
        "flag_hash": _h("DARKVAULT{f0rg0t_my_p4ssw0rd_4nd_my_ethics}"),
    },
    "fund_transfer_flaws": {
        "tier": "Easy",
        "title": "Negative Balance, Positive Outcome",
        "briefing": (
            "The transfer endpoint never imagined someone would send it a negative number. "
            "Show NULLWAVE what happens when you do."
        ),
        "flag_hash": _h("DARKVAULT{m4th_is_h4rd_v4lid4tion_h4rder}"),
    },
    "mass_assignment_role": {
        "tier": "Medium",
        "title": "Self-Promotion",
        "briefing": (
            "Somewhere in the profile update handler, every field you send gets trusted. "
            "Give yourself the title you deserve."
        ),
        "flag_hash": _h("DARKVAULT{pr0m0ted_mys3lf_n0_hr_n33ded}"),
    },
    "stored_xss_support_ticket": {
        "tier": "Medium",
        "title": "The Ticket That Bites Back",
        "briefing": (
            "Every support ticket eventually crosses an admin's screen. NULLWAVE needs "
            "eyes inside that queue -- borrow someone else's session to get them."
        ),
        "flag_hash": _h("DARKVAULT{s4f3_filter_0n_0n3_p4g3_0nly}"),
    },
    "sqli_transaction_search": {
        "tier": "Medium",
        "title": "Ask The Database Nicely",
        "briefing": (
            "The transaction search bar talks straight to SQL with zero manners. "
            "Ask it about the users table instead."
        ),
        "flag_hash": _h("DARKVAULT{uni0n_s3l3ct_st4r_fr0m_secrets}"),
    },
    "file_upload_kyc": {
        "tier": "Medium",
        "title": "Wrong File, Right Result",
        "briefing": (
            "KYC document review accepts anything you throw at it and serves it back "
            "however the browser wants to read it. Upload something the reviewer isn't expecting."
        ),
        "flag_hash": _h("DARKVAULT{.html_is_a_v4lid_id_document_4pp4rently}"),
    },
    "ssrf_statement_fetch": {
        "tier": "Hard",
        "title": "Ask The Server To Do It For You",
        "briefing": (
            "Statement import fetches whatever URL you give it, from wherever it happens to "
            "be sitting on the network. Point it somewhere it was never meant to reach."
        ),
        "flag_hash": _h("DARKVAULT{th3_s3rv3r_is_my_pr0xy_n0w}"),
    },
    "xxe_kyc_xml": {
        "tier": "Hard",
        "title": "Define Your Own Entities",
        "briefing": (
            "The corporate KYC parser will resolve any DTD you write for it, including "
            "one that points straight at the filesystem."
        ),
        "flag_hash": None,  # verified via reading flags/xxe_flag.txt, not a static hash
    },
    "ssti_notification": {
        "tier": "Hard",
        "title": "Your Nickname, Executed",
        "briefing": (
            "The notification preview builds its template out of whatever nickname you pick. "
            "Pick an expression instead of a name."
        ),
        "flag_hash": None,  # verified via reading flags/ssti_flag.txt through RCE
    },
    "jwt_alg_confusion": {
        "tier": "Hard",
        "title": "Two Keys, One Mistake",
        "briefing": (
            "The mobile API's public key was never meant to double as a shared secret. "
            "The verification code disagrees."
        ),
        "flag_hash": _h("DARKVAULT{rs256_hs256_sh0uld_n3v3r_m33t}"),
    },
    "race_condition_double_spend": {
        "tier": "Advanced",
        "title": "Faster Than The Ledger",
        "briefing": (
            "The balance check and the balance update aren't the same moment. "
            "Land ten requests in that gap."
        ),
        "flag_hash": _h("DARKVAULT{sp3nt_m0n3y_i_n3v3r_h4d}"),
    },
    "insecure_deserialization_admin_import": {
        "tier": "Advanced",
        "title": "Restore From Backup",
        "briefing": (
            "The admin 'restore' feature never stopped trusting pickle. Neither should you "
            "stop trusting what it lets you do."
        ),
        "flag_hash": None,  # verified via reading flags/deserialization_flag.txt through RCE
    },
    "capstone_chain": {
        "tier": "Advanced",
        "title": "Full Compromise",
        "briefing": (
            "NULLWAVE's final ask: a customer account, zero special access, full server "
            "compromise and unlimited funds. No new tools -- just the ones you already have."
        ),
        "flag_hash": None,  # derived: complete once its 3 prerequisite modules are solved
        "requires": ["mass_assignment_role", "insecure_deserialization_admin_import", "fund_transfer_flaws"],
    },
}
