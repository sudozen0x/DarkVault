"""
Module: file_upload_kyc
Difficulty: Medium
OWASP: A04:2021 Insecure Design (Unrestricted File Upload)
CWE: CWE-434 (Unrestricted Upload of File with Dangerous Type) +
     CWE-22 (Path Traversal, via unsanitized filename)

Business context: customers upload an ID document for KYC
verification. No file type is enforced, and the original filename is
used as-is (not run through something like werkzeug's
secure_filename()) when saving. Uploaded files are served back from
a public, unauthenticated static route -- realistic for "here's a
link to view your submitted document."

Two chainable findings:
1. No content-type/extension allowlist -- an attacker can upload an
   .html file containing JavaScript. Since it's served back with
   Flask's default extension-based content-type guessing, visiting
   the file's URL renders it as a live HTML page ON THE BANK'S OWN
   DOMAIN -- usable to host a convincing phishing page or, if a
   victim is tricked into visiting it, an XSS payload with full
   access to that same-origin session (paired with
   SESSION_COOKIE_HTTPONLY = False, same mechanism as the
   stored_xss_support_ticket module).
2. Filename isn't sanitized, so `../../` sequences in the filename
   are not stripped -- allows writing outside the intended upload
   directory.
"""
import os

from flask import Blueprint, request, jsonify, session, abort, send_from_directory

bp = Blueprint("file_upload_kyc", __name__)

UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploaded_documents")
os.makedirs(UPLOAD_DIR, exist_ok=True)


@bp.route("/kyc/upload", methods=["POST"])
def upload_kyc_document():
    if "user_id" not in session:
        abort(401)

    if "document" not in request.files:
        return jsonify({"error": "no file provided"}), 400

    file = request.files["document"]

    # VULNERABLE: no extension/content-type allowlist, and the raw
    # client-supplied filename is used directly instead of being run
    # through werkzeug.utils.secure_filename().
    filename = file.filename
    save_path = os.path.join(UPLOAD_DIR, filename)
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    file.save(save_path)

    response = {"message": "Document uploaded for review", "filename": filename}
    # Flag proves the missing type allowlist specifically -- awarded
    # when a file type that shouldn't be accepted for KYC (anything
    # not an image) gets through anyway.
    ALLOWED_IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".pdf"}
    _, ext = os.path.splitext(filename.lower())
    if ext not in ALLOWED_IMAGE_EXTENSIONS:
        response["flag"] = "DARKVAULT{.html_is_a_v4lid_id_document_4pp4rently}"

    return jsonify(response), 200


@bp.route("/kyc/documents/<path:filename>")
def view_kyc_document(filename):
    if "user_id" not in session:
        abort(401)
    # send_from_directory infers Content-Type from the extension --
    # an uploaded .html file gets served as text/html, not forced
    # to download, which is what makes finding 1 exploitable.
    return send_from_directory(UPLOAD_DIR, filename)
