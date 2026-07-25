# file_upload_kyc

| Field | Value |
|---|---|
| OWASP | A04:2021 Insecure Design |
| CWE | CWE-434 (Unrestricted Upload) + CWE-22 (Path Traversal, upload side) |
| Difficulty | Medium |
| Chains into | Host a phishing/XSS page on the bank's own trusted domain |

## Finding 1 (primary): Unrestricted file type
`upload_kyc_document()` accepts any file type and `view_kyc_document()`
serves it back with a content-type inferred purely from the extension.
Upload a `.html` file containing a `<script>` payload, then visit
`GET /kyc/documents/<filename>` directly — it renders as a live HTML page,
same-origin with the bank's real session cookie (paired with
`SESSION_COOKIE_HTTPONLY = False`, same underlying issue as
`stored_xss_support_ticket`).

## Finding 2 (secondary): Path traversal on write
The saved path is built with `os.path.join(UPLOAD_DIR, file.filename)`
using the raw client-supplied filename — never passed through
`werkzeug.utils.secure_filename()`. A filename containing `../` sequences
escapes the intended upload directory on write. (Note: the *read* side
uses `send_from_directory`, which has its own built-in traversal
protection — so this finding's impact is arbitrary-location file write,
not necessarily direct read-back through this same endpoint. Worth
reporting on its own merits regardless.)

## Player path
1. Log in, `POST /kyc/upload` with a file named `phish.html` containing
   `<h1>DarkVault Bank</h1><script>document.title='pwned'</script>`.
2. `GET /kyc/documents/phish.html` — observe it renders as HTML, not
   downloaded as a file.

## Hints
- Hint 1: "What file types does the upload actually check for?"
- Hint 2: "When you view an uploaded document, what decides whether the browser downloads it or renders it?"

## Remediation
- Allowlist specific extensions/MIME types (e.g. `.jpg`, `.png`, `.pdf` only), validated server-side by actually inspecting file content/magic bytes, not just the extension.
- Always run uploaded filenames through `werkzeug.utils.secure_filename()`.
- Serve uploaded files with `Content-Disposition: attachment` and a fixed `Content-Type` (or from a separate cookieless domain/CDN entirely) so they can never be rendered as live HTML in the app's own origin.
