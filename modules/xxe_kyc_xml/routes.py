"""
Module: xxe_kyc_xml
Difficulty: Hard
OWASP: A05:2021 Security Misconfiguration (XXE is now folded under
       this category as of the 2021 list)
CWE: CWE-611 (Improper Restriction of XML External Entity Reference)

Business context: corporate/business customers can submit KYC data
in bulk via XML (a realistic pattern -- many banks accept structured
XML/ISO-20022-style submissions from business clients' own systems
rather than requiring manual form entry). The parser is explicitly
configured to resolve external entities and process DTDs.

Note: lxml's actual default is safe (resolve_entities=False as of
recent versions) -- this module explicitly opts into the unsafe
configuration via XMLParser(resolve_entities=True), which is exactly
the kind of thing a developer might do while debugging or copying an
old Stack Overflow answer, then never revert. Modeling the realistic
mistake rather than assuming the vulnerable default.

Player path: submit XML with a DOCTYPE defining an external entity
pointing at a local file, referenced inside one of the fields that
gets echoed back in the response.
"""
from lxml import etree
from flask import Blueprint, request, jsonify, session, abort

bp = Blueprint("xxe_kyc_xml", __name__)


@bp.route("/kyc/submit-xml", methods=["POST"])
def submit_kyc_xml():
    if "user_id" not in session:
        abort(401)

    xml_data = request.data
    if not xml_data:
        return jsonify({"error": "XML body required"}), 400

    # VULNERABLE: explicitly enables external entity resolution and
    # network access for DTD/entity fetches.
    parser = etree.XMLParser(resolve_entities=True, no_network=False)
    try:
        root = etree.fromstring(xml_data, parser=parser)
    except etree.XMLSyntaxError as e:
        return jsonify({"error": f"invalid XML: {e}"}), 400

    def get_text(tag):
        el = root.find(tag)
        return el.text if el is not None else None

    return jsonify({
        "company_name": get_text("companyName"),
        "registration_number": get_text("registrationNumber"),
        "contact_email": get_text("contactEmail"),
    })
