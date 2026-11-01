import hashlib
from email.message import EmailMessage

import pytest

from mailsec.enrichment import enrich
from mailsec.parsing import MAX_BODY_CHARS, normalize_domain, parse_email, root_domain

ORG = {
    "domains": ["examplecompany.com"],
    "executives": [{"name": "Jane Smith", "email": "jane@examplecompany.com"}],
    "known_vendors": {"Microsoft": {"domains": ["microsoft.com", "microsoftonline.com"]}},
    "trusted_authserv_ids": ["mx.google.com"],
}


def raw_message(headers="", body="Hello."):
    return ("From: Microsoft Support <support@microsoft-secure-login.net>\r\n"
            "To: user@examplecompany.com\r\nSubject: Your account\r\n"
            + headers + "\r\n" + body).encode()


def test_uploaded_auth_assertions_never_become_verified_results():
    raw = raw_message("Received: from sender.test by mx.google.com with ESMTPS; Tue, 1 Sep 2026 12:00:00 +0000\r\n"
                      "Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=microsoft-secure-login.net; dkim=pass header.d=microsoft-secure-login.net; dmarc=pass header.from=microsoft-secure-login.net\r\n")
    evidence = enrich(parse_email(raw), ORG)
    assert evidence["authentication"]["status"] == "unverified"
    assert evidence["authentication"]["dmarc"] == "unknown"
    assert evidence["authentication"]["unverified_header_assertions"][0]["results"][0]["result"] == "pass"
    assert evidence["identity"]["sender_claimed_vendor_domain_match"] is False


def test_gmail_receiver_results_keep_authentication_separate_from_identity():
    raw = raw_message("Received: by 2002:abcd with SMTP; Tue, 1 Sep 2026 12:00:00 +0000\r\n"
                      "Received: from sender.test by mx.google.com with ESMTPS; Tue, 1 Sep 2026 12:00:00 +0000\r\n"
                      "Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=microsoft-secure-login.net; dkim=pass header.d=microsoft-secure-login.net; dmarc=pass header.from=microsoft-secure-login.net\r\n")
    evidence = enrich(parse_email(raw, provider="gmail"), ORG)
    assert evidence["authentication"]["dmarc"] == "pass"
    assert evidence["authentication"]["dkim_aligned"] is True
    assert evidence["identity"]["identity_contradictions"][0]["claimed_identity"] == "Microsoft"
    assert evidence["identity"]["lookalike_domain"] is True


def test_spoofed_auth_headers_below_another_received_are_ignored():
    raw = raw_message("Received: from sender.test by mx.google.com with ESMTPS; date\r\n"
                      "Authentication-Results: mx.google.com; dmarc=fail header.from=microsoft.com\r\n"
                      "Received: from forged.test by sender.test; date\r\n"
                      "Authentication-Results: mx.google.com; dmarc=pass header.from=microsoft.com\r\n")
    evidence = enrich(parse_email(raw, provider="gmail"), ORG)
    assert evidence["authentication"]["dmarc"] == "fail"
    assert len(evidence["authentication"]["unverified_header_assertions"]) == 2


@pytest.mark.parametrize("headers", [
    "Authentication-Results: mx.google.com; dmarc=pass header.from=microsoft.com\r\n",
    "Received: from outsider.test by unrelated-gateway.test; date\r\nReceived: from forged.test by mx.google.com; date\r\nAuthentication-Results: mx.google.com; dmarc=pass header.from=microsoft.com\r\n",
    "Received: from outsider.test by mx.google.com.evil.test; date\r\nAuthentication-Results: mx.google.com; dmarc=pass header.from=microsoft.com\r\n",
    "Received: from outsider.test by mx.google.com; date\r\nAuthentication-Results: unrelated.test; dmarc=fail header.from=microsoft.com\r\nAuthentication-Results: mx.google.com; dmarc=pass header.from=microsoft.com\r\n",
])
def test_gmail_cannot_trust_claimed_authserv_without_receiver_boundary(headers):
    assert enrich(parse_email(raw_message(headers), provider="gmail"), ORG)["authentication"]["dmarc"] == "unknown"


def test_no_auth_configuration_means_unknown():
    raw = raw_message("Received: from sender.test by mx.google.com; date\r\nAuthentication-Results: mx.google.com; dmarc=pass header.from=microsoft.com\r\n")
    assert enrich(parse_email(raw, provider="gmail"), {})["authentication"]["dmarc"] == "unknown"


def test_multiple_dkim_prefers_aligned_passing_signature():
    raw = raw_message("Received: from sender.test by mx.google.com; date\r\nAuthentication-Results: mx.google.com; dkim=pass header.d=relay.test; dkim=pass header.d=microsoft-secure-login.net\r\n")
    auth = enrich(parse_email(raw, provider="gmail"), ORG)["authentication"]
    assert auth["dkim_domain"] == "microsoft-secure-login.net"
    assert auth["dkim_aligned"] is True


def test_html_alternative_preserves_anchor_mismatch_and_plain_body():
    msg = EmailMessage()
    msg["From"] = "=?utf-8?b?Sm9zw6k=?= <jose@example.com>"
    msg["To"] = "user@examplecompany.com"
    msg["Subject"] = "A receipt"
    msg.set_content("Plain receipt https://example.com/receipt")
    msg.add_alternative('<html><head><title>hidden title</title><style>evil style</style></head>'
                        '<body><p>HTML receipt</p><a href="https://evil.example/signin">https://microsoft.com/signin</a>'
                        '<script>alert("not visible")</script></body></html>', subtype="html")
    evidence = parse_email(msg.as_bytes())
    assert evidence["message"]["sender"]["display_name"] == "José"
    assert "Plain receipt" in evidence["body"]
    assert "HTML receipt" in evidence["body"]
    assert "not visible" not in evidence["body"]
    assert "evil style" not in evidence["body"]
    assert "hidden title" not in evidence["body"]
    anchor = next(link for link in evidence["links"] if link["source"] == "html_anchor")
    assert anchor["display_domain_mismatch"] is True
    assert anchor["affirmatively_malicious"] is False


def test_attachment_hashes_and_static_hints_do_not_claim_malware():
    msg = EmailMessage()
    msg["From"] = "sender@example.com"
    msg.set_content("Attached documents")
    executable = b"MZ" + b"test bytes"
    msg.add_attachment(executable, maintype="application", subtype="pdf", filename="invoice.pdf.exe")
    msg.add_attachment(b"%PDF-1.5 test", maintype="application", subtype="pdf", filename="report.pdf")
    evidence = parse_email(msg.as_bytes())
    first = evidence["attachments"][0]
    assert first["sha256"] == hashlib.sha256(executable).hexdigest()
    assert first["declared_mime_type"] == "application/pdf"
    assert first["detected_mime_type"] == "application/x-dosexec"
    assert first["executable"] is True
    assert first["multiple_filename_extensions"] is True
    assert first["affirmatively_malicious"] is False
    assert evidence["attachments"][1]["pdf"] is True


def test_attached_email_is_not_folded_into_top_level_body():
    inner = EmailMessage()
    inner["From"] = "nested@example.com"
    inner.set_content("Nested secrets https://nested.example.com/")
    outer = EmailMessage()
    outer["From"] = "sender@example.com"
    outer.set_content("See attached email")
    outer.add_attachment(inner, filename="forwarded.eml")
    evidence = parse_email(outer.as_bytes())
    assert "Nested secrets" not in evidence["body"]
    assert evidence["attachments"][0]["declared_mime_type"] == "message/rfc822"
    assert evidence["links"] == []


def test_registered_domains_use_private_psl_and_idna():
    assert root_domain("billing.example.co.uk") == "example.co.uk"
    assert root_domain("tenant.github.io") == "tenant.github.io"
    assert root_domain("other.github.io") != root_domain("tenant.github.io")
    assert normalize_domain("BÜCHER.DE.") == "xn--bcher-kva.de"
    assert root_domain("127.0.0.1") == "127.0.0.1"
    assert root_domain("login.microsoft.com.evil.co.uk") == "evil.co.uk"


def test_unrelated_suffix_and_sibling_hosts_are_not_authorized_vendor_domains():
    organization = {"known_vendors": {"Vendor": {"domains": ["trusted.github.io"]}}}
    raw = b"From: Vendor <a@attacker.github.io>\r\n\r\nWelcome"
    evidence = enrich(parse_email(raw), organization)
    assert evidence["identity"]["sender_domain_matches_known_vendor"] is False
    assert evidence["identity"]["sender_claimed_vendor_domain_match"] is False


def test_unknown_enrichment_remains_neutral_and_input_is_not_mutated():
    parsed = parse_email(raw_message(body="A message https://unknown-destination.test/sign-in"))
    enriched = enrich(parsed, ORG)
    assert parsed["identity"] == {}
    assert enriched["identity"]["sender_first_seen"] is None
    assert enriched["organization_context"]["existing_thread"] is None
    assert enriched["links"][0]["reputation"] == "unknown"
    assert enriched["links"][0]["affirmatively_malicious"] is False


def test_history_only_uses_explicit_supplied_facts():
    enriched = enrich(parse_email(raw_message()), ORG, {"sender_first_seen": True, "sender_messages_previous_90d": 0, "existing_thread": False})
    assert enriched["identity"]["sender_first_seen"] is True
    assert enriched["identity"]["domain_messages_previous_90d"] is None
    assert enriched["organization_context"]["existing_thread"] is False


def test_malformed_charset_falls_back_and_flags_missing_and_truncated_content():
    charset = parse_email(b"From: a@example.com\r\nContent-Type: text/plain; charset=does-not-exist\r\n\r\nHello \xff")
    assert charset["quality"]["decoding_replacement"] is True
    empty = parse_email(b"From: a@example.com\r\nSubject: Empty\r\n\r\n")
    assert empty["quality"]["missing_body"] is True
    large = parse_email(raw_message(body="a" * (MAX_BODY_CHARS + 5)))
    assert large["quality"]["body_truncated"] is True
    assert len(large["body"]) == MAX_BODY_CHARS


def test_duplicate_from_headers_and_punycode_are_explicit_evidence():
    raw = b"From: Microsoft <a@xn--bcher-kva.de>\r\nFrom: b@other.test\r\n\r\nhttps://user@microsoft.com.evil.test/login"
    evidence = enrich(parse_email(raw), ORG)
    assert evidence["quality"]["multiple_from_headers"] is True
    assert evidence["identity"]["contains_punycode"] is True
    assert evidence["links"][0]["has_userinfo"] is True
    assert evidence["links"][0]["domain"] == "microsoft.com.evil.test"


def test_received_timestamp_source_does_not_promote_sender_date_to_provider_fact():
    raw = raw_message("Date: Tue, 1 Sep 2026 12:00:00 +0000\r\n")
    assert parse_email(raw, provider="gmail")["message"]["received_at_source"] == "message_header_or_import"
    assert parse_email(raw, provider="gmail", received_at="2026-09-01T12:00:05Z")["message"]["received_at_source"] == "provider"


def test_html_resource_urls_are_preserved_with_context_and_no_execution():
    raw = (b'From: sender@example.com\r\nContent-Type: text/html\r\n\r\n'
           b'<head><link rel="stylesheet" href="https://cdn.example.com/style.css">'
           b'<script src="https://scripts.example.com/app.js">https://script-data.example.com/</script></head>'
           b'<p>Receipt</p><img src="https://tracking.example.com/pixel.gif" alt="Logo">')
    evidence = parse_email(raw)
    assert len(evidence["links"]) == 4
    assert {item["source"] for item in evidence["links"]} == {"html_link_href", "html_script_src", "html_nonvisible_source", "html_img_src"}
    assert "script-data" not in evidence["body"]
    assert all(item["affirmatively_malicious"] is False for item in evidence["links"])


def test_large_html_template_preserves_actual_body_and_action_after_styles():
    raw = ('From: sender@example.com\nContent-Type: text/html; charset=utf-8\n\n'
           '<html><head><style>' + '.template {color: red;} ' * 4000 + '</style></head><body>'
           '<p>Transfer funds to the new bank account.</p><a href="https://evil.test/pay">Pay</a></body></html>').encode()
    evidence = parse_email(raw)
    assert 'Transfer funds' in evidence['body']
    assert not evidence['quality']['body_truncated']
    assert any(link['raw_url'] == 'https://evil.test/pay' for link in evidence['links'])


def test_formatting_whitespace_does_not_consume_visible_body_budget():
    raw = ('From: sender@example.com\nContent-Type: text/html\n\n<div>' + ' ' * 60000 +
           'Account alert\n      Check settings.</div>').encode()
    evidence = parse_email(raw)
    assert evidence['body'] == 'Account alert\nCheck settings.'
    assert not evidence['quality']['body_truncated']


def test_text_source_bound_remains_explicit_and_action_links_precede_resources():
    from mailsec.parsing import MAX_TEXT_SOURCE_CHARS
    raw = ('Content-Type: text/html\n\n<head><style>' + ' ' * MAX_TEXT_SOURCE_CHARS +
           '</style></head><body>Hidden by limit</body>').encode()
    assert parse_email(raw)['quality']['text_source_truncated']
    raw = ('Content-Type: text/html\n\n' + ''.join(f'<img src="https://img.test/{i}">' for i in range(220)) +
           '<a href="https://evil.test/collect">Enter password</a>').encode()
    evidence = parse_email(raw)
    assert evidence['quality']['links_truncated']
    assert evidence['links'][0]['raw_url'] == 'https://evil.test/collect'


def test_malformed_address_registry_does_not_discard_body(monkeypatch):
    from email.policy import EmailPolicy

    original = EmailPolicy.header_fetch_parse
    def broken_address(self, name, value):
        if name.lower() == 'to':
            raise AttributeError("Group object has no local_part")
        return original(self,name,value)
    monkeypatch.setattr(EmailPolicy,'header_fetch_parse',broken_address)
    raw=b'From: Sender <sender@example.com>\nTo: Broken group\nSubject: Invoice\n\nPayment instructions in body.'
    result=parse_email(raw)
    assert result['body']=='Payment instructions in body.'
    assert result['message']['sender']['address']=='sender@example.com'
    assert result['message']['recipients']==[]
    assert result['quality']['header_parse_failed'] is True
    assert result['quality']['unparsed_headers']==['To']
