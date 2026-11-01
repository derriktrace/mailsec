"""Offline regression cases for evidence lost behind HTML formatting."""
from email.message import EmailMessage

import pytest

from mailsec.html_visibility import extract_html
from mailsec.parsing import parse_email


def parse_html(html):
    return parse_email(("From: sender@example.test\nContent-Type: text/html; charset=utf-8\n\n" + html).encode())


def test_stylesheet_hidden_thread_is_not_presented_as_visible_or_preferred_to_cta():
    result = parse_html('''<div class="old-thread"><p>Normal laptop replacement conversation.</p>
      <a href="https://corporate.test">Our corporate portal</a></div>
      <a href="https://unknown.test/pay"><img src="https://image.test/offer.png" width="600" height="400" alt="Pay deposit"></a>
      <style>div.old-thread {visibility: collapse; max-height:0; width:0}</style>''')
    assert "laptop replacement" not in result["body"]
    assert "laptop replacement" in result["content"]["hidden_text"]
    assert "Pay deposit" in result["body"]
    assert result["links"][0]["domain"] == "unknown.test"
    assert result["links"][0]["display_text"].endswith("Pay deposit]")
    assert result["links"][0]["image_context"][0]["src"] == "https://image.test/offer.png"
    corporate = next(link for link in result["links"] if link["domain"] == "corporate.test")
    assert corporate["visibility"] == "hidden"


@pytest.mark.parametrize("hiding", ["display:none", "visibility:hidden", "visibility:collapse", "opacity:0", "height:0;overflow:hidden", "max-height:0px;overflow-y:hidden", "font-size:0", "clip:rect(0, 0, 0, 0)"])
def test_inherited_hiding_cannot_pollute_visible_evidence(hiding):
    result = extract_html(f'<div style="{hiding}">Secret <span>filler</span></div><p>Actual request</p>')
    assert result["visible_text"] == "Actual request"
    assert "Secret filler" in result["hidden_text"]


def test_css_cascade_important_specificity_and_inherited_visibility_override():
    result = extract_html('''<style>.block {display:none} #one {display:block}
      .forced {display:none!important} div > .child {visibility:visible}</style>
      <div id="one" class="block">Visible by specificity</div>
      <div class="forced" style="display:block">Hidden despite inline</div>
      <div style="visibility:hidden">Hidden parent<span class="child">Visible child</span></div>
      <div style="display:none"><span style="display:block">Still hidden</span></div>''')
    assert "Visible by specificity" in result["visible_text"]
    assert "Visible child" in result["visible_text"]
    assert "Hidden parent" not in result["visible_text"]
    assert "Hidden despite inline" in result["hidden_text"]
    assert "Still hidden" in result["hidden_text"]


def test_descendant_and_attribute_selectors_respect_element_boundaries():
    result = extract_html('''<style>#outer .removed[data-kind="private.content"] {display:none}</style>
      <div id="outer"><section><span class="removed" data-kind="private.content">Hidden note</span></section></div>
      <span class="removed" data-kind="private.content">Visible outside container</span>''')
    assert result["hidden_text"] == "Hidden note"
    assert result["visible_text"] == "Visible outside container"


def test_adjacent_sibling_hiding_is_applied_only_to_the_matching_sibling():
    result = extract_html('''<style>.image_block img+div {display:none}</style>
      <section class="image_block"><img src="https://example.test/pixel">
        <div>Hidden adjacent content</div><p>Visible sibling content</p></section>
      <section><img src="https://example.test/pixel"><div>Visible outside content</div></section>''')
    assert "Hidden adjacent content" in result["hidden_text"]
    assert "Hidden adjacent content" not in result["visible_text"]
    assert "Visible sibling content" in result["visible_text"]
    assert "Visible outside content" in result["visible_text"]
    assert result["coverage"] == "supported_static_rules"


def test_unmatched_adjacent_sibling_rule_does_not_invent_missing_content():
    result = parse_html('''<style>.image_block img+div {display:none}</style>
      <div class="image_block"><img src="https://example.test/pixel">
        <p>Account notice with complete text.</p></div>''')
    assert result["quality"]["content_visibility_incomplete"] is False
    assert result["content"]["visible_text"] == "Account notice with complete text."


def test_zero_dimensions_without_clipping_do_not_invent_invisibility():
    # CSS text overflows a zero-size box unless clipping/font/visibility hides it.
    result = extract_html('<div style="height:0;width:0">Still overflows visibly</div>')
    assert result["visible_text"] == "Still overflows visibly"


def test_font_zero_hides_text_but_not_visible_image_action():
    result = extract_html('<a style="font-size:0" href="https://action.test/">Hidden filler<img src="https://image.test/offer" alt="Visible offer"></a>')
    assert "Hidden filler" in result["hidden_text"]
    assert "Hidden filler" not in result["visible_text"]
    assert "Visible offer" in result["visible_text"]
    assert next(link for link in result["links"] if link["source"] == "html_anchor")["visibility"] == "visible"


def test_visible_child_of_hidden_anchor_preserves_action_visibility():
    result = extract_html('<a style="visibility:hidden" href="https://action.test/"><span style="visibility:visible">Visible action</span></a>')
    assert result["visible_text"] == "Visible action"
    assert result["links"][0]["visibility"] == "visible"


def test_normal_hidden_preheader_does_not_assert_malware_or_missing_content():
    result = parse_html('<div style="display:none">Your monthly newsletter is ready.</div><p>Here is this month’s newsletter.</p>')
    assert result["quality"]["content_visibility_incomplete"] is False
    assert result["quality"]["missing_body"] is False
    assert "hidden_text_dominates_visible" not in result["content"]["visibility"]["findings"]
    assert result["threat_intelligence"]["affirmative_malicious_url"] is False


def test_quoted_history_has_a_separate_role_and_links():
    result = parse_html('<p>Please review the attached report.</p><blockquote><p>Old instructions: pay now</p><a href="https://past.test/pay">Old payment link</a></blockquote>')
    assert result["content"]["visible_text"] == "Please review the attached report."
    assert "Old instructions" in result["content"]["quoted_text"]
    assert "Quoted history" in result["body"]
    assert result["links"][0]["quoted_context"] is True


def test_plain_alternative_preserved_but_visible_html_action_comes_first():
    msg = EmailMessage()
    msg["From"] = "sender@example.test"
    msg.set_content("Plain mail client shows different instructions.")
    msg.add_alternative('<a href="https://unknown.test/pay">Send a deposit.</a>', subtype="html")
    result = parse_email(msg.as_bytes())
    assert result["body"].startswith("Send a deposit.")
    assert result["content"]["plain_alternative"].startswith("Plain mail client")
    assert "html_plain_alternatives_differ" in result["content"]["visibility"]["findings"]


def test_duplicate_mime_alternatives_are_not_repeated():
    msg = EmailMessage()
    msg.set_content("Same message")
    msg.add_alternative('<p>Same message</p>', subtype="html")
    result = parse_email(msg.as_bytes())
    assert result["body"] == "Same message"
    assert result["content"]["plain_alternative"] == ""


def test_image_only_remote_content_gap_excludes_tracking_pixel_and_small_logo():
    image_only = parse_html('<a href="https://unknown.test/"><img src="https://image.test/banner.png" width="600" height="400"></a>')
    assert image_only["content"]["visibility"]["material_remote_image_gap"] is True
    decorative = parse_html('<img src="https://image.test/pixel" width="1" height="1"><img src="https://image.test/logo" width="64" height="64"><p>Receipt received.</p>')
    assert decorative["content"]["visibility"]["material_remote_image_gap"] is False


def test_small_nonaction_header_logo_with_omitted_width_is_not_a_material_gap():
    logo = '<img src="https://image.test/logo.png" height="37"><p>Reset your password using the account settings page.</p>'
    assert parse_html(logo)["content"]["visibility"]["material_remote_image_gap"] is False
    clickable = '<a href="https://unknown.test/"><img src="https://image.test/offer.png" height="37"></a>'
    assert parse_html(clickable)["content"]["visibility"]["material_remote_image_gap"] is True
    banner = '<img src="https://image.test/offer.png" height="90">'
    assert parse_html(banner)["content"]["visibility"]["material_remote_image_gap"] is True


def test_raw_header_surrogateescape_is_sanitized_only_in_derived_evidence():
    import hashlib
    import json
    raw = b'From: sender@example.test\nSender: "\xe2\x9c\x94\xef\xb8\x8f"<other@example.test>\nSubject: Notice\n\nBody preserved.'
    evidence = parse_email(raw)
    assert evidence['message']['raw_sha256'] == hashlib.sha256(raw).hexdigest()
    assert evidence['quality']['decoding_replacement'] is True
    assert '\ufffd' in evidence['authentication']['transport_headers'][0]['value']
    json.dumps(evidence, ensure_ascii=False).encode('utf-8')
    assert evidence['body'] == 'Body preserved.'


def test_hidden_image_is_not_a_visible_content_gap():
    result = parse_html('<div hidden><a href="https://hidden.test/"><img src="https://image.test/large.png"></a></div><p>Visible message.</p>')
    assert result["content"]["visibility"]["material_remote_image_gap"] is False


def test_conditional_hiding_is_explicit_not_assumed_for_every_device():
    result = extract_html('<style>@media (max-width:600px) {.mobile {display:none}}</style><p class="mobile">Device-dependent content</p>')
    assert result["visible_text"] == "Device-dependent content"
    assert result["unsupported_hiding"] is True
    assert result["coverage"] == "partial"


def test_responsive_layout_alone_does_not_claim_material_missing_content():
    result = parse_html('<style>@media (max-width:600px) {.desktop {display:none}}</style><p class="desktop">' + 'Ordinary newsletter text. ' * 100 + '</p>')
    assert result["quality"]["content_visibility_incomplete"] is False
    assert "conditional_visibility" in result["content"]["visibility"]["uncertainties"]


def test_work_bound_has_explicit_coverage_and_does_not_claim_complete_extraction(monkeypatch):
    import mailsec.html_visibility as module
    monkeypatch.setattr(module, "MAX_NODES", 4)
    result = parse_html('<p>One</p><p>Two</p><p>Three</p><p>Four</p>')
    assert result["quality"]["content_visibility_incomplete"] is True
    assert "html_structure_limit" in result["content"]["visibility"]["limits"]


def test_long_body_retains_separate_source_for_segment_analysis():
    source = "A long paragraph. " * 4000 + "Do not lose the payment demand in the middle." + " More text." * 3000
    result = parse_html('<p>' + source + '</p>')
    assert result["quality"]["body_truncated"] is True
    assert "payment demand" not in result["body"]
    assert "payment demand" in result["content"]["visible_text"]
