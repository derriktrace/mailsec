"""Unsupported image-focused HTML must not be represented as fully read."""

import pytest

from mailsec.action_evidence import build_action_evidence
from mailsec.config import Settings
from mailsec.inspection.documents import inspect_document
from mailsec.parsing import parse_email
from mailsec.protection import decide


def message(html):
    return ("From: sender@example.test\r\nSubject: Account notice\r\n"
            "Content-Type: text/html; charset=utf-8\r\n\r\n" + html).encode()


def test_image_focused_embedded_data_remains_unread_through_model_and_policy():
    html = '<p>View notice:</p><img src="data:image/png;base64,YQ==Yg==" width="320" height="320">'
    original = parse_email(message(html))
    assert original["content"]["visibility"]["material_inline_image_gap"]
    assert not original["content"]["visibility"]["material_remote_image_gap"]
    assert not original["quality"]["transfer_decoding_ambiguous"]  # URI never decoded.
    state = build_action_evidence(original)
    assert not state["coverage"]["material_content_complete"]
    assert any(gap["kind"] == "material_inline_image_gap" for gap in state["coverage"]["upstream_gaps"])
    original["inspection"] = {"status": "complete", "antivirus": {"status": "clean"}}
    original["url_inspection"] = {"complete": True, "results": []}
    model = {"answers": {"verdict": {"choice": "clean", "probabilities": {"clean": .99}},
                          "recommended_security_action": {"choice": "deliver"}}}
    result = decide(model, original, Settings(enforcement_mode="auto_quarantine"))
    assert result["verdict"] == "suspicious" and result["eligible_action"] == "flag"
    assert any(gap["kind"] == "inline_image_content_unread" for gap in result["material_evidence_gaps"])
    assert not result["hard_detection"]


def test_html_attachment_records_its_unread_embedded_image_scope():
    html = b'<img src="data:image/png;base64,YQ==" width="600" height="300">'
    result = inspect_document(html, "notice.html", "text/html", limits={})
    assert result["coverage"]["status"] == "partial"
    assert result["coverage"]["material_content_gap"]
    assert "embedded_data_images_not_decoded" in result["coverage"]["scope_exclusions"]
    assert any(row["kind"] == "unread_embedded_image" for row in result["findings"])


@pytest.mark.parametrize("attributes", ['width="1" height="1"', 'width="32" height="32"',
                                        'height="24"', 'style="display:none"', 'hidden'])
def test_small_or_hidden_embedded_decoration_does_not_become_a_material_gap(attributes):
    html = f'<p>Receipt received.</p><img src="data:image/png;base64,YQ==" {attributes}>'
    original = parse_email(message(html))
    assert not original["content"]["visibility"]["material_inline_image_gap"]
    result = inspect_document(html.encode(), "receipt.html", "text/html", limits={})
    assert not result["coverage"].get("material_content_gap")
    assert "embedded_data_images_not_decoded" in result["coverage"]["scope_exclusions"]


@pytest.mark.parametrize("source", ["https://images.example.test/notice.png", "data:image/png;base64,YQ=="])
def test_oversized_html_dimension_is_bounded_and_does_not_abort_message_parsing(source):
    html = f'<img src="{source}" width="{"9" * 5000}" height="300">'
    original = parse_email(message(html))
    key = "material_inline_image_gap" if source.startswith("data:") else "material_remote_image_gap"
    assert original["content"]["visibility"][key]


def test_quoted_embedded_image_is_not_a_current_request_gap():
    html = '<p>Thanks.</p><blockquote><img src="data:image/png;base64,YQ==" width="600" height="300"></blockquote>'
    assert not parse_email(message(html))["content"]["visibility"]["material_inline_image_gap"]
