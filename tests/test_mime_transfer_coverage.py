"""Malformed transfer encoding must not disappear between MIME and policy."""

import base64

import pytest

from mailsec.action_evidence import build_action_evidence
from mailsec.config import Settings
from mailsec.parsing import parse_email
from mailsec.protection import decide


def message(payload, attachment):
    headers = (b"From: sender@example.test\r\nTo: recipient@example.test\r\n"
               b"Subject: Attached notice\r\nContent-Transfer-Encoding: base64\r\n")
    if attachment:
        headers += (b"Content-Type: application/octet-stream\r\n"
                    b'Content-Disposition: attachment; filename="notice.bin"\r\n')
    else:
        headers += b"Content-Type: text/plain; charset=utf-8\r\n"
    return headers + b"\r\n" + payload + b"\r\n"


@pytest.mark.parametrize("attachment", [False, True])
@pytest.mark.parametrize("payload", [b"YQ==Yg==", b"YQ", b"YQ==!", b"Y"])
@pytest.mark.parametrize("verdict", ["clean", "spam"])
def test_lazy_transfer_defects_reach_model_and_policy(payload, attachment, verdict):
    raw = message(payload, attachment)
    original = parse_email(raw)
    assert original["quality"]["transfer_decoding_ambiguous"]
    assert any(name.startswith("InvalidBase64") for name in original["quality"]["mime_defects"])
    # Complete scanner status cannot repair a different MIME decoder's view.
    original["inspection"] = {"status": "complete", "antivirus": {"status": "clean"},
                              "coverage": {}, "attachments": []}
    original["url_inspection"] = {"complete": True, "results": []}
    state = build_action_evidence(original)
    assert not state["coverage"]["material_content_complete"]
    assert any(gap["kind"] == "transfer_decoding_ambiguous"
               for gap in state["coverage"]["upstream_gaps"])
    model = {"answers": {"verdict": {"choice": verdict, "probabilities": {verdict: .99}},
                          "recommended_security_action": {"choice": "deliver"}}}
    decision = decide(model, original, Settings(enforcement_mode="auto_quarantine"))
    assert decision["verdict"] == "suspicious"
    assert decision["eligible_action"] == "flag"
    assert not decision["hard_detection"]
    assert any(gap["kind"] == "transfer_decoding_ambiguous"
               for gap in decision["material_evidence_gaps"])


@pytest.mark.parametrize("attachment", [False, True])
def test_valid_wrapped_base64_does_not_create_transfer_gap(attachment):
    payload = b"A normal notice that continues across MIME line wrapping. " * 10
    original = parse_email(message(base64.encodebytes(payload), attachment))
    assert not original["quality"]["transfer_decoding_ambiguous"]
    assert not original["quality"]["mime_defects"]
    if attachment:
        assert original["attachments"][0]["size"] == len(payload)
    else:
        assert "normal notice" in original["body"]


def test_unrelated_mime_defect_does_not_create_transfer_gap():
    original = parse_email(b"From: sender@example.test\r\nContent-Type: multipart/mixed\r\n\r\nHello.")
    assert "NoBoundaryInMultipartDefect" in original["quality"]["mime_defects"]
    assert not original["quality"]["transfer_decoding_ambiguous"]
