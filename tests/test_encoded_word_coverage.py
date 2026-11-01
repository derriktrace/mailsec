"""Encoded headers must not hide data through permissive base64 fallback."""

import base64

import pytest

from mailsec import parsing
from mailsec.action_evidence import build_action_evidence
from mailsec.config import Settings
from mailsec.protection import decide


def message(field, word):
    headers = {
        "From": "sender@example.test",
        "To": "recipient@example.test",
        "Subject": "A normal notice",
        "Content-Type": "text/plain; charset=utf-8",
    }
    if field in {"From", "Reply-To"}:
        headers[field] = word + " <sender@example.test>"
    elif field == "filename":
        headers["Content-Disposition"] = f'attachment; filename="{word}"'
    elif field == "name":
        headers["Content-Type"] = f'text/plain; name="{word}"'
    else:
        headers[field] = word
    return ("\r\n".join(f"{key}: {value}" for key, value in headers.items())
            + "\r\n\r\nA normal readable notice.\r\n").encode()


def complete_inspection(evidence):
    evidence["inspection"] = {"status": "complete", "antivirus": {"status": "clean"},
                              "coverage": {}, "attachments": []}
    evidence["url_inspection"] = {"complete": True, "results": []}
    return evidence


@pytest.mark.parametrize("field", ["Subject", "From", "Reply-To", "filename", "name"])
@pytest.mark.parametrize("payload", ["YQ==Yg==", "YQ==!", "YQ", "Y", "YQ==?Yg=="])
@pytest.mark.parametrize("verdict", ["clean", "spam"])
def test_encoded_header_ambiguity_reaches_policy_even_with_complete_scanner(field, payload, verdict):
    evidence = complete_inspection(parsing.parse_email(message(field, f"=?utf-8?B?{payload}?=")))
    assert evidence["quality"]["transfer_decoding_ambiguous"]
    assert any(name.startswith("InvalidBase64") for name in evidence["quality"]["mime_defects"])
    projection = build_action_evidence(evidence)
    assert not projection["coverage"]["material_content_complete"]
    assert any(gap["kind"] == "transfer_decoding_ambiguous" for gap in projection["coverage"]["upstream_gaps"])
    output = {"answers": {"verdict": {"choice": verdict, "probabilities": {verdict: .99}},
                           "recommended_security_action": {"choice": "deliver"}}}
    decision = decide(output, evidence, Settings(enforcement_mode="auto_quarantine"))
    assert decision["verdict"] == "suspicious"
    assert decision["eligible_action"] == "flag"
    assert not decision["hard_detection"]


@pytest.mark.parametrize("field", ["Subject", "From", "Reply-To", "filename", "name"])
@pytest.mark.parametrize("word", ["=?utf-8?b?UmVjZWlwdA==?=", "=?utf-8?B?UmVj?=\r\n =?utf-8?b?ZWlwdA==?=",
                                    "=?utf-8?q?Receipt?=", "Ordinary notice"])
def test_valid_and_folded_encoded_words_do_not_create_transfer_gap(field, word):
    evidence = parsing.parse_email(message(field, word))
    assert not evidence["quality"]["transfer_decoding_ambiguous"]
    assert not any(name.startswith("InvalidBase64") for name in evidence["quality"]["mime_defects"])


def test_malformed_encoded_filename_in_nested_attachment_is_not_lost():
    raw = (b'From: sender@example.test\r\nSubject: Notice\r\nContent-Type: multipart/mixed; boundary="boundary"\r\n\r\n'
           b'--boundary\r\nContent-Type: text/plain\r\n\r\nReadable body.\r\n'
           b'--boundary\r\nContent-Type: application/octet-stream\r\n'
           b'Content-Disposition: attachment; filename="=?utf-8?b?YQ==Yg==?="\r\n\r\ncontent\r\n--boundary--\r\n')
    evidence = parsing.parse_email(raw)
    assert evidence["quality"]["transfer_decoding_ambiguous"]


@pytest.mark.parametrize("malicious", [False, True])
def test_ambiguous_header_never_erases_affirmative_phishing_or_malware(malicious):
    evidence = complete_inspection(parsing.parse_email(message("Subject", "=?utf-8?b?YQ==Yg==?=")))
    if malicious:
        evidence["inspection"]["antivirus"]["status"] = "malicious"
    output = {"answers": {"verdict": {"choice": "phishing", "probabilities": {"phishing": .99}},
                           "recommended_security_action": {"choice": "quarantine"}}}
    decision = decide(output, evidence, Settings(enforcement_mode="auto_quarantine"))
    assert decision["verdict"] == "phishing"
    assert decision["hard_detection"] is malicious
    assert decision["eligible_action"] == ("quarantine" if malicious else "flag")


def test_encoded_word_validation_never_decodes_past_header_budget(monkeypatch):
    calls = []
    original = base64.b64decode

    def bounded(encoded, **kwargs):
        assert len(encoded) <= parsing.MAX_HEADER_CHARS
        assert kwargs == {"validate": True}
        calls.append(encoded)
        return original(encoded, **kwargs)

    monkeypatch.setattr(parsing.base64, "b64decode", bounded)
    value = "=?utf-8?b?" + "A" * (parsing.MAX_HEADER_CHARS * 20) + "?="
    assert parsing._encoded_word_defects(value) == {"InvalidBase64CharactersDefect"}
    assert calls == []
    assert parsing._encoded_word_defects("=?utf-8?b?YQ==?=") == set()
    assert calls == ["YQ=="]


@pytest.mark.parametrize("field", ["X-Unused", "Received", "Authentication-Results", "DKIM-Signature"])
def test_unused_metadata_does_not_make_readable_content_materially_incomplete(field):
    evidence = complete_inspection(parsing.parse_email(message(field, "=?utf-8?b?YQ==Yg==?=")))
    assert not evidence["quality"]["transfer_decoding_ambiguous"]
    assert build_action_evidence(evidence)["coverage"]["material_content_complete"]
    output = {"answers": {"verdict": {"choice": "clean", "probabilities": {"clean": .99}, "confidence": .99},
                           "recommended_security_action": {"choice": "deliver"}}}
    decision = decide(output, evidence, Settings(enforcement_mode="auto_quarantine"))
    assert decision["verdict"] == "clean"
    assert decision["eligible_action"] == "none"
    assert not decision["material_evidence_gaps"]
