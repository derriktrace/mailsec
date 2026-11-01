"""Recipient masking must operate on all actual model views, not just headers."""
import copy
import json
import time
from urllib.parse import quote

import pytest

from mailsec.action_evidence import build_action_evidence
from mailsec.enrichment import enrich
from mailsec.jev import QUESTIONS, JevError
from mailsec.jev_sections import prepare_evaluations
from mailsec.parsing import parse_email
from mailsec.provider_redaction import collect_recipient_addresses, mask_payload


def evidence():
    raw = b"""From: Example Sender <sender@example.test>
To: Alex <alex@example.test>
Cc: Casey <casey@example.test>
Bcc: Blair <blair@example.test>
Reply-To: service@example.test
Subject: Appointment for alex@example.test
Message-ID: <local-id@example.test>
Content-Type: text/plain; charset=utf-8

Hello Alex, copy casey@example.test and blair@example.test.
See https://example.test/visit?email=alex%40example.test#casey@example.test
"""
    value = enrich(parse_email(raw, mailbox="owner@example.test", provider="gmail",
                              provider_message_id="private-provider-id"), {"domains": ["example.test"]})
    value["inspection"] = {"status": "complete", "antivirus": {"status": "clean"}, "findings": [],
        "attachments": [{"filename": "alex@example.test.pdf", "sha256": "a" * 64,
                         "text": "OCR: casey@example.test. QR: https://example.test/?u=blair%40example.test"}]}
    return value


def test_primary_view_is_identifiable_until_masking_is_selected():
    requests, coverage = prepare_evaluations(evidence(), QUESTIONS, "jev-1.13.0")
    assert coverage["material_content_complete"]
    state = requests[0][0]
    assert state["message"]["mailbox"] == "owner@example.test"
    assert set(state["message"]["recipients"]) == {"alex@example.test", "casey@example.test", "blair@example.test"}
    assert state["message"]["sender"]["address"] == "sender@example.test"
    assert "provider_message_id" not in state["message"]


def test_masking_known_recipients_covers_primary_actions_questions_and_exact_urls():
    original = evidence()
    before = copy.deepcopy(original)
    addresses = collect_recipient_addresses(original)
    assert addresses == ("alex@example.test", "blair@example.test", "casey@example.test", "owner@example.test")
    questions = copy.deepcopy(QUESTIONS)
    questions["verdict"]["instructions"] += " Contact alex@example.test."
    requests, _ = prepare_evaluations(original, questions, "jev-1.13.0")
    views = [requests[0][0], build_action_evidence(original)]
    for view in views:
        masked, masked_questions, audit = mask_payload(view, questions, addresses)
        serialized = json.dumps([masked, masked_questions])
        for address in addresses:
            assert address not in serialized
            assert quote(address, safe="") not in serialized
        assert "sender@example.test" in serialized
        assert "service@example.test" in serialized
        assert "Hello Alex" in serialized  # Never claim full anonymity.
        assert "recipient-1@masked.invalid" in serialized
        assert audit["known_recipient_count"] == 4 and audit["replacement_count"] > 0
        assert "reduce detection accuracy" in audit["limitations"]
    assert original == before
    assert "alex@example.test" in questions["verdict"]["instructions"]


def test_pasted_header_block_supplies_cc_bcc_but_prose_addresses_are_not_guessed():
    assert collect_recipient_addresses({"body": "To: Alex <alex@example.test>\nCc: c@example.test\nBcc: b@example.test\n\nBody."}) == (
        "alex@example.test", "b@example.test", "c@example.test")
    assert collect_recipient_addresses({"body": "Contact sales@example.test.\nTo: do-not-guess@example.test"}) == ()


def test_case_percent_encodings_dictionary_keys_and_per_message_aliases():
    address = "alex+tag@example.test"
    values = [address.upper()]
    value = address
    for _ in range(3):
        value = quote(value, safe="")
        values.append(value)
    state, _, audit = mask_payload({address: values}, {}, (address,))
    assert audit["replacement_count"] == 5
    assert set(state) == {"recipient-1@masked.invalid", "recipient_address_privacy"}
    for item in state["recipient-1@masked.invalid"]:
        assert "alex" not in item and "example.test" not in item


def test_no_known_address_is_explicit_not_claimed_as_anonymous():
    state, _, audit = mask_payload({"body": "Hi Alex, call 555-0100."}, {}, ())
    assert state["body"] == "Hi Alex, call 555-0100."
    assert audit["status"] == "no_known_recipient_addresses"
    assert "not anonymization" in audit["limitations"]


def test_recipient_overflow_and_key_collision_fail_closed():
    with pytest.raises(JevError, match="Too many"):
        collect_recipient_addresses({"message": {"recipients": [f"r{i}@example.test" for i in range(1025)]}})
    with pytest.raises(JevError, match="merge distinct"):
        mask_payload({"alex@example.test": "one", "recipient-1@masked.invalid": "two"}, {}, ("alex@example.test",))


def test_many_long_shared_prefixes_do_not_cause_regex_backtracking():
    addresses = tuple("a" * 150 + f"{index}@example.test" for index in range(1024))
    started = time.monotonic()
    masked, _, _ = mask_payload({"body": "a" * 12_000 + " " + addresses[-1]}, {}, addresses)
    assert addresses[-1] not in masked["body"]
    assert time.monotonic() - started < 3


def test_matcher_resource_limit_fails_closed_before_model_dispatch():
    # Distinct large local parts make a very large matcher without a useful
    # common prefix. Limits must reject it, never return unmasked evidence.
    from mailsec import provider_redaction
    original = provider_redaction.MAX_MATCHER_NODES
    provider_redaction.MAX_MATCHER_NODES = 10
    try:
        with pytest.raises(JevError, match="safe matcher budget"):
            mask_payload({"body": "alex@example.test"}, {}, ("alex@example.test",))
    finally:
        provider_redaction.MAX_MATCHER_NODES = original
