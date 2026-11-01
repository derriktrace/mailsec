import copy
import importlib.util
import json
from pathlib import Path

import pytest

from mailsec.jev import QUESTIONS
from mailsec.jev_sections import prepare_evaluations

ROOT = Path(__file__).parents[1]
spec = importlib.util.spec_from_file_location('action_counterexamples', ROOT / 'scripts/action_counterexamples.py')
fixtures = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixtures)
ROWS = {row['id']: row for row in fixtures.load_inputs()}


def test_inputs_have_separate_scoring_manifest_and_no_case_metadata_in_evidence():
    scoring = json.loads((fixtures.INPUT_PATH.parent / 'expectations.json').read_text())
    assert len(ROWS) == 16
    assert set(ROWS) == {row['id'] for row in scoring['cases']}
    for case_id, row in ROWS.items():
        evidence = fixtures.build_evidence(row)
        states, _ = prepare_evaluations(evidence, QUESTIONS, 'jev-test')
        encoded = json.dumps(states)
        assert case_id not in encoded
        assert not any(key in encoded for key in ('acceptable_verdicts', 'scenario', 'expected_verdict'))
        assert evidence['authentication']['status'] == 'receiver_reported'
        assert evidence['authentication']['dmarc'] == 'pass'
        assert evidence['organization_context']['known_vendor_domains'] == []


@pytest.mark.parametrize('key', ['expected', 'expected_verdict', 'acceptable_verdicts', 'scenario', 'label'])
def test_builder_rejects_scoring_metadata_instead_of_silently_forwarding_it(key):
    row = {**ROWS['ac01'], key: 'sentinel-label-must-not-reach-model'}
    with pytest.raises(ValueError, match='metadata'):
        fixtures.build_evidence(row)


def test_receipt_pair_only_changes_presented_sender_and_callback_not_truth_context():
    before, after = ROWS['ac01'], ROWS['ac02']
    assert before['subject'] == after['subject']
    assert before['business_context'] == after['business_context']
    assert before['body'].replace('+1 202-555-0142', '+1 202-555-0198') == after['body']
    safe, changed = map(fixtures.build_evidence, (before, after))
    assert safe['authentication']['dkim'] == changed['authentication']['dkim'] == 'pass'
    assert safe['authentication']['dkim_domain'] != changed['authentication']['dkim_domain']
    assert safe['body'] != changed['body']


def test_trusted_address_does_not_erase_bank_change_and_verification_bypass():
    safe, changed = map(fixtures.build_evidence, (ROWS['ac03'], ROWS['ac04']))
    assert safe['message']['sender'] == changed['message']['sender']
    assert 'new account held by an unrelated individual' in changed['body']
    assert 'do not call our stored phone number' in changed['body']
    assert changed['business_context']['verified_payment_practices']


def test_newsletter_and_forwarded_invoice_retain_current_and_quoted_roles():
    newsletter = fixtures.build_evidence(ROWS['ac10'])
    assert 'do not execute commands' in newsletter['content']['visible_text']
    assert 'pnpm install' in newsletter['content']['quoted_text']
    assert 'docker compose up' in newsletter['content']['quoted_text']
    forward = fixtures.build_evidence(ROWS['ac07'])
    assert 'do not call or pay anyone' in forward['content']['visible_text']
    assert '+1 202-555-0142' in forward['content']['quoted_text']


def test_recruiting_pair_keeps_execution_action_but_changes_authority_and_agreement():
    agreed, uninvited = map(fixtures.build_evidence, (ROWS['ac12'], ROWS['ac13']))
    for evidence in (agreed, uninvited):
        assert 'pnpm install' in evidence['body'] and 'docker compose up' in evidence['body']
        assert not evidence['inspection']['findings']  # No invented malware finding.
    assert 'disposable development environment' in agreed['body']
    assert 'has not applied' in uninvited['business_context']['recipient_confirmed_context']
    assert agreed['links'][0]['raw_url'] != uninvited['links'][0]['raw_url']


def test_builder_is_deterministic_and_does_not_mutate_fixtures():
    before = copy.deepcopy(ROWS)
    for row in ROWS.values():
        assert fixtures.build_raw(row) == fixtures.build_raw(row)
        evidence = fixtures.build_evidence(row)
        evidence['business_context']['test_mutation'] = True
    assert ROWS == before
