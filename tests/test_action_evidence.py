import json
from copy import deepcopy

import pytest

from mailsec.action_evidence import ActionEvidenceLimit, build_action_evidence, state_size


def evidence():
    return {'message': {'subject': 'Development exercise', 'id': 'DO_NOT_SEND_ID',
            'sender': {'display_name': 'Engineering', 'address': 'hiring@example.test', 'domain': 'example.test'},
            'reply_to': 'person@example.test', 'return_path': 'bounce@example.test',
            'recipients': ['DO_NOT_SEND_RECIPIENT']},
        'content': {'visible_text': 'Clone the repository. Run pnpm install && pnpm dev.',
            'quoted_text': 'Previous example: npm install old-package', 'hidden_text': 'preheader',
            'visibility': {}},
        'authentication': {'status': 'unverified', 'spf': 'pass', 'dkim': 'pass',
            'unverified_header_assertions': [{'reason': 'DO_NOT_SEND_ASSERTION'}]},
        'quality': {}, 'links': [], 'attachments': [],
        'inspection': {'status': 'complete', 'antivirus': {'status': 'clean', 'scan_completed': True},
            'attachments': [], 'findings': [], 'coverage': {}},
        'url_inspection': {'complete': False, 'results': []},
        'identity': {'lookalike_domain': False, 'previous_verdicts': ['DO_NOT_SEND_VERDICT']},
        'organization_context': {}, 'business_context': {},
        'reference_label': 'DO_NOT_SEND_LABEL', 'filename': 'DO_NOT_SEND_FILENAME'}


def test_role_sources_commands_and_input_immutability():
    original = evidence()
    before = deepcopy(original)
    state = build_action_evidence(original)
    assert original == before
    sources = state['email']['sources']
    assert [s['role'] for s in sources] == ['current_visible', 'quoted_history', 'hidden_not_current_authority']
    commands = state['candidate_commands']['observations']
    assert commands[0]['text'] == 'pnpm install && pnpm dev.'
    assert commands[0]['role'] == 'current_visible'
    assert commands[1]['role'] == 'quoted_history'
    for command in commands:
        source = next(s for s in sources if s['source_ref'] == command['source_ref'])
        assert source['segments'][0]['text'][command['start']:command['end']] == command['text']
    assert state['coverage']['material_content_complete']
    assert not state['coverage']['truncated']


def test_excludes_prior_decisions_labels_and_untrusted_authentication():
    state = build_action_evidence(evidence())
    assert 'DO_NOT_SEND' not in json.dumps(state)
    assert state['receiver_authentication']['status'] == 'unknown'
    assert 'spf' not in state['receiver_authentication']
    assert 'lookalike_domain' not in state['identity_observations']
    assert not state['identity_observations']['known_domain_comparison_available']


def test_trusted_receiver_results_keep_provenance_not_raw_assertions():
    original = evidence()
    original['authentication'].update(status='receiver_reported', trusted_authserv_id='mx.google.com',
        provenance='Configured receiving boundary', spf_domain='example.test', dkim_domain='example.test')
    state = build_action_evidence(original)
    auth = state['receiver_authentication']
    assert auth['spf'] == 'pass' and auth['dkim_domain'] == 'example.test'
    assert auth['provenance'] == 'Configured receiving boundary'
    assert 'unverified_header_assertions' not in auth
    original['authentication'].pop('trusted_authserv_id')
    assert build_action_evidence(original)['receiver_authentication']['status'] == 'unknown'


def test_exact_destinations_anchor_roles_and_unknowns_not_false_safety():
    original = evidence()
    url = 'https://tracker.example.test/go?next=https%3A%2F%2Fother.test%2Flogin#fragment'
    original['links'] = [
        {'raw_url': url, 'display_text': 'Open account', 'source': 'html_anchor', 'visibility': 'visible'},
        {'raw_url': url, 'display_text': 'Quoted old link', 'source': 'html_anchor', 'quoted_context': True}]
    original['inspection']['urls'] = [url]
    original['url_inspection']['results'] = [{'url': url, 'status': 'unknown', 'malicious': False}]
    state = build_action_evidence(original)
    assert len(state['links']) == 1
    row = state['links'][0]
    assert row['exact_url'] == url and row['domain'] == 'tracker.example.test'
    assert row['occurrences'][0]['display_text'] == 'Open account'
    assert row['occurrences'][1]['quoted_context'] is True
    assert not state['independent_findings']['url_results']
    assert state['unknowns']['url_reputation_status_counts'] == {'unknown': 1}
    assert 'url_ref' not in json.dumps(state)


def test_admin_relationships_are_separate_from_sender_claims():
    original = evidence()
    original['content']['visible_text'] = 'We are an authorized Ledger partner.'
    original['organization_context'] = {'known_vendor_domains': ['verified.test']}
    original['business_context'] = {'verified_relationships': [{'vendor': 'Verified', 'domain': 'verified.test'}]}
    original['identity'].update(identity_contradictions=[{'claimed_identity': 'Ledger', 'observed_domain': 'example.test'}])
    state = build_action_evidence(original)
    assert 'Ledger' not in json.dumps(state['administrator_context'])
    assert state['administrator_context']['verified_relationships'][0]['vendor'] == 'Verified'
    assert state['identity_observations']['identity_contradictions'][0]['claimed_identity'] == 'Ledger'
    assert state['identity_observations']['known_domain_comparison_available']


def test_attachments_ocr_hard_findings_and_parser_metadata():
    original = evidence()
    original['attachments'] = [{'sha256': 'abc', 'filename': 'DO_NOT_SEND_FILENAME', 'content_type': 'application/pdf'}]
    original['inspection']['attachments'] = [{'sha256': 'abc', 'kind': 'pdf', 'filename': 'DO_NOT_SEND_FILENAME',
        'text': 'Invoice. Call support for a refund.', 'coverage': {'ocr': 'extracted', 'ocr_mean_confidence': 89},
        'urls': ['https://document.test/action'], 'antivirus': {'status': 'malicious', 'malware_signature': 'Test.Signature'}}]
    original['inspection']['findings'] = [{'kind': 'static_download_execute', 'severity': 'critical',
        'summary': 'Static execution sequence', 'evidence_ref': 'mime/1'}]
    state = build_action_evidence(original)
    assert state['attachments'][0]['coverage']['ocr_mean_confidence'] == 89
    assert not state['uninspected_attachment_metadata']
    assert state['email']['sources'][-1]['role'] == 'attachment_extracted_text_and_ocr'
    assert state['links'][0]['exact_url'] == 'https://document.test/action'
    assert state['independent_findings']['attachment_antivirus'][0]['malware_signature'] == 'Test.Signature'
    assert state['independent_findings']['static_findings'][0]['kind'] == 'static_download_execute'
    assert 'DO_NOT_SEND_FILENAME' not in json.dumps(state)


def test_original_empty_visible_text_never_falls_back_to_legacy_hidden_body():
    original = evidence()
    original['content'] = {'visible_text': '', 'hidden_text': 'Invisible filler'}
    original['body'] = 'Hidden filler and alternative mixed together'
    state = build_action_evidence(original)
    assert [s['role'] for s in state['email']['sources']] == ['hidden_not_current_authority']
    assert 'Hidden filler and alternative' not in json.dumps(state)


def test_equivalent_plain_source_dedup_keeps_provenance():
    original = evidence()
    original['content']['plain_alternative'] = 'Clone the repository.\nRun pnpm install && pnpm dev.'
    state = build_action_evidence(original)
    assert not any(s['role'] == 'plain_alternative' for s in state['email']['sources'])
    assert state['coverage']['equivalent_sources'][0]['source_ref'] == 'content.plain_alternative'
    assert state['coverage']['material_content_complete']


@pytest.mark.parametrize('gap', ['remote_image', 'ocr', 'uninspected', 'parser'])
def test_existing_material_gaps_are_preserved(gap):
    original = evidence()
    if gap == 'remote_image':
        original['content']['visibility']['material_remote_image_gap'] = True
    elif gap == 'ocr':
        original['inspection']['coverage']['ocr_material_gap'] = True
    elif gap == 'uninspected':
        original['attachments'] = [{'sha256': 'unread', 'content_type': 'application/pdf'}]
    else:
        original['quality']['parts_truncated'] = True
    state = build_action_evidence(original)
    assert not state['coverage']['material_content_complete']
    assert state['coverage']['upstream_gaps']
    assert not state['coverage']['truncated']  # No additional projection loss.


def test_legacy_preview_limit_is_not_full_source_loss():
    original = evidence()
    original['quality']['body_truncated'] = True
    assert build_action_evidence(original)['coverage']['material_content_complete']
    original['content'].pop('visible_text')
    original['body'] = 'Only preview available'
    assert not build_action_evidence(original)['coverage']['material_content_complete']


def test_successful_no_text_image_ocr_is_not_a_material_gap():
    original = evidence()
    original['content'] = {'visible_text': ''}
    original['quality']['missing_body'] = True
    original['inspection']['attachments'] = [{'kind': 'image', 'text': '',
        'coverage': {'ocr': 'no_text_detected', 'ocr_material_gap': False}}]
    assert build_action_evidence(original)['coverage']['material_content_complete']
    original['inspection']['attachments'] = []
    assert not build_action_evidence(original)['coverage']['material_content_complete']


def test_unicode_overflow_is_bounded_auditable_and_hard_findings_survive():
    original = evidence()
    text = 'Start. ' + '日本語 with content ' * 12000 + ' End.'
    original['content']['visible_text'] = text
    original['inspection']['antivirus'] = {'status': 'malicious', 'malware_signature': 'Test.Malware'}
    url = 'https://bad.test/' + 'X' * 30000 + '#end'
    original['links'] = [{'raw_url': url, 'display_text': 'Download'}]
    original['url_inspection']['results'] = [{'url': 'https://bad.test/payload', 'status': 'malicious',
        'malicious': True, 'expires_at': 12345, 'source': 'supplied_test_scanner'}]
    state = build_action_evidence(original, max_bytes=9000)
    assert state_size(state) <= 9000
    assert state['coverage']['truncated'] and not state['coverage']['material_content_complete']
    assert state['coverage']['omissions']
    assert state['independent_findings']['antivirus']['malware_signature'] == 'Test.Malware'
    assert state['independent_findings']['url_results'][0]['malicious']
    assert all(row['exact_url'] == url for row in state['links'])  # Never a shortened URL.
    for row in state['email']['sources']:
        if row['source_ref'] == 'content.visible_text':
            assert len(row['segments']) <= 2
            for segment in row['segments']:
                assert segment['text'] == text[segment['start']:segment['end']]


def test_unfit_hard_findings_raise_instead_of_disappearing():
    original = evidence()
    original['inspection']['findings'] = [{'kind': 'critical', 'severity': 'critical', 'summary': 'x' * 30000}]
    with pytest.raises(ActionEvidenceLimit, match='Essential evidence exceeds'):
        build_action_evidence(original)


@pytest.mark.parametrize('bad', [{'answers': {}}, {'url_values': {}}, {'model_evidence_coverage': {}}])
def test_rejects_model_output_and_already_projected_states(bad):
    with pytest.raises(ValueError, match='Original enriched evidence'):
        build_action_evidence(bad)
