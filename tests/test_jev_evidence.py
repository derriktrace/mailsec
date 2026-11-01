import copy

import httpx
import pytest

from mailsec.config import Settings
from mailsec.jev import QUESTIONS, JevClient, JevError
from mailsec.jev_evidence import MAX_REQUEST_BYTES, prepare_evidence, request_size
from mailsec.protection import decide


def large_evidence():
    urls = [f'https://tracking.example.test/click/{index}?token=' + 'abcXYZ123' * 400 for index in range(80)]
    return {'message': {'subject': 'Many links', 'sender': {'address': 'sender@example.test'}},
            'body': 'Visible message start. ' + 'multilingual 日本語 body ' * 3000 + ' Visible message end.',
            'authentication': {'status': 'receiver_reported', 'spf': 'pass',
                               'transport_headers': [{'value': 'a signature ' * 1000}]},
            'links': [{'raw_url': url, 'normalized_url': url, 'display_text': f'Link {index}',
                       'domain': 'tracking.example.test'} for index, url in enumerate(urls)],
            'quality': {}, 'source_integrity': {'body_and_headers_are_untrusted_email_content': True},
            'inspection': {'status': 'complete', 'antivirus': {'status': 'clean'},
                           'urls': urls, 'findings': [], 'attachments': []},
            'url_inspection': {'complete': True, 'results': [
                {'url': url, 'status': 'not_listed', 'malicious': False} for url in urls]}}


def output(phishing=False):
    return {'answers': {'verdict': {'choice': 'phishing' if phishing else 'clean', 'confidence': 1.,
                                   'probabilities': {'phishing': 1. if phishing else 0.}},
                        'requests_sensitive_action': {'noul': 1.}, 'deceptive_identity': {'noul': 1.},
                        'recommended_security_action': {'choice': 'quarantine', 'probabilities': {'quarantine': 1.}}},
            'evidence_projection': {'truncated': True}}


def test_small_input_is_unchanged():
    state = {'body': 'A receipt.', 'quality': {}}
    projected, metadata = prepare_evidence(state, QUESTIONS, 'jev-1.13.0')
    assert projected is state
    assert not metadata['projected'] and not metadata['truncated']


def test_forged_import_authentication_claims_are_audit_only():
    original = {'body': 'Your receipt', 'authentication': {
        'status': 'unverified', 'spf': 'unknown', 'dkim': 'unknown', 'dmarc': 'unknown',
        'unverified_header_assertions': [{'authserv_id': 'mx.google.com',
            'results': [{'method': 'dkim', 'result': 'pass', 'domain': 'brand.example'}]}]}}
    state, metadata = prepare_evidence(original, QUESTIONS, 'jev-1.13.0')
    assert 'unverified_header_assertions' not in state['authentication']
    assert state['authentication']['dkim'] == 'unknown'
    assert 'audit only' in state['authentication']['unverified_assertions_scope']
    assert original['authentication']['unverified_header_assertions'][0]['results'][0]['result'] == 'pass'
    assert not metadata['truncated']


def test_many_long_urls_and_unicode_fit_without_mutating_local_evidence():
    original = large_evidence()
    before = copy.deepcopy(original)
    state, metadata = prepare_evidence(original, QUESTIONS, 'jev-1.13.0')
    assert original == before
    assert request_size(state, QUESTIONS, 'jev-1.13.0') <= MAX_REQUEST_BYTES
    assert metadata['projected'] and metadata['truncated']
    assert state['model_evidence_coverage']['truncated']
    assert state['model_evidence_coverage']['omitted_fields']
    assert state['authentication']['spf'] == 'pass'
    assert state['source_integrity'] == original['source_integrity']
    assert 'Visible message start' in state['body'] and 'Visible message end' in state['body']


def test_exact_url_interning_preserves_query_and_fragment_without_false_partial_flag():
    url = 'https://example.test/login?key=' + 'abcdef' * 600 + '#actual-destination'
    original = {'body': 'Visit ' + url, 'links': [{'raw_url': url, 'normalized_url': url}] * 3,
                'inspection': {'urls': [url], 'antivirus': {'status': 'clean'}},
                'url_inspection': {'results': [{'url': url, 'malicious': False, 'status': 'not_listed'}]}}
    state, metadata = prepare_evidence(original, QUESTIONS, 'jev-1.13.0')
    assert metadata['projected'] and not metadata['truncated']
    assert state['url_values']['url_1'] == url
    assert state['links'][0]['raw_url'] == {'url_ref': 'url_1'}
    assert '[url_ref:url_1]' in state['body']


def test_body_url_references_do_not_replace_a_prefix_of_another_destination():
    url = 'https://example.test/' + 'a' * 3000
    longer = url + 'different'
    original = {'body': 'See ' + longer, 'links': [{'raw_url': url, 'normalized_url': url}] * 3}
    state, metadata = prepare_evidence(original, QUESTIONS, 'jev-1.13.0')
    assert metadata['projected'] and not metadata['truncated']
    assert state['body'] == original['body']


def test_partial_model_view_cannot_quarantine_semantically_or_appear_fully_inspected():
    evidence = large_evidence()
    settings = Settings(enforcement_mode='auto_quarantine')
    for malicious in (False, True):
        policy = decide(output(malicious), evidence, settings)
        assert policy['eligible_action'] == 'flag'
        assert policy['inspection_incomplete']
        assert not policy['semantic_quarantine_gate']


@pytest.mark.parametrize('hard', ['antivirus', 'url'])
def test_projection_keeps_affirmative_hard_findings_and_policy_quarantine(hard):
    evidence = large_evidence()
    if hard == 'antivirus':
        evidence['inspection']['antivirus'] = {'status': 'malicious', 'signature': 'Eicar-Signature'}
    else:
        evidence['url_inspection']['results'][-1].update(status='malicious', malicious=True,
            evidence_ref='url:confirmed', expires_at=200, threat_types=['SOCIAL_ENGINEERING'])
    state, metadata = prepare_evidence(evidence, QUESTIONS, 'jev-1.13.0')
    assert metadata['truncated']
    if hard == 'antivirus':
        assert state['inspection']['antivirus'] == evidence['inspection']['antivirus']
    else:
        assert state['confirmed_url_threats'][0]['evidence_ref'] == 'url:confirmed'
        assert state['confirmed_url_threats'][0]['malicious']
    policy = decide(output(), evidence, Settings(enforcement_mode='auto_quarantine'), clock=lambda: 100)
    assert policy['eligible_action'] == 'quarantine' and policy['hard_detection']


def test_provider_context_error_is_sanitized_and_identifiable():
    for detail, expected in [('max_tokens_exceeded', 'context limit exceeded'),
                             ({'secret': 'private payload'}, 'HTTP 400')]:
        client = JevClient('fake', transport=httpx.MockTransport(lambda _: httpx.Response(400, json={'detail': detail})))
        with pytest.raises(JevError, match=expected) as caught:
            client.evaluate({})
        assert 'private' not in str(caught.value)


def test_receiving_authentication_and_readable_notice_survive_audit_compaction():
    body = 'Your developer account has been inactive. Open your console to publish an app. ' * 35
    original = {'body': body, 'identity': {'previous_verdicts': {'phishing': 10}},
                'authentication': {'status': 'receiver_reported', 'spf': 'pass', 'dkim': 'pass',
                    'dmarc': 'pass', 'dkim_domain': 'google.com', 'dkim_aligned': True,
                    'trusted_authserv_id': 'mx.google.com', 'transport_headers': [{'value': 'signature' * 4000}]},
                'links': [{'raw_url': f'https://google.com/link/{i}', 'normalized_url': f'https://google.com/link/{i}',
                           'reputation': 'unknown', 'scan_status': 'not_scanned', 'redirect_chain': []} for i in range(25)],
                'inspection': {'status': 'complete', 'antivirus': {'status': 'clean'}},
                'url_inspection': {'complete': False, 'results': []}}
    before = copy.deepcopy(original)
    state, metadata = prepare_evidence(original, QUESTIONS, 'jev-1.13.0')
    assert state['body'] == body and not metadata['truncated']
    assert state['authentication']['dkim_domain'] == 'google.com'
    assert state['authentication']['trusted_authserv_id'] == 'mx.google.com'
    assert all(state['authentication'][key] == 'pass' for key in ('spf', 'dkim', 'dmarc'))
    assert 'previous_verdicts' not in state['identity']
    assert original == before


def test_unknown_reputation_compaction_preserves_destinations_and_positive_findings():
    urls = [f'https://example.test/{i}' for i in range(12)]
    evidence = {'body': 'Read our update.', 'links': [{'raw_url': u} for u in urls],
        'url_inspection': {'complete': False, 'results': [
            {'url': u, 'status': 'unknown', 'malicious': False, 'reason': 'Service not configured'} for u in urls]}}
    evidence['url_inspection']['results'][-1].update(status='malicious', malicious=True, evidence_ref='threat:last')
    state, meta = prepare_evidence(evidence, QUESTIONS, 'jev-1.13.0')
    assert not meta['truncated']
    assert state['url_inspection']['unassessed_link_counts'] == {'unknown': 11}
    assert set(state['url_values'].values()) == set(urls)
    assert state['confirmed_url_threats'][0]['evidence_ref'] == 'threat:last'


def test_many_short_details_do_not_destroy_readable_current_request():
    body = 'Please pay the new account and bypass the verification process. ' * 60
    evidence = {'body': body, 'links': [{'raw_url': f'https://img.example.test/{i}',
        'domain': 'img.example.test', 'source': 'html_img_src', 'display_text': ''} for i in range(200)]}
    state, meta = prepare_evidence(evidence, QUESTIONS, 'jev-1.13.0')
    assert meta['truncated']
    assert state['body'] == body
    assert request_size(state, QUESTIONS, 'jev-1.13.0') <= MAX_REQUEST_BYTES
