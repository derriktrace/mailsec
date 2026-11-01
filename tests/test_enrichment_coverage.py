import copy

from mailsec.enrichment import ENRICHMENT_VERSION, enrich
from mailsec.jev import QUESTIONS
from mailsec.jev_evidence import prepare_evidence
from mailsec.parsing import parse_email


def message(sender='Vendor Support <support@vend0r.test>', body='Open https://vend0r.test/login', headers=''):
    return (f'From: {sender}\nTo: user@recipient.test\nSubject: Account notice\n{headers}\n{body}').encode()


def test_no_targets_means_not_evaluated_not_false_identity_assurance():
    parsed = parse_email(message())
    original = copy.deepcopy(parsed)
    evidence = enrich(parsed, {})
    assert parsed == original
    identity = evidence['identity']
    for name in ('display_name_matches_internal_user', 'display_name_matches_known_vendor',
                 'sender_domain_matches_known_vendor', 'sender_claimed_vendor_domain_match',
                 'sender_domain_is_internal', 'lookalike_domain'):
        assert identity[name] is None
    assert evidence['enrichment_version'] == ENRICHMENT_VERSION
    assert identity['identity_contradictions'] == []
    for name, coverage in identity['comparison_coverage'].items():
        if name != 'scope':
            assert coverage['status'] == 'not_evaluated'
            assert coverage['target_count'] == 0
    assert evidence['links'][0]['lookalike_hints'] is None
    assert evidence['links'][0]['display_text_brand_claims'] is None


def test_empty_domain_entries_are_not_comparison_targets():
    evidence = enrich(parse_email(message()), {'domains': ['', '  '], 'known_vendors': {'Vendor': {'domains': ['']}}})
    identity = evidence['identity']
    assert identity['display_name_matches_known_vendor'] is True
    assert identity['sender_domain_matches_known_vendor'] is None
    assert identity['sender_claimed_vendor_domain_match'] is None
    assert identity['lookalike_domain'] is None
    assert identity['identity_contradictions'] == []


def test_configured_comparisons_keep_actual_match_mismatch_and_lookalike_results():
    configuration = {'domains': ['recipient.test'], 'known_vendors': {'Vendor': {'domains': ['vendor.test']}}}
    mismatch = enrich(parse_email(message()), configuration)['identity']
    assert mismatch['display_name_matches_known_vendor'] is True
    assert mismatch['sender_domain_matches_known_vendor'] is False
    assert mismatch['sender_claimed_vendor_domain_match'] is False
    assert mismatch['lookalike_domain'] is True
    assert mismatch['identity_contradictions'][0]['claimed_identity'] == 'Vendor'
    assert mismatch['comparison_coverage']['sender_lookalike']['status'] == 'evaluated'
    coherent = enrich(parse_email(message('Vendor Support <support@vendor.test>')), configuration)['identity']
    assert coherent['sender_domain_matches_known_vendor'] is True
    assert coherent['sender_claimed_vendor_domain_match'] is True
    assert coherent['lookalike_domain'] is False


def test_no_observed_domain_does_not_fabricate_contradiction_against_known_targets():
    evidence = enrich(parse_email(message('Vendor')), {'known_vendors': {'Vendor': {'domains': ['vendor.test']}}})
    assert evidence['identity']['sender_domain_matches_known_vendor'] is None
    assert evidence['identity']['sender_claimed_vendor_domain_match'] is None
    assert evidence['identity']['lookalike_domain'] is None
    assert evidence['identity']['identity_contradictions'] == []
    assert evidence['identity']['comparison_coverage']['sender_lookalike']['reason'] == 'Observed value is unavailable.'


def test_named_vendor_without_domains_does_not_make_link_brand_mismatch_false():
    raw = message(body='<a href="https://portal.test/">Vendor Account</a>', headers='Content-Type: text/html\n')
    evidence = enrich(parse_email(raw), {'known_vendors': {'Vendor': {}}})
    link = evidence['links'][0]
    assert link['display_text_brand_claims'] == ['Vendor']
    assert link['claimed_brand_domain_matches'] == {'Vendor': None}
    assert link['lookalike_hints'] is None


def test_partial_domain_knowledge_cannot_turn_all_claims_into_verified_match():
    evidence = enrich(parse_email(message('Vendor Partner <support@vendor.test>')),
                      {'known_vendors': {'Vendor': {'domains': ['vendor.test']}, 'Partner': {}}})
    assert evidence['identity']['sender_domain_matches_known_vendor'] is True
    assert evidence['identity']['sender_claimed_vendor_domain_match'] is None
    assert evidence['identity']['identity_contradictions'] == []


def test_link_comparison_coverage_reports_invalid_domain_separately():
    parsed = parse_email(message(body='<a href="https://vendor.test/">Vendor portal</a><a href="mailto:help@vendor.test">Contact</a>',
                                 headers='Content-Type: text/html\n'))
    evidence = enrich(parsed, {'known_vendors': {'Vendor': {'domains': ['vendor.test']}}})
    coverage = evidence['identity']['comparison_coverage']['link_lookalike']
    assert coverage == {'status': 'partial', 'target_count': 1, 'evaluated_links': 1, 'total_links': 2}
    assert evidence['links'][1]['lookalike_hints'] is None


def test_comparison_coverage_survives_model_projection_even_when_nulls_are_removed():
    evidence = enrich(parse_email(message()), {})
    state, metadata = prepare_evidence(evidence, QUESTIONS, 'jev-test')
    assert not metadata['truncated']
    assert state['identity'].get('lookalike_domain') is None
    assert state['identity']['comparison_coverage']['sender_lookalike']['status'] == 'not_evaluated'
    assert 'message-body identity claims' in state['identity']['comparison_coverage']['scope']


def test_identity_coverage_does_not_promote_imported_authentication_headers():
    headers = ('Received: from sender.test by mx.google.com; date\n'
               'Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=vend0r.test; dkim=pass header.d=vend0r.test; dmarc=pass header.from=vend0r.test\n')
    organization = {'trusted_authserv_ids': ['mx.google.com']}
    imported = enrich(parse_email(message(headers=headers)), organization)
    assert imported['authentication']['status'] == 'unverified'
    assert imported['authentication']['dmarc'] == 'unknown'
    assert imported['authentication']['unverified_header_assertions'][0]['results'][0]['result'] == 'pass'
    received = enrich(parse_email(message(headers=headers), provider='gmail'), organization)
    assert received['authentication']['status'] == 'receiver_reported'
    assert received['authentication']['spf'] == received['authentication']['dkim'] == received['authentication']['dmarc'] == 'pass'
    assert received['authentication']['trusted_authserv_id'] == 'mx.google.com'
    assert received['identity']['lookalike_domain'] is None
    assert received['identity']['comparison_coverage']['sender_lookalike']['status'] == 'not_evaluated'
