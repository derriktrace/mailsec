import copy
import json

from mailsec.jev import QUESTIONS
from mailsec.jev_evidence import MAX_REQUEST_BYTES, request_size
from mailsec.jev_sections import (
    MAX_SECTIONS,
    _normalize_padding,
    _sources,
    combine_evaluations,
    prepare_evaluations,
)

MODEL = 'jev-test'


def test_missing_url_fields_do_not_crash_or_discard_malformed_link_evidence():
    evidence = {'body': 'Review this notice. ' * 1600,
        'links': [{'source': 'html_anchor', 'display_text': 'Open account',
                   'visibility': 'visible', 'malformed': True},
                  {'source': 'html_anchor', 'raw_url': 'https://account.test/',
                   'normalized_url': 'https://account.test/', 'visibility': 'visible'}]}
    requests, _ = plans(evidence)
    rows = [row for state, _ in requests if state.get('analysis_scope', {}).get('source') == 'action_links'
            for row in json.loads(state['body'])]
    assert any(row.get('malformed') is True and row.get('display_text') == 'Open account' for row in rows)
    assert any(row.get('raw_url') == 'https://account.test/' for row in rows)


def plans(evidence):
    before = copy.deepcopy(evidence)
    requests, metadata = prepare_evaluations(evidence, QUESTIONS, MODEL)
    assert before == evidence
    assert len(requests) <= MAX_SECTIONS
    assert all(request_size(state, QUESTIONS, MODEL) <= MAX_REQUEST_BYTES for state, _ in requests)
    return requests, metadata


def test_long_blank_filler_is_auditable_and_cannot_hide_middle_deposit_request():
    original = 'Legitimate-looking introduction.\n' + '\u3164' * 14000 + '\nSend a wallet deposit to unlock the grant.\n' + '\u3164' * 14000 + '\nFooter'
    requests, metadata = plans({'body': original, 'links': []})
    assert metadata['material_content_complete']
    assert any('Send a wallet deposit' in state['body'] for state, _ in requests)
    assert metadata['sources'][0]['normalized_padding_runs'] == 2
    assert metadata['sources'][0]['original_characters'] == len(original)


def test_padding_normalization_preserves_exact_url_queries_and_fragments():
    url = 'https://example.test/path?value=' + '\u3164' * 20 + '#destination'
    normalized, count = _normalize_padding('Start' + '\u3164' * 20 + '\n' + url + '\nEnd')
    assert url in normalized
    assert count == 1
    assert '日本語の正文' == _normalize_padding('日本語の正文')[0]


def test_empty_visible_source_does_not_promote_hidden_or_quoted_legacy_body():
    sources = _sources({'body': 'Old trusted corporate conversation',
        'content': {'visible_text': '', 'hidden_text': 'Old trusted corporate conversation', 'quoted_text': 'Old request'}})
    assert all(source['source'] != 'body' for source in sources)
    assert {source['source'] for source in sources} == {'content.hidden_text', 'content.quoted_text'}


def test_formatting_equivalent_mime_has_one_full_view_and_auditable_alias():
    visible = '[Image description: Service logo]\n\nYour account notice. Please use account settings.\n\nThank you.'
    plain = 'Service logo\nYour account notice. Please use\naccount settings. Thank you.'
    evidence = {'body': visible + '\n[Plain-text MIME alternative]\n' + plain,
        'content': {'visible_text': visible, 'plain_alternative': plain,
                    'visibility': {'findings': ['html_plain_alternatives_differ']}}}
    requests, metadata = plans(evidence)
    assert metadata['section_count'] == 1
    assert metadata['material_content_complete']
    assert requests[0][0]['body'] == visible
    assert 'plain_alternative' not in requests[0][0]['content']
    assert metadata['sources'][0]['equivalent_sources'][0]['source'] == 'content.plain_alternative'


def test_distinct_mime_words_or_url_destination_are_never_deduplicated():
    for plain in ('Send funds to https://other.test/', 'Do NOT send funds to https://account.test/'):
        sources = _sources({'content': {'visible_text': 'Send funds to https://account.test/', 'plain_alternative': plain}})
        assert len(sources) == 2
        assert sources[1]['text'] == plain


def test_known_passive_image_is_not_reintroduced_as_an_attachment_action_url():
    image = 'https://cdn.test/logo.png'
    evidence = {'body': 'A long source paragraph. ' * 1600,
        'links': [{'raw_url': image, 'source': 'html_img_src', 'visibility': 'visible'},
                  {'raw_url': 'https://account.test/', 'source': 'html_anchor', 'visibility': 'visible'}],
        'inspection': {'urls': [image], 'attachments': []}}
    requests, metadata = plans(evidence)
    rows = [row for state, _ in requests if state.get('analysis_scope', {}).get('source') == 'action_links'
            for row in json.loads(state['body'])]
    assert {row['raw_url'] for row in rows} == {'https://account.test/'}
    assert metadata['material_content_complete']


def test_long_message_sections_cover_middle_and_keep_source_roles():
    body = 'Opening context. ' * 1200 + '\nIMPORTANT MIDDLE PAYMENT REQUEST\n' + 'Ending context. ' * 1200
    requests, metadata = plans({'body': body, 'content': {'visible_text': body,
        'quoted_text': 'An old unrelated approval', 'hidden_text': 'Invisible preheader'}})
    assert metadata['material_content_complete']
    assert any('IMPORTANT MIDDLE PAYMENT REQUEST' in state['body'] for state, _ in requests)
    scopes = [state.get('analysis_scope', {}) for state, _ in requests]
    assert any('quoted history' in scope.get('role', '') for scope in scopes)
    assert any('CSS-hidden' in scope.get('role', '') for scope in scopes)
    assert all(scope.get('offset_basis') == 'normalized_source_characters' for scope in scopes)


def test_whole_action_destinations_survive_sectioning_and_inspection_only_urls():
    urls = [f'https://track.test/click/{n}?token=' + str(n) * 2500 + '#actual-target' for n in range(5)]
    attachment_url = 'https://document.test/payment?full=1#destination'
    evidence = {'body': 'Please review this invoice. ' * 1400,
        'links': [{'raw_url': url, 'source': 'html_anchor', 'display_text': 'Open invoice', 'visibility': 'visible'} for url in urls],
        'inspection': {'urls': [attachment_url], 'attachments': [], 'findings': []}}
    requests, metadata = plans(evidence)
    assert metadata['material_content_complete']
    complete_rows = [json.loads(state['body']) for state, _ in requests if state.get('analysis_scope', {}).get('source') == 'action_links']
    retained = {row['raw_url'] for rows in complete_rows for row in rows}
    assert set(urls + [attachment_url]) <= retained


def test_wrapped_anchor_prose_cannot_displace_its_exact_destination():
    url = 'https://action.test/claim?token=' + 'x' * 1500 + '#full-fragment'
    message = 'A very long newsletter paragraph. ' * 700
    requests, metadata = plans({'body': message,
        'links': [{'raw_url': url, 'source': 'html_anchor',
                   'display_text': message[:6500], 'visibility': 'visible'}]})
    assert metadata['material_content_complete']
    rows = [row for state, _ in requests
            if state.get('analysis_scope', {}).get('source') == 'action_links'
            for row in json.loads(state['body'])]
    assert len(rows) == 1
    assert rows[0]['raw_url'] == url
    assert 'full text in message section' in rows[0]['display_text']


def test_link_only_projection_loss_triggers_link_sections_instead_of_accepting_partial():
    urls = ['https://action.test/?token=' + str(i) * 3000 for i in range(9)]
    requests, metadata = plans({'body': 'Pay via the supplied portal.', 'links': [
        {'raw_url': url, 'source': 'html_anchor', 'visibility': 'visible'} for url in urls]})
    assert metadata['section_count'] > 1
    assert metadata['material_content_complete']
    retained = [row['raw_url'] for state, _ in requests if state.get('analysis_scope', {}).get('source') == 'action_links'
                for row in json.loads(state['body'])]
    assert set(urls) <= set(retained)


def test_unrecoverable_source_cutoff_and_section_cap_are_explicit():
    requests, metadata = plans({'body': 'Known start', 'content': {'visible_text': 'Huge message. ' * 30000,
        'visibility': {'source_text_truncated': True}}})
    assert len(requests) == MAX_SECTIONS
    assert not metadata['material_content_complete']
    assert {gap['kind'] for gap in metadata['material_gaps']} >= {'source_content_limit', 'section_limit'}


def test_legacy_body_limit_remains_a_gap_but_complete_parser_source_does_not():
    _, legacy = plans({'body': 'Only the retained text', 'quality': {'body_truncated': True}})
    assert not legacy['material_content_complete']
    _, complete = plans({'body': 'Legacy shortened display', 'quality': {'body_truncated': True},
        'content': {'visible_text': 'A complete visible source remains available.'}})
    assert complete['material_content_complete']


def test_adverse_section_not_averaged_away_and_multisection_always_review_only():
    def result(choice, confidence):
        return {'answers': {'verdict': {'choice': choice, 'confidence': confidence}},
                'usage': {'input_tokens': 100, 'output_tokens': 10}}
    rows = [result('clean', .99), result('phishing', .71), result('suspicious', .8)]
    combined = combine_evaluations(rows, {'material_content_complete': True})
    assert combined['answers']['verdict']['choice'] == 'phishing'
    assert combined['aggregation']['review_only'] is True
    assert combined['aggregation']['selected_section'] == 1
    assert combined['usage']['input_tokens'] == 300
    assert combined['chunk_evaluations'] == rows
