import asyncio
import copy
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest

from mailsec.api import create_app
from mailsec.config import Settings
from mailsec.protection import decide
from mailsec.reputation import ENDPOINT, ReputationClient, canonical_url
from mailsec.runtime_controls import refresh_controls, update_controls
from mailsec.security_cache import SecurityCache
from mailsec.storage import Store


def evidence():
    return {'inspection': {'status': 'complete', 'antivirus': {'status': 'clean'}, 'findings': []},
            'url_inspection': {'complete': True, 'results': []}}


def prediction(phishing=False, anomaly=False):
    return {'answers': {'verdict': {'choice': 'phishing' if phishing else 'clean', 'confidence': .99,
                                   'probabilities': {'phishing': .99 if phishing else .001}},
                        'requests_sensitive_action': {'noul': .99 if phishing else 0},
                        'deceptive_identity': {'noul': .01 if anomaly else .99},
                        'business_context_anomaly': {'noul': .99 if anomaly else 0},
                        'recommended_security_action': {'choice': 'quarantine' if phishing else 'deliver'}}}


def test_unknown_never_quarantines_and_hard_signature_survives_model_failure():
    settings = Settings(enforcement_mode='auto_quarantine')
    missing = decide(prediction(), {}, settings)
    assert missing['recommended_action'] == 'flag' and not missing['hard_detection']
    scanned = evidence()
    scanned['inspection']['antivirus']['status'] = 'malicious'
    for model in (None, prediction()):
        result = decide(model, scanned, settings)
        assert result['eligible_action'] == 'quarantine'
        assert result['verdict'] == 'phishing' and result['hard_detection']


def test_semantic_gate_requires_corroboration_and_respects_operator_mode():
    settings = Settings(enforcement_mode='auto_quarantine')
    for anomaly in (True, False):
        model = prediction(True, anomaly)
        assert decide(model, evidence(), settings)['eligible_action'] == 'quarantine'
        model['answers']['requests_sensitive_action']['noul'] = .1
        assert decide(model, evidence(), settings)['eligible_action'] == 'flag'
    for mode, expected in [('passive', 'none'), ('flag_only', 'flag')]:
        settings.enforcement_mode = mode
        assert decide(prediction(True), evidence(), settings)['eligible_action'] == expected


def test_expired_reputation_cannot_support_quarantine_but_independent_gate_survives():
    state = evidence()
    state['url_inspection']['results'] = [{'status': 'malicious', 'malicious': True,
                                         'evidence_ref': 'url:test', 'expires_at': 99}]
    settings = Settings(enforcement_mode='auto_quarantine')
    result = decide(prediction(), state, settings, clock=lambda: 100)
    assert result['eligible_action'] == 'flag' and not result['hard_detection']
    state['url_inspection']['results'][0]['expires_at'] = 120
    result = decide(prediction(), state, settings, clock=lambda: 100)
    assert result['eligible_action'] == 'quarantine' and result['action_expires_at'] == 120
    assert decide(prediction(True), state, settings, clock=lambda: 100)['action_expires_at'] == 120
    state['url_inspection']['results'][0]['expires_at'] = 99
    assert decide(prediction(True), state, settings, clock=lambda: 100)['eligible_action'] == 'flag'


@pytest.fixture
def cache(tmp_path):
    store = Store(f'sqlite:///{tmp_path / "security.db"}')
    yield SecurityCache(store.engine, 'tenant-a', clock=lambda: 1000)
    store.engine.dispose()


def test_cache_tenant_epoch_expiration_and_atomic_budget(cache):
    cache.put('test', 'key', {'value': 1}, 1001)
    assert cache.get('test', 'key')['value'] == {'value': 1}
    assert SecurityCache(cache.engine, 'tenant-b', clock=lambda: 1000).get('test', 'key') is None
    assert SecurityCache(cache.engine, 'tenant-a', epoch='2', clock=lambda: 1000).get('test', 'key') is None
    cache.clock = lambda: 1002
    assert cache.get('test', 'key') is None
    with ThreadPoolExecutor(max_workers=8) as pool:
        values = list(pool.map(lambda _: cache.reserve_lookup(3), range(20)))
    assert sum(values) == 3
    assert cache.status()['lookups_reserved'] == 3


def test_reputation_only_contacts_provider_and_preserves_query_fragment(cache):
    seen = []
    def provider(request):
        seen.append(request)
        return httpx.Response(200, json={})
    settings = Settings(web_risk_api_key='sentinel-only')
    client = ReputationClient(settings, cache, httpx.MockTransport(provider))
    first = client.check('https://EVIL.example/path?token=a#page')
    assert first['status'] == 'not_listed' and first['malicious'] is False
    assert client.check('https://EVIL.example/path?token=a#page')['cache_hit']
    client.check('https://EVIL.example/path?token=b#page')
    assert len(seen) == 2
    assert all(str(r.url).split('?')[0] == ENDPOINT for r in seen)
    assert seen[0].url.params['uri'] == 'https://evil.example/path?token=a#page'
    assert 'sentinel-only' not in str(first) and 'sentinel-only' not in str(seen[0].url)
    assert seen[0].headers['X-Goog-Api-Key'] == 'sentinel-only'
    cache.clock = lambda: 1400
    assert not client.check('https://EVIL.example/path?token=a#page')['cache_hit']


@pytest.mark.parametrize('url', ['http://127.0.0.1/', 'http://192.168.1.1/', 'http://[::1]/',
                                 'https://localhost/', 'http://intranet/', 'https://a:b@example.com/'])
def test_reputation_does_not_submit_private_or_credential_bearing_urls(url):
    with pytest.raises(ValueError):
        canonical_url(url)


def test_positive_expiration_budget_and_provider_errors(cache):
    settings = Settings(web_risk_api_key='test', url_lookup_monthly_limit=2)
    results = [httpx.Response(200, json={'threat': {'threatTypes': ['MALWARE'], 'expireTime': '1970-01-01T00:20:00Z'}}),
               httpx.Response(401, text='secret-key')]
    client = ReputationClient(settings, cache, httpx.MockTransport(lambda r: results.pop(0)))
    hit = client.check('https://bad.example/')
    assert hit['malicious'] and hit['expires_at'] == 1200
    assert client.check('https://bad.example/')['cache_hit']
    bad = client.check('https://error.example/')
    assert bad['status'] == 'unavailable' and 'secret-key' not in str(bad)
    assert client.check('https://budget.example/')['status'] == 'budget_exhausted'


def test_runtime_controls_persist_and_api_requires_auth(tmp_path):
    settings = Settings(database_url=f'sqlite:///{tmp_path / "app.db"}', app_token='test')
    app = create_app(settings)
    async def check():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url='http://testserver') as client:
            assert (await client.patch('/api/protection', json={'mode':'auto_quarantine'})).status_code == 401
            auth = {'Authorization':'Bearer test'}
            result = await client.patch('/api/protection', json={'mode':'auto_quarantine','notifications_enabled':True}, headers=auth)
            assert result.status_code == 200 and result.json()['mode'] == 'auto_quarantine'
            assert not result.json()['services']['url_reputation']['configured']
            assert (await client.patch('/api/protection', json={'mode':'arbitrary'}, headers=auth)).status_code == 422
    asyncio.run(check())
    other = copy.copy(settings)
    other.enforcement_mode = 'passive'
    assert refresh_controls(other, app.state.pipeline.store) == {'mode':'auto_quarantine','notifications_enabled':True}
    update_controls(other, app.state.pipeline.store, {'mode':'passive'})
    assert refresh_controls(settings, app.state.pipeline.store)['mode'] == 'passive'


def test_concurrent_control_edits_cannot_lose_emergency_pause(tmp_path):
    from threading import Barrier
    settings = Settings(database_url=f'sqlite:///{tmp_path / "controls.db"}', enforcement_mode='auto_quarantine', notifications_enabled=True)
    store = Store(settings.database_url)
    update_controls(settings, store, {})
    barrier = Barrier(2)
    def change(value):
        separate_settings = copy.copy(settings)
        barrier.wait(timeout=3)
        return update_controls(separate_settings, store, value)
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(change, [{'mode':'passive'}, {'notifications_enabled':False}]))
    assert refresh_controls(settings, store) == {'mode':'passive','notifications_enabled':False}



def test_direct_fraud_can_quarantine_without_impersonation_but_needs_strict_agreement():
    settings = Settings(enforcement_mode='auto_quarantine')
    model = prediction(True)
    model['answers']['deceptive_identity']['noul'] = .2
    model['answers']['recommended_security_action']['probabilities'] = {'quarantine':.99}
    result = decide(model, evidence(), settings)
    assert result['eligible_action'] == 'quarantine'
    assert result['semantic_basis'] == 'sensitive_fraud_agreement'
    model['answers']['recommended_security_action']['probabilities']['quarantine'] = .8
    assert decide(model, evidence(), settings)['eligible_action'] == 'flag'
    model = prediction(False)
    model['answers']['requests_sensitive_action']['noul'] = 1
    model['answers']['recommended_security_action'] = {'choice':'quarantine','probabilities':{'quarantine':1}}
    assert decide(model, evidence(), settings)['eligible_action'] == 'none'


def test_weak_phishing_is_uncertain_and_review_recommendation_is_actionable():
    model = prediction(True)
    model['answers']['verdict'].update(confidence=.4, probabilities={'phishing': .55})
    decision = decide(model, evidence(), Settings(enforcement_mode='auto_quarantine'))
    assert decision['verdict'] == 'suspicious'
    assert decision['model_verdict'] == 'phishing'
    assert decision['verdict_requires_review']
    assert decision['eligible_action'] == 'flag'
    model = prediction(False)
    model['answers']['recommended_security_action']['choice'] = 'review'
    assert decide(model, evidence(), Settings())['recommended_action'] == 'flag'


@pytest.mark.parametrize('verdict', ['clean', 'spam'])
def test_neutral_reputation_and_nonmaterial_css_do_not_label_routine_mail_for_review(verdict):
    state = evidence()
    state['inspection'].update(status='partial', findings=[{
        'kind': 'document_incomplete', 'severity': 'review', 'evidence_ref': 'mime/0',
        'summary': 'Conditional email CSS was not rendered.'}])
    state['url_inspection'] = {'complete': False, 'results': [{
        'status': 'unknown', 'malicious': False, 'reason': 'Web Risk not configured.'}]}
    model = prediction()
    model['answers']['verdict']['choice'] = verdict
    model['answers']['recommended_security_action']['choice'] = 'review'
    model['action_review'] = {'status': 'complete', 'findings': []}
    result = decide(model, state, Settings(enforcement_mode='flag_only'))
    assert result['verdict'] == verdict
    assert result['recommended_action'] == result['eligible_action'] == 'none'
    assert result['inspection_incomplete'] is False


def test_material_document_gap_and_active_content_still_label_for_review():
    model = prediction()
    model['action_review'] = {'status': 'complete', 'findings': []}
    model['answers']['recommended_security_action']['choice'] = 'review'
    state = evidence()
    state['inspection'].update(status='partial', findings=[{
        'kind': 'document_incomplete', 'severity': 'review', 'evidence_ref': 'attachment:1'}],
        attachments=[{'evidence_ref': 'attachment:1', 'coverage': {'material_content_gap': True}}])
    result = decide(model, state, Settings(enforcement_mode='flag_only'))
    assert result['verdict'] == 'suspicious' and result['eligible_action'] == 'flag'
    state = evidence()
    state['inspection'].update(status='partial', findings=[{
        'kind': 'active_content', 'severity': 'review', 'evidence_ref': 'mime/0'}])
    result = decide(model, state, Settings(enforcement_mode='flag_only'))
    assert result['verdict'] == 'clean' and result['eligible_action'] == 'flag'


@pytest.mark.parametrize('verdict', ['clean', 'spam'])
def test_low_benign_confidence_alone_does_not_apply_review_after_complete_action_check(verdict):
    model = prediction()
    model['answers']['verdict'].update(choice=verdict, confidence=.38)
    model['answers']['recommended_security_action']['choice'] = 'review'
    model['action_review'] = {'status': 'complete', 'findings': []}
    result = decide(model, evidence(), Settings(enforcement_mode='flag_only'))
    assert result['verdict'] == verdict
    assert result['eligible_action'] == 'none'
    assert 'The verdict confidence is below the review threshold.' not in result['reasons']

    model['action_review'] = {'status': 'incomplete', 'findings': [],
                              'coverage': {'truncated': True, 'upstream_gaps': [{'kind': 'source_content_limit'}]}}
    assert decide(model, evidence(), Settings(enforcement_mode='flag_only'))['eligible_action'] == 'flag'


def test_secondary_budget_limit_does_not_override_complete_primary_spam_judgment():
    model = prediction()
    model['answers']['verdict']['choice'] = 'spam'
    model['answers']['recommended_security_action']['choice'] = 'review'
    model['evidence_projection'] = {'material_content_complete': True, 'truncated': False}
    model['action_review'] = {'status': 'incomplete', 'findings': [],
        'coverage': {'truncated': True, 'upstream_gaps': [], 'material_content_complete': False}}
    result = decide(model, evidence(), Settings(enforcement_mode='flag_only'))
    assert result['verdict'] == 'spam'
    assert result['eligible_action'] == 'none'
    assert result['secondary_review_budget_only'] is True
    assert result['action_review_incomplete'] is False
    model['evidence_projection']['material_content_complete'] = False
    result = decide(model, evidence(), Settings(enforcement_mode='flag_only'))
    assert result['eligible_action'] == 'flag'


def test_strong_phishing_and_hard_findings_survive_review_threshold():
    model = prediction(True)
    settings = Settings(enforcement_mode='auto_quarantine')
    assert decide(model, evidence(), settings)['verdict'] == 'phishing'
    model['evidence_projection'] = {'truncated': True}
    assert decide(model, evidence(), settings)['verdict'] == 'phishing'
    assert decide(model, evidence(), settings)['eligible_action'] == 'flag'
    malicious = evidence()
    malicious['inspection']['antivirus']['status'] = 'malicious'
    decision = decide(model, malicious, settings)
    assert decision['verdict'] == 'phishing'
    assert decision['eligible_action'] == 'quarantine'


@pytest.mark.parametrize('gap', ['body', 'visibility', 'remote_image', 'ocr', 'document', 'projection', 'empty', 'execution'])
def test_clean_semantics_with_material_unread_evidence_is_suspicious_review(gap):
    state = evidence()
    state['body'] = 'Please review the enclosed information.'
    model = prediction()
    if gap == 'body':
        state['quality'] = {'body_truncated': True}
    elif gap == 'visibility':
        state['quality'] = {'content_visibility_incomplete': True}
    elif gap == 'remote_image':
        state['content'] = {'visibility': {'material_remote_image_gap': True}}
    elif gap in ('ocr', 'document'):
        key = 'ocr_material_gap' if gap == 'ocr' else 'material_content_gap'
        state['inspection']['attachments'] = [{'evidence_ref': 'attachment:1', 'coverage': {key: True}}]
    elif gap == 'projection':
        model['evidence_projection'] = {'truncated': True, 'material_content_complete': False,
            'material_gaps': [{'kind': 'body_omitted', 'reason': 'The requested action was not read.', 'evidence_ref': 'body'}]}
    elif gap == 'empty':
        state.update(body='', quality={'missing_body': True})
    else:
        state['inspection']['findings'] = [{'kind': 'static_download_execute', 'severity': 'critical',
                                           'evidence_ref': 'attachment:1'}]
    original = copy.deepcopy(model)
    decision = decide(model, state, Settings(enforcement_mode='auto_quarantine'))
    assert decision['verdict'] == 'suspicious'
    assert decision['model_verdict'] == 'clean' and model == original
    assert decision['eligible_action'] == 'flag'
    assert decision['verdict_requires_review']
    assert decision['verdict_review_basis'] == 'material_evidence_gap'
    assert decision['material_evidence_incomplete'] and decision['material_evidence_gaps']
    assert not decision['hard_detection'] and not decision['semantic_quarantine_gate']


@pytest.mark.parametrize('uncertainty', ['unknown_reputation', 'unknown_history', 'low_confidence',
                                      'review_recommendation', 'decorative_image', 'read_document',
                                      'no_text_image', 'benign_download', 'auxiliary_truncation', 'full_chunks'])
def test_benign_counterexamples_keep_clean_when_no_material_content_is_missing(uncertainty):
    state = evidence()
    state['body'] = 'Your account activation is complete. View the project release notes when convenient.'
    model = prediction()
    if uncertainty == 'unknown_reputation':
        state['url_inspection'] = {'complete': False, 'results': [{'status': 'unknown', 'malicious': False}]}
    elif uncertainty == 'unknown_history':
        state['identity'] = {'sender_first_seen': None, 'history_status': 'not_available'}
        state['authentication'] = {'spf': 'unknown', 'dkim': 'unknown', 'dmarc': 'unknown'}
    elif uncertainty == 'low_confidence':
        model['answers']['verdict']['confidence'] = .3
    elif uncertainty == 'review_recommendation':
        model['answers']['recommended_security_action']['choice'] = 'review'
    elif uncertainty == 'decorative_image':
        state['inspection']['attachments'] = [{'kind': 'image', 'coverage': {'ocr': 'not_applicable', 'ocr_material_gap': False}}]
        state['content'] = {'visibility': {'material_remote_image_gap': False, 'findings': ['visible_image_without_text']}}
    elif uncertainty == 'read_document':
        state.update(body='', quality={'missing_body': True})
        state['inspection']['attachments'] = [{'text': 'Receipt paid in full.', 'coverage': {'ocr': 'extracted', 'ocr_material_gap': False}}]
    elif uncertainty == 'no_text_image':
        state.update(body='', quality={'missing_body': True})
        state['inspection']['attachments'] = [{'kind': 'image', 'text': '', 'coverage': {'ocr': 'no_text_detected', 'ocr_material_gap': False}}]
    elif uncertainty == 'benign_download':
        state['inspection']['findings'] = [{'kind': 'html_download', 'severity': 'review', 'summary': 'Offline report export'}]
    elif uncertainty == 'auxiliary_truncation':
        model['evidence_projection'] = {'truncated': True, 'material_content_complete': True, 'material_gaps': []}
    else:
        model['aggregation'] = {'method': 'max_severity_selected_section', 'review_only': True, 'count': 4}
        model['evidence_projection'] = {'truncated': False, 'material_content_complete': True, 'material_gaps': []}
    decision = decide(model, state, Settings(enforcement_mode='auto_quarantine'))
    assert decision['verdict'] == decision['model_verdict'] == 'clean'
    assert not decision['material_evidence_incomplete'] and not decision['verdict_requires_review']
    assert decision['eligible_action'] in ('none', 'flag')


def test_section_scores_and_new_fraud_signals_are_not_new_containment_authority():
    model = prediction(True)
    model['aggregation'] = {'method': 'max_severity_selected_section', 'review_only': True, 'count': 3}
    settings = Settings(enforcement_mode='auto_quarantine')
    decision = decide(model, evidence(), settings)
    assert decision['verdict'] == 'phishing' and decision['eligible_action'] == 'flag'
    assert decision['section_review_only'] and not decision['semantic_quarantine_gate']
    benign = prediction()
    for key in ('callback_fraud', 'platform_content_abuse', 'execution_or_wallet_fraud'):
        benign['answers'][key] = {'noul': 1.}
    decision = decide(benign, evidence(), settings)
    assert decision['verdict'] == 'clean' and decision['eligible_action'] == 'none'
    known_malware = evidence()
    known_malware['inspection']['antivirus']['status'] = 'malicious'
    known_malware['quality'] = {'body_truncated': True}
    decision = decide(model, known_malware, settings)
    assert decision['verdict'] == 'phishing' and decision['eligible_action'] == 'quarantine'
    assert decision['hard_detection']


def test_material_review_is_stored_and_counted_as_suspicious_without_rewriting_jev(tmp_path):
    from mailsec.storage import now
    store = Store(f'sqlite:///{tmp_path / "effective-verdict.db"}')
    state = evidence()
    state.update(message={'subject': 'Unread invoice', 'sender': {}}, body='See attached.',
                 quality={'body_truncated': True})
    model = prediction()
    decision = decide(model, state, Settings())
    item = store.ingest(b'Subject: Unread invoice\r\n\r\nSee attached.', state)
    store.finish(store.claim(), state, model, decision, {}, {}, now())
    detail = store.detail(item['id'])
    assert detail['message']['verdict'] == 'suspicious'
    assert detail['runs'][0]['output']['answers']['verdict']['choice'] == 'clean'
    assert store.status()['counts']['suspicious'] == 1
    assert store.status()['counts']['clean'] == 0
    store.engine.dispose()


def test_truncated_preview_does_not_hide_complete_full_source_analysis():
    state = evidence()
    state.update(body='Preview', quality={'body_truncated': True},
                 content={'visible_text': 'Complete source content', 'visibility': {}})
    model = prediction()
    model['evidence_projection'] = {'material_content_complete': True, 'truncated': False, 'material_gaps': []}
    model['aggregation'] = {'count': 3, 'review_only': True}
    decision = decide(model, state, Settings())
    assert decision['verdict'] == 'clean' and not decision['inspection_incomplete']
    state['content']['visibility']['source_text_truncated'] = True
    decision = decide(model, state, Settings())
    assert decision['verdict'] == 'suspicious' and decision['material_evidence_incomplete']
