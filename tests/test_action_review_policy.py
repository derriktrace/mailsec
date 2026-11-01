from copy import deepcopy

import httpx
import pytest
from privacy_helpers import authorize_test_provider

from mailsec.config import Settings
from mailsec.jev import JevClient
from mailsec.pipeline import Pipeline
from mailsec.protection import decide


def response(questions, decision='clean'):
    answers = {}
    for key, question in questions.items():
        if question['type'] == 'noul':
            answers[key] = {'type': 'noul', 'noul': .98 if key == 'software_execution_requested' else .01}
        else:
            choice = {'verdict': decision, 'recommended_security_action': 'deliver',
                      'claimed_authority': 'official_representative',
                      'authority_relationship': 'unresolved'}[key]
            answers[key] = {'type': 'choice', 'choice': choice, 'confidence': 1.,
                'probabilities': {c: float(c == choice) for c in question['criteria']}}
    return {'model': 'jev-test', 'answers': answers, 'usage': {'input_tokens': 100, 'output_tokens': 20}}


def evidence():
    return {'message': {'subject': 'Exercise', 'sender': {'address': 'hiring@unknown.test'}},
            'body': 'Run pnpm install then pnpm dev.', 'quality': {},
            'inspection': {'status': 'complete', 'antivirus': {'status': 'clean'}},
            'url_inspection': {'complete': True, 'results': []}}


@pytest.mark.parametrize('initial', ['clean', 'spam'])
def test_pipeline_records_both_stages_and_policy_preserves_raw_verdict(tmp_path, initial):
    import json
    calls = []
    def provider(request):
        payload = json.loads(request.content)
        calls.append(payload)
        return httpx.Response(200, json=response(payload['questions'], initial))
    settings = Settings(database_url=f'sqlite:///{tmp_path / "test.db"}', action_review_enabled=True,
                        enforcement_mode='auto_quarantine', jev_cache_seconds=0)
    pipeline = Pipeline(settings, jev=JevClient('test', transport=httpx.MockTransport(provider)))
    original = evidence()
    result = pipeline._evaluate(original, settings.versions())
    policy = decide(result, original, settings)
    assert len(calls) == 3
    assert 'verdict' not in calls[2]['state']['action_observations']['answers']
    assert result['action_review']['status'] == 'complete'
    assert result['usage'] == {'input_tokens': 300, 'output_tokens': 60}
    assert result['answers']['verdict']['choice'] == initial
    assert policy['model_verdict'] == initial
    assert policy['verdict'] == 'suspicious'
    assert policy['eligible_action'] == 'flag'
    assert policy['verdict_review_basis'] == 'action_authority_gap'
    assert not policy['semantic_quarantine_gate']
    assert result['action_review']['stages']['authority']['state'] == calls[2]['state']
    pipeline.store.engine.dispose()


def test_extra_review_does_not_override_hard_detection_or_downgrade_phishing():
    from mailsec.jev import QUESTIONS
    output = response(QUESTIONS, 'phishing')
    output['action_review'] = {'status': 'complete', 'findings': [{'reason': 'Review execution authority.'}]}
    original = evidence()
    assert decide(output, original, Settings())['verdict'] == 'phishing'
    original['inspection']['antivirus']['status'] = 'malicious'
    policy = decide(output, original, Settings(enforcement_mode='auto_quarantine'))
    assert policy['hard_detection'] and policy['eligible_action'] == 'quarantine'


def test_review_failure_cannot_authorize_containment_or_claim_completion():
    from mailsec.jev import QUESTIONS
    output = response(QUESTIONS)
    output['action_review'] = {'status': 'error', 'findings': []}
    policy = decide(deepcopy(output), evidence(), Settings(enforcement_mode='auto_quarantine'))
    assert policy['action_review_incomplete']
    assert policy['eligible_action'] == 'flag'
    assert not policy['semantic_quarantine_gate']


def test_failed_authority_stage_is_a_retryable_error_with_original_audit(tmp_path):
    import json
    def provider(request):
        payload = json.loads(request.content)
        if 'authority_relationship' in payload['questions']:
            return httpx.Response(401, text='DO_NOT_LEAK_private_details')
        return httpx.Response(200, json=response(payload['questions']))
    settings = Settings(database_url=f'sqlite:///{tmp_path / "failed.db"}', action_review_enabled=True)
    pipeline = Pipeline(settings, jev=JevClient('test', transport=httpx.MockTransport(provider)))
    authorize_test_provider(settings, pipeline.store)
    item = pipeline.ingest(b'From: hiring@unknown.test\r\nSubject: Exercise\r\n\r\nRun pnpm install.')
    result = pipeline.process_one()
    detail = pipeline.store.detail(item['id'])
    assert result['status'] == detail['message']['status'] == detail['runs'][0]['status'] == 'error'
    assert result['verdict'] is None and detail['message']['verdict'] is None
    run = detail['runs'][0]
    assert run['output']['answers']['verdict']['choice'] == 'clean'
    assert run['output']['action_review']['stages']['authority']['status'] == 'error'
    assert run['policy']['recommended_action'] == 'flag'
    assert 'DO_NOT_LEAK' not in json.dumps(detail)
    assert pipeline.store.enqueue(item['id'])
    pipeline.store.engine.dispose()
