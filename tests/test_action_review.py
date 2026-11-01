import hashlib
import json
from copy import deepcopy

import pytest

from mailsec.action_review import FACT_QUESTIONS, RELATIONSHIP_QUESTIONS, evaluate_action_review
from mailsec.jev import JevError


def evidence():
    return {'message': {'subject': 'A message', 'sender': {'address': 'sender@example.test'}},
        'content': {'visible_text': 'Please review the attached instructions.'}, 'quality': {},
        'inspection': {'status': 'complete', 'attachments': []},
        'baseline_verdict': 'DO_NOT_SEND_BASELINE', 'reference_label': 'DO_NOT_SEND_LABEL',
        'identity': {'previous_verdicts': ['DO_NOT_SEND_PRIOR']}}


def response(questions, overrides=None, coherent=.9, authority=None):
    overrides = overrides or {}
    answers = {}
    for key, question in questions.items():
        if question['type'] == 'noul':
            answers[key] = {'type': 'noul', 'noul': overrides.get(key, .1)}
        else:
            criteria = question['criteria']
            probabilities = {k: 0. for k in criteria}
            if key == 'authority_relationship':
                probabilities.update(coherent=coherent, contradicted=1-coherent)
                if authority == 'unresolved':
                    probabilities.update(contradicted=0., unresolved=1-coherent)
                elif authority == 'no_authority_claim':
                    probabilities.update(contradicted=0., no_authority_claim=1-coherent)
            else:
                probabilities['official_representative'] = 1.
            answers[key] = {'type': 'choice', 'choice': max(probabilities, key=probabilities.get),
                'probabilities': probabilities, 'confidence': .8}
    return {'model': 'jev-test', 'answers': answers, 'usage': {'input_tokens': 100, 'output_tokens': 50}}


def evaluate_with(overrides=None, coherent=.9, authority=None, original=None):
    calls = []
    def evaluate(state, questions):
        calls.append({'state': deepcopy(state), 'questions': deepcopy(questions)})
        return response(questions, overrides, coherent, authority)
    return evaluate_action_review(original or evidence(), evaluate), calls


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True).encode()).hexdigest()


def test_ordering_exact_audit_fallible_fact_forwarding_and_usage():
    result, calls = evaluate_with()
    assert len(calls) == result['evaluation_calls_attempted'] == 2
    assert calls[0]['questions'] == FACT_QUESTIONS
    assert calls[1]['questions'] == RELATIONSHIP_QUESTIONS
    assert len(FACT_QUESTIONS) == 6 and len(RELATIONSHIP_QUESTIONS) == 2
    assert 'action_observations' not in calls[0]['state']
    observations = calls[1]['state']['action_observations']
    assert set(observations['answers']) == set(FACT_QUESTIONS)
    assert 'Fallible' in observations['provenance']
    assert 'DO_NOT_SEND' not in json.dumps(calls)
    assert result['status'] == 'complete'
    assert result['usage'] == {'input_tokens': 200, 'output_tokens': 100}
    assert result['usage_complete']
    for index, name in enumerate(('facts', 'authority')):
        stage = result['stages'][name]
        assert stage['state'] == calls[index]['state']
        assert stage['state_sha256'] == digest(calls[index]['state'])
        assert stage['questions_sha256'] == digest(stage['questions'])
        assert stage['response_sha256'] == digest(stage['response'])
        assert stage['status'] == 'complete'
    assert result['thresholds_provisional'] and result['review_only']
    assert not result['review_required'] and not result['findings']
    assert not {'verdict', 'eligible_action', 'confidence'} & result.keys()
    assert 'No finding is not proof of safety.' in result['limitations']


def test_unexpected_provider_answer_fields_are_audited_and_rejected():
    def evaluate(state, questions):
        result = response(questions)
        for answer in result['answers'].values():
            answer['baseline_verdict'] = 'DO_NOT_FORWARD_PROVIDER_EXTRA'
        return result
    result = evaluate_action_review(evidence(), evaluate)
    assert 'DO_NOT_FORWARD_PROVIDER_EXTRA' in json.dumps(result['stages']['facts']['response'])
    assert result['status'] == 'error'
    assert result['stages']['facts']['status'] == 'error'
    assert 'authority' not in result['stages']


@pytest.mark.parametrize('key,threshold,kind', [
    ('software_execution_requested', .65, 'execution_authority_review'),
    ('wallet_control_requested', .65, 'wallet_authority_review'),
    ('transaction_callback', .80, 'callback_authority_review'),
])
def test_specific_action_and_coherence_boundaries(key, threshold, kind):
    assert not evaluate_with({key: threshold-.01}, coherent=.70)[0]['review_required']
    assert not evaluate_with({key: threshold}, coherent=.75)[0]['review_required']
    result, _ = evaluate_with({key: threshold}, coherent=.74)
    assert result['review_required']
    assert result['findings'][0]['kind'] == kind
    assert result['findings'][0]['action'] == 'review'
    assert result['findings'][0]['action_probability'] == threshold
    assert result['findings'][0]['coherent_probability'] == .74


@pytest.mark.parametrize('authority', ['contradicted', 'unresolved'])
def test_payment_requires_requested_payment_and_specific_authority_choice(authority):
    assert not evaluate_with({'payment_requested': .89}, coherent=.2, authority=authority)[0]['review_required']
    result, _ = evaluate_with({'payment_requested': .90}, coherent=.2, authority=authority)
    assert result['findings'][0]['kind'] == 'payment_authority_review'
    assert result['findings'][0]['authority_choice'] == authority
    assert not evaluate_with({'payment_requested': 1.}, coherent=.6)[0]['review_required']
    assert not evaluate_with({'payment_requested': 1.}, coherent=.2, authority='no_authority_claim')[0]['review_required']


def test_secrets_require_strong_contradicted_relationship():
    assert not evaluate_with({'secrets_or_login_requested': .79}, coherent=.1)[0]['review_required']
    assert not evaluate_with({'secrets_or_login_requested': .8}, coherent=.31)[0]['review_required']
    assert not evaluate_with({'secrets_or_login_requested': 1.}, coherent=.1, authority='unresolved')[0]['review_required']
    result, _ = evaluate_with({'secrets_or_login_requested': .8}, coherent=.3)
    assert result['findings'][0]['kind'] == 'secrets_authority_review'


def test_general_risk_and_confidence_alone_do_not_create_finding():
    def evaluate(state, questions):
        result = response(questions, {'current_request_risk': 1.}, coherent=.01)
        for answer in result['answers'].values():
            if 'confidence' in answer:
                answer['confidence'] = .01
        return result
    result = evaluate_action_review(evidence(), evaluate)
    assert result['status'] == 'complete' and not result['review_required']


@pytest.mark.parametrize('positive', [False, True])
def test_incomplete_input_is_explicit_even_when_no_action_finding(positive):
    original = evidence()
    original['quality']['parts_truncated'] = True
    result, calls = evaluate_with({'software_execution_requested': .9 if positive else .1},
        coherent=.2, original=original)
    assert len(calls) == 2
    assert result['status'] == 'incomplete'
    assert result['coverage']['upstream_gaps']
    assert result['review_required'] is positive
    assert result['stages']['authority']['state']['coverage']['material_content_complete'] is False


def test_projection_budget_omissions_do_not_become_negative_clear_result():
    original = evidence()
    original['content']['visible_text'] = 'Large body ' * 15000
    result, calls = evaluate_with(original=original)
    assert len(calls) == 2
    assert result['status'] == 'incomplete'
    assert result['coverage']['omissions']
    assert not result['review_required']


def test_unrepresentable_essential_evidence_records_incomplete_without_provider_call():
    original = evidence()
    original['inspection']['findings'] = [{'kind': 'critical', 'summary': 'x' * 30000}]
    result, calls = evaluate_with(original=original)
    assert not calls and not result['stages']
    assert result['status'] == 'incomplete'
    assert result['error'] == {'stage': 'projection', 'type': 'ActionEvidenceLimit'}


@pytest.mark.parametrize('failed_stage', ['facts', 'authority'])
def test_provider_errors_keep_partial_audit_and_sanitize_messages(failed_stage):
    def evaluate(state, questions):
        if (questions == FACT_QUESTIONS) == (failed_stage == 'facts'):
            raise JevError('DO_NOT_LEAK_SECRET_OR_RESPONSE')
        return response(questions)
    result = evaluate_action_review(evidence(), evaluate)
    assert result['status'] == 'error'
    assert result['error'] == {'stage': failed_stage, 'type': 'JevError'}
    assert 'DO_NOT_LEAK' not in json.dumps(result)
    assert result['stages'][failed_stage]['response'] is None
    assert result['stages'][failed_stage]['state_sha256']
    assert result['usage']['input_tokens'] == (0 if failed_stage == 'facts' else 100)
    assert not result['usage_complete'] and not result['review_required']


def test_invalid_typed_response_is_retained_without_advancing_stage():
    def evaluate(state, questions):
        result = response(questions)
        result['answers']['software_execution_requested']['noul'] = 2.
        return result
    result = evaluate_action_review(evidence(), evaluate)
    assert result['status'] == 'error'
    assert set(result['stages']) == {'facts'}
    assert result['stages']['facts']['response']['answers']['software_execution_requested']['noul'] == 2.
    assert result['usage'] == {'input_tokens': 100, 'output_tokens': 50}


def test_lease_failure_propagates_before_second_call():
    class LostLease(Exception):
        pass
    checks, calls = [], []
    def check():
        checks.append(True)
        # Initial check, facts-before, facts-after, authority-before.
        if len(checks) == 4:
            raise LostLease()
    def evaluate(state, questions):
        calls.append(questions)
        return response(questions)
    with pytest.raises(LostLease):
        evaluate_action_review(evidence(), evaluate, lease_check=check)
    assert calls == [FACT_QUESTIONS]


def test_client_mutation_cannot_rewrite_audit_inputs_or_global_questions():
    before = deepcopy(FACT_QUESTIONS)
    def evaluate(state, questions):
        result = response(questions)
        state['email']['subject'] = 'CHANGED_BY_CLIENT'
        questions.clear()
        return result
    result = evaluate_action_review(evidence(), evaluate)
    assert result['status'] == 'complete'
    assert FACT_QUESTIONS == before
    assert 'CHANGED_BY_CLIENT' not in json.dumps(result)
