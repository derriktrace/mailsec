"""Two-stage, review-only action/authority assessment with exact inference audit.

The caller supplies ``evaluate(state, questions)`` and owns the provider/model,
request retries and mailbox policy. Same-model judgments are fallible estimates,
not independent corroboration. No result here declares mail safe or authorizes
containment. Thresholds are provisional development rules, not calibrated rates.
"""
import hashlib
import json
from copy import deepcopy
from pathlib import Path

from .action_evidence import ActionEvidenceLimit, build_action_evidence, state_size
from .jev import validate_response
from .jev_evidence import MAX_REQUEST_BYTES, request_size
from .provider_consent import PrivacyConsentRequired

VERSION = 'action-review-v1'
THRESHOLDS_VERSION = 'action-review-thresholds-v1'
FACT_QUESTIONS = json.loads(Path(__file__).with_name('action_questions.json').read_text())
RELATIONSHIP_QUESTIONS = json.loads(Path(__file__).with_name('authority_questions.json').read_text())
THRESHOLDS = {'software_execution_requested': .65, 'wallet_control_requested': .65,
    'transaction_callback': .80, 'coherent_probability_below': .75,
    'payment_requested': .90, 'secrets_or_login_requested': .80,
    'secrets_contradicted_probability': .70}
_FACT_KEYS = ('software_execution_requested', 'wallet_control_requested', 'payment_requested',
              'transaction_callback', 'secrets_or_login_requested', 'claimed_authority')


def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, ensure_ascii=True).encode()).hexdigest()


def _observed_usage(response):
    usage = response.get('usage') if isinstance(response, dict) else None
    if not isinstance(usage, dict) or any(isinstance(usage.get(key), bool) or
            not isinstance(usage.get(key), int) or usage[key] < 0 for key in ('input_tokens', 'output_tokens')):
        return None
    return {key: usage[key] for key in ('input_tokens', 'output_tokens')}


def _action_observations(response):
    # Only the six validated action answers enter the next request. Provider
    # metadata/extra fields and any unrelated prior verdict never become facts.
    observations = {}
    for key in _FACT_KEYS:
        answer = response['answers'][key]
        fields = ('type', 'noul') if answer['type'] == 'noul' else ('type', 'choice', 'probabilities', 'confidence')
        observations[key] = {field: deepcopy(answer[field]) for field in fields}
    return {'provenance': 'Fallible same-model action estimates, not verified facts, fraud findings or independent corroboration.',
            'answers': observations}


def _findings(facts, relationships):
    authority = relationships['authority_relationship']
    coherent = authority['probabilities']['coherent']
    findings = []
    def add(kind, key, reason):
        findings.append({'kind': kind, 'action': 'review', 'reason': reason,
            'action_question': key, 'action_probability': facts[key]['noul'],
            'authority_choice': authority['choice'], 'coherent_probability': coherent,
            'evidence_refs': [f'action_review.stages.facts.response.answers.{key}',
                              'action_review.stages.authority.response.answers.authority_relationship'],
            'provenance': 'Composed model estimates; not independently confirmed deception.'})
    for key, kind, action in (
        ('software_execution_requested', 'execution_authority_review', 'installing or running software'),
        ('wallet_control_requested', 'wallet_authority_review', 'a wallet-control operation'),
        ('transaction_callback', 'callback_authority_review', 'a callback about a transaction or security issue'),
    ):
        if facts[key]['noul'] >= THRESHOLDS[key] and coherent < THRESHOLDS['coherent_probability_below']:
            add(kind, key, f'The message asks for {action}, and the authority assessment does not sufficiently establish a coherent sender/action relationship; review is required.')
    if (facts['payment_requested']['noul'] >= THRESHOLDS['payment_requested'] and
            authority['choice'] in ('contradicted', 'unresolved')):
        add('payment_authority_review', 'payment_requested',
            'A requested payment is paired with a contradicted or materially unresolved authority/destination relationship; review is required.')
    if (facts['secrets_or_login_requested']['noul'] >= THRESHOLDS['secrets_or_login_requested'] and
            authority['choice'] == 'contradicted' and
            authority['probabilities']['contradicted'] >= THRESHOLDS['secrets_contradicted_probability']):
        add('secrets_authority_review', 'secrets_or_login_requested',
            'A request for secrets, sensitive data or account authentication accompanies a strongly contradicted authority relationship; review is required.')
    return findings


def evaluate_action_review(evidence, evaluate, *, lease_check=lambda: None,
                           fact_questions=None, authority_questions=None):
    """Evaluate both stages and return audit plus optional review findings.

    ``status`` is complete, incomplete (coverage/budget), or error (provider/input
    failure). Incomplete views may still yield positive review findings; absence
    of a finding never proves safety. Lease-check failures deliberately propagate
    rather than becoming a completed/error analysis eligible for stale commit.
    """
    result = {'version': VERSION, 'thresholds_version': THRESHOLDS_VERSION,
        'thresholds': deepcopy(THRESHOLDS), 'thresholds_provisional': True,
        'review_only': True, 'status': 'error', 'review_required': False, 'findings': [],
        'stages': {}, 'evaluation_calls_attempted': 0,
        'usage': {'input_tokens': 0, 'output_tokens': 0}, 'usage_complete': False,
        'limitations': ['No finding is not proof of safety.',
            'Same-model action and authority estimates are not independent evidence.',
            'No general confidence threshold or automatic containment is applied.']}
    lease_check()
    try:
        state = build_action_evidence(evidence)
    except ActionEvidenceLimit:
        result.update(status='incomplete', coverage={'material_content_complete': False,
            'reason': 'Essential evidence could not fit the compact view; original evidence requires split analysis or review.'})
        result['error'] = {'stage': 'projection', 'type': 'ActionEvidenceLimit'}
        return result
    except (ValueError, TypeError, KeyError):
        result['error'] = {'stage': 'projection', 'type': 'InvalidEvidence'}
        return result
    result['coverage'] = deepcopy(state['coverage'])
    incomplete = (state['coverage'].get('material_content_complete') is not True or
        bool(state['coverage'].get('truncated') or state['coverage'].get('omissions') or state['coverage'].get('upstream_gaps')))

    def run_stage(name, view, questions):
        stage = {'state': deepcopy(view), 'questions': deepcopy(questions),
            'state_sha256': _digest(view), 'questions_sha256': _digest(questions),
            'state_bytes': state_size(view), 'status': 'not_started', 'response': None}
        result['stages'][name] = stage
        # The reserved model name is longer than the configured Jev model names;
        # the client still owns its final HTTP payload check. Never trim stage 2.
        if request_size(view, questions, 'reserved-model-version') > MAX_REQUEST_BYTES:
            stage.update(status='incomplete', error={'type': 'RequestBudgetExceeded'})
            result.update(status='incomplete', error={'stage': name, 'type': 'RequestBudgetExceeded'})
            return None
        lease_check()
        result['evaluation_calls_attempted'] += 1
        try:
            # Passing copies keeps the stored request exact even with a mutable
            # injected client. No credentials belong in this callable's result.
            response = evaluate(deepcopy(view), deepcopy(questions))
        except PrivacyConsentRequired:
            raise
        except Exception as exc:
            stage.update(status='error', error={'type': type(exc).__name__})
            result['error'] = {'stage': name, 'type': type(exc).__name__}
            lease_check()
            return None
        lease_check()
        stage['response'] = deepcopy(response)
        if response.get('provider_request'):
            submitted = response['provider_request']
            stage['local_input_state'] = stage['state']
            stage['local_input_questions'] = stage['questions']
            stage['state'] = deepcopy(submitted['state'])
            stage['questions'] = deepcopy(submitted['questions'])
            stage['state_sha256'] = _digest(stage['state'])
            stage['questions_sha256'] = _digest(stage['questions'])
            stage['state_bytes'] = state_size(stage['state'])
            stage['recipient_address_masking'] = deepcopy(submitted['recipient_address_masking'])
        stage['response_sha256'] = _digest(response)
        usage = _observed_usage(response)
        if usage is not None:
            stage['usage'] = usage
            for key in result['usage']:
                result['usage'][key] += usage[key]
        try:
            validate_response(response, questions)
        except Exception as exc:
            stage.update(status='error', error={'type': type(exc).__name__})
            result['error'] = {'stage': name, 'type': type(exc).__name__}
            return None
        stage['status'] = 'complete'
        return response

    facts = run_stage('facts', state, FACT_QUESTIONS if fact_questions is None else fact_questions)
    if facts is None:
        return result
    authority_state = {**deepcopy(state), 'action_observations': _action_observations(facts)}
    relationships = run_stage('authority', authority_state,
                              RELATIONSHIP_QUESTIONS if authority_questions is None else authority_questions)
    if relationships is None:
        return result
    result['status'] = 'incomplete' if incomplete else 'complete'
    result['usage_complete'] = True
    result['findings'] = _findings(facts['answers'], relationships['answers'])
    result['review_required'] = bool(result['findings'])
    result['audit_sha256'] = _digest({'stages': result['stages'], 'thresholds': result['thresholds'],
                                    'version': VERSION, 'thresholds_version': THRESHOLDS_VERSION})
    return result
