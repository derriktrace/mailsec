"""Human corrections change the review queue without rewriting model history."""
import asyncio
import copy

import httpx
import pytest

from mailsec.api import create_app
from mailsec.config import Settings
from mailsec.parsing import parse_email
from mailsec.pipeline import Pipeline
from mailsec.storage import Store, now

RAW = b"From: service@example.com\r\nSubject: Account notice\r\n\r\nReview your account."


@pytest.fixture
def store(tmp_path):
    value = Store(f"sqlite:///{tmp_path / 'review.db'}")
    yield value
    value.engine.dispose()


def completed(store, verdict='suspicious', provider_id='one'):
    mid = store.ingest(RAW, parse_email(RAW), provider='gmail', mailbox='owner@example.test',
                       provider_message_id=provider_id, received_at=now())['id']
    job = store.claim()
    rid = store.finish(job, {}, {'answers': {'verdict': {'choice': verdict, 'confidence': .71}}},
                       {'verdict': verdict}, {}, {}, now())
    return mid, rid


@pytest.mark.parametrize('verdict', ['clean', 'spam', 'suspicious', 'phishing'])
def test_correction_changes_list_filter_counts_and_preserves_original(store, verdict):
    mid, rid = completed(store)
    original = copy.deepcopy(store.detail(mid)['runs'])
    review = store.add_feedback(mid, verdict, 'Verified sender and destination.', 'owner', rid,
                                apply_verdict=True)
    message = store.detail(mid)['message']
    assert message['verdict'] == verdict
    assert message['system_verdict'] == 'suspicious'
    assert message['confidence'] is None and message['system_confidence'] == .71
    assert message['analyst_override']['review_id'] == review['id']
    assert store.list_messages(verdict=verdict)['total'] == 1
    assert store.status()['counts'][verdict] == 1
    overview = store.overview()
    assert overview['verdict_counts'][verdict] == 1
    assert overview['daily'][-1][verdict] == 1
    assert overview['review_needed'] == 0
    assert store.detail(mid)['runs'] == original
    # Analysis input and stored output still use the original system decision.
    assert store.get_message(mid)['verdict'] == 'suspicious'
    assert store.get_analyst_override(mid)['verdict'] == verdict
    if verdict != 'suspicious':
        assert store.list_messages(verdict='suspicious')['total'] == 0
        assert store.status()['counts']['suspicious'] == 0
    assert store.evaluation()['confusion_matrix'][verdict]['suspicious'] == 1


def test_existing_feedback_is_not_silently_promoted_to_an_override(store):
    mid, rid = completed(store)
    store.add_feedback(mid, 'clean', 'Prior review.', 'owner', rid)
    assert store.detail(mid)['message']['verdict'] == 'suspicious'
    assert store.get_analyst_override(mid) is None


def test_latest_correction_wins_and_replay_cannot_erase_it(store):
    mid, rid = completed(store)
    store.add_feedback(mid, 'clean', 'First review.', 'owner', rid, apply_verdict=True)
    last = store.add_feedback(mid, 'spam', 'Marketing was unsolicited.', 'owner', rid, apply_verdict=True)
    store.enqueue(mid)
    job = store.claim()
    store.finish(job, {}, {'answers': {'verdict': {'choice': 'phishing', 'confidence': .8}}},
                 {'verdict': 'phishing'}, {}, {}, now())
    detail = store.detail(mid)
    assert detail['message']['verdict'] == 'spam'
    assert detail['message']['system_verdict'] == 'phishing'
    assert detail['message']['analyst_override']['review_id'] == last['id']
    assert len(detail['feedback']) == len(detail['runs']) == 2
    assert store.list_messages(verdict='spam')['total'] == 1


def test_override_does_not_hide_failed_scan_or_forge_model_confidence(store):
    mid, rid = completed(store)
    store.add_feedback(mid, 'clean', 'Reviewed.', 'owner', rid, apply_verdict=True)
    store.enqueue(mid)
    store.finish(store.claim(), {}, None, {}, {}, {}, now(), error='Provider unavailable')
    message = store.detail(mid)['message']
    assert message['verdict'] == 'clean' and message['status'] == 'error'
    assert message['confidence'] is None and message['system_verdict'] is None
    assert store.status()['counts']['error'] == 1
    assert store.status()['counts']['clean'] == 0


def test_invalid_or_wrong_message_review_is_atomic(store):
    mid, _ = completed(store)
    _, wrong = completed(store, provider_id='two')
    with pytest.raises(ValueError):
        store.add_feedback(mid, 'clean', 'Wrong run.', 'owner', wrong, apply_verdict=True)
    with pytest.raises(ValueError):
        store.add_feedback(mid, 'invented', '', 'owner', apply_verdict=True)
    assert not store.detail(mid)['feedback']
    assert store.get_analyst_override(mid) is None


def test_correction_cancels_queued_automatic_actions_in_same_transaction(store):
    from mailsec.mailbox_actions import enqueue_action, list_actions
    mid, rid = completed(store)
    action = enqueue_action(store, 'owner@example.test', 'one', 'flag', rid, message_id=mid)
    store.add_feedback(mid, 'clean', 'Expected sender.', 'owner', rid, apply_verdict=True)
    saved = list_actions(store, message_id=mid)
    assert saved[0]['id'] == action and saved[0]['status'] == 'cancelled'
    assert enqueue_action(store, 'owner@example.test', 'one', 'quarantine', rid, message_id=mid) is None


def test_api_correction_is_explicit_and_does_not_enqueue_mailbox_changes(tmp_path):
    settings = Settings(database_url=f"sqlite:///{tmp_path / 'api.db'}")
    pipeline = Pipeline(settings)
    mid, rid = completed(pipeline.store)
    async def request():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app(settings, pipeline)),
                                     base_url='http://testserver') as client:
            response = await client.post(f'/api/messages/{mid}/feedback', json={
                'verdict': 'clean', 'reason': 'Verified.', 'run_id': rid, 'apply_verdict': True})
            detail = await client.get(f'/api/messages/{mid}')
            return response, detail
    try:
        response, detail = asyncio.run(request())
        assert response.status_code == 201 and response.json()['applied_to_console']
        assert detail.json()['message']['verdict'] == 'clean'
        assert detail.json()['actions'] == []
    finally:
        pipeline.store.engine.dispose()
