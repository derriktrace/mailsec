"""Opt-in durable manual-edit checks on an isolated PostgreSQL schema."""
from concurrent.futures import ThreadPoolExecutor

from sqlalchemy import select, update
from test_manual_actions import GmailState
from test_postgres import pg_store as pg_store

from mailsec.accounts import accounts, initialize
from mailsec.config import Settings
from mailsec.gmail import MODIFY_SCOPE
from mailsec.mailbox_actions import actions, apply_pending_actions, list_actions, manual_actions
from mailsec.manual_actions import enqueue_manual_action, enqueue_manual_undo


def prepare(store):
    settings = Settings(authorized_mailboxes=['owner@example.test'], enforcement_mode='passive', notifications_enabled=False)
    initialize(store)
    with store.engine.begin() as db:
        db.execute(accounts.insert().values(mailbox='owner@example.test', encrypted_tokens='synthetic-token',
                                           scopes=MODIFY_SCOPE, connected_at='test'))
    mid = store.ingest(b'Synthetic manual PostgreSQL test', {'message': {'subject': 'PG test'}},
        provider='gmail', provider_message_id='test-provider-id', mailbox='owner@example.test')['id']
    return settings, mid, GmailState()


def test_postgres_manual_intent_dedup_concurrency_snapshot_and_undo(pg_store):
    settings, mid, gmail = prepare(pg_store)
    gmail.labels.add('review')
    original = set(gmail.labels)
    with ThreadPoolExecutor(max_workers=4) as pool:
        intents = list(pool.map(lambda _: enqueue_manual_action(settings, pg_store, mid, 'phishing', True, 'same-request'), range(8)))
    assert len({item['action_id'] for item in intents}) == 1
    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(lambda _: apply_pending_actions(settings, pg_store, client_factory=gmail.factory), range(3)))
    assert sum(item['applied'] for item in results) == 1 and len(gmail.modified) == 1
    with pg_store.engine.connect() as db:
        snapshot = db.execute(select(manual_actions.c.snapshot)).scalar_one()
    assert snapshot['original_inbox'] is True and 'review' in snapshot['original_labels']
    enqueue_manual_undo(settings, pg_store, intents[0]['action_id'])
    assert apply_pending_actions(settings, pg_store, client_factory=gmail.factory)['applied'] == 1
    assert gmail.labels == original
    assert all(item['analysis_run_id'] is None for item in list_actions(pg_store, mid))


def test_postgres_old_manual_retry_cannot_overwrite_newer_verdict(pg_store):
    settings, mid, gmail = prepare(pg_store)
    gmail.lose_response = True
    first = enqueue_manual_action(settings, pg_store, mid, 'phishing', False, 'first-request')
    assert apply_pending_actions(settings, pg_store, client_factory=gmail.factory)['retry'] == 1
    enqueue_manual_action(settings, pg_store, mid, 'clean', False, 'newer-request')
    assert apply_pending_actions(settings, pg_store, client_factory=gmail.factory)['applied'] == 1
    with pg_store.engine.begin() as db:
        db.execute(update(actions).where(actions.c.id == first['action_id']).values(status='retry', retry_at='2000-01-01'))
    assert apply_pending_actions(settings, pg_store, client_factory=gmail.factory)['cancelled'] == 1
    assert 'label-Clean' in gmail.labels and 'label-Phishing' not in gmail.labels
