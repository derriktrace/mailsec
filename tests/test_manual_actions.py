"""Explicit Gmail edits use a durable intent; mocked Google state exercises recovery."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager

import httpx
import pytest
from sqlalchemy import func, select, update

from mailsec.accounts import accounts
from mailsec.accounts import initialize as initialize_accounts
from mailsec.api import create_app
from mailsec.config import Settings
from mailsec.gmail import MODIFY_SCOPE, READONLY_SCOPE, GmailError
from mailsec.mailbox_actions import (
    actions,
    apply_pending_actions,
    enqueue_action,
    list_actions,
    manual_actions,
)
from mailsec.manual_actions import enqueue_manual_action, enqueue_manual_undo, has_manual_override
from mailsec.storage import Store, messages, runs


class GmailState:
    def __init__(self):
        self.labels = {'INBOX', 'UNREAD', 'unrelated'}
        self.named = {'Mailsec/Review': 'review', 'Mailsec/Quarantine': 'quarantine'}
        self.modified = []
        self.lose_response = False

    def message_labels(self, mid):
        return list(self.labels)

    def ensure_label(self, name):
        return self.named.setdefault(name, 'label-' + name.rsplit('/', 1)[1])

    def list_labels(self):
        return [{'name': name, 'id': identifier} for name, identifier in self.named.items()]

    def modify_labels(self, mid, *, add, remove):
        self.modified.append((mid, add, remove))
        self.labels.update(add)
        self.labels.difference_update(remove)
        if self.lose_response:
            self.lose_response = False
            raise GmailError('Synthetic lost response after Gmail applied the change')

    @contextmanager
    def factory(self, settings, store, mailbox):
        yield self


@pytest.fixture
def setup(tmp_path):
    settings = Settings(database_url=f'sqlite:///{tmp_path}/manual.db', authorized_mailboxes=['owner@example.test'],
                        app_token='test-console', enforcement_mode='passive', notifications_enabled=False)
    store = Store(settings.database_url)
    initialize_accounts(store)
    with store.engine.begin() as db:
        db.execute(accounts.insert().values(mailbox='owner@example.test', encrypted_tokens='test-only-token',
                                           scopes=MODIFY_SCOPE, connected_at='test'))
    mid = store.ingest(b'Synthetic pending email', {'message': {'subject': 'Pending test'}},
                       provider='gmail', provider_message_id='gmail-test-id', mailbox='owner@example.test')['id']
    return settings, store, mid, GmailState()


def label(setup, verdict='phishing', move=False, key='request-one'):
    settings, store, mid, _ = setup
    return enqueue_manual_action(settings, store, mid, verdict, move, key)


def apply(setup):
    settings, store, _, gmail = setup
    return apply_pending_actions(settings, store, client_factory=gmail.factory)


def retry_now(store):
    with store.engine.begin() as db:
        db.execute(update(actions).where(actions.c.status == 'retry').values(retry_at='2000-01-01'))


@pytest.mark.parametrize('verdict', ['clean', 'spam', 'suspicious', 'phishing'])
def test_explicit_label_in_passive_mode_needs_no_analysis_and_preserves_other_labels(setup, verdict):
    _, store, mid, gmail = setup
    old = gmail.ensure_label('Mailsec/Suspicious')
    gmail.labels.update({old, 'review', 'quarantine'})
    result = label(setup, verdict)
    assert result['status'] == 'pending' and not gmail.modified
    assert apply(setup)['applied'] == 1
    assert gmail.labels == {'INBOX', 'UNREAD', 'unrelated', 'quarantine', 'label-' + verdict.title()}
    assert store.get_message(mid)['status'] == 'pending'  # Gmail edit is no fabricated model result.
    with store.engine.connect() as db:
        assert db.execute(select(func.count()).select_from(runs)).scalar_one() == 0
    row = list_actions(store, mid)[0]
    assert row['analysis_run_id'] is None and row['manual']['can_undo']
    assert row['manual']['label'] == 'Mailsec/' + verdict.title()


@pytest.mark.parametrize('inbox', [True, False])
@pytest.mark.parametrize('already_labeled', [True, False])
def test_move_and_undo_restore_only_recorded_labels_and_original_inbox(setup, inbox, already_labeled):
    settings, store, mid, gmail = setup
    if not inbox:
        gmail.labels.remove('INBOX')
    previous = gmail.ensure_label('Mailsec/Spam' if already_labeled else 'Mailsec/Suspicious')
    gmail.labels.update({previous, 'review'})
    original = set(gmail.labels)
    result = label(setup, 'spam', True)
    assert apply(setup)['applied'] == 1
    assert 'INBOX' not in gmail.labels and 'label-Spam' in gmail.labels
    undo = enqueue_manual_undo(settings, store, result['action_id'])
    assert enqueue_manual_undo(settings, store, result['action_id']) == undo
    assert apply(setup)['applied'] == 1
    assert gmail.labels == original
    assert not next(r for r in list_actions(store, mid) if r['id'] == result['action_id'])['manual']['can_undo']


def test_lost_remote_response_keeps_original_snapshot_and_retries_without_duplicate_edit(setup):
    settings, store, _, gmail = setup
    original = set(gmail.labels)
    gmail.lose_response = True
    result = label(setup, move=True)
    assert apply(setup)['retry'] == 1 and 'INBOX' not in gmail.labels
    with store.engine.connect() as db:
        snapshot = db.execute(select(manual_actions.c.snapshot)).scalar_one()
    assert snapshot['original_inbox'] is True
    retry_now(store)
    assert apply(setup)['applied'] == 1 and len(gmail.modified) == 1
    enqueue_manual_undo(settings, store, result['action_id'])
    gmail.lose_response = True
    assert apply(setup)['retry'] == 1 and gmail.labels == original
    retry_now(store)
    assert apply(setup)['applied'] == 1 and len(gmail.modified) == 2


def test_undo_uncertain_apply_cancels_retry_and_restores_state(setup):
    settings, store, _, gmail = setup
    original = set(gmail.labels)
    gmail.lose_response = True
    result = label(setup, move=True)
    assert apply(setup)['retry'] == 1
    enqueue_manual_undo(settings, store, result['action_id'])
    assert apply(setup)['applied'] == 1 and gmail.labels == original
    with store.engine.connect() as db:
        assert db.execute(select(actions.c.status).where(actions.c.id == result['action_id'])).scalar_one() == 'cancelled'


def test_idempotent_request_has_one_durable_intent_and_rejects_conflicting_payload(setup):
    settings, store, mid, _ = setup
    with ThreadPoolExecutor(max_workers=4) as pool:
        result = list(pool.map(lambda _: label(setup), range(8)))
    assert len({r['action_id'] for r in result}) == 1
    assert len(list_actions(store, mid)) == 1
    with pytest.raises(ValueError, match='different Gmail change'):
        enqueue_manual_action(settings, store, mid, 'clean', False, 'request-one')


@pytest.mark.parametrize('restriction', ['readonly', 'disconnected', 'not_allowed', 'evaluation'])
def test_permission_denied_before_enqueue_and_after_enqueue(setup, restriction):
    settings, store, mid, gmail = setup
    label(setup)
    if restriction in {'readonly', 'disconnected'}:
        with store.engine.begin() as db:
            values = {'scopes': READONLY_SCOPE} if restriction == 'readonly' else {'encrypted_tokens': ''}
            db.execute(update(accounts).values(**values))
    elif restriction == 'not_allowed':
        settings.authorized_mailboxes = []
    else:
        settings.evaluation_mode = True
    with pytest.raises(ValueError):
        label(setup, key='request-two')
    assert apply(setup)['cancelled'] == 1
    assert not gmail.modified and len(list_actions(store, mid)) == 1


def test_undo_refuses_to_overwrite_newer_mailbox_action_or_external_verdict_edit(setup):
    settings, store, _, gmail = setup
    first = label(setup)
    apply(setup)
    extra = gmail.ensure_label('Mailsec/Clean')
    gmail.labels.add(extra)
    undo = enqueue_manual_undo(settings, store, first['action_id'])
    assert apply(setup)['cancelled'] == 1
    assert extra in gmail.labels
    assert next(r for r in list_actions(store) if r['id'] == undo['action_id'])['status'] == 'cancelled'


def test_undo_newer_action_conflict_is_rejected_before_enqueue(setup):
    settings, store, _, _ = setup
    first = label(setup)
    apply(setup)
    label(setup, 'spam', key='request-two')
    with pytest.raises(ValueError, match='newer mailbox action'):
        enqueue_manual_undo(settings, store, first['action_id'])


def test_stale_uncertain_label_cannot_overwrite_a_newer_operator_choice(setup):
    _, store, _, gmail = setup
    gmail.lose_response = True
    first = label(setup, 'phishing')
    assert apply(setup)['retry'] == 1
    label(setup, 'clean', key='newer-clean')
    assert apply(setup)['applied'] == 1
    assert 'label-Clean' in gmail.labels and 'label-Phishing' not in gmail.labels
    # Even a recovered in-flight worker that writes its older retry state must
    # be rejected by the final eligibility guard, not only queue cancellation.
    with store.engine.begin() as db:
        db.execute(update(actions).where(actions.c.id == first['action_id']).values(status='retry', retry_at='2000-01-01'))
    assert apply(setup)['cancelled'] == 1
    assert 'label-Clean' in gmail.labels and 'label-Phishing' not in gmail.labels


def test_manual_label_holds_automatic_organization_until_undo_without_model_override(setup):
    settings, store, mid, gmail = setup
    settings.enforcement_mode = 'auto_quarantine'
    with store.engine.begin() as db:
        db.execute(update(messages).where(messages.c.id == mid).values(status='complete'))
        db.execute(runs.insert().values(id='auto-run', message_id=mid, status='complete',
            created_at='2026-01-01', completed_at='2026-01-01', policy={'eligible_action': 'quarantine'}))
    automatic = enqueue_action(store, 'owner@example.test', 'gmail-test-id', 'quarantine', 'auto-run', mid)
    manual = label(setup, 'clean')
    assert has_manual_override(store, mid)
    assert enqueue_action(store, 'owner@example.test', 'gmail-test-id', 'quarantine', 'auto-run', mid) is None
    assert apply(setup)['applied'] == 1 and 'quarantine' not in gmail.labels
    assert next(r for r in list_actions(store) if r['id'] == automatic)['status'] == 'cancelled'
    assert store.get_analyst_override(mid) is None
    enqueue_manual_undo(settings, store, manual['action_id'])
    assert apply(setup)['applied'] == 1
    assert not has_manual_override(store, mid)


def test_undo_blocked_by_revoked_permission_can_be_explicitly_retried_after_reconnect(setup):
    settings, store, mid, gmail = setup
    original = set(gmail.labels)
    manual = label(setup, move=True)
    apply(setup)
    undo = enqueue_manual_undo(settings, store, manual['action_id'])
    with store.engine.begin() as db:
        db.execute(update(accounts).values(scopes=READONLY_SCOPE))
    assert apply(setup)['cancelled'] == 1
    assert next(r for r in list_actions(store, mid) if r['id'] == manual['action_id'])['manual']['can_undo']
    with store.engine.begin() as db:
        db.execute(update(accounts).values(scopes=MODIFY_SCOPE))
    retried = enqueue_manual_undo(settings, store, manual['action_id'])
    assert retried['action_id'] == undo['action_id'] and retried['status'] == 'pending'
    assert apply(setup)['applied'] == 1 and gmail.labels == original


def test_scope_rechecked_after_label_reads_before_message_mutation(setup):
    _, store, _, gmail = setup
    label(setup, move=True)
    original = gmail.list_labels
    def revoke_and_list():
        with store.engine.begin() as db:
            db.execute(update(accounts).values(scopes=READONLY_SCOPE))
        return original()
    gmail.list_labels = revoke_and_list
    assert apply(setup)['cancelled'] == 1
    assert not gmail.modified and 'INBOX' in gmail.labels


def test_concurrent_workers_apply_one_manual_intent_once(setup):
    _, _, _, gmail = setup
    label(setup, move=True)
    with ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(lambda _: apply(setup), range(8)))
    assert sum(r['applied'] for r in results) == 1 and len(gmail.modified) == 1


@pytest.mark.parametrize('location', ['TRASH', 'SPAM', 'quarantine'])
def test_undo_does_not_restore_inbox_over_later_external_relocation(setup, location):
    settings, store, _, gmail = setup
    action = label(setup, move=True)
    apply(setup)
    gmail.labels.add(location)
    enqueue_manual_undo(settings, store, action['action_id'])
    assert apply(setup)['cancelled'] == 1
    assert location in gmail.labels and 'INBOX' not in gmail.labels


def test_analyst_override_prevents_automatic_gmail_action_even_on_later_model_result(setup):
    settings, store, mid, gmail = setup
    settings.enforcement_mode = 'auto_quarantine'
    with store.engine.begin() as db:
        db.execute(update(messages).where(messages.c.id == mid).values(status='complete'))
        db.execute(runs.insert().values(id='original-run', message_id=mid, status='complete',
            created_at='2026-01-01', completed_at='2026-01-01', policy={'eligible_action': 'quarantine'},
            output={'answers': {'verdict': {'choice': 'phishing'}}}))
    enqueue_action(store, 'owner@example.test', 'gmail-test-id', 'quarantine', 'original-run', mid)
    store.add_feedback(mid, 'clean', 'Known expected message', 'tester', apply_verdict=True)
    assert list_actions(store, mid)[0]['status'] == 'cancelled'
    # Simulate recovery of a request already in flight when the correction was
    # saved: the final provider-write guard must independently block it too.
    with store.engine.begin() as db:
        db.execute(update(actions).where(actions.c.action == 'quarantine').values(status='pending'))
    assert apply(setup)['cancelled'] == 1 and not gmail.modified
    label(setup, 'clean')
    assert apply(setup)['applied'] == 1 and 'label-Clean' in gmail.labels


def test_api_requires_auth_manage_access_and_explicit_supported_label(setup):
    settings, store, mid, _ = setup
    app = create_app(settings)
    body = {'verdict': 'phishing', 'move_to_label': True, 'idempotency_key': 'request-one'}
    async def check():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url='http://testserver') as client:
            path = f'/api/messages/{mid}/gmail-label'
            assert (await client.post(path, json=body)).status_code == 401
            client.headers['Authorization'] = 'Bearer test-console'
            response = await client.post(path, json=body)
            assert response.status_code == 202 and response.json()['label'] == 'Mailsec/Phishing'
            assert (await client.post(path, json={**body, 'verdict': 'arbitrary'})).status_code == 422
            with store.engine.begin() as db:
                db.execute(update(accounts).values(scopes=READONLY_SCOPE))
            denied = await client.post(path, json={**body, 'idempotency_key': 'new-request'})
            assert denied.status_code == 409 and 'monitoring only' in denied.json()['detail']
            protection = await client.patch('/api/protection', json={'mode': 'flag_only'})
            assert protection.status_code == 200
            assert any('monitoring only' in problem for problem in protection.json()['blockers'])
    asyncio.run(check())


def test_manual_label_and_undo_use_real_gmail_http_contract_with_no_cross_account_changes(setup, monkeypatch):
    import json

    from mailsec.gmail import GmailClient
    settings, store, mid, remote = setup
    original = set(remote.labels)
    calls = []
    monkeypatch.setattr('mailsec.gmail._quota_pacer.wait', lambda *args: None)

    class Credentials:
        def before_request(self, request, method, url, headers):
            headers['Authorization'] = 'Bearer synthetic-owner-only-token'

    def handler(request):
        assert request.url.host == 'gmail.googleapis.com'
        assert request.headers['authorization'] == 'Bearer synthetic-owner-only-token'
        path = request.url.path
        calls.append((request.method, path))
        if path.endswith('/labels'):
            if request.method == 'GET':
                return httpx.Response(200, json={'labels': remote.list_labels()})
            name = json.loads(request.content)['name']
            assert name == 'Mailsec/Phishing'
            return httpx.Response(200, json={'id': remote.ensure_label(name)})
        assert path in {'/gmail/v1/users/me/messages/gmail-test-id',
                        '/gmail/v1/users/me/messages/gmail-test-id/modify'}
        if request.method == 'POST':
            payload = json.loads(request.content)
            remote.modify_labels('gmail-test-id', add=payload['addLabelIds'], remove=payload['removeLabelIds'])
        return httpx.Response(200, json={'id': 'gmail-test-id', 'labelIds': sorted(remote.labels)})

    @contextmanager
    def factory(_settings, _store, mailbox):
        assert mailbox == 'owner@example.test'
        with GmailClient('', mailbox, scopes=[MODIFY_SCOPE], credentials=Credentials(),
                         transport=httpx.MockTransport(handler)) as client:
            yield client

    queued = label(setup, move=True)
    assert apply_pending_actions(settings, store, client_factory=factory)['applied'] == 1
    assert remote.labels == {'UNREAD', 'unrelated', 'label-Phishing'}
    enqueue_manual_undo(settings, store, queued['action_id'])
    assert apply_pending_actions(settings, store, client_factory=factory)['applied'] == 1
    assert remote.labels == original
    assert len(remote.modified) == 2
    assert sum(method == 'POST' and path.endswith('/labels') for method, path in calls) == 1
    assert store.get_message(mid)['run_count'] == 0
