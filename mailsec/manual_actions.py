"""Explicit operator Gmail labels, with durable before-state and reversible intent.

An operator label does not invent a model run or silently change its verdict.
Only application-owned verdict/review labels and optional Inbox membership change.
"""
from __future__ import annotations

import hashlib
import re
import uuid

from sqlalchemy import and_, or_, select, update
from sqlalchemy.exc import IntegrityError

from .accounts import allowed_mailboxes, connected_mailboxes, oauth_write_restriction
from .gmail import GmailError
from .mailbox_actions import (
    _eligibility,
    _now,
    _set_action,
    _target_key,
    actions,
    initialize,
    manual_actions,
    targets,
)

VERDICT_LABELS = {value: 'Mailsec/' + value.title() for value in ('clean', 'spam', 'suspicious', 'phishing')}
REVIEWED_LABELS = {*VERDICT_LABELS.values(), 'Mailsec/Review'}


def require_manual_access(settings, store, message):
    if getattr(settings, 'evaluation_mode', False):
        raise ValueError('Evaluation workspaces cannot change Gmail')
    if not message or message['provider'] != 'gmail':
        raise ValueError('Select a message imported from a connected Gmail account')
    mailbox = message['mailbox']
    if mailbox not in allowed_mailboxes(settings, store):
        raise ValueError('Mailbox is not explicitly authorized')
    if mailbox not in connected_mailboxes(settings, store):
        raise ValueError('Mailbox is disconnected; reconnect with Manage protection access')
    restriction = oauth_write_restriction(store, mailbox)
    if restriction:
        raise ValueError(restriction)


def _ensure_target(store, target):
    try:
        with store.engine.begin() as db:
            if not db.execute(select(targets.c.target_key).where(targets.c.target_key == target)).first():
                db.execute(targets.insert().values(target_key=target, quarantine_active=False))
    except IntegrityError:
        pass


def _response(action, detail):
    return {'action_id': action['id'], 'status': action['status'], 'verdict': detail['verdict'],
            'label': VERDICT_LABELS[detail['verdict']], 'move_to_label': detail['move_to_label']}


def has_manual_override(store, mid):
    """Keep automatic organization from fighting an outstanding operator intent."""
    initialize(store)
    with store.engine.connect() as db:
        latest = db.execute(select(actions.c.id, actions.c.status, manual_actions.c.snapshot)
            .join(manual_actions, manual_actions.c.action_id == actions.c.id)
            .where(actions.c.message_id == mid, actions.c.action == 'manual_label')
            .order_by(actions.c.created_at.desc(), actions.c.id.desc()).limit(1)).mappings().first()
        if not latest:
            return False
        undone = db.execute(select(actions.c.id).join(manual_actions, manual_actions.c.action_id == actions.c.id)
            .where(manual_actions.c.undo_of == latest['id'], actions.c.status == 'applied')).first()
        if undone:
            return False
        return latest['status'] in {'pending', 'processing', 'retry', 'applied'} or bool(latest['snapshot'])


def enqueue_manual_action(settings, store, mid, verdict, move_to_label, idempotency_key):
    initialize(store)
    if verdict not in VERDICT_LABELS or type(move_to_label) is not bool:
        raise ValueError('Choose a supported verdict label and move option')
    if not isinstance(idempotency_key, str) or not re.fullmatch(r'[A-Za-z0-9_-]{8,80}', idempotency_key):
        raise ValueError('A unique request identifier is required')
    message = store.get_message(mid)
    require_manual_access(settings, store, message)
    target = _target_key(message['mailbox'], message['provider_message_id'])
    _ensure_target(store, target)
    key = hashlib.sha256(('manual-label\0' + mid + '\0' + idempotency_key).encode()).hexdigest()
    identifier, stamp = uuid.uuid4().hex, _now()
    detail = {'action_id': identifier, 'verdict': verdict, 'move_to_label': move_to_label,
              'undo_of': None, 'snapshot': None, 'actor': 'authenticated_console'}
    action = {'id': identifier, 'dedup_key': key, 'target_key': target, 'message_id': mid,
              'mailbox': message['mailbox'], 'provider_message_id': message['provider_message_id'],
              'action': 'manual_label', 'analysis_run_id': None, 'status': 'pending', 'attempts': 0,
              'created_at': stamp, 'updated_at': stamp}
    try:
        with store.engine.begin() as db:
            db.execute(actions.insert().values(**action))
            db.execute(manual_actions.insert().values(**detail))
            # New explicit intent supersedes older queued organization. Keep
            # attempted actions/snapshots in the ledger for honest reconciliation.
            db.execute(update(actions).where(actions.c.target_key == target, actions.c.id != identifier,
                actions.c.action.in_(['flag', 'quarantine', 'clear_review', 'manual_label']),
                or_(actions.c.created_at < stamp,
                    and_(actions.c.created_at == stamp, actions.c.id < identifier)),
                actions.c.status.in_(['pending', 'retry'])).values(status='cancelled', updated_at=stamp,
                    error='A newer operator Gmail label request superseded this action'))
    except IntegrityError:
        with store.engine.connect() as db:
            previous = db.execute(select(actions).where(actions.c.dedup_key == key)).mappings().one()
            previous_detail = db.execute(select(manual_actions).where(manual_actions.c.action_id == previous['id'])).mappings().one()
        if previous_detail['verdict'] != verdict or previous_detail['move_to_label'] != move_to_label:
            raise ValueError('Request identifier was already used for a different Gmail change') from None
        return _response(previous, previous_detail)
    return _response(action, detail)


def _later_change(db, original, exclude_id=None):
    """An old undo must never overwrite a newer queued or attempted mailbox edit."""
    query = select(actions.c.id).where(actions.c.target_key == original['target_key'],
        actions.c.id != original['id'],
        or_(actions.c.created_at > original['created_at'],
            and_(actions.c.created_at == original['created_at'], actions.c.id > original['id'])),
        or_(actions.c.status.in_(['pending', 'processing', 'retry', 'applied']), actions.c.attempts > 0))
    if exclude_id:
        query = query.where(actions.c.id != exclude_id)
    return db.execute(query.limit(1)).first() is not None


def enqueue_manual_undo(settings, store, action_id):
    initialize(store)
    with store.engine.connect() as db:
        original = db.execute(select(actions).where(actions.c.id == action_id,
            actions.c.action == 'manual_label')).mappings().first()
        detail = db.execute(select(manual_actions).where(manual_actions.c.action_id == action_id)).mappings().first()
    if not original or not detail:
        raise ValueError('Manual Gmail label action not found')
    require_manual_access(settings, store, store.get_message(original['message_id']))
    key = hashlib.sha256(('manual-undo\0' + action_id).encode()).hexdigest()
    with store.engine.connect() as db:
        existing = db.execute(select(actions).where(actions.c.dedup_key == key)).mappings().first()
        if existing and existing['status'] not in {'cancelled', 'failed'}:
            return {'action_id': existing['id'], 'status': existing['status']}
        if not detail['snapshot'] or original['attempts'] < 1:
            raise ValueError('No attempted Gmail label change with a saved original state is available to undo')
        if _later_change(db, original, existing['id'] if existing else None):
            raise ValueError('A newer mailbox action exists; undo would overwrite a later change')
    if existing:
        # A fresh operator click can retry an undo that was previously blocked
        # by revoked consent or a transient failure; retain its attempt count.
        with store.engine.begin() as db:
            db.execute(update(actions).where(actions.c.id == existing['id'],
                actions.c.status.in_(['cancelled', 'failed'])).values(status='pending', updated_at=_now(), retry_at=None))
        return {'action_id': existing['id'], 'status': 'pending'}
    identifier, stamp = uuid.uuid4().hex, _now()
    try:
        with store.engine.begin() as db:
            db.execute(actions.insert().values(id=identifier, dedup_key=key, target_key=original['target_key'],
                message_id=original['message_id'], mailbox=original['mailbox'], provider_message_id=original['provider_message_id'],
                action='manual_undo', analysis_run_id=None, status='pending', attempts=0, created_at=stamp, updated_at=stamp))
            db.execute(manual_actions.insert().values(action_id=identifier, verdict=detail['verdict'],
                move_to_label=detail['move_to_label'], undo_of=action_id, snapshot=None, actor='authenticated_console'))
            db.execute(update(actions).where(actions.c.id == action_id,
                actions.c.status.in_(['pending', 'retry'])).values(status='cancelled', updated_at=stamp,
                    error='Operator undo superseded this label request'))
    except IntegrityError:
        with store.engine.connect() as db:
            existing = db.execute(select(actions).where(actions.c.dedup_key == key)).mappings().one()
        return {'action_id': existing['id'], 'status': existing['status']}
    return {'action_id': identifier, 'status': 'pending'}


def manual_eligibility(settings, store, action):
    if getattr(settings, 'evaluation_mode', False):
        return 'Evaluation workspaces cannot change Gmail'
    with store.engine.connect() as db:
        detail = db.execute(select(manual_actions).where(manual_actions.c.action_id == action['id'])).mappings().first()
        if not detail:
            return 'Manual Gmail intent is missing'
        if action['action'] == 'manual_label':
            undo = db.execute(select(manual_actions.c.action_id).where(manual_actions.c.undo_of == action['id'])).first()
            if undo:
                return 'Operator undo superseded this label request'
            if _later_change(db, action):
                return 'A newer mailbox action superseded this earlier label request'
            return None
        original = db.execute(select(actions).where(actions.c.id == detail['undo_of'])).mappings().first()
        if not original or _later_change(db, original, action['id']):
            return 'A newer mailbox action prevents safely undoing this earlier change'
    return None


def describe_manual_actions(store, rows):
    if not rows:
        return rows
    with store.engine.connect() as db:
        details = {r['action_id']: dict(r) for r in db.execute(select(manual_actions).where(
            manual_actions.c.action_id.in_([r['id'] for r in rows]))).mappings()}
        for row in rows:
            detail = details.get(row['id'])
            if not detail:
                continue
            undo = db.execute(select(actions.c.id, actions.c.status)
                .join(manual_actions, manual_actions.c.action_id == actions.c.id)
                .where(manual_actions.c.undo_of == row['id'])).mappings().first()
            # The public action projection deliberately omits target_key; fetch
            # the original privately for the conservative ordering guard.
            original = db.execute(select(actions).where(actions.c.id == row['id'])).mappings().one()
            row['manual'] = {'verdict': detail['verdict'], 'label': VERDICT_LABELS[detail['verdict']],
                'move_to_label': detail['move_to_label'], 'undo_of': detail['undo_of'],
                'can_undo': bool(row['action'] == 'manual_label' and detail['snapshot'] and row['attempts'] > 0
                                 and (not undo or undo['status'] in {'cancelled', 'failed'})
                                 and not _later_change(db, original, undo['id'] if undo else None))}
    return rows


def apply_manual_action(settings, store, action, client):
    with store.engine.connect() as db:
        detail = dict(db.execute(select(manual_actions).where(manual_actions.c.action_id == action['id'])).mappings().one())
    current = set(client.message_labels(action['provider_message_id']))
    if current & {'SENT', 'DRAFT'}:
        _set_action(store, action, 'cancelled', error='Outbound or draft messages are not eligible')
        return 'cancelled'
    if action['action'] == 'manual_label':
        snapshot = detail['snapshot']
        if snapshot is None:
            selected = client.ensure_label(VERDICT_LABELS[detail['verdict']])
            labels = client.list_labels()
            owned = {label['id'] for label in labels if label['name'] in REVIEWED_LABELS}
            quarantine = {label['id'] for label in labels if label['name'] == 'Mailsec/Quarantine'}
            owned.add(selected)
            snapshot = {'affected_labels': sorted(owned), 'original_labels': sorted(current & owned),
                        'selected_label': selected, 'original_inbox': 'INBOX' in current,
                        'original_system_locations': sorted(current & {'TRASH', 'SPAM'}),
                        'original_quarantined': bool(current & quarantine),
                        'move_to_label': detail['move_to_label']}
            with store.engine.begin() as db:
                db.execute(update(manual_actions).where(manual_actions.c.action_id == action['id'],
                    manual_actions.c.snapshot.is_(None)).values(snapshot=snapshot))
        add = {snapshot['selected_label']}
        remove = set(snapshot['affected_labels']) - add
        if snapshot['move_to_label']:
            remove.add('INBOX')
    else:
        with store.engine.connect() as db:
            snapshot = db.execute(select(manual_actions.c.snapshot).where(
                manual_actions.c.action_id == detail['undo_of'])).scalar_one()
        if not snapshot:
            _set_action(store, action, 'cancelled', error='Original Gmail label state is unavailable')
            return 'cancelled'
        owned = set(snapshot['affected_labels'])
        labels = client.list_labels()
        current_owned = {label['id'] for label in labels if label['name'] in REVIEWED_LABELS}
        quarantine = {label['id'] for label in labels if label['name'] == 'Mailsec/Quarantine'}
        # A retry may already have restored the original state. Accept exactly
        # either recorded state, never clobber an unrelated later label edit.
        observed = current & (owned | current_owned)
        if observed not in ({snapshot['selected_label']}, set(snapshot['original_labels'])):
            _set_action(store, action, 'cancelled', error='Gmail labels changed since this action; refusing to overwrite them')
            return 'cancelled'
        add = set(snapshot['original_labels'])
        remove = owned - add
        if snapshot['move_to_label'] and snapshot['original_inbox']:
            if (current & {'TRASH', 'SPAM'} != set(snapshot.get('original_system_locations', [])) or
                    (current & quarantine and not snapshot.get('original_quarantined', False))):
                _set_action(store, action, 'cancelled', error='Gmail location or quarantine changed; refusing to restore Inbox over that later change')
                return 'cancelled'
            add.add('INBOX')
    why = _eligibility(settings, store, action)
    if why:
        _set_action(store, action, 'cancelled', error=why)
        return 'cancelled'
    if not add.issubset(current) or remove & current:
        client.modify_labels(action['provider_message_id'], add=sorted(add), remove=sorted(remove))
    confirmed = set(client.message_labels(action['provider_message_id']))
    if not add.issubset(confirmed) or remove & confirmed:
        raise GmailError('Gmail manual label change was not confirmed')
    if not _set_action(store, action, 'applied', error=None):
        raise GmailError('Action lease changed before completion')
    return 'applied'
