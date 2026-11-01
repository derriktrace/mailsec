"""Durable, reversible Gmail labels and notifications with explicit uncertainty.

Labels are idempotent and reconciled after interruptions. Gmail send is not
idempotent: once a notification enters 'sending', a crash or unknown response
makes it 'uncertain'; this module never automatically sends it again. Operators
can reconcile uncertain sends by the unique RFC Message-ID using read-only Gmail
search, then record the confirmed provider ID through reconcile_notification().
"""
from __future__ import annotations

import hashlib
import math
import threading
import time
import uuid
import weakref
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from email.policy import SMTP

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    and_,
    or_,
    select,
    update,
)
from sqlalchemy.exc import IntegrityError

from .accounts import allowed_mailboxes, gmail_client, oauth_write_restriction
from .gmail import GmailError, GmailMessageMissing
from .runtime_controls import refresh_controls
from .security_cache import digest
from .storage import messages, runs

metadata = MetaData()
actions = Table("mailsec_mailbox_actions", metadata,
    Column("id", String(32), primary_key=True), Column("dedup_key", String(64), nullable=False, unique=True),
    Column("target_key", String(64), nullable=False, index=True), Column("message_id", String(32)),
    Column("mailbox", String(320), nullable=False), Column("provider_message_id", Text, nullable=False),
    Column("action", String(20), nullable=False), Column("analysis_run_id", String(32)),
    Column("status", String(20), nullable=False, index=True), Column("attempts", Integer, nullable=False),
    Column("created_at", String(40)), Column("updated_at", String(40)), Column("retry_at", String(40)),
    Column("lease_token", String(32)), Column("error", Text))
targets = Table("mailsec_action_targets", metadata,
    Column("target_key", String(64), primary_key=True), Column("lease_token", String(32)),
    Column("lease_until", String(40)), Column("released_run_id", String(32)),
    Column("restore_inbox", Boolean), Column("quarantine_active", Boolean, nullable=False, default=False))
notifications = Table("mailsec_notifications", metadata,
    Column("id", String(32), primary_key=True), Column("action_id", String(32), unique=True, nullable=False),
    Column("mailbox", String(320), nullable=False), Column("status", String(20), nullable=False),
    Column("rfc_message_id", Text, nullable=False, unique=True), Column("provider_message_id", Text),
    Column("created_at", String(40)), Column("updated_at", String(40)), Column("error", Text))
notification_resolutions = Table("mailsec_notification_resolutions", metadata,
    Column("notification_id", String(32), primary_key=True), Column("resolution", String(40), nullable=False),
    Column("resolved_at", String(40), nullable=False), Column("actor", String(80), nullable=False))
manual_actions = Table("mailsec_manual_actions", metadata,
    Column("action_id", String(32), primary_key=True), Column("verdict", String(20), nullable=False),
    Column("move_to_label", Boolean, nullable=False), Column("undo_of", String(32)),
    Column("snapshot", JSON(none_as_null=True)), Column("actor", String(80), nullable=False))
LEASE_SECONDS = 900
_initialized = weakref.WeakSet()
_init_lock = threading.Lock()


def initialize(store):
    with _init_lock:
        if store.engine not in _initialized:
            metadata.create_all(store.engine)
            from .runtime_controls import metadata as controls_metadata
            controls_metadata.create_all(store.engine)
            _initialized.add(store.engine)


def _now():
    return datetime.now(UTC).isoformat(timespec="microseconds")


def _after(seconds):
    return (datetime.now(UTC) + timedelta(seconds=seconds)).isoformat(timespec="microseconds")


def _target_key(mailbox, provider_id):
    return hashlib.sha256(f"{mailbox}\0{provider_id}".encode()).hexdigest()


def enqueue_action(store, mailbox, provider_message_id, action, analysis_run_id, message_id=None):
    """Enqueue after analysis commits. A release is an explicit operator request.

    Repeating an identical request returns its existing ledger ID. A release
    blocks subsequent automatic changes from that same analysis run.
    """
    initialize(store)
    mailbox = mailbox.strip().lower()
    if action not in {"flag", "quarantine", "release", "clear_review"}:
        raise ValueError("Unknown mailbox action")
    if not mailbox or "@" not in mailbox or not provider_message_id or not analysis_run_id:
        raise ValueError("Mailbox, Gmail message ID, and analysis run ID are required")
    target = _target_key(mailbox, provider_message_id)
    key = hashlib.sha256(f"{target}\0{analysis_run_id}\0{action}".encode()).hexdigest()
    with store.engine.connect() as db:
        source = db.execute(select(messages.c.id).where(messages.c.provider == "gmail",
            messages.c.mailbox == mailbox, messages.c.provider_message_id == provider_message_id)).scalar_one_or_none()
        if not source or (message_id is not None and source != message_id):
            raise ValueError("Mailbox action must reference an ingested Gmail message")
        if not db.execute(select(runs.c.id).where(runs.c.id == analysis_run_id, runs.c.message_id == source)).first():
            raise ValueError("Analysis run must belong to the selected message")
        if action == "clear_review" and not db.execute(select(actions.c.id).where(
                actions.c.message_id == source, actions.c.action == "flag",
                actions.c.status == "applied").limit(1)).first():
            return None
    message_id = source
    if action != 'release':
        from .manual_actions import has_manual_override
        if store.get_analyst_override(message_id) or has_manual_override(store, message_id):
            return None
    try:
        with store.engine.begin() as db:
            if not db.execute(select(targets.c.target_key).where(targets.c.target_key == target)).first():
                db.execute(targets.insert().values(target_key=target, quarantine_active=False))
    except IntegrityError:
        pass
    identifier, stamp = uuid.uuid4().hex, _now()
    try:
        with store.engine.begin() as db:
            db.execute(actions.insert().values(id=identifier, dedup_key=key, target_key=target,
                message_id=message_id, mailbox=mailbox, provider_message_id=provider_message_id,
                action=action, analysis_run_id=analysis_run_id, status="pending", attempts=0,
                created_at=stamp, updated_at=stamp))
            if action == "release":
                db.execute(update(targets).where(targets.c.target_key == target).values(released_run_id=analysis_run_id))
                db.execute(update(actions).where(actions.c.target_key == target,
                    actions.c.analysis_run_id == analysis_run_id, actions.c.action != "release",
                    actions.c.status.in_(["pending", "retry"])).values(status="cancelled",
                    updated_at=stamp, error="Operator release superseded this action"))
    except IntegrityError:
        with store.engine.connect() as db:
            existing = db.execute(select(actions.c.id).where(actions.c.dedup_key == key)).scalar_one_or_none()
        if existing:
            return existing
        raise
    return identifier


def list_actions(store, message_id=None, limit=100):
    initialize(store)
    cols = [col for col in actions.c if col.name not in {"dedup_key", "target_key", "lease_token"}]
    query = select(*cols, notifications.c.status.label("notification_status"),
                   notifications.c.id.label("notification_id"),
                   notification_resolutions.c.resolution.label("notification_resolution"),
                   notification_resolutions.c.resolved_at.label("notification_resolved_at")).select_from(
        actions.outerjoin(notifications, notifications.c.action_id == actions.c.id).outerjoin(
            notification_resolutions, notification_resolutions.c.notification_id == notifications.c.id))
    if message_id:
        query = query.where(actions.c.message_id == message_id)
    with store.engine.connect() as db:
        result = [dict(row) for row in db.execute(query.order_by(actions.c.created_at.desc(), actions.c.id)
                                                 .limit(max(1, min(limit, 500)))).mappings()]
    from .manual_actions import describe_manual_actions
    return describe_manual_actions(store, result)


def is_notification(store, mailbox, provider_id):
    """Suppress only provider IDs durably returned by Gmail or confirmed during reconciliation."""
    initialize(store)
    with store.engine.connect() as db:
        return bool(db.execute(select(notifications.c.id).where(notifications.c.mailbox == mailbox.strip().lower(),
            notifications.c.provider_message_id == provider_id, notifications.c.status == "sent")).first())


def reconcile_committed_actions(settings, store, limit=100):
    """Recover the analysis-commit/enqueue gap without reactivating terminal actions.

    A correlated latest-run selection avoids replaying historical verdicts. The
    scan omits runs with any existing flag/quarantine ledger entry, so completed
    work cannot starve unqueued work on subsequent bounded passes.
    """
    initialize(store)
    later = runs.alias("later_action_run")
    existing = select(actions.c.id).where(actions.c.analysis_run_id == runs.c.id,
        actions.c.action.in_(["flag", "quarantine", "release", "clear_review"])).exists()
    previously_flagged = select(actions.c.id).where(actions.c.message_id == messages.c.id,
        actions.c.action == "flag", actions.c.status == "applied").exists()
    newer = select(later.c.id).where(later.c.message_id == runs.c.message_id,
        or_(later.c.completed_at > runs.c.completed_at,
            and_(later.c.completed_at == runs.c.completed_at, later.c.id > runs.c.id))).exists()
    with store.engine.connect() as db:
        candidates = [dict(row) for row in db.execute(select(runs.c.id, runs.c.policy, messages.c.id.label("message_id"),
            messages.c.mailbox, messages.c.provider_message_id).join(messages, messages.c.id == runs.c.message_id)
            .where(messages.c.provider == "gmail", messages.c.mailbox.in_(allowed_mailboxes(settings)),
                messages.c.status.in_(["complete", "error"]), ~existing, ~newer,
                or_(runs.c.policy["eligible_action"].as_string().in_(["flag", "quarantine"]),
                    and_(previously_flagged,
                         runs.c.policy["eligible_action"].as_string() == "none",
                         runs.c.policy["recommended_action"].as_string() == "none",
                         runs.c.policy["verdict"].as_string().in_(["clean", "spam"]))))
            .order_by(runs.c.completed_at, runs.c.id).limit(max(0, min(limit, 1000)))).mappings()]
    enqueued = 0
    for row in candidates:
        from .manual_actions import has_manual_override
        if store.get_analyst_override(row['message_id']) or has_manual_override(store, row['message_id']):
            continue
        kind = (row["policy"] or {}).get("eligible_action")
        if (kind == "none" and (row["policy"] or {}).get("recommended_action") == "none"
                and (row["policy"] or {}).get("verdict") in {"clean", "spam"}):
            kind = "clear_review"
        if kind not in {"flag", "quarantine", "clear_review"}:
            continue
        if enqueue_action(store, row["mailbox"], row["provider_message_id"], kind, row["id"], row["message_id"]):
            enqueued += 1
    return {"enqueued": enqueued}


def notification_delivery_in_progress(store, mailbox):
    """Pollers should defer this mailbox while a notification's provider ID is not yet durable.

    Uncertain sends also pause polling until reconciled; this prevents self-mail
    from becoming a new scan without trusting attacker-controlled mail headers.
    """
    initialize(store)
    with store.engine.connect() as db:
        return bool(db.execute(select(notifications.c.id).outerjoin(notification_resolutions,
            notification_resolutions.c.notification_id == notifications.c.id).where(
            notifications.c.mailbox == mailbox.strip().lower(), or_(notifications.c.status == "sending",
                and_(notifications.c.status == "uncertain", notification_resolutions.c.notification_id.is_(None))))).first())


def abandon_notification(store, notification_id, *, actor="authenticated_console"):
    """Explicit operator decision: resume scans without retrying an uncertain send.

    The original uncertain outcome stays intact; a separate durable resolution
    records that the operator accepted it. Gmail's SENT exclusion remains active.
    """
    initialize(store)
    with store.engine.connect() as db:
        row = db.execute(select(notifications.c.status).where(notifications.c.id == notification_id)).first()
    if not row or row.status != "uncertain":
        raise ValueError("Only an uncertain notification can be acknowledged without retry")
    try:
        with store.engine.begin() as db:
            db.execute(notification_resolutions.insert().values(notification_id=notification_id,
                resolution="resume_without_retry", resolved_at=_now(), actor=actor[:80]))
    except IntegrityError:
        pass  # The same acknowledged resolution is idempotent.
    return {"status": "uncertain", "resolution": "resume_without_retry", "polling_resumed": True, "resend": False}


def _lock_target(db, target, token):
    return db.execute(update(targets).where(targets.c.target_key == target,
        or_(targets.c.lease_token.is_(None), targets.c.lease_until < _now())).values(
        lease_token=token, lease_until=_after(LEASE_SECONDS))).rowcount == 1


def _unlock_target(store, target, token):
    with store.engine.begin() as db:
        db.execute(update(targets).where(targets.c.target_key == target, targets.c.lease_token == token)
                   .values(lease_token=None, lease_until=None))


def _claim(store):
    token = uuid.uuid4().hex
    with store.engine.begin() as db:
        # Interrupted label operations are safe to reconcile after their target lease expires.
        query = select(actions).where(or_(actions.c.status == "pending",
            and_(actions.c.status == "retry", actions.c.retry_at <= _now()),
            actions.c.status == "processing")).order_by(actions.c.created_at, actions.c.id).limit(100)
        candidates = list(db.execute(query).mappings())
        for row in candidates:
            if not _lock_target(db, row["target_key"], token):
                continue
            changed = db.execute(update(actions).where(actions.c.id == row["id"],
                actions.c.status == row["status"]).values(status="processing", lease_token=token,
                attempts=actions.c.attempts + 1, updated_at=_now())).rowcount
            if changed:
                return {**dict(row), "lease_token": token, "attempts": row["attempts"] + 1}
            db.execute(update(targets).where(targets.c.target_key == row["target_key"],
                targets.c.lease_token == token).values(lease_token=None, lease_until=None))
    return None


def _eligibility(settings, store, action):
    refresh_controls(settings, store)
    if action["mailbox"] not in allowed_mailboxes(settings, store):
        return "Mailbox is no longer explicitly authorized"
    restriction = oauth_write_restriction(store, action["mailbox"])
    if restriction:
        return restriction
    if action['action'] in {'manual_label', 'manual_undo'}:
        from .manual_actions import manual_eligibility
        return manual_eligibility(settings, store, action)
    if action["action"] == "release":
        return None
    if store.get_analyst_override(action['message_id']):
        return 'An analyst correction supersedes automatic mailbox actions for this message'
    from .manual_actions import has_manual_override
    if has_manual_override(store, action['message_id']):
        return 'An explicit operator Gmail label request supersedes automatic mailbox actions until undone'
    mode = getattr(settings, "enforcement_mode", "passive")
    if mode == "passive" or (action["action"] == "quarantine" and mode != "auto_quarantine"):
        return "Current enforcement mode does not authorize this action"
    with store.engine.connect() as db:
        target = db.execute(select(targets).where(targets.c.target_key == action["target_key"])).mappings().one()
        if target["released_run_id"] == action["analysis_run_id"] and action["action"] != "clear_review":
            return "Operator released this analysis run"
        message_status = db.execute(select(messages.c.status).where(messages.c.id == action["message_id"])).scalar_one_or_none()
        # A later error or a queued replay prevents applying stale successful evidence.
        latest = db.execute(select(runs.c.id, runs.c.status, runs.c.policy).where(
            runs.c.message_id == action["message_id"]).order_by(runs.c.completed_at.desc(), runs.c.id.desc()).limit(1)).mappings().first()
    if not latest or latest["id"] != action["analysis_run_id"] or latest["status"] not in {"complete", "error"} or message_status not in {"complete", "error"}:
        return "Analysis is no longer the latest completed result"
    policy = latest["policy"] or {}
    expiry = policy.get("action_expires_at")
    context = policy.get("action_context_sha256")
    expired = expiry is not None and (not isinstance(expiry, (int, float)) or
        not math.isfinite(expiry) or expiry <= time.time())
    changed = context is not None and context != digest(getattr(settings, "organization", {}))
    if expired or changed:
        store.enqueue(action["message_id"])
        return "Action evidence expired or organization context changed; fresh analysis was queued"
    recommended = policy.get("eligible_action", policy.get("recommended_action"))
    if action["action"] == "clear_review":
        if (recommended != "none" or policy.get("recommended_action") != "none"
                or policy.get("verdict") not in {"clean", "spam"}):
            return "Latest policy still requires a review label"
    else:
        expected = {"flag", "analyst_review"} if action["action"] == "flag" else {"quarantine"}
        if recommended not in expected:
            return "Latest policy no longer recommends this action"
    return None


class _ActionCancelled(RuntimeError):
    """A local policy decision, never evidence of failed Gmail authorization."""
    pass


def _write_guard(settings, store, action, *, notification=False):
    why = _eligibility(settings, store, action)
    if notification and not getattr(settings, "notifications_enabled", False):
        why = "Notifications were disabled before sending"
    if why:
        raise _ActionCancelled(why)


def _set_action(store, action, status, **values):
    with store.engine.begin() as db:
        return db.execute(update(actions).where(actions.c.id == action["id"],
            actions.c.lease_token == action["lease_token"], actions.c.status == "processing").values(
            status=status, updated_at=_now(), **values)).rowcount == 1


def _apply_one(settings, store, action, client):
    why = _eligibility(settings, store, action)
    if why:
        _set_action(store, action, "cancelled", error=why)
        return "cancelled"
    if action['action'] in {'manual_label', 'manual_undo'}:
        from .manual_actions import apply_manual_action
        return apply_manual_action(settings, store, action, client)
    mid = action["provider_message_id"]
    current = client.message_labels(mid)
    if "SENT" in current or "DRAFT" in current:
        _set_action(store, action, "cancelled", error="Outbound or draft messages are not eligible")
        return "cancelled"
    kind = action["action"]
    with store.engine.connect() as db:
        target = dict(db.execute(select(targets).where(targets.c.target_key == action["target_key"])).mappings().one())
    if kind == "quarantine":
        label = client.ensure_label("Mailsec/Quarantine")
        # Save original inbox state before the remote change. A retry must never
        # replace it with the already-quarantined message's current state.
        if not target["quarantine_active"]:
            with store.engine.begin() as db:
                db.execute(update(targets).where(targets.c.target_key == action["target_key"],
                    targets.c.lease_token == action["lease_token"]).values(
                    restore_inbox="INBOX" in current, quarantine_active=True))
        add, remove = [label], ["INBOX"]
    elif kind == "flag":
        add, remove = [client.ensure_label("Mailsec/Review")], []
    elif kind == "clear_review":
        add = []
        remove = [label["id"] for label in client.list_labels()
                  if label["name"] == "Mailsec/Review"]
    else:
        owned = [label["id"] for label in client.list_labels()
                 if label["name"] in {"Mailsec/Quarantine", "Mailsec/Review"}]
        add, remove = (["INBOX"] if target["restore_inbox"] else []), owned
    # Recheck immediately before the remote write (a concurrent new analysis or
    # release can arrive while Google's preceding reads are in flight).
    why = _eligibility(settings, store, action)
    if why:
        _set_action(store, action, "cancelled", error=why)
        return "cancelled"
    if not set(add).issubset(current) or set(remove) & set(current):
        client.modify_labels(mid, add=add, remove=remove)
    confirmed = client.message_labels(mid)
    if not set(add).issubset(confirmed) or set(remove) & set(confirmed):
        raise GmailError("Gmail label change was not confirmed")
    with store.engine.begin() as db:
        changed = db.execute(update(actions).where(actions.c.id == action["id"],
            actions.c.lease_token == action["lease_token"], actions.c.status == "processing").values(
            status="applied", updated_at=_now(), error=None)).rowcount
        if not changed:
            raise GmailError("Action lease changed before completion")
        if kind == "release":
            db.execute(update(targets).where(targets.c.target_key == action["target_key"])
                       .values(quarantine_active=False, restore_inbox=None, released_run_id=action["analysis_run_id"]))
        if kind == "quarantine" and getattr(settings, "notifications_enabled", False):
            identifier = uuid.uuid4().hex
            db.execute(notifications.insert().values(id=identifier, action_id=action["id"], mailbox=action["mailbox"],
                status="pending", rfc_message_id=f"<{identifier}@mailsec.invalid>", created_at=_now(), updated_at=_now()))
    return "applied"


def _notification_bytes(item, action):
    msg = EmailMessage(policy=SMTP)
    msg["From"] = item["mailbox"]
    msg["To"] = item["mailbox"]
    msg["Subject"] = "Mailsec: a message was moved out of your inbox"
    msg["Message-ID"] = item["rfc_message_id"]
    # Do not interpolate original subject, sender, URL, body, or attachment.
    msg.set_content("Mailsec confirmed that a message was labeled Mailsec/Quarantine and removed from your inbox.\n\n"
                    "It remains accessible in Gmail All Mail. Open your Mailsec console to review the decision or release it.\n\n"
                    f"Mailsec action reference: {action['id']}\n")
    return msg.as_bytes()


def _send_pending_notifications(settings, store, factory, limit):
    result = {"sent": 0, "uncertain": 0, "skipped": 0}
    # Recovery: a stale 'sending' lease means the outcome is unknown, never pending again.
    with store.engine.begin() as db:
        stale = select(notifications.c.id).join(actions, notifications.c.action_id == actions.c.id).join(
            targets, targets.c.target_key == actions.c.target_key).where(notifications.c.status == "sending",
                or_(targets.c.lease_token.is_(None), targets.c.lease_until < _now()))
        ids = list(db.execute(stale).scalars())
        if ids:
            db.execute(update(notifications).where(notifications.c.id.in_(ids), notifications.c.status == "sending")
                .values(status="uncertain", updated_at=_now(), error="Send was interrupted; reconcile before any further send"))
            result["uncertain"] += len(ids)
    with store.engine.connect() as db:
        pending = [dict(row) for row in db.execute(select(notifications).where(notifications.c.status == "pending")
                                                   .order_by(notifications.c.created_at).limit(limit)).mappings()]
    for item in pending:
        token = uuid.uuid4().hex
        with store.engine.begin() as db:
            action = dict(db.execute(select(actions).where(actions.c.id == item["action_id"])).mappings().one())
            if not _lock_target(db, action["target_key"], token):
                continue
        try:
            reason = _eligibility(settings, store, action)
            if not getattr(settings, "notifications_enabled", False):
                reason = "Notifications are disabled"
            if action["status"] != "applied" or action["action"] != "quarantine":
                reason = "Quarantine was not successfully applied"
            if reason:
                with store.engine.begin() as db:
                    db.execute(update(notifications).where(notifications.c.id == item["id"],
                        notifications.c.status == "pending").values(status="skipped", error=reason, updated_at=_now()))
                result["skipped"] += 1
                continue
            with factory(settings, store, item["mailbox"]) as client:
                client.write_guard = lambda: _write_guard(settings, store, action, notification=True)
                labels = client.message_labels(action["provider_message_id"])
                qlabels = {label["id"] for label in client.list_labels() if label["name"] == "Mailsec/Quarantine"}
                if "INBOX" in labels or not set(labels) & qlabels:
                    with store.engine.begin() as db:
                        db.execute(update(notifications).where(notifications.c.id == item["id"],
                            notifications.c.status == "pending").values(status="skipped", updated_at=_now(),
                            error="Message is no longer confirmed quarantined"))
                    result["skipped"] += 1
                    continue
                with store.engine.begin() as db:
                    changed = db.execute(update(notifications).where(notifications.c.id == item["id"],
                        notifications.c.status == "pending").values(status="sending", updated_at=_now())).rowcount
                if changed != 1:
                    continue
                _write_guard(settings, store, action, notification=True)
                # From this committed transition onward, every failure is uncertain.
                sent = client.send_message(_notification_bytes(item, action))
                provider_id = sent.get("id")
                if not isinstance(provider_id, str) or not provider_id:
                    raise GmailError("Send response did not contain a provider message ID")
                with store.engine.begin() as db:
                    db.execute(update(notifications).where(notifications.c.id == item["id"],
                        notifications.c.status == "sending").values(status="sent", provider_message_id=provider_id,
                        updated_at=_now(), error=None))
                result["sent"] += 1
        except GmailMessageMissing:
            with store.engine.begin() as db:
                db.execute(update(notifications).where(notifications.c.id == item["id"],
                    notifications.c.status == "pending").values(status="skipped",
                    updated_at=_now(), error="Original message no longer exists in Gmail"))
            result["skipped"] += 1
        except _ActionCancelled as exc:
            with store.engine.begin() as db:
                db.execute(update(notifications).where(notifications.c.id == item["id"],
                    notifications.c.status.in_(["pending", "sending"])).values(status="skipped",
                    updated_at=_now(), error=str(exc)))
            result["skipped"] += 1
        except Exception:
            with store.engine.begin() as db:
                changed = db.execute(update(notifications).where(notifications.c.id == item["id"],
                    notifications.c.status == "sending").values(status="uncertain", updated_at=_now(),
                    error="Notification delivery is uncertain; it will not be retried automatically")).rowcount
                # Pre-send failures remain pending, preserving the safe ability to retry reads.
                if not changed:
                    db.execute(update(notifications).where(notifications.c.id == item["id"],
                        notifications.c.status == "pending").values(updated_at=_now(),
                        error="Unable to confirm quarantine or access Gmail before sending"))
            result["uncertain"] += bool(changed)
        finally:
            _unlock_target(store, action["target_key"], token)
    return result


def apply_pending_actions(settings, store, limit=20, *, client_factory=None):
    """Apply durable label intents and at-most-once send attempts; no network at enqueue time."""
    initialize(store)
    factory = client_factory or (lambda settings, store, mailbox: gmail_client(settings, store, mailbox, for_actions=True))
    summary = {"applied": 0, "cancelled": 0, "retry": 0, "failed": 0}
    for _ in range(max(0, min(limit, 500))):
        action = _claim(store)
        if not action:
            break
        try:
            reason = _eligibility(settings, store, action)
            if reason:
                _set_action(store, action, "cancelled", error=reason)
                summary["cancelled"] += 1
                continue
            with factory(settings, store, action["mailbox"]) as client:
                client.write_guard = lambda: _write_guard(settings, store, action)
                outcome = _apply_one(settings, store, action, client)
            summary[outcome] += 1
        except _ActionCancelled as exc:
            _set_action(store, action, "cancelled", error=str(exc))
            summary["cancelled"] += 1
        except GmailMessageMissing:
            _set_action(store, action, "cancelled", error="Original message no longer exists in Gmail; stored analysis is retained")
            summary["cancelled"] += 1
        except Exception as exc:
            if isinstance(exc, GmailError) and exc.rate_limited:
                # Throttling is temporary, not five separate failed security
                # decisions. Stop this batch so later intents do not hammer the
                # same quota; recheck every write when the intent resumes.
                # Keep one attempt recorded: a remote mutation might have
                # succeeded before its verification read was rate-limited.
                # Operators must still be able to release that uncertain change.
                _set_action(store, action, "retry", error="Gmail temporarily rate-limited this action; automatic retry scheduled",
                            retry_at=_after(60), attempts=max(1, action["attempts"] - 1))
                summary["retry"] += 1
                break
            status = "failed" if action["attempts"] >= 5 else "retry"
            _set_action(store, action, status, error="Gmail change could not be confirmed; inspect account health and retry status",
                        retry_at=_after(min(900, 30 * 2 ** (action["attempts"] - 1))))
            summary[status] += 1
        finally:
            _unlock_target(store, action["target_key"], action["lease_token"])
    summary["notifications"] = _send_pending_notifications(settings, store, factory, max(0, min(limit, 500)))
    return summary


def reconcile_notification(settings, store, notification_id, *, client_factory=None):
    """Read-only reconciliation of one uncertain send; never sends or retries mail.

    Only a message already in this account's SENT folder, with an exact matching
    Message-ID and expected self sender/recipient, may acquire durable suppression.
    Zero matches remains uncertain (absence is not proof a send never happened).
    """
    from email import policy
    from email.parser import BytesParser
    from email.utils import getaddresses
    initialize(store)
    with store.engine.connect() as db:
        row = db.execute(select(notifications).where(notifications.c.id == notification_id)).mappings().first()
    if not row or row["status"] != "uncertain":
        raise ValueError("Only uncertain notification deliveries can be reconciled")
    item = dict(row)
    found = []
    factory = client_factory or gmail_client
    with factory(settings, store, item["mailbox"]) as client:
        query = "in:sent rfc822msgid:" + item["rfc_message_id"].strip("<>")
        listing = client.list_messages(query, max_results=10)
        if listing.get("nextPageToken"):
            return {"status": "uncertain", "reason": "Multiple matching sent messages require operator review"}
        for candidate in listing.get("messages", []):
            msg = client.get_message(candidate["id"])
            parsed = BytesParser(policy=policy.default).parsebytes(msg["raw"])
            sender = [address.lower() for _, address in getaddresses(parsed.get_all("From", []))]
            recipient = [address.lower() for _, address in getaddresses(parsed.get_all("To", []))]
            if ("SENT" in msg["labels"] and parsed.get_all("Message-ID", []) == [item["rfc_message_id"]]
                and sender == [item["mailbox"]] and recipient == [item["mailbox"]]):
                found.append(msg["id"])
    if len(found) == 1:
        with store.engine.begin() as db:
            db.execute(update(notifications).where(notifications.c.id == notification_id,
                notifications.c.status == "uncertain").values(status="sent", provider_message_id=found[0],
                error=None, updated_at=_now()))
        return {"status": "sent", "provider_message_id": found[0]}
    return {"status": "uncertain", "reason": "No unique verified sent message; no automatic retry"}
