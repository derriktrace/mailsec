from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from email import policy
from email.parser import BytesParser
from types import SimpleNamespace

import pytest
from sqlalchemy import update

from mailsec.gmail import GmailError, GmailMessageMissing
from mailsec.mailbox_actions import (
    actions,
    apply_pending_actions,
    enqueue_action,
    is_notification,
    list_actions,
    notification_delivery_in_progress,
    notifications,
    reconcile_committed_actions,
    reconcile_notification,
    targets,
)
from mailsec.storage import Store, jobs, messages, runs


class FakeGmail:
    def __init__(self, labels=None):
        self.labels = set(labels if labels is not None else ["INBOX", "UNREAD"])
        self.named = {"Mailsec/Quarantine": "q", "Mailsec/Review": "review"}
        self.modified = []
        self.sent = []
        self.fail_after_modify = False
        self.fail_send = False

    def message_labels(self, mid):
        return sorted(self.labels)

    def ensure_label(self, name):
        return self.named[name]

    def list_labels(self):
        return [{"id": val, "name": key} for key, val in self.named.items()]

    def modify_labels(self, mid, *, add, remove):
        self.modified.append((mid, add, remove))
        self.labels.update(add)
        self.labels.difference_update(remove)
        if self.fail_after_modify:
            self.fail_after_modify = False
            raise GmailError("response lost after modification")
        return {"id": mid}

    def send_message(self, raw):
        self.sent.append(raw)
        if self.fail_send:
            raise GmailError("response lost after send")
        return {"id": "notification-provider-id"}

    def list_messages(self, query, max_results=10):
        return {"messages": [{"id": "notification-provider-id"}]} if self.sent else {}

    def get_message(self, mid):
        return {"id": mid, "raw": self.sent[0], "labels": ["SENT"]}

    @contextmanager
    def factory(self, settings, store, mailbox):
        assert mailbox == "me@example.test"
        yield self


@pytest.fixture
def setup(tmp_path):
    store = Store(f"sqlite:///{tmp_path}/mail.db")
    settings = SimpleNamespace(tenant_id="test", authorized_mailboxes=["me@example.test"], enforcement_mode="auto_quarantine",
                               notifications_enabled=True)
    source = store.ingest(b"original private email", {"message": {"subject": "https://unsafe.example secret"}},
                         provider="gmail", provider_message_id="provider-id", mailbox="me@example.test")
    mid = source["id"]
    with store.engine.begin() as db:
        db.execute(update(jobs).values(status="complete"))
        db.execute(update(messages).where(messages.c.id == mid).values(status="complete"))
        db.execute(runs.insert().values(id="run1", message_id=mid, status="complete", created_at="2026-01-01",
            completed_at="2026-01-01", policy={"recommended_action": "quarantine", "eligible_action": "quarantine"}))
    return settings, store, mid, FakeGmail()


def enqueue(setup, kind="quarantine", rid="run1"):
    _, store, mid, _ = setup
    return enqueue_action(store, "me@example.test", "provider-id", kind, rid, mid)


@pytest.mark.parametrize("scope,token", [
    ("https://www.googleapis.com/auth/gmail.readonly", "opaque-token"), ("", "")])
@pytest.mark.parametrize("kind", ["flag", "quarantine", "release"])
def test_readonly_or_disconnected_oauth_cancels_all_gmail_writes(setup, scope, token, kind):
    from mailsec.accounts import accounts, initialize
    settings, store, _, client = setup
    initialize(store)
    with store.engine.begin() as db:
        db.execute(accounts.insert().values(mailbox="me@example.test", encrypted_tokens=token,
                                           scopes=scope, connected_at="original"))
    enqueue(setup, kind=kind)
    result = apply_pending_actions(settings, store, client_factory=client.factory)
    assert result["cancelled"] == 1 and result["retry"] == 0
    assert not client.modified and not client.sent


def test_quarantine_is_idempotent_confirmed_and_notification_safe(setup):
    settings, store, mid, client = setup
    identifier = enqueue(setup)
    assert enqueue(setup) == identifier
    result = apply_pending_actions(settings, store, client_factory=client.factory)
    assert result["applied"] == 1 and result["notifications"]["sent"] == 1
    assert client.labels == {"q", "UNREAD"}
    assert len(client.modified) == 1 and len(client.sent) == 1
    msg = BytesParser(policy=policy.default).parsebytes(client.sent[0])
    assert msg["To"] == msg["From"] == "me@example.test"
    assert "unsafe.example" not in str(msg) and "original private" not in str(msg)
    assert msg.get_content_type() == "text/plain"
    assert is_notification(store, "me@example.test", "notification-provider-id")
    assert not is_notification(store, "other@example.test", "notification-provider-id")
    assert not is_notification(store, "me@example.test", "forged-id")
    assert not notification_delivery_in_progress(store, "me@example.test")
    assert list_actions(store, mid)[0]["notification_status"] == "sent"
    assert apply_pending_actions(settings, store, client_factory=client.factory)["applied"] == 0
    assert len(client.sent) == 1


@pytest.mark.parametrize("inbox", [True, False])
def test_release_preserves_original_inbox_and_blocks_same_run_requarantine(setup, inbox):
    settings, store, mid, client = setup
    settings.notifications_enabled = False
    if not inbox:
        client.labels.discard("INBOX")
    enqueue(setup)
    apply_pending_actions(settings, store, client_factory=client.factory)
    enqueue(setup, "release")
    result = apply_pending_actions(settings, store, client_factory=client.factory)
    assert result["applied"] == 1
    assert ("INBOX" in client.labels) is inbox
    assert "q" not in client.labels
    assert enqueue(setup)  # Existing terminal quarantine intent never becomes pending.
    assert apply_pending_actions(settings, store, client_factory=client.factory)["applied"] == 0
    assert "q" not in client.labels


def test_remote_success_lost_response_reconciles_without_losing_original_inbox(setup):
    settings, store, mid, client = setup
    settings.notifications_enabled = False
    client.fail_after_modify = True
    enqueue(setup)
    assert apply_pending_actions(settings, store, client_factory=client.factory)["retry"] == 1
    assert client.labels == {"q", "UNREAD"}
    with store.engine.begin() as db:
        db.execute(update(actions).values(retry_at="2000-01-01"))
    assert apply_pending_actions(settings, store, client_factory=client.factory)["applied"] == 1
    assert len(client.modified) == 1  # Read confirms remote outcome, no repeated mutation.
    enqueue(setup, "release")
    apply_pending_actions(settings, store, client_factory=client.factory)
    assert "INBOX" in client.labels


def test_stale_analysis_and_passive_mode_cancel_without_network(setup):
    settings, store, mid, client = setup
    enqueue(setup)
    with store.engine.begin() as db:
        db.execute(runs.insert().values(id="run2", message_id=mid, status="error", completed_at="2026-01-02",
            policy={"eligible_action": "flag"}))
        db.execute(update(messages).where(messages.c.id == mid).values(status="error"))
    assert apply_pending_actions(settings, store, client_factory=client.factory)["cancelled"] == 1
    assert not client.modified and not client.sent
    enqueue(setup, "flag", "run2")
    settings.enforcement_mode = "passive"
    assert apply_pending_actions(settings, store, client_factory=client.factory)["cancelled"] == 1


def test_latest_error_hard_detection_can_quarantine_but_never_replays_old_result(setup):
    settings, store, mid, client = setup
    with store.engine.begin() as db:
        db.execute(update(runs).values(status="error", policy={"eligible_action": "quarantine", "hard_detection": True}))
        db.execute(update(messages).where(messages.c.id == mid).values(status="error"))
    assert reconcile_committed_actions(settings, store) == {"enqueued": 1}
    assert apply_pending_actions(settings, store, client_factory=client.factory)["applied"] == 1
    assert reconcile_committed_actions(settings, store) == {"enqueued": 0}


def test_flag_only_adds_review_without_send(setup):
    settings, store, mid, client = setup
    settings.enforcement_mode = "flag_only"
    with store.engine.begin() as db:
        db.execute(update(runs).values(policy={"eligible_action": "flag"}))
    enqueue(setup, "flag")
    assert apply_pending_actions(settings, store, client_factory=client.factory)["applied"] == 1
    assert client.labels == {"INBOX", "UNREAD", "review"} and not client.sent


def test_later_clean_or_spam_run_clears_only_its_automatic_review_label(setup):
    settings, store, mid, client = setup
    settings.enforcement_mode = "flag_only"
    settings.notifications_enabled = False
    with store.engine.begin() as db:
        db.execute(update(runs).values(policy={"eligible_action": "flag", "recommended_action": "flag",
                                            "verdict": "suspicious"}))
    enqueue(setup, "flag")
    assert apply_pending_actions(settings, store, client_factory=client.factory)["applied"] == 1
    assert client.labels == {"INBOX", "UNREAD", "review"}
    with store.engine.begin() as db:
        db.execute(runs.insert().values(id="run2", message_id=mid, status="complete",
            created_at="2026-01-02", completed_at="2026-01-02",
            policy={"eligible_action": "none", "recommended_action": "none", "verdict": "spam"}))
    assert reconcile_committed_actions(settings, store) == {"enqueued": 1}
    assert apply_pending_actions(settings, store, client_factory=client.factory)["applied"] == 1
    assert client.labels == {"INBOX", "UNREAD"}
    assert client.modified[-1] == ("provider-id", [], ["review"])
    assert list_actions(store, mid)[0]["action"] == "clear_review"
    assert reconcile_committed_actions(settings, store) == {"enqueued": 0}


def test_clear_review_is_cancelled_when_a_newer_analysis_requires_review(setup):
    settings, store, mid, client = setup
    settings.enforcement_mode = "flag_only"
    settings.notifications_enabled = False
    with store.engine.begin() as db:
        db.execute(update(runs).values(policy={"eligible_action": "flag", "recommended_action": "flag",
                                            "verdict": "suspicious"}))
    enqueue(setup, "flag")
    assert apply_pending_actions(settings, store, client_factory=client.factory)["applied"] == 1
    with store.engine.begin() as db:
        db.execute(runs.insert().values(id="run2", message_id=mid, status="complete",
            created_at="2026-01-02", completed_at="2026-01-02",
            policy={"eligible_action": "none", "recommended_action": "none", "verdict": "clean"}))
    assert enqueue(setup, "clear_review", "run2")
    with store.engine.begin() as db:
        db.execute(runs.insert().values(id="run3", message_id=mid, status="complete",
            created_at="2026-01-03", completed_at="2026-01-03",
            policy={"eligible_action": "flag", "recommended_action": "flag", "verdict": "suspicious"}))
    assert apply_pending_actions(settings, store, client_factory=client.factory)["cancelled"] == 1
    assert "review" in client.labels


def test_provider_throttling_keeps_action_retryable_without_burning_attempts(setup):
    settings, store, mid, client = setup
    settings.notifications_enabled = False
    enqueue(setup)
    with store.engine.begin() as db:
        db.execute(update(actions).values(attempts=4))
    def limited(mid):
        raise GmailError("Gmail returned HTTP 403 (userRateLimitExceeded)", 403, reason="userRateLimitExceeded")
    original = client.message_labels
    client.message_labels = limited
    result = apply_pending_actions(settings, store, client_factory=client.factory)
    assert result["retry"] == 1 and result["failed"] == 0
    row = list_actions(store, mid)[0]
    assert row["status"] == "retry" and row["attempts"] == 4
    assert "rate-limited" in row["error"] and not client.modified and not client.sent
    client.message_labels = original
    with store.engine.begin() as db:
        db.execute(update(actions).values(retry_at="2000-01-01"))
    assert apply_pending_actions(settings, store, client_factory=client.factory)["applied"] == 1


def test_gmail_message_removed_after_import_cancels_label_action_without_retries(setup):
    settings, store, mid, client = setup
    settings.notifications_enabled = False
    enqueue(setup)
    def missing(_mid):
        raise GmailMessageMissing("Message no longer exists in Gmail", 404)
    client.message_labels = missing
    result = apply_pending_actions(settings, store, client_factory=client.factory)
    assert result["cancelled"] == 1 and result["retry"] == result["failed"] == 0
    row = list_actions(store, mid)[0]
    assert row["status"] == "cancelled" and row["attempts"] == 1
    assert "no longer exists" in row["error"] and not client.modified
    assert apply_pending_actions(settings, store, client_factory=client.factory)["cancelled"] == 0


def test_quota_after_remote_quarantine_preserves_console_release(setup):
    from mailsec.api import create_app
    from mailsec.config import Settings

    settings, store, mid, client = setup
    settings.notifications_enabled = False
    enqueue(setup)
    original = client.message_labels
    def limited_after_write(mid):
        if client.modified:
            raise GmailError("quota", 403, reason="userRateLimitExceeded")
        return original(mid)
    client.message_labels = limited_after_write
    assert apply_pending_actions(settings, store, client_factory=client.factory)["retry"] == 1
    row = list_actions(store, mid)[0]
    assert row["status"] == "retry" and row["attempts"] == 1
    assert "q" in client.labels and "INBOX" not in client.labels and not client.sent
    # Exercise the actual console endpoint's attempted-quarantine eligibility.
    from mailsec.accounts import accounts, initialize
    from mailsec.gmail import MODIFY_SCOPE
    initialize(store)
    with store.engine.begin() as db:
        db.execute(accounts.insert().values(mailbox='me@example.test', encrypted_tokens='test-only-token',
            scopes=MODIFY_SCOPE, connected_at='original'))
    app = create_app(Settings(authorized_mailboxes=['me@example.test']), pipeline=SimpleNamespace(store=store))
    release = next(route.endpoint for route in app.routes if route.path == "/api/messages/{mid}/release")
    assert release(mid)["status"] == "queued"
    client.message_labels = original
    assert apply_pending_actions(settings, store, client_factory=client.factory)["applied"] == 1
    assert client.labels == {"INBOX", "UNREAD"}
    assert not client.sent


def test_send_uncertainty_never_retries_and_read_only_reconciliation_suppresses_id(setup):
    settings, store, mid, client = setup
    client.fail_send = True
    enqueue(setup)
    result = apply_pending_actions(settings, store, client_factory=client.factory)
    assert result["applied"] == 1 and result["notifications"]["uncertain"] == 1
    assert notification_delivery_in_progress(store, "me@example.test")
    apply_pending_actions(settings, store, client_factory=client.factory)
    assert len(client.sent) == 1
    item = list_actions(store, mid)[0]
    assert item["notification_status"] == "uncertain"
    assert reconcile_notification(settings, store, item["notification_id"], client_factory=client.factory)["status"] == "sent"
    assert is_notification(store, "me@example.test", "notification-provider-id")
    assert not notification_delivery_in_progress(store, "me@example.test")


def test_interrupted_sending_becomes_uncertain_and_is_never_sent_again(setup):
    settings, store, mid, client = setup
    enqueue(setup)
    apply_pending_actions(settings, store, client_factory=client.factory)
    with store.engine.begin() as db:
        db.execute(update(notifications).values(status="sending", provider_message_id=None))
    result = apply_pending_actions(settings, store, client_factory=client.factory)
    assert result["notifications"]["uncertain"] == 1
    assert len(client.sent) == 1
    assert list_actions(store, mid)[0]["notification_status"] == "uncertain"


def test_crash_processing_lease_recovered_after_expiration(setup):
    settings, store, mid, client = setup
    settings.notifications_enabled = False
    enqueue(setup)
    with store.engine.begin() as db:
        db.execute(update(actions).values(status="processing", lease_token="dead", attempts=1))
        db.execute(update(targets).values(lease_token="dead", lease_until="2000-01-01"))
    assert apply_pending_actions(settings, store, client_factory=client.factory)["applied"] == 1
    assert list_actions(store, mid)[0]["attempts"] == 2


def test_concurrent_workers_do_not_duplicate_notification(setup):
    settings, store, mid, client = setup
    enqueue(setup)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: apply_pending_actions(settings, store, client_factory=client.factory), range(2)))
    assert sum(result["applied"] for result in results) == 1
    assert len(client.modified) == 1 and len(client.sent) == 1


def test_recovery_skips_existing_terminal_and_enqueues_only_latest(setup):
    settings, store, mid, client = setup
    assert reconcile_committed_actions(settings, store)["enqueued"] == 1
    assert reconcile_committed_actions(settings, store)["enqueued"] == 0
    with store.engine.begin() as db:
        db.execute(runs.insert().values(id="run2", message_id=mid, status="complete", completed_at="2026-01-02",
                                       policy={"eligible_action": "flag"}))
    assert reconcile_committed_actions(settings, store)["enqueued"] == 1
    result = apply_pending_actions(settings, store, client_factory=client.factory)
    assert result["cancelled"] == 1 and result["applied"] == 1
    assert "q" not in client.labels and "review" in client.labels


def test_action_requires_same_provider_message_and_analysis(setup):
    _, store, mid, _ = setup
    with pytest.raises(ValueError, match="ingested Gmail"):
        enqueue_action(store, "me@example.test", "forged", "quarantine", "run1", mid)
    with pytest.raises(ValueError, match="must belong"):
        enqueue(setup, rid="nonexistent")


def test_operator_can_resume_after_uncertain_send_without_ever_retrying(setup):
    from mailsec.mailbox_actions import abandon_notification
    settings, store, mid, client = setup
    client.fail_send = True
    enqueue(setup)
    apply_pending_actions(settings, store, client_factory=client.factory)
    item = list_actions(store, mid)[0]
    assert notification_delivery_in_progress(store, "me@example.test")
    assert abandon_notification(store, item["notification_id"])["polling_resumed"]
    assert abandon_notification(store, item["notification_id"])["resend"] is False
    assert not notification_delivery_in_progress(store, "me@example.test")
    item = list_actions(store, mid)[0]
    assert item["notification_status"] == "uncertain"
    assert item["notification_resolution"] == "resume_without_retry"
    apply_pending_actions(settings, store, client_factory=client.factory)
    assert len(client.sent) == 1


def test_persisted_kill_switch_is_rechecked_after_provider_reads(setup):
    from mailsec.runtime_controls import update_controls
    settings, store, mid, client = setup
    enqueue(setup)
    previous = client.message_labels
    def labels_and_disable(mid):
        result = previous(mid)
        update_controls(settings, store, {"mode": "passive"})
        return result
    client.message_labels = labels_and_disable
    assert apply_pending_actions(settings, store, client_factory=client.factory)["cancelled"] == 1
    assert not client.modified and not client.sent


@pytest.mark.parametrize("stale", ["expired", "organization_changed"])
def test_stale_action_evidence_queues_reanalysis_without_gmail_write(setup, stale):
    from mailsec.security_cache import digest
    settings, store, mid, client = setup
    settings.organization = {"internal_domains": ["new.example"]}
    policy = {"eligible_action": "quarantine", "action_expires_at": None,
              "action_context_sha256": digest(settings.organization)}
    if stale == "expired":
        policy["action_expires_at"] = 1
    else:
        policy["action_context_sha256"] = digest({"internal_domains": ["old.example"]})
    with store.engine.begin() as db:
        db.execute(update(runs).values(policy=policy))
    enqueue(setup)
    assert apply_pending_actions(settings, store, client_factory=client.factory)["cancelled"] == 1
    assert not client.modified and not client.sent
    assert store.get_message(mid)["status"] == "pending"
    assert "fresh analysis" in list_actions(store, mid)[0]["error"]
