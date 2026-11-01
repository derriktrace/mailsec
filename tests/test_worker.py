"""Storage/worker integration tests: real SQLite, fake external providers."""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from threading import Barrier, Event, local
from typing import ClassVar

import pytest
from privacy_helpers import authorize_test_provider
from sqlalchemy import event, func, select

from mailsec.config import Settings
from mailsec.gmail import GmailAuthorizationError, GmailError
from mailsec.jev import JevError
from mailsec.pipeline import Pipeline
from mailsec.storage import JobLeaseLost, Store, jobs, messages, now, runs
from mailsec.worker import poll_gmail, run_worker

RAW = b"From: Vendor <vendor@example.com>\r\nTo: analyst@example.test\r\nDate: Sun, 1 Jan 2023 00:00:00 +0000\r\nSubject: Receipt\r\n\r\nYour order shipped."


class FakeJev:
    def __init__(self):
        self.calls = []
        self.error = None

    def evaluate(self, evidence, questions=None):
        self.calls.append(evidence)
        if self.error:
            raise self.error
        return {
            "model": "test-model",
            "answers": {
                "verdict": {
                    "type": "choice",
                    "choice": "clean",
                    "confidence": 0.98,
                    "probabilities": {"clean": 0.98, "spam": 0.01, "suspicious": 0.01, "phishing": 0},
                },
                **{
                    key: {"type": "noul", "noul": 0}
                    for key in (
                        "deceptive_identity",
                        "requests_sensitive_action",
                        "hostile_destination_or_payload",
                    )
                },
            },
            "usage": {"input_tokens": 10, "output_tokens": 10},
        }


@pytest.fixture
def pipeline(tmp_path):
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'mailsec.db'}",
        google_service_account_file="not-used.json",
        mailboxes=["analyst@example.test"],
        authorized_mailboxes=["analyst@example.test"],
    )
    result = Pipeline(settings, store=Store(settings.database_url), jev=FakeJev())
    authorize_test_provider(settings, result.store)
    yield result
    result.store.engine.dispose()


@pytest.fixture
def gmail(monkeypatch):
    class FakeGmail:
        events: ClassVar[list] = []
        initial_ids: ClassVar[list[str]] = ["a", "b"]
        added_ids: ClassVar[list[str]] = []
        failed_id = None
        history_error = None

        def __init__(self, service_account_file, mailbox):
            self.mailbox = mailbox.lower()

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.events.append(("close", self.mailbox))

        def get_profile(self):
            self.events.append(("profile",))
            return {"historyId": "100"}

        def list_messages(self, query="", page_token=None, max_results=100):
            self.events.append(("list", query, page_token))
            offset = int(page_token or 0)
            selected = self.initial_ids[offset : offset + max_results]
            result = {"messages": [{"id": identifier} for identifier in selected]}
            if offset + len(selected) < len(self.initial_ids):
                result["nextPageToken"] = str(offset + len(selected))
            return result

        def get_message(self, identifier):
            if identifier == self.failed_id:
                raise GmailError("transient", 503)
            return {
                "raw": RAW,
                "id": identifier,
                "thread_id": "thread-" + identifier,
                "received_at": datetime(2026, 1, 2, tzinfo=UTC),
                "labels": ["INBOX"],
            }

        def history(self, start_history_id, page_token=None):
            self.events.append(("history", start_history_id, page_token))
            if self.history_error:
                raise self.history_error
            return {
                "historyId": "110",
                "history": [
                    {"messagesAdded": [{"message": {"id": identifier}} for identifier in self.added_ids]}
                ],
            }

    monkeypatch.setattr("mailsec.accounts.gmail_client", lambda settings, store, mailbox: FakeGmail("unused", mailbox))
    return FakeGmail


def count_rows(store, table):
    with store.engine.connect() as db:
        return db.execute(select(func.count()).select_from(table)).scalar_one()


def test_poll_gmail_durably_imports_and_incremental_replay_deduplicates(pipeline, gmail):
    poll_gmail(pipeline)
    state = pipeline.store.mailbox_state("analyst@example.test")
    assert state["history_id"] == "100" and state["last_successful_poll"]
    assert state["sync_summary"]["complete"] and state["last_error"] is None
    assert count_rows(pipeline.store, messages) == count_rows(pipeline.store, jobs) == 2
    assert not pipeline.jev.calls  # Polling and paid model analysis are separate.
    row = pipeline.store.list_messages()["messages"][0]
    assert datetime.fromisoformat(row["received_at"]) == datetime(2026, 1, 2, tzinfo=UTC)
    assert row["provider"] == "gmail"
    gmail.added_ids = ["a", "c"]
    poll_gmail(pipeline)
    state = pipeline.store.mailbox_state("analyst@example.test")
    assert state["history_id"] == "110"
    assert state["sync_summary"]["duplicates"] == 1
    assert count_rows(pipeline.store, messages) == count_rows(pipeline.store, jobs) == 3
    assert ("history", "100", None) in gmail.events
    assert sum(event[0] == "profile" for event in gmail.events) == 1


def test_poll_midstream_failure_retains_checkpoint_and_retry_completes(pipeline, gmail):
    gmail.failed_id = "b"
    poll_gmail(pipeline)
    state = pipeline.store.mailbox_state("analyst@example.test")
    assert state["history_id"] is None and state["last_successful_poll"] is None
    assert state["last_error"] == "Gmail sync failed (GmailError)"
    assert count_rows(pipeline.store, messages) == count_rows(pipeline.store, jobs) == 1
    gmail.failed_id = None
    poll_gmail(pipeline)
    state = pipeline.store.mailbox_state("analyst@example.test")
    assert state["history_id"] == "100" and state["last_error"] is None
    assert state["sync_summary"]["duplicates"] == 1
    assert count_rows(pipeline.store, messages) == count_rows(pipeline.store, jobs) == 2


def test_poll_truncation_is_visible_and_never_records_success(pipeline, gmail):
    pipeline.settings.max_initial_messages = 1
    poll_gmail(pipeline)
    state = pipeline.store.mailbox_state("analyst@example.test")
    assert state["history_id"] is None and state["last_successful_poll"] is None
    assert state["sync_summary"]["truncated"]
    assert state["last_error"] is None
    assert state["sync_summary"]["complete"] is False
    assert state["sync_summary"]["backfill_resume"]
    pipeline.settings.max_initial_messages = 2
    poll_gmail(pipeline)
    assert pipeline.store.mailbox_state("analyst@example.test")["history_id"] == "100"
    assert count_rows(pipeline.store, jobs) == 2


def test_poll_rate_limit_retains_cursor_and_clears_on_success(pipeline, gmail):
    pipeline.store.update_mailbox("analyst@example.test", history_id="100")
    gmail.history_error = GmailError("Gmail returned HTTP 403", 403, reason="userRateLimitExceeded")
    poll_gmail(pipeline)
    state = pipeline.store.mailbox_state("analyst@example.test")
    assert state["history_id"] == "100"
    assert "rate-limited" in state["last_error"]
    assert "reconnect" not in state["last_error"].lower()
    gmail.history_error = None
    poll_gmail(pipeline)
    state = pipeline.store.mailbox_state("analyst@example.test")
    assert state["history_id"] == "110" and state["last_error"] is None


def test_expired_gmail_consent_is_actionable_and_preserves_checkpoint(pipeline, gmail):
    pipeline.store.update_mailbox('analyst@example.test', history_id='100',
        sync_summary={'complete': True, 'mode': 'incremental'}, last_successful_poll='2026-01-01T00:00:00+00:00')
    gmail.history_error = GmailAuthorizationError()
    poll_gmail(pipeline)
    state = pipeline.store.mailbox_state('analyst@example.test')
    assert state['last_error'] == 'Reconnect Gmail: authorization expired or revoked.'
    assert state['history_id'] == '100'
    assert state['sync_summary'] == {'complete': True, 'mode': 'incremental'}
    assert state['last_successful_poll'] == '2026-01-01T00:00:00+00:00'
    assert not pipeline.jev.calls
    gmail.history_error = None
    poll_gmail(pipeline)
    state = pipeline.store.mailbox_state('analyst@example.test')
    assert state['history_id'] == '110' and state['last_error'] is None


def test_poll_stale_history_recovery_persists_coverage_notice(pipeline, gmail):
    pipeline.store.update_mailbox("analyst@example.test", history_id="5")
    gmail.history_error = GmailError("stale", 404)
    poll_gmail(pipeline)
    state = pipeline.store.mailbox_state("analyst@example.test")
    assert state["history_id"] == "100"
    assert state["sync_summary"]["mode"] == "recovery"
    assert "coverage" in state["sync_summary"]["notice"]


def test_analysis_failure_is_durable_and_replay_preserves_failed_run(pipeline):
    mid = pipeline.ingest(RAW, mailbox="analyst@example.test")["id"]
    pipeline.jev.error = JevError("Jev returned HTTP 503")
    result = pipeline.process_one()
    assert result["status"] == "error"
    first = pipeline.store.detail(mid)["runs"][0]
    assert first["status"] == "error" and first["evidence"]["source_integrity"]["raw_sha256"]
    assert pipeline.process_one() is None
    pipeline.jev.error = None
    pipeline.store.enqueue(mid)
    result = pipeline.process_one()
    detail = pipeline.store.detail(mid)
    assert result["status"] == "complete" and detail["message"]["run_count"] == 2
    assert len(detail["runs"]) == 2
    assert next(run for run in detail["runs"] if run["id"] == first["id"]) == first
    assert detail["runs"][0]["policy"]["executed_action"] == "none"


def test_expired_worker_cannot_finish_a_reclaimed_job(pipeline):
    mid = pipeline.ingest(RAW)["id"]
    first = pipeline.store.claim()
    with pipeline.store.engine.begin() as db:
        db.execute(
            jobs.update()
            .where(jobs.c.id == first["id"])
            .values(claimed_at=(datetime.now(UTC) - timedelta(minutes=11)).isoformat())
        )
    second = pipeline.store.claim()
    assert second["id"] == first["id"] and second["lease_token"] != first["lease_token"]
    assert pipeline.store.finish(first, {}, None, None, {}, {}, now(), "failed") is False
    assert count_rows(pipeline.store, runs) == 0
    assert pipeline.store.finish(second, {}, None, None, {}, {}, now(), "failed")
    assert pipeline.store.get_message(mid)["run_count"] == 1


def test_live_job_lease_renews_and_keeps_crash_recovery_after_exit(pipeline, monkeypatch):
    pipeline.ingest(RAW)
    job = pipeline.store.claim()
    original = pipeline.store.renew_job_lease
    renewed = Event()
    calls = []
    def track(item, worker_id=None):
        result = original(item, worker_id)
        calls.append(result)
        if len(calls) >= 2:
            renewed.set()
        return result
    monkeypatch.setattr(pipeline.store, 'renew_job_lease', track)
    pipeline.store.heartbeat('test-worker', 'working')
    with pipeline.store.keep_job_lease(job, worker_id='test-worker', interval=.01) as lease:
        assert renewed.wait(2)
        lease.check()
        assert pipeline.store.claim() is None
        assert pipeline.store.status()['worker']['instances'][0]['state'] == 'analyzing'
    assert not lease.thread.is_alive()
    with pipeline.store.engine.begin() as db:
        db.execute(jobs.update().where(jobs.c.id == job['id'])
                   .values(claimed_at=(datetime.now(UTC) - timedelta(minutes=11)).isoformat()))
    replacement = pipeline.store.claim()
    assert replacement['id'] == job['id'] and replacement['lease_token'] != job['lease_token']
    assert not original(job)


@pytest.mark.parametrize('failure', ['database_error', 'reclaimed'])
def test_failed_renewal_stops_the_lease_and_rejects_further_work(pipeline, monkeypatch, failure):
    pipeline.ingest(RAW)
    job = pipeline.store.claim()
    original = pipeline.store.renew_job_lease
    calls = []
    def renew(item, worker_id=None):
        calls.append(item['id'])
        if len(calls) == 1:
            return original(item, worker_id)
        if failure == 'database_error':
            raise RuntimeError('private connection data')
        return False
    monkeypatch.setattr(pipeline.store, 'renew_job_lease', renew)
    with pipeline.store.keep_job_lease(job, interval=.01) as lease:
        assert lease.lost.wait(2)
        with pytest.raises(JobLeaseLost, match='ownership could not be confirmed'):
            lease.check()
    assert not lease.thread.is_alive()


def test_lost_lease_cannot_commit_result_or_queue_mailbox_action(pipeline, monkeypatch):
    from mailsec.mailbox_actions import list_actions
    pipeline.ingest(RAW, provider='gmail', provider_message_id='lost-lease', mailbox='analyst@example.test')
    original = pipeline.jev.evaluate
    def lose_ownership(evidence, questions=None):
        result = original(evidence, questions=questions)
        pipeline._job_lease.lost.set()
        return result
    monkeypatch.setattr(pipeline.jev, 'evaluate', lose_ownership)
    result = pipeline.process_one()
    assert result['status'] == 'superseded' and result['run_id'] is None
    assert count_rows(pipeline.store, runs) == 0
    assert list_actions(pipeline.store) == []


def test_stalled_renewal_fails_closed_before_the_reclaim_deadline(pipeline, monkeypatch):
    pipeline.ingest(RAW)
    job = pipeline.store.claim()
    original = pipeline.store.renew_job_lease
    blocked, release = Event(), Event()
    calls = []
    def renew(item, worker_id=None):
        calls.append(item['id'])
        if len(calls) > 1:
            blocked.set()
            release.wait(2)
        return original(item, worker_id)
    monkeypatch.setattr(pipeline.store, 'renew_job_lease', renew)
    with pipeline.store.keep_job_lease(job, interval=.01) as lease:
        assert blocked.wait(2)
        confirmed = lease.confirmed_at
        monkeypatch.setattr('mailsec.storage.time.monotonic', lambda: confirmed + 301)
        try:
            with pytest.raises(JobLeaseLost):
                lease.check()
            assert lease.lost.is_set()
        finally:
            release.set()
    assert not lease.thread.is_alive()


def test_rejected_completion_is_reported_as_superseded(pipeline, monkeypatch):
    pipeline.ingest(RAW)
    monkeypatch.setattr(pipeline.store, "finish", lambda *args, **kwargs: False)
    result = pipeline.process_one()
    assert result["status"] == "superseded"
    assert not result["run_id"]


def test_concurrent_replay_requests_create_one_active_job(pipeline):
    mid = pipeline.ingest(RAW)["id"]
    pipeline.process_one()
    barrier = Barrier(2)

    # A per-thread flag prevents the post-conflict duplicate lookup from waiting.
    state = local()

    def synchronize_once(*args):
        if not getattr(state, "seen", False) and args[2].startswith("SELECT analysis_jobs.id"):
            state.seen = True
            barrier.wait(timeout=5)

    event.listen(pipeline.store.engine, "after_cursor_execute", synchronize_once)
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(pipeline.store.enqueue, mid) for _ in range(2)]
            identifiers = [future.result(timeout=10) for future in futures]
    finally:
        event.remove(pipeline.store.engine, "after_cursor_execute", synchronize_once)
    assert identifiers[0] == identifiers[1]
    with pipeline.store.engine.connect() as db:
        active = db.execute(
            select(func.count())
            .select_from(jobs)
            .where(jobs.c.message_id == mid, jobs.c.status.in_(["pending", "processing"]))
        ).scalar_one()
    assert active == 1


def test_worker_reports_clean_shutdown(pipeline, monkeypatch):
    stop = Event()
    pipeline.settings.google_service_account_file = ""
    monkeypatch.setattr("mailsec.worker.Pipeline", lambda settings: pipeline)

    def finish_loop():
        stop.set()

    monkeypatch.setattr(pipeline, "process_one", finish_loop)
    run_worker(pipeline.settings, stop)
    assert pipeline.store.status()["worker"]["instances"][0]["state"] == "stopped"


def test_poll_capped_backfill_resumes_without_changing_operator_limit(pipeline, gmail):
    pipeline.settings.max_initial_messages = 1
    gmail.initial_ids = ["a", "b", "c"]
    for imported in (1, 2):
        poll_gmail(pipeline)
        state = pipeline.store.mailbox_state("analyst@example.test")
        assert state["history_id"] is None
        assert state["sync_summary"]["backfill_resume"]["enumerated_total"] == imported
        assert count_rows(pipeline.store, messages) == imported
    poll_gmail(pipeline)
    state = pipeline.store.mailbox_state("analyst@example.test")
    assert state["history_id"] == "100" and state["sync_summary"]["complete"]
    assert state["sync_summary"]["backfill_resume"] is None
    assert count_rows(pipeline.store, messages) == 3
    assert len([call for call in gmail.events if call[0] == "profile"]) == 1
