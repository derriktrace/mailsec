"""Opt-in PostgreSQL tests; each test owns and removes a random isolated schema.

Set MAILSEC_TEST_POSTGRES_URL or MAILSEC_TEST_POSTGRES_URL_FILE to a disposable
PostgreSQL database with CREATE SCHEMA privileges. No existing schema is changed.
These tests never contact Gmail or Jev.
"""

import asyncio
import os
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Barrier

import httpx
import pytest
from sqlalchemy import create_engine, func, select, text
from sqlalchemy.engine import make_url

from mailsec.api import create_app
from mailsec.config import Settings
from mailsec.parsing import parse_email
from mailsec.pipeline import Pipeline
from mailsec.storage import Store, jobs, messages, now, runs

RAW = b"From: vendor@example.com\r\nTo: analyst@example.test\r\nSubject: Receipt\r\n\r\nYour order shipped."


@pytest.fixture
def pg_store():
    configured = os.getenv("MAILSEC_TEST_POSTGRES_URL", "")
    if not configured and os.getenv("MAILSEC_TEST_POSTGRES_URL_FILE"):
        configured = Path(os.environ["MAILSEC_TEST_POSTGRES_URL_FILE"]).read_text().strip()
    if not configured:
        pytest.skip("Set MAILSEC_TEST_POSTGRES_URL[_FILE] to run PostgreSQL integration tests")
    url = make_url(configured)
    if url.get_backend_name() != "postgresql":
        raise ValueError("PostgreSQL integration requires a PostgreSQL URL")
    schema = "mailsec_test_" + uuid.uuid4().hex
    admin = create_engine(url, pool_pre_ping=True)
    try:
        with admin.begin() as db:
            db.execute(text(f'CREATE SCHEMA "{schema}"'))
    except Exception:
        admin.dispose()
        # Driver tracebacks can contain connection arguments, including passwords.
        pytest.fail("Could not connect to PostgreSQL or create the isolated test schema", pytrace=False)
    scoped = url.update_query_dict({"options": f"-csearch_path={schema}"})
    store = None
    try:
        try:
            store = Store(scoped.render_as_string(hide_password=False))
        except Exception:
            pytest.fail("Could not initialize the isolated PostgreSQL test tables", pytrace=False)
        yield store
    finally:
        if store:
            store.engine.dispose()
        with admin.begin() as db:
            db.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        admin.dispose()


def ingest(store, identifier, received_at=None):
    return store.ingest(
        RAW,
        parse_email(RAW),
        provider="gmail",
        mailbox="analyst@example.test",
        provider_message_id=identifier,
        provider_thread_id="thread-" + identifier,
        received_at=received_at or datetime(2026, 1, 1, tzinfo=UTC),
    )


def count_rows(store, table):
    with store.engine.connect() as db:
        return db.execute(select(func.count()).select_from(table)).scalar_one()


def finish(store, job, verdict="clean"):
    return store.finish(
        job,
        {"test_evidence": True},
        {"answers": {"verdict": {"choice": verdict, "confidence": 0.99}}},
        {"executed_action": "none"},
        {"model": "test"},
        {"test": True},
        now(),
    )


def test_postgres_question_schema_and_initial_defaults_are_cross_process_safe(pg_store):
    from mailsec.question_settings import Questions
    others = [Store(pg_store.engine.url.render_as_string(hide_password=False)) for _ in range(4)]
    barrier = Barrier(4)
    def first_use(store):
        barrier.wait(timeout=10)
        return Questions(store).active()
    try:
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(first_use, others))
        assert len({result['id'] for result in results}) == 1
        assert Questions(pg_store).history()[1] == 1
    finally:
        for store in others:
            store.engine.dispose()


def test_postgres_question_activation_cas_and_global_comparison_lease(pg_store, monkeypatch):
    import copy

    from privacy_helpers import authorize_test_provider
    from test_question_settings import answers

    from mailsec import question_settings as qs
    from mailsec.security_cache import digest

    settings = Settings(database_url=pg_store.engine.url.render_as_string(hide_password=False), api_key='synthetic')
    authorize_test_provider(settings, pg_store)
    questions = qs.Questions(pg_store)
    active = questions.active()
    bundles = copy.deepcopy(active['bundles'])
    bundles['primary']['verdict']['instructions'] += ' Current message only.'
    candidate = questions.draft(bundles, 'PostgreSQL test', active['id'])
    class Client:
        def evaluate(self, state, questions=None):
            return answers(questions)
    monkeypatch.setattr(qs, 'decision_client', lambda settings, **kwargs: Client())
    snapshot, provider = qs.provider_snapshot(settings, pg_store)
    evidence, source = qs._comparison_evidence(pg_store, qs.TestBody(revision_id=candidate['id'],
        expected_provider_fingerprint=provider['fingerprint'], text='Your order shipped.'))
    record = questions.begin_test(candidate, active, provider, evidence, source)
    with pytest.raises(qs.QuestionConflict):
        questions.begin_test(candidate, active, provider, evidence, source)
    qs.run_comparison(questions, record['id'], active, candidate, snapshot, evidence)
    assert questions.test(record['id'])['status'] == 'complete'
    assert candidate['sha256'] == digest(candidate['bundles'])
    barrier = Barrier(2)
    def activate():
        barrier.wait(timeout=10)
        try:
            questions.activate(candidate['id'], active['id'], provider['fingerprint'], record['id'], settings=settings)
            return 'activated'
        except qs.QuestionConflict:
            return 'stale'
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(lambda _: activate(), range(2))) == ['activated', 'stale']
    assert questions.active()['id'] == candidate['id']


def test_postgres_privacy_first_use_and_events_are_process_safe_without_auto_grants(pg_store):
    from mailsec.provider_consent import PrivacyConsents, destination, privacy_events

    others = [Store(pg_store.engine.url.render_as_string(hide_password=False)) for _ in range(4)]
    barrier = Barrier(4)
    scope = destination('jev')
    def first_use(store):
        barrier.wait(timeout=10)
        return PrivacyConsents(store, 'synthetic-owner').status(scope)
    try:
        with ThreadPoolExecutor(max_workers=4) as pool:
            statuses = list(pool.map(first_use, others))
        assert all(not status['accepted'] for status in statuses)
        with pg_store.engine.connect() as db:
            assert db.execute(select(func.count()).select_from(privacy_events)).scalar_one() == 0
    finally:
        for store in others:
            store.engine.dispose()


def test_postgres_reaccept_or_revoke_invalidates_old_saved_privacy_authorization(pg_store):
    from privacy_helpers import authorize_test_provider

    from mailsec.provider_consent import PrivacyConsents, destination, privacy_events, privacy_status

    settings = Settings(database_url=pg_store.engine.url.render_as_string(hide_password=False), api_key='synthetic')
    authorize_test_provider(settings, pg_store)
    assert privacy_status(settings, pg_store)['analysis_allowed']
    scope = destination('jev')
    barrier = Barrier(4)
    def record(value):
        barrier.wait(timeout=10)
        return PrivacyConsents(pg_store, settings.tenant_id).record(scope, value)
    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(record, [True, False, True, False]))
    with pg_store.engine.connect() as db:
        events = list(db.execute(select(privacy_events).order_by(privacy_events.c.id)).mappings())
    assert len(events) == 5 and len({row['id'] for row in events}) == 5
    # Neither an acceptance nor a revocation can leave the original provider
    # stamp active. A new acceptance must be paired with a subsequent model Save.
    assert not privacy_status(settings, pg_store)['analysis_allowed']


def test_postgres_analyst_override_survives_replay_and_updates_aggregates(pg_store):
    item = ingest(pg_store, 'human-correction', received_at=now())
    rid = finish(pg_store, pg_store.claim(), verdict='suspicious')
    pg_store.add_feedback(item['id'], 'clean', 'Verified by mailbox owner.', 'owner', rid,
                          apply_verdict=True)
    assert pg_store.list_messages(verdict='clean')['total'] == 1
    assert pg_store.list_messages(verdict='suspicious')['total'] == 0
    assert pg_store.status()['counts']['clean'] == 1
    assert pg_store.overview()['daily'][-1]['clean'] == 1
    pg_store.enqueue(item['id'])
    finish(pg_store, pg_store.claim(), verdict='phishing')
    message = pg_store.detail(item['id'])['message']
    assert message['verdict'] == 'clean'
    assert message['system_verdict'] == 'phishing'
    assert message['analyst_override']['reviewer'] == 'owner'
    assert len(pg_store.detail(item['id'])['runs']) == 2


def test_postgres_concurrent_import_is_durable_and_idempotent(pg_store):
    barrier = Barrier(8)

    def import_same_message():
        barrier.wait(timeout=10)
        return ingest(pg_store, "same-provider-id")

    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: import_same_message(), range(8)))
    assert len({result["id"] for result in results}) == 1
    assert sum(result["duplicate"] for result in results) == 7
    assert count_rows(pg_store, messages) == count_rows(pg_store, jobs) == 1
    saved = pg_store.get_message(results[0]["id"])
    assert saved["raw"] == RAW
    assert saved["provider_message_id"] == "same-provider-id"


def test_postgres_concurrent_workers_claim_each_job_once(pg_store):
    for index in range(16):
        ingest(pg_store, str(index))
    barrier = Barrier(4)

    def claim_available():
        barrier.wait(timeout=10)
        claimed = []
        while job := pg_store.claim():
            claimed.append(job)
        return claimed

    with ThreadPoolExecutor(max_workers=4) as pool:
        groups = list(pool.map(lambda _: claim_available(), range(4)))
    claimed = [job for group in groups for job in group]
    assert len(claimed) == len({job["id"] for job in claimed}) == 16
    assert len({job["lease_token"] for job in claimed}) == 16
    assert pg_store.claim() is None


def test_postgres_claim_skips_another_transaction_row_lock(pg_store):
    first = ingest(pg_store, "first")
    second = ingest(pg_store, "second")
    with pg_store.engine.connect() as lock_owner:
        transaction = lock_owner.begin()
        lock_owner.execute(select(jobs).where(jobs.c.id == first["job_id"]).with_for_update()).first()
        try:
            with ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(pg_store.claim)
                try:
                    claimed = future.result(timeout=3)
                finally:
                    transaction.rollback()
        finally:
            if transaction.is_active:
                transaction.rollback()
    assert claimed["id"] == second["job_id"]


def test_postgres_concurrent_replay_has_one_job_and_keeps_prior_run(pg_store):
    today = datetime.now(UTC)
    message = ingest(pg_store, "replay", received_at=today)
    first_run = finish(pg_store, pg_store.claim())
    barrier = Barrier(8)

    def enqueue_same_message():
        barrier.wait(timeout=10)
        return pg_store.enqueue(message["id"])

    with ThreadPoolExecutor(max_workers=8) as pool:
        queued = list(pool.map(lambda _: enqueue_same_message(), range(8)))
    assert len(set(queued)) == 1
    second_run = finish(pg_store, pg_store.claim(), "suspicious")
    detail = pg_store.detail(message["id"])
    assert detail["message"]["run_count"] == 2
    assert detail["message"]["verdict"] == "suspicious"
    assert {run["id"] for run in detail["runs"]} == {first_run, second_run}
    assert (
        next(run for run in detail["runs"] if run["id"] == first_run)["output"]["answers"]["verdict"][
            "choice"
        ]
        == "clean"
    )
    assert "raw" not in detail["message"] and "parsed" not in detail["message"]
    reviewed = ingest(pg_store, "reviewed", received_at=today - timedelta(days=1))
    reviewed_run = finish(pg_store, pg_store.claim(), "phishing")
    pg_store.add_feedback(reviewed["id"], "phishing", "Confirmed", "test", run_id=reviewed_run)
    ingest(pg_store, "failed", received_at=today)
    pg_store.finish(pg_store.claim(), {}, None, None, {}, {}, now(), error="test provider failure")
    ingest(pg_store, "pending", received_at=today)
    listed = pg_store.list_messages(query="Receipt")
    assert listed["total"] == 4
    assert all("raw" not in row and "parsed" not in row for row in listed["messages"])
    overview = pg_store.overview()
    assert overview["total_messages"] == 4 and overview["analyzed_messages"] == 2
    assert overview["review_needed"] == overview["reviewed_messages"] == 1
    assert overview["pending_messages"] == overview["error_messages"] == 1
    assert len(overview["recent_risks"]) == 1
    daily = {day["date"]: day for day in overview["daily"]}
    assert daily[today.date().isoformat()]["total"] == 3
    assert daily[(today - timedelta(days=1)).date().isoformat()]["phishing"] == 1
    settings = Settings()
    async def request_overview():
        app = create_app(settings, Pipeline(settings, store=pg_store))
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://testserver") as api:
            return await api.get("/api/overview")
    response = asyncio.run(request_overview())
    assert response.status_code == 200 and response.json() == overview


def test_postgres_stale_lease_cannot_commit_over_new_owner(pg_store):
    ingest(pg_store, "lease")
    stale = pg_store.claim()
    with pg_store.engine.begin() as db:
        db.execute(
            jobs.update()
            .where(jobs.c.id == stale["id"])
            .values(claimed_at=(datetime.now(UTC) - timedelta(minutes=11)).isoformat())
        )
    replacement = pg_store.claim()
    assert replacement["id"] == stale["id"]
    assert replacement["lease_token"] != stale["lease_token"]
    assert finish(pg_store, stale) is False
    assert finish(pg_store, replacement)
    assert count_rows(pg_store, runs) == 1


def test_postgres_mailbox_checkpoint_round_trip(pg_store):
    pg_store.update_mailbox("analyst@example.test", history_id="100", sync_summary={"complete": True})
    pg_store.update_mailbox("analyst@example.test", history_id="110", last_successful_poll=now())
    saved = pg_store.mailbox_state("analyst@example.test")
    assert saved["history_id"] == "110"
    assert saved["sync_summary"] == {"complete": True}
    assert saved["last_successful_poll"]


def test_postgres_scan_retry_schedule_does_not_block_other_jobs(pg_store):
    from mailsec.storage import scan_retries
    first = ingest(pg_store, 'retry-first')['id']
    job = pg_store.claim()
    assert pg_store.defer_scan(job, {}, {}, now(), 'Scanner unavailable')
    assert pg_store.claim() is None
    second = ingest(pg_store, 'ready-second')['id']
    other = pg_store.claim()
    assert other['message_id'] == second
    assert finish(pg_store, other)
    with pg_store.engine.begin() as db:
        db.execute(scan_retries.update().where(scan_retries.c.job_id == job['id']).values(
            next_attempt_at=(datetime.now(UTC) - timedelta(seconds=1)).isoformat()))
    retry = pg_store.claim()
    assert retry['message_id'] == first and retry['id'] == job['id']
    assert not pg_store.defer_scan(job, {}, {}, now(), 'Stale owner')
    assert finish(pg_store, retry)
    assert pg_store.detail(first)['scan_retry'] is None
    assert pg_store.status()['scan_retries']['pending'] == 0
