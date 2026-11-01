"""Real durable queue, simulated scanner failures; no external provider calls."""
from datetime import datetime, timedelta, timezone

import pytest
from privacy_helpers import authorize_test_provider
from sqlalchemy import select
from test_worker import RAW, FakeJev

from mailsec.config import Settings
from mailsec.inspection_client import scan_retry_reason, unavailable
from mailsec.pipeline import Pipeline
from mailsec.storage import jobs, runs, scan_retries


class Scanner:
    result = unavailable('busy')
    def inspect(self, raw):
        return self.result


def due(store, jid):
    with store.engine.begin() as db:
        db.execute(scan_retries.update().where(scan_retries.c.job_id == jid).values(
            next_attempt_at=(datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()))


def test_scanner_outage_survives_restart_and_recovers_without_premature_jev_or_actions(tmp_path):
    settings = Settings(database_url=f'sqlite:///{tmp_path / "retry.db"}', inspection_url='http://scanner')
    scanner, jev = Scanner(), FakeJev()
    p = Pipeline(settings, inspector=scanner, jev=jev)
    authorize_test_provider(settings, p.store)
    mid = p.ingest(RAW, provider='gmail', mailbox='analyst@example.test', provider_message_id='test')['id']
    result = p.process_one()
    assert result['status'] == 'retrying' and result['verdict'] is None
    assert not jev.calls
    detail = p.store.detail(mid)
    assert detail['message']['status'] == 'pending' and detail['message']['verdict'] is None
    assert detail['runs'][0]['output'] is None
    assert detail['runs'][0]['policy']['eligible_action'] == 'none'
    jid = detail['scan_retry']['job_id']
    assert p.store.enqueue(mid) == jid
    assert p.process_one() is None
    p.store.engine.dispose()
    # Retry schedule is in storage, not process memory.
    p = Pipeline(settings, inspector=scanner, jev=jev)
    assert p.process_one() is None
    for failures in (2, 3):
        due(p.store, jid)
        assert p.process_one()['status'] == 'retrying'
        row = p.store.detail(mid)['scan_retry']
        assert row['failures'] == failures
        wait = datetime.fromisoformat(row['next_attempt_at']) - datetime.now(timezone.utc)
        assert wait.total_seconds() >= 30 * 2 ** (failures - 1) - 1
    assert p.store.status()['scan_retries']['needs_attention'] == 1
    assert not jev.calls
    scanner.result = {'status':'complete', 'antivirus':{'status':'clean'}, 'findings':[], 'attachments':[], 'urls':[], 'coverage':{}}
    due(p.store, jid)
    assert p.process_one()['status'] == 'complete'
    assert jev.calls
    detail = p.store.detail(mid)
    assert detail['scan_retry'] is None
    assert len(detail['runs']) == 4
    assert p.store.status()['scan_retries']['pending'] == 0
    assert p.process_one() is None
    p.store.engine.dispose()


def test_lost_lease_cannot_defer_reclaimed_job(tmp_path):
    p = Pipeline(Settings(database_url=f'sqlite:///{tmp_path / "lease.db"}'), jev=FakeJev())
    p.ingest(RAW)
    first = p.store.claim()
    with p.store.engine.begin() as db:
        db.execute(jobs.update().where(jobs.c.id == first['id']).values(
            claimed_at=(datetime.now(timezone.utc) - timedelta(minutes=11)).isoformat()))
    second = p.store.claim()
    assert not p.store.defer_scan(first, {}, {}, '', 'retry')
    with p.store.engine.connect() as db:
        assert not db.execute(select(scan_retries)).first()
        assert not db.execute(select(runs)).first()
    assert p.store.defer_scan(second, {}, {}, '', 'retry')
    p.store.engine.dispose()


@pytest.mark.parametrize('status', ['unavailable', 'stale', 'error'])
def test_operational_failure_requires_retry(status):
    assert scan_retry_reason({'status':'partial', 'antivirus':{'status':status}})


def test_heuristic_review_is_not_retried_forever_and_does_not_hide_other_failures():
    heuristic = {'status':'error', 'detection_type':'heuristic_review'}
    assert scan_retry_reason({'status':'partial', 'antivirus':heuristic}) is None
    assert scan_retry_reason({'status':'partial', 'antivirus':heuristic,
        'attachments':[{'antivirus':{'status':'unavailable'}}]})


def test_confirmed_malware_is_not_delayed_by_partial_scanning():
    assert scan_retry_reason({'status':'partial', 'antivirus':{'status':'malicious'},
        'attachments':[{'antivirus':{'status':'unavailable'}}]}) is None


def test_configured_url_provider_failure_defers_before_paid_analysis(tmp_path):
    class Reputation:
        def inspect(self, urls):
            return {'results':[{'status':'unavailable', 'malicious':False}], 'complete':False}
    scanner = Scanner()
    scanner.result = {'status':'complete','antivirus':{'status':'clean'},'findings':[],'urls':[]}
    jev = FakeJev()
    p = Pipeline(Settings(database_url=f'sqlite:///{tmp_path / "urls.db"}',
        inspection_url='http://scanner', web_risk_api_key='test'), inspector=scanner, jev=jev, reputation=Reputation())
    authorize_test_provider(p.settings, p.store)
    p.ingest(RAW)
    assert p.process_one()['status'] == 'retrying'
    assert not jev.calls
    assert p.store.status()['scan_retries']['pending'] == 1
    p.store.engine.dispose()
