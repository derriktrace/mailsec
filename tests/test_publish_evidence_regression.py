import hashlib
import importlib.util
import json
from pathlib import Path

import pytest
from sqlalchemy import select

from mailsec.config import Settings
from mailsec.corpus import metadata as corpus_metadata
from mailsec.corpus import samples
from mailsec.storage import Store, jobs, messages, now, runs

spec = importlib.util.spec_from_file_location('regression_publisher', Path(__file__).parents[1] / 'scripts/publish_evidence_regression.py')
publisher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publisher)
QUESTIONS = {'verdict': {'type': 'choice', 'criteria': {key: key for key in ('clean', 'spam', 'suspicious', 'phishing')}}}
OUTPUT = {'model': 'test-model', 'usage': {'input_tokens': 10, 'output_tokens': 2}, 'answers': {
    'verdict': {'type': 'choice', 'choice': 'clean', 'confidence': 1.,
                'probabilities': {'clean': 1., 'spam': 0., 'suspicious': 0., 'phishing': 0.}}}}


def seal(root, rows):
    plan = {'selected': [row['sha256'] for row in rows], 'questions': QUESTIONS, 'kind': 'synthetic development regression'}
    files = []
    for row in rows:
        data = json.dumps(row).encode()
        (root / (row['sha256'] + '.json')).write_bytes(data)
        files.append([row['sha256'], hashlib.sha256(data).hexdigest()])
    value = {'plan_sha256': publisher.digest(plan), 'files': files, 'summary': {
        'status': {'complete': len(rows)}, 'result_seal_sha256': publisher.digest(files)}}
    (root / 'plan.json').write_text(json.dumps(plan))
    (root / 'seal.json').write_text(json.dumps(value))


@pytest.fixture
def regression(tmp_path):
    settings = Settings(database_url=f'sqlite:///{tmp_path / "evaluation.db"}',
                        evaluation_mode=True, tenant_id='evaluation-phishing-pot')
    store = Store(settings.database_url)
    corpus_metadata.create_all(store.engine)
    root = tmp_path / 'sealed'
    root.mkdir()
    rows = []
    for index in range(2):
        raw = f'Subject: Synthetic {index}\r\n\r\nFixture'.encode()
        sha = hashlib.sha256(raw).hexdigest()
        evidence = {'message': {'subject': f'Synthetic {index}', 'sender': {}},
                    'source_integrity': {'raw_sha256': sha}}
        item = store.ingest(raw, evidence)
        policy = {'verdict': 'clean', 'mode': 'passive', 'eligible_action': 'none', 'executed_action': 'none'}
        store.finish(store.claim(), evidence, OUTPUT, policy, {'baseline': True}, QUESTIONS, now())
        with store.engine.begin() as db:
            db.execute(samples.insert().values(source_sha256=sha, message_id=item['id'], revision='test',
                filename=f'fixture-{index}.eml', batch=1, reference_label='unreviewed'))
        rows.append({'id': item['id'], 'sha256': sha, 'status': 'complete', 'evidence': evidence,
            'output': OUTPUT, 'policy': {**policy, 'verdict': 'suspicious'}, 'versions': {'engine': 'test'}})
    seal(root, rows)
    yield root, settings, store, rows
    store.engine.dispose()


def snapshot(store):
    with store.engine.connect() as db:
        return {table.name: [dict(row) for row in db.execute(select(table).order_by(*table.primary_key.columns)).mappings()]
                for table in (messages, jobs, runs, samples)}


def test_publisher_is_idempotent_and_preserves_raw_original_runs_and_provenance(regression):
    root, settings, store, rows = regression
    before = snapshot(store)
    first = publisher.publish(root, settings)
    assert first['appended'] == 2 and first['mailbox_actions'] == 0
    after = snapshot(store)
    assert len(after['analysis_runs']) == len(after['analysis_jobs']) == 4
    assert all(row in after['analysis_runs'] for row in before['analysis_runs'])
    assert after['corpus_samples'] == before['corpus_samples']
    for old, new in zip(before['messages'], after['messages'], strict=True):
        assert new['raw'] == old['raw'] and new['raw_sha256'] == old['raw_sha256']
        assert new['run_count'] == old['run_count'] + 1 and new['verdict'] == 'suspicious'
    second = publisher.publish(root, settings)
    assert second['appended'] == 0 and second['already_published'] == 2
    assert snapshot(store) == after


@pytest.mark.parametrize('wrong', ['main', 'tenant', 'active_mode'])
def test_rejects_customer_workspace_before_accessing_artifacts(regression, wrong):
    root, settings, store, _ = regression
    before = snapshot(store)
    if wrong == 'main':
        settings.evaluation_mode = False
    elif wrong == 'tenant':
        settings.tenant_id = 'trace-technology-group'
    else:
        settings.enforcement_mode = 'auto_quarantine'
    with pytest.raises(ValueError, match='restricted'):
        publisher.publish(root / 'does-not-exist', settings)
    assert snapshot(store) == before


@pytest.mark.parametrize('bad', ['plan', 'file', 'seal_identity', 'duplicates', 'unsafe_action'])
def test_rejects_bad_seals_and_unsafe_results_without_writes(regression, bad):
    root, settings, store, rows = regression
    if bad == 'plan':
        (root / 'plan.json').write_text('{}')
    elif bad == 'file':
        path = root / (rows[0]['sha256'] + '.json')
        path.write_bytes(path.read_bytes() + b' ')
    elif bad == 'seal_identity':
        value = json.loads((root / 'seal.json').read_text())
        value['summary']['result_seal_sha256'] = '0' * 64
        (root / 'seal.json').write_text(json.dumps(value))
    elif bad == 'duplicates':
        seal(root, rows + rows[:1])
    else:
        rows[0]['policy']['eligible_action'] = 'quarantine'
        seal(root, rows)
    before = snapshot(store)
    with pytest.raises(ValueError):
        publisher.publish(root, settings)
    assert snapshot(store) == before


@pytest.mark.parametrize('bad', ['raw_bytes', 'raw_hash', 'provenance', 'gmail', 'active_job'])
def test_late_integrity_failure_rolls_back_every_prior_append(regression, bad):
    root, settings, store, rows = regression
    last = rows[-1]['id']
    with store.engine.begin() as db:
        if bad == 'raw_bytes':
            db.execute(messages.update().where(messages.c.id == last).values(raw=b'changed after import'))
        elif bad == 'raw_hash':
            db.execute(messages.update().where(messages.c.id == last).values(raw_sha256='0' * 64))
        elif bad == 'provenance':
            db.execute(samples.delete().where(samples.c.message_id == last))
        elif bad == 'gmail':
            db.execute(messages.update().where(messages.c.id == last).values(provider='gmail'))
        else:
            db.execute(jobs.update().where(jobs.c.message_id == last).values(status='pending'))
    before = snapshot(store)
    with pytest.raises(ValueError):
        publisher.publish(root, settings)
    assert snapshot(store) == before
