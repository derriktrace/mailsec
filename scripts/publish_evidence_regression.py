"""Append a sealed passive regression to the isolated evaluation workspace only."""
import argparse
import hashlib
import json
import re
from pathlib import Path

from sqlalchemy import func, inspect, select

from mailsec.config import Settings
from mailsec.corpus import samples
from mailsec.jev import validate_response
from mailsec.storage import Store, jobs, messages, new_id, now, runs


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def publish(root, settings):
    if (not settings.evaluation_mode or settings.tenant_id != 'evaluation-phishing-pot'
            or settings.enforcement_mode != 'passive'):
        raise ValueError('This publisher is restricted to the passive Phishing Pot workspace')
    root = Path(root)
    plan = json.loads((root / 'plan.json').read_text())
    seal = json.loads((root / 'seal.json').read_text())
    if digest(plan) != seal['plan_sha256'] or seal['summary']['status'] != {'complete': len(seal['files'])}:
        raise ValueError('Only a complete sealed run may be published')
    if digest(seal['files']) != seal['summary']['result_seal_sha256']:
        raise ValueError('Result seal identity mismatch')
    if (len(plan['selected']) != len(set(plan['selected']))
            or len(seal['files']) != len({item[0] for item in seal['files']})):
        raise ValueError('Duplicate regression membership')
    values = []
    for sha, saved_hash in seal['files']:
        if not re.fullmatch('[0-9a-f]{64}', sha) or not re.fullmatch('[0-9a-f]{64}', saved_hash):
            raise ValueError('Invalid sealed file identity')
        data = (root / (sha + '.json')).read_bytes()
        if hashlib.sha256(data).hexdigest() != saved_hash:
            raise ValueError('Prediction seal mismatch')
        row = json.loads(data)
        if (row['sha256'] != sha or row['status'] != 'complete'
                or row['policy']['eligible_action'] != 'none' or row['policy']['mode'] != 'passive'
                or row['policy'].get('executed_action') != 'none'
                or row['policy'].get('verdict') not in ('clean', 'spam', 'suspicious', 'phishing')
                or row['evidence'].get('source_integrity', {}).get('raw_sha256') != sha):
            raise ValueError('Unsafe or invalid evaluation result')
        validate_response(row['output'], plan['questions'])
        values.append(row)
    if {r['sha256'] for r in values} != set(plan['selected']) or len({r['id'] for r in values}) != len(values):
        raise ValueError('Plan membership mismatch')
    store = Store(settings.database_url)
    if not inspect(store.engine).has_table(samples.name):
        store.engine.dispose()
        raise ValueError('Evaluation corpus provenance is missing')
    seal_id = seal['summary']['result_seal_sha256']
    appended = skipped = 0
    with store.engine.begin() as db:
        if db.dialect.name == 'postgresql':
            db.exec_driver_sql('LOCK TABLE analysis_jobs IN SHARE ROW EXCLUSIVE MODE')
        elif db.dialect.name == 'sqlite':
            db.exec_driver_sql('BEGIN IMMEDIATE')
        if db.execute(select(func.count()).select_from(jobs).where(jobs.c.status.in_(['pending', 'processing']))).scalar_one():
            raise ValueError('Stop evaluation workers and finish active jobs before publishing')
        for row in values:
            message = db.execute(select(messages.c.raw_sha256, messages.c.provider, messages.c.raw)
                                 .where(messages.c.id == row['id']).with_for_update()).one()
            provenance = db.execute(select(samples.c.source_sha256).where(samples.c.message_id == row['id'])).scalar_one_or_none()
            if (message.raw_sha256 != row['sha256'] or message.provider == 'gmail'
                    or hashlib.sha256(message.raw).hexdigest() != row['sha256'] or provenance != row['sha256']):
                raise ValueError('Evaluation message integrity/provenance mismatch')
            existing = db.execute(select(runs.c.versions).where(runs.c.message_id == row['id'])).scalars()
            if any((version or {}).get('regression_seal') == seal_id for version in existing):
                skipped += 1
                continue
            job_id, run_id, timestamp = new_id(), new_id(), now()
            version = {**row['versions'], 'regression_seal': seal_id,
                       'regression_kind': plan['kind'], 'regression_plan_sha256': seal['plan_sha256']}
            db.execute(jobs.insert().values(id=job_id, message_id=row['id'], status='complete',
                created_at=timestamp, claimed_at=timestamp, attempts=1))
            db.execute(runs.insert().values(id=run_id, message_id=row['id'], job_id=job_id,
                created_at=timestamp, completed_at=timestamp, status='complete', evidence=row['evidence'],
                output=row['output'], policy=row['policy'], versions=version, questions=plan['questions']))
            db.execute(messages.update().where(messages.c.id == row['id']).values(status='complete',
                verdict=row['policy']['verdict'], confidence=None if row['policy'].get('verdict_review_basis') == 'action_authority_gap'
                else row['output']['answers']['verdict']['confidence'],
                run_count=messages.c.run_count + 1))
            appended += 1
    store.engine.dispose()
    return {'appended': appended, 'already_published': skipped,
            'prior_runs_retained': True, 'mailbox_actions': 0, 'regression_seal': seal_id}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('results')
    args = parser.parse_args()
    print(json.dumps(publish(args.results, Settings.load())))


if __name__ == '__main__':
    main()
