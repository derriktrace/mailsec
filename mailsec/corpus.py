"""Evaluation provenance stays outside the model's evidence and mailbox store."""
import re
from collections import Counter

from sqlalchemy import Column, Integer, MetaData, String, Table, select

from .storage import messages

metadata = MetaData()
samples = Table('corpus_samples', metadata,
    Column('source_sha256', String(64), primary_key=True),
    Column('message_id', String(32), nullable=False, unique=True),
    Column('revision', String(64), nullable=False),
    Column('filename', String(400), nullable=False),
    Column('batch', Integer, nullable=False),
    Column('reference_label', String(40), nullable=False, default='unreviewed'))


def blind_evidence(evidence):
    """Neutralize the publisher's explicit recipient marker, not attack language.

    Runs retain original bytes/evidence. Replacement occurs after MIME decoding
    and document extraction, only in the provider input. No source filenames,
    directory names, dataset labels or reference labels are sent to Jev.
    """
    def visit(value):
        if isinstance(value, dict):
            return {key:visit(item) for key,item in value.items()}
        if isinstance(value, list):
            return [visit(item) for item in value]
        if isinstance(value, str):
            return re.sub(r'phishing(?:@|%40)pot', 'recipient@example.invalid', value, flags=re.I)
        return value
    return visit(evidence)


def corpus_status(store):
    metadata.create_all(store.engine)
    with store.engine.connect() as db:
        rows = list(db.execute(select(samples.c.batch, samples.c.revision,
            samples.c.reference_label, messages.c.status, messages.c.verdict)
            .join(messages,messages.c.id==samples.c.message_id)).mappings())
    batches = {}
    batch_summary = {}
    for row in rows:
        batches.setdefault(row['batch'], []).append(row['status'])
        summary = batch_summary.setdefault(row['batch'], {'batch':row['batch'],'date':f"Batch {row['batch']}",'total':0})
        summary['total'] += 1
        key = row['verdict'] if row['status']=='complete' else 'error' if row['status']=='error' else 'pending'
        summary[key] = summary.get(key,0)+1
    return {'source':'https://github.com/rf-peixoto/phishing_pot',
            'revisions':sorted({row['revision'] for row in rows}),
            'imported':len(rows), 'completed':sum(row['status']=='complete' for row in rows),
            'errors':sum(row['status']=='error' for row in rows),
            'batches':len(batches),
            'batch_summary':[batch_summary[key] for key in sorted(batch_summary)],
            'batches_complete':sum(all(status=='complete' for status in statuses) for statuses in batches.values()),
            'verdicts':dict(Counter(row['verdict'] for row in rows if row['status']=='complete')),
            'reference_labels':dict(Counter(row['reference_label'] for row in rows)),
            'accuracy':None,
            'limitations':['Source membership is not verified ground truth; no accuracy claim.',
                           'Imported authentication headers are unverified. No organization or mailbox history is assumed.',
                           'Original evidence is retained; the publisher recipient marker is neutralized only in model input.']}
