"""Import inert RFC email files into an explicitly isolated evaluation store."""
import argparse
import hashlib
import json
from email.errors import HeaderParseError
from pathlib import Path

from sqlalchemy import select

from .config import Settings
from .corpus import corpus_status, metadata, samples
from .pipeline import Pipeline


def import_corpus(root, revision, pipeline):
    if not pipeline.settings.evaluation_mode:
        raise ValueError('Corpus import requires an evaluation workspace')
    metadata.create_all(pipeline.store.engine)
    files = sorted(root.rglob('*.eml'))
    # Order by content hash, not source filename, label or campaign folder.
    candidates = []
    skipped = []
    for path in files:
        if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(root.resolve()):
            skipped.append({'file':str(path.relative_to(root)), 'reason':'not a regular in-root file'})
            continue
        if not 0 < path.stat().st_size <= pipeline.settings.max_message_bytes:
            skipped.append({'file':str(path.relative_to(root)), 'reason':'outside message size limits'})
            continue
        candidates.append((hashlib.sha256(path.read_bytes()).hexdigest(), path))
    candidates.sort(key=lambda item:item[0])
    duplicate_files, imported = 0, 0
    seen = set()
    for sha,path in candidates:
        if sha in seen:
            duplicate_files += 1
            continue
        seen.add(sha)
        with pipeline.store.engine.connect() as db:
            existing = db.execute(select(samples.c.message_id).where(samples.c.source_sha256==sha)).scalar_one_or_none()
        if existing:
            continue
        try:
            result = pipeline.ingest(path.read_bytes(), provider='eml', mailbox='')
        except (ValueError,RecursionError,AttributeError,IndexError,HeaderParseError):
            # Preserve malformed input and queue it for antivirus + explicit
            # analysis failure/review, rather than dropping it or aborting a run.
            result = pipeline.store.ingest(path.read_bytes(),
                {'message':{'subject':'[Message requires manual parsing]','sender':{}},
                 'quality':{'parsing_failed':True}},provider='eml',mailbox='')
        with pipeline.store.engine.begin() as db:
            db.execute(samples.insert().values(source_sha256=sha,message_id=result['id'],revision=revision,
                filename=str(path.relative_to(root)),batch=(len(seen)-1)//250+1,reference_label='unreviewed'))
        imported += 1
    return {'files_found':len(files),'newly_imported':imported,'exact_duplicate_files':duplicate_files,
            'skipped':skipped, **corpus_status(pipeline.store)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('root',type=Path)
    parser.add_argument('--revision',required=True)
    args = parser.parse_args()
    print(json.dumps(import_corpus(args.root,args.revision,Pipeline(Settings.load()))))


if __name__ == '__main__':
    main()
