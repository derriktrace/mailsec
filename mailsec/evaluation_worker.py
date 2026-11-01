"""Bounded evaluation workers; no Gmail polling, actions or notification access."""
import logging
import os
import signal
import threading
from concurrent.futures import ThreadPoolExecutor

from .config import Settings
from .pipeline import Pipeline
from .worker import run_worker


def main():
    os.umask(0o077)
    logging.basicConfig(level=logging.INFO,format='%(asctime)s %(levelname)s %(message)s')
    settings = Settings.load()
    if not settings.evaluation_mode:
        raise ValueError('This worker requires an evaluation workspace')
    # Initialize tables before starting concurrent connections.
    pipeline = Pipeline(settings)
    pipeline.cache.status()
    from .mailbox_actions import metadata as action_metadata
    action_metadata.create_all(pipeline.store.engine)
    from .accounts import metadata as account_metadata
    account_metadata.create_all(pipeline.store.engine)
    stop = threading.Event()
    signal.signal(signal.SIGTERM,lambda *_:stop.set())
    signal.signal(signal.SIGINT,lambda *_:stop.set())
    workers = min(16,max(1,int(os.getenv('MAILSEC_EVALUATION_WORKERS','4'))))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(run_worker,Settings.load(),stop) for _ in range(workers)]
        for future in futures:
            future.result()


if __name__ == '__main__':
    main()
