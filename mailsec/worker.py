import logging
import os
import signal
import threading
import time
import uuid

from .config import Settings, configuration_snapshot
from .pipeline import Pipeline
from .storage import now

log = logging.getLogger("mailsec.worker")


def poll_gmail(pipeline):
    if pipeline.settings.evaluation_mode:
        return
    from .accounts import connected_mailboxes, gmail_client
    from .gmail import GmailAuthorizationError, GmailError, sync_mailbox
    from .mailbox_actions import is_notification, notification_delivery_in_progress
    settings = pipeline.settings
    for mailbox in connected_mailboxes(settings,pipeline.store):
        try:
            if notification_delivery_in_progress(pipeline.store,mailbox):
                pipeline.store.update_mailbox(mailbox,last_error='A notification send is awaiting reconciliation; polling is paused to prevent notification loops.')
                continue
            def ingest(raw,**source):
                if is_notification(pipeline.store,source.get('mailbox',mailbox),source.get('provider_message_id','')):
                    return {'id':source['provider_message_id'],'duplicate':True}
                return pipeline.ingest(raw,**source)
            with gmail_client(settings,pipeline.store,mailbox) as client:
                state = pipeline.store.mailbox_state(mailbox)
                summary = sync_mailbox(client, state.get("history_id"), ingest=ingest,
                    save_cursor=lambda cursor: pipeline.store.update_mailbox(mailbox, history_id=cursor),
                    initial_query=settings.initial_query, max_initial_messages=settings.max_initial_messages,
                    resume=(state.get("sync_summary") or {}).get("backfill_resume"))
                complete = summary.get("complete", True)
                # A saved continuation is normal progress, not a connection error.
                values = {"sync_summary": summary, "last_error": None}
                if complete:
                    values["last_successful_poll"] = now()
                pipeline.store.update_mailbox(mailbox, **values)
        except Exception as exc:
            error = (str(exc) if isinstance(exc, GmailAuthorizationError) else
                     "Gmail temporarily rate-limited requests; the next poll retries from the saved checkpoint."
                     if isinstance(exc, GmailError) and exc.rate_limited else
                     f"Gmail sync failed ({type(exc).__name__})")
            pipeline.store.update_mailbox(mailbox, last_error=error)
            log.warning("Gmail sync failed (%s)", type(exc).__name__)


def run_worker(settings=None, stop=None):
    settings = settings or Settings.load()
    settings = configuration_snapshot(settings)
    stop = stop or threading.Event()
    pipeline = Pipeline(settings)
    worker_id = f"{os.getpid()}-{uuid.uuid4().hex[:8]}"
    pipeline.worker_id = worker_id
    next_poll = 0
    next_prune = 0
    while not stop.is_set():
        try:
            from .mailbox_actions import apply_pending_actions, reconcile_committed_actions
            from .runtime_controls import refresh_controls
            refresh_controls(settings,pipeline.store)
            pipeline.store.heartbeat(worker_id, "working")
            if time.monotonic() >= next_poll:
                poll_gmail(pipeline)
                next_poll = time.monotonic() + settings.poll_seconds
            if time.monotonic() >= next_prune:
                pipeline.cache.prune()
                next_prune = time.monotonic()+3600
            result = pipeline.process_one()
            if stop.is_set():
                break
            if not settings.evaluation_mode:
                reconcile_committed_actions(settings,pipeline.store)
                apply_pending_actions(settings,pipeline.store)
            pipeline.store.heartbeat(worker_id, (getattr(pipeline, 'analysis_paused_reason', None) or "idle")
                                     if result is None else result["status"])
            if result:
                log.info("Analysis %s: %s", result["message_id"], result["status"])
            else:
                stop.wait(2)
        except Exception as exc:
            log.error("Worker iteration failed (%s)", type(exc).__name__)
            stop.wait(5)
    pipeline.store.heartbeat(worker_id, "stopped")


def main():
    os.umask(0o077)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    run_worker(stop=stop)


if __name__ == "__main__":
    main()
