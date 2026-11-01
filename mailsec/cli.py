import argparse
import json
import os
import sys
from pathlib import Path

from sqlalchemy import select

from .config import Settings
from .demo import CASES, samples
from .pipeline import Pipeline
from .storage import messages


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description="Jev email security pilot")
    commands = parser.add_subparsers(dest="command", required=True)
    serve = commands.add_parser("serve", help="Start the local UI and an embedded worker")
    serve.add_argument("--port", type=int, default=8025)
    serve.add_argument("--host", help="Listening address; defaults to MAILSEC_BIND_HOST or 127.0.0.1")
    serve.add_argument("--no-worker", action="store_true")
    commands.add_parser("worker", help="Run the standalone ingestion/analysis worker")
    analyze = commands.add_parser("analyze-eml", help="Import and analyze one EML or a directory")
    analyze.add_argument("path", type=Path)
    analyze.add_argument("--mailbox", default="")
    analyze.add_argument("--queue-only", action="store_true")
    commands.add_parser("demo", help="Analyze synthetic samples with LIVE Jev")
    replay = commands.add_parser("replay", help="Reparse and reanalyze stored originals; preserve earlier runs")
    replay.add_argument("--from", dest="start", default="")
    replay.add_argument("--to", dest="end", default="")
    replay.add_argument("--limit", type=int, default=100)
    replay.add_argument("--queue-only", action="store_true")
    commands.add_parser("status", help="Show safe configuration and processing status")
    commands.add_parser("evaluation", help="Export feedback-based confusion matrix")
    commands.add_parser("sync", help="Perform one Gmail polling pass and analyze queued mail")
    export = commands.add_parser("export", help="Export the evidence and all runs for a message")
    export.add_argument("message_id")
    export.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    settings = Settings.load()
    if args.command == "serve":
        import uvicorn

        from .api import create_app
        settings.embedded_worker = not args.no_worker
        host = args.host or settings.bind_host
        try:
            settings.validate_bind(host)
        except ValueError as exc:
            parser.error(str(exc))
        uvicorn.run(create_app(settings), host=host, port=args.port, access_log=False, server_header=False)
        return
    if args.command == "worker":
        from .worker import main as worker_main
        worker_main()
        return
    pipeline = Pipeline(settings)
    if args.command == "status":
        from .accounts import connected_mailboxes
        from .model_setup import model_status
        from .runtime_controls import refresh_controls
        refresh_controls(settings,pipeline.store)
        model = model_status(settings, pipeline.store)
        connections = connected_mailboxes(settings,pipeline.store)
        result = {"mode": settings.enforcement_mode, "key_configured": model['configured'], "model": model['model'],
            "decision": model,
            "google_configured": bool(connections),
            "mailboxes": [pipeline.store.mailbox_state(m) for m in connections], **pipeline.store.status()}
    elif args.command == "evaluation":
        result = pipeline.store.evaluation()
    elif args.command == "export":
        result = pipeline.store.detail(args.message_id)
        if not result:
            parser.error("Message not found")
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump(result, stream, indent=2)
        print(f"Saved {args.output}")
        return
    elif args.command == "sync":
        from .accounts import connected_mailboxes
        if not connected_mailboxes(settings,pipeline.store):
            parser.error("Connect an explicitly authorized Gmail account in the console first; see docs/google-workspace.md")
        from .worker import poll_gmail
        poll_gmail(pipeline)
        from .mailbox_actions import apply_pending_actions, reconcile_committed_actions
        result = {"mailboxes": [pipeline.store.mailbox_state(m) for m in connected_mailboxes(settings,pipeline.store)], "analyses": pipeline.drain()}
        reconcile_committed_actions(settings,pipeline.store)
        result["actions"] = apply_pending_actions(settings,pipeline.store)
    elif args.command == "analyze-eml":
        paths = sorted(args.path.glob("*.eml")) if args.path.is_dir() else [args.path]
        if not paths:
            parser.error("No .eml files found")
        result = {"imports": [pipeline.ingest(p.read_bytes(), mailbox=args.mailbox, provider="eml") for p in paths]}
        if not args.queue_only:
            result["analyses"] = pipeline.drain()
    elif args.command == "demo":
        result = {"source": "synthetic fixtures; not a real-world accuracy benchmark", "imports": []}
        for name, raw in samples():
            result["imports"].append({"sample": name, **pipeline.ingest(raw, mailbox="analyst@example.org", provider="demo")})
        result["analyses"] = pipeline.drain()
        result["expected_labels"] = {case[0]: case[4] for case in CASES}
    else:
        if args.limit < 1:
            parser.error("Replay limit must be positive")
        stmt = select(messages.c.id).order_by(messages.c.received_at)
        if args.start:
            stmt = stmt.where(messages.c.received_at >= args.start)
        if args.end:
            stmt = stmt.where(messages.c.received_at < args.end)
        with pipeline.store.engine.connect() as db:
            ids = list(db.execute(stmt.limit(args.limit)).scalars())
        result = {"queued": [pipeline.store.enqueue(mid) for mid in ids], "limit": args.limit}
        if not args.queue_only:
            result["analyses"] = pipeline.drain(args.limit)
    if getattr(pipeline, 'analysis_paused_reason', None) == 'awaiting_privacy_consent':
        result['analysis_paused'] = True
        result['pause_reason'] = 'Accept the email-sharing disclosure, then save the provider and masking choice in the console. Queued mail is preserved.'
    print(json.dumps(result, indent=2))
    if any(r.get("status") == "error" for r in result.get("analyses", [])):
        sys.exit(1)


if __name__ == "__main__":
    main()
