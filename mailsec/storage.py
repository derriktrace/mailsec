"""Small durable queue and append-only analysis history, SQLite or PostgreSQL."""
import hashlib
import threading
import time
import uuid
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

from sqlalchemy import (
    JSON,
    Column,
    Float,
    Index,
    Integer,
    LargeBinary,
    MetaData,
    String,
    Table,
    Text,
    and_,
    create_engine,
    event,
    func,
    or_,
    select,
    update,
)
from sqlalchemy.exc import IntegrityError


def now():
    return datetime.now(timezone.utc).isoformat()


def new_id():
    return uuid.uuid4().hex


class JobLeaseLost(Exception):
    """Ownership could not be renewed; never carries database error details."""


class JobLease:
    def __init__(self):
        self.lost = threading.Event()
        self.thread = None
        self.confirmed_at = None

    def check(self):
        # A wedged database renewal must not leave a stale owner sending more
        # sections indefinitely. Stop before the ten-minute reclaim threshold.
        if self.confirmed_at is None or time.monotonic() - self.confirmed_at >= 300:
            self.lost.set()
        if self.lost.is_set():
            raise JobLeaseLost('Analysis lease ownership could not be confirmed')


metadata = MetaData()
messages = Table("messages", metadata,
    Column("id", String(32), primary_key=True), Column("source_key", String(64), unique=True, nullable=False),
    Column("provider", String(20)), Column("provider_message_id", Text), Column("provider_thread_id", Text),
    Column("mailbox", Text), Column("raw", LargeBinary, nullable=False), Column("raw_sha256", String(64)),
    Column("subject", Text), Column("from_address", Text), Column("from_name", Text), Column("root_domain", Text),
    Column("received_at", String(40), index=True), Column("created_at", String(40)),
    Column("status", String(20), index=True), Column("verdict", String(20), index=True),
    Column("confidence", Float), Column("parsed", JSON), Column("run_count", Integer, default=0))
jobs = Table("analysis_jobs", metadata,
    Column("id", String(32), primary_key=True), Column("message_id", String(32), nullable=False, index=True),
    Column("status", String(20), nullable=False, index=True), Column("created_at", String(40)),
    Column("claimed_at", String(40)), Column("lease_token", String(32)), Column("attempts", Integer, default=0))
Index("one_active_job_per_message", jobs.c.message_id, unique=True,
      sqlite_where=jobs.c.status.in_(["pending", "processing"]),
      postgresql_where=jobs.c.status.in_(["pending", "processing"]))
scan_retries = Table("analysis_scan_retries", metadata,
    Column("job_id", String(32), primary_key=True),
    Column("failures", Integer, nullable=False), Column("first_failure_at", String(40)),
    Column("next_attempt_at", String(40), nullable=False, index=True), Column("reason", Text))
runs = Table("analysis_runs", metadata,
    Column("id", String(32), primary_key=True), Column("message_id", String(32), nullable=False, index=True),
    Column("job_id", String(32)), Column("created_at", String(40)), Column("completed_at", String(40)),
    Column("status", String(20)), Column("evidence", JSON), Column("output", JSON),
    Column("policy", JSON), Column("versions", JSON), Column("questions", JSON), Column("error", Text))
feedback = Table("feedback", metadata,
    Column("id", String(32), primary_key=True), Column("message_id", String(32), nullable=False, index=True),
    Column("run_id", String(32)), Column("system_verdict", String(20)), Column("verdict", String(20)),
    Column("reviewer", String(120)), Column("reason", Text), Column("created_at", String(40)))
analyst_overrides = Table("analyst_overrides", metadata,
    Column("message_id", String(32), primary_key=True), Column("review_id", String(32), nullable=False),
    Column("verdict", String(20), nullable=False), Column("reviewer", String(120)),
    Column("reason", Text), Column("created_at", String(40)))
mailboxes = Table("mailboxes", metadata,
    Column("mailbox", String(320), primary_key=True), Column("history_id", String(80)),
    Column("last_successful_poll", String(40)), Column("last_error", Text), Column("sync_summary", JSON))
heartbeats = Table("worker_heartbeats", metadata,
    Column("id", String(80), primary_key=True), Column("last_seen", String(40)), Column("state", String(40)))


PUBLIC_FIELDS = ("id", "provider", "provider_message_id", "provider_thread_id", "mailbox", "subject",
                 "from_address", "from_name", "received_at", "created_at", "status", "verdict",
                 "confidence", "run_count", "raw_sha256")


def public_message(row):
    result = {k: row[k] for k in PUBLIC_FIELDS}
    result["system_verdict"] = row["verdict"]
    result["system_confidence"] = row["confidence"]
    override = row.get("analyst_override")
    if row.get("override_review_id"):
        override = {key: row["override_" + key] for key in
                    ("review_id", "verdict", "reviewer", "reason", "created_at")}
    result["analyst_override"] = override or None
    if override:
        result["verdict"] = override["verdict"]
        # A person's correction has no model probability or confidence score.
        result["confidence"] = None
    return result


def _message_source():
    return messages.outerjoin(analyst_overrides, analyst_overrides.c.message_id == messages.c.id)


def _effective_verdict():
    return func.coalesce(analyst_overrides.c.verdict, messages.c.verdict)


def _public_select():
    return select(*(messages.c[k] for k in PUBLIC_FIELDS),
                  *(analyst_overrides.c[k].label("override_" + k) for k in
                    ("review_id", "verdict", "reviewer", "reason", "created_at"))).select_from(_message_source())


class Store:
    def __init__(self, url):
        self.engine = create_engine(url, connect_args={"check_same_thread": False, "timeout": 30}
                                    if url.startswith("sqlite") else {}, pool_pre_ping=True)
        if url.startswith("sqlite"):
            @event.listens_for(self.engine, "connect")
            def sqlite_setup(connection, _):
                connection.execute("PRAGMA journal_mode=WAL")
                connection.execute("PRAGMA foreign_keys=ON")
        metadata.create_all(self.engine)
        for index in jobs.indexes:
            index.create(self.engine, checkfirst=True)

    def ingest(self, raw, parsed, rejection_reason=None, rejection_policy=None, **source):
        digest = hashlib.sha256(raw).hexdigest()
        mailbox = source.get("mailbox", "").strip().lower()
        provider = source.get("provider", "eml")
        provider_id = source.get("provider_message_id") or digest
        source_key = hashlib.sha256(f"{provider}\0{mailbox}\0{provider_id}".encode()).hexdigest()
        msg = parsed["message"]
        received = source.get("received_at") or msg.get("received_at") or now()
        try:
            received_dt = received if isinstance(received, datetime) else datetime.fromisoformat(received)
            if received_dt.tzinfo is None:
                received_dt = received_dt.replace(tzinfo=timezone.utc)
            received = received_dt.astimezone(timezone.utc).isoformat(timespec="microseconds")
        except (ValueError, TypeError):
            received = now()
        sender = msg.get("sender", {})
        mid, jid = new_id(), new_id()
        try:
            with self.engine.begin() as db:
                db.execute(messages.insert().values(id=mid, source_key=source_key, provider=provider,
                    provider_message_id=provider_id, provider_thread_id=source.get("provider_thread_id"),
                    mailbox=mailbox, raw=raw, raw_sha256=digest, subject=msg.get("subject", "(no subject)"),
                    from_address=sender.get("address", ""), from_name=sender.get("display_name", ""),
                    root_domain=sender.get("root_domain", ""), received_at=received,
                    created_at=now(), status="error" if rejection_reason else "pending", parsed=parsed,
                    run_count=1 if rejection_reason else 0))
                if rejection_reason:
                    db.execute(runs.insert().values(id=new_id(), message_id=mid, created_at=now(),
                        completed_at=now(), status="error", evidence=parsed, policy=rejection_policy, error=rejection_reason,
                        versions={"engine": "0.2.0", "stage": "ingestion"}))
                else:
                    db.execute(jobs.insert().values(id=jid, message_id=mid, status="pending", created_at=now(), attempts=0))
        except IntegrityError:
            with self.engine.connect() as db:
                existing = db.execute(select(messages.c.id).where(messages.c.source_key == source_key)).scalar_one_or_none()
            if existing:
                return {"id": existing, "duplicate": True}
            raise
        return {"id": mid, "job_id": None if rejection_reason else jid, "duplicate": False,
                **({"rejected": True} if rejection_reason else {})}

    def get_message(self, mid):
        with self.engine.connect() as db:
            row = db.execute(select(messages).where(messages.c.id == mid)).mappings().first()
            if not row:
                return None
            result = dict(row)
            override = db.execute(select(analyst_overrides)
                .where(analyst_overrides.c.message_id == mid)).mappings().first()
            result['analyst_override'] = dict(override) if override else None
            return result

    def get_analyst_override(self, mid):
        with self.engine.connect() as db:
            row = db.execute(select(analyst_overrides)
                .where(analyst_overrides.c.message_id == mid)).mappings().first()
            return dict(row) if row else None

    def list_messages(self, query="", verdict="", limit=200, offset=0):
        # Lists never load MIME bodies/attachments from the database.
        statement = _public_select()
        if query:
            pattern = "%" + query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            statement = statement.where(or_(*[c.ilike(pattern, escape="\\") for c in
                (messages.c.subject, messages.c.from_address, messages.c.from_name, messages.c.mailbox)]))
        if verdict:
            if verdict == "pending":
                statement = statement.where(messages.c.status.in_(["pending", "processing"]))
            elif verdict in ("error", "processing"):
                statement = statement.where(messages.c.status == verdict)
            else:
                statement = statement.where(_effective_verdict() == verdict, messages.c.status == "complete")
        with self.engine.connect() as db:
            total = db.execute(select(func.count()).select_from(statement.subquery())).scalar_one()
            rows = db.execute(statement.order_by(messages.c.received_at.desc(), messages.c.id).limit(limit).offset(offset)).mappings()
            return {"messages": [public_message(r) for r in rows], "total": total}

    def detail(self, mid):
        with self.engine.connect() as db:
            msg = db.execute(_public_select()
                             .where(messages.c.id == mid)).mappings().first()
            if not msg:
                return None
            history = [dict(r) for r in db.execute(select(runs).where(runs.c.message_id == mid)
                       .order_by(runs.c.created_at.desc())).mappings()]
            reviews = [dict(r) for r in db.execute(select(feedback).where(feedback.c.message_id == mid)
                       .order_by(feedback.c.created_at.desc())).mappings()]
            retry = db.execute(select(scan_retries).join(jobs, jobs.c.id == scan_retries.c.job_id)
                .where(jobs.c.message_id == mid, jobs.c.status.in_(['pending', 'processing']))).mappings().first()
        return {"message": public_message(msg), "runs": history, "feedback": reviews,
                "scan_retry": dict(retry) if retry else None}

    def enqueue(self, mid):
        try:
            return self._enqueue(mid)
        except IntegrityError:
            with self.engine.connect() as db:
                existing = db.execute(select(jobs.c.id).where(jobs.c.message_id == mid,
                    jobs.c.status.in_(["pending", "processing"]))).scalar_one_or_none()
            if existing:
                return existing
            raise

    def _enqueue(self, mid):
        with self.engine.begin() as db:
            # Row lock serializes enqueue against completion on PostgreSQL.
            row = db.execute(select(messages).where(messages.c.id == mid).with_for_update()).mappings().first()
            if not row:
                raise KeyError(mid)
            existing = db.execute(select(jobs.c.id).where(jobs.c.message_id == mid,
                                  jobs.c.status.in_(["pending", "processing"]))).scalar_one_or_none()
            if existing:
                return existing
            jid = new_id()
            db.execute(jobs.insert().values(id=jid, message_id=mid, status="pending", created_at=now(), attempts=0))
            db.execute(messages.update().where(messages.c.id == mid).values(status="pending"))
            return jid

    def claim(self):
        # Live workers renew their lease during multi-section inference. A crashed
        # worker becomes reclaimable after ten minutes without a successful renewal.
        cutoff = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
        with self.engine.begin() as db:
            waiting = select(scan_retries.c.job_id).where(scan_retries.c.job_id == jobs.c.id,
                scan_retries.c.next_attempt_at > now()).exists()
            eligible = or_(and_(jobs.c.status == "pending", ~waiting),
                           and_(jobs.c.status == "processing", jobs.c.claimed_at < cutoff))
            row = db.execute(select(jobs).where(eligible).order_by(jobs.c.created_at)
                .with_for_update(skip_locked=True).limit(1)).mappings().first()
            if not row:
                return None
            token = new_id()
            result = db.execute(update(jobs).where(jobs.c.id == row["id"], eligible)
                .values(status="processing", claimed_at=now(), lease_token=token, attempts=jobs.c.attempts + 1))
            if result.rowcount != 1:
                return None
            db.execute(messages.update().where(messages.c.id == row["message_id"]).values(status="processing"))
            return {**dict(row), "lease_token": token}

    def renew_job_lease(self, job, worker_id=None):
        with self.engine.begin() as db:
            renewed = db.execute(update(jobs).where(jobs.c.id == job['id'], jobs.c.status == 'processing',
                jobs.c.lease_token == job['lease_token']).values(claimed_at=now())).rowcount == 1
            if renewed and worker_id:
                db.execute(update(heartbeats).where(heartbeats.c.id == worker_id)
                           .values(last_seen=now(), state='analyzing'))
            return renewed

    @contextmanager
    def keep_job_lease(self, job, *, worker_id=None, interval=30):
        """Renew only the claimed owner; stop renewal on every exit path.

        Database errors fail closed. Callers check the guard before subsequent
        provider requests and before committing a result or queuing an action.
        A daemon cannot prevent shutdown; process death leaves the normal durable
        ten-minute crash-recovery path intact.
        """
        lease = JobLease()
        stopped = threading.Event()
        def renew():
            try:
                if not self.renew_job_lease(job, worker_id):
                    lease.lost.set()
                else:
                    lease.confirmed_at = time.monotonic()
            except Exception:
                lease.lost.set()
        def maintain():
            while not stopped.wait(interval):
                renew()
                if lease.lost.is_set():
                    return
        renew()
        lease.check()
        lease.thread = threading.Thread(target=maintain, name='mailsec-job-lease', daemon=True)
        lease.thread.start()
        try:
            yield lease
        finally:
            stopped.set()
            # A database connection that is itself blocked cannot delay shutdown.
            # Its conditional UPDATE cannot revive a completed or reclaimed job.
            lease.thread.join(timeout=1)

    def defer_scan(self, job, evidence, versions, started, reason):
        """Atomically release only our lease and retain a durable, delayed retry."""
        rid = new_id()
        with self.engine.begin() as db:
            changed = db.execute(jobs.update().where(jobs.c.id == job['id'], jobs.c.status == 'processing',
                jobs.c.lease_token == job['lease_token']).values(status='pending', claimed_at=None, lease_token=None))
            if changed.rowcount != 1:
                return False
            prior = db.execute(select(scan_retries).where(scan_retries.c.job_id == job['id'])).mappings().first()
            failures = (prior['failures'] if prior else 0) + 1
            delay = min(1800, 30 * 2 ** min(failures - 1, 6))
            # Stable per-job jitter avoids a synchronized retry storm after an outage.
            delay += int(hashlib.sha256(job['id'].encode()).hexdigest()[:4], 16) % 16
            values = dict(failures=failures, first_failure_at=prior['first_failure_at'] if prior else now(),
                          next_attempt_at=(datetime.now(timezone.utc) + timedelta(seconds=delay)).isoformat(), reason=reason)
            if prior:
                db.execute(scan_retries.update().where(scan_retries.c.job_id == job['id']).values(**values))
            else:
                db.execute(scan_retries.insert().values(job_id=job['id'], **values))
            db.execute(runs.insert().values(id=rid, message_id=job['message_id'], job_id=job['id'],
                created_at=started, completed_at=now(), status='retrying', evidence=evidence,
                output=None, policy={'verdict':None, 'eligible_action':'none', 'executed_action':'none',
                                    'scan_retry':values}, versions=versions, questions={}, error=reason))
            db.execute(messages.update().where(messages.c.id == job['message_id']).values(
                status='pending', verdict=None, confidence=None, run_count=messages.c.run_count + 1))
        return rid

    def pause_for_privacy_consent(self, job):
        """Release only our job, preserving every previous assessment and run."""
        with self.engine.begin() as db:
            changed = db.execute(jobs.update().where(jobs.c.id == job['id'], jobs.c.status == 'processing',
                jobs.c.lease_token == job['lease_token']).values(status='pending', claimed_at=None, lease_token=None))
            if changed.rowcount != 1:
                return False
            db.execute(messages.update().where(messages.c.id == job['message_id']).values(status='pending'))
        return True

    def finish(self, job, evidence, output, policy, versions, questions, started, error=None):
        rid = new_id()
        with self.engine.begin() as db:
            changed = db.execute(jobs.update().where(jobs.c.id == job["id"], jobs.c.status == "processing",
                jobs.c.lease_token == job["lease_token"]).values(status="error" if error else "complete"))
            if changed.rowcount != 1:
                return False
            db.execute(runs.insert().values(id=rid, message_id=job["message_id"], job_id=job["id"],
                created_at=started, completed_at=now(), status="error" if error else "complete", evidence=evidence,
                output=output, policy=policy, versions=versions, questions=questions, error=error))
            values = {"status": "error" if error else "complete", "run_count": messages.c.run_count + 1}
            if not error:
                values.update(verdict=(policy or {}).get('verdict') or output["answers"]["verdict"]["choice"],
                              confidence=None if (policy or {}).get('verdict_review_basis') == 'action_authority_gap'
                              else output["answers"]["verdict"]["confidence"])
            else:
                values.update(verdict='phishing' if (policy or {}).get('hard_detection') else None, confidence=None)
            db.execute(messages.update().where(messages.c.id == job["message_id"]).values(**values))
        return rid

    def sender_history(self, msg):
        # Observations only. Absence of local history never proves a new relationship.
        end = msg["received_at"]
        try:
            start = (datetime.fromisoformat(end) - timedelta(days=90)).isoformat()
        except ValueError:
            start = ""
        with self.engine.connect() as db:
            prior = list(db.execute(select(messages.c.from_address, messages.c.root_domain, messages.c.received_at,
                    messages.c.mailbox, messages.c.verdict).where(messages.c.id != msg["id"],
                    messages.c.received_at < end, messages.c.received_at >= start,
                    or_(messages.c.from_address == msg["from_address"],
                        messages.c.root_domain == msg["root_domain"]))).mappings())
        sender = [r for r in prior if r["from_address"] == msg["from_address"] and msg["from_address"]]
        domain = [r for r in prior if r["root_domain"] == msg["root_domain"] and msg["root_domain"]]
        def count(rows, days):
            cutoff = (datetime.fromisoformat(end) - timedelta(days=days)).isoformat()
            return sum(r["received_at"] >= cutoff for r in rows)
        result = {"coverage": "locally_observed_only", "complete_90d_history": False,
            "sender_messages_previous_90d": len(sender), "domain_messages_previous_90d": len(domain),
            "sender_first_seen": None if not sender else False,
            "recipient_has_communicated_with_sender_before": None,
            "recipient_has_communicated_with_sender_domain_before": None,
            "recipient_received_from_sender_before":
                any(r["mailbox"] == msg["mailbox"] for r in sender) if msg["mailbox"] else None,
            "first_observed_sender": min((r["received_at"] for r in sender), default=None),
            "last_observed_sender": max((r["received_at"] for r in sender), default=None),
            "number_of_observed_recipients": len({r["mailbox"] for r in sender if r["mailbox"]}),
            "previous_verdicts": dict(Counter(r["verdict"] for r in sender if r["verdict"]))}
        for days in (7, 30):
            result[f"sender_messages_previous_{days}d"] = count(sender, days)
            result[f"domain_messages_previous_{days}d"] = count(domain, days)
        return result

    def add_feedback(self, mid, verdict, reason, reviewer, run_id=None, *, apply_verdict=False):
        if verdict not in ('clean', 'spam', 'suspicious', 'phishing'):
            raise ValueError('Select a supported verdict')
        if apply_verdict:
            from .mailbox_actions import actions, initialize
            initialize(self)
        with self.engine.begin() as db:
            msg = db.execute(select(messages.c.id).where(messages.c.id == mid).with_for_update()).first()
            if not msg:
                raise KeyError(mid)
            stmt = select(runs.c.id, runs.c.output).where(runs.c.message_id == mid, runs.c.status == "complete")
            if run_id:
                stmt = stmt.where(runs.c.id == run_id)
            run = db.execute(stmt.order_by(runs.c.created_at.desc()).limit(1)).mappings().first()
            if run_id and not run:
                raise ValueError("The selected completed analysis does not belong to this message")
            item = {"id": new_id(), "message_id": mid, "run_id": run["id"] if run else None,
                    "system_verdict": run["output"]["answers"]["verdict"]["choice"] if run else None,
                    "verdict": verdict, "reason": reason, "reviewer": reviewer, "created_at": now()}
            db.execute(feedback.insert().values(**item))
            if apply_verdict:
                values = {key: item[key] for key in ('verdict', 'reviewer', 'reason', 'created_at')}
                values['review_id'] = item['id']
                from sqlalchemy.dialects.postgresql import insert as pg_insert
                from sqlalchemy.dialects.sqlite import insert as sqlite_insert
                insert = pg_insert if self.engine.dialect.name == 'postgresql' else sqlite_insert
                db.execute(insert(analyst_overrides).values(message_id=mid, **values)
                    .on_conflict_do_update(index_elements=['message_id'], set_=values))
                db.execute(actions.update().where(actions.c.message_id == mid,
                    actions.c.action.in_(['flag', 'quarantine']), actions.c.status.in_(['pending', 'retry']))
                    .values(status='cancelled', updated_at=item['created_at'],
                            error='Analyst correction superseded this automatic action'))
        return item

    def mailbox_state(self, address):
        with self.engine.connect() as db:
            row = db.execute(select(mailboxes).where(mailboxes.c.mailbox == address)).mappings().first()
            return dict(row) if row else {"mailbox": address, "history_id": None}

    def update_mailbox(self, address, **values):
        with self.engine.begin() as db:
            exists = db.execute(select(mailboxes.c.mailbox).where(mailboxes.c.mailbox == address)).first()
            if exists:
                cursor = values.pop("history_id", None)
                if values:
                    db.execute(mailboxes.update().where(mailboxes.c.mailbox == address).values(**values))
                if cursor is not None:
                    # Gmail history IDs are decimal strings. Atomic monotonic update
                    # prevents an overlapping slower poll from moving the cursor back.
                    db.execute(mailboxes.update().where(mailboxes.c.mailbox == address, or_(
                        mailboxes.c.history_id.is_(None), func.length(mailboxes.c.history_id) < len(cursor),
                        and_(func.length(mailboxes.c.history_id) == len(cursor), mailboxes.c.history_id < cursor)))
                        .values(history_id=cursor))
            else:
                db.execute(mailboxes.insert().values(mailbox=address, **values))

    def heartbeat(self, worker_id, state):
        with self.engine.begin() as db:
            if db.execute(select(heartbeats.c.id).where(heartbeats.c.id == worker_id)).first():
                db.execute(heartbeats.update().where(heartbeats.c.id == worker_id).values(last_seen=now(), state=state))
            else:
                db.execute(heartbeats.insert().values(id=worker_id, last_seen=now(), state=state))

    def status(self):
        counts = {k: 0 for k in ("clean", "spam", "suspicious", "phishing", "pending", "error")}
        with self.engine.connect() as db:
            for row in db.execute(select(messages.c.status, _effective_verdict().label('verdict'), func.count())
                                  .select_from(_message_source()).group_by(messages.c.status, _effective_verdict())):
                key = row.verdict if row.status == "complete" else "pending" if row.status == "processing" else row.status
                counts[key] = counts.get(key, 0) + row[2]
            workers = [dict(r) for r in db.execute(select(heartbeats)).mappings()]
            retry_rows = list(db.execute(select(scan_retries).join(jobs, jobs.c.id == scan_retries.c.job_id)
                .where(jobs.c.status.in_(['pending', 'processing']))).mappings())
        return {"counts": counts, "worker": {"instances": workers},
                "scan_retries": {"pending":len(retry_rows),
                    "needs_attention":sum(r['failures'] >= 3 for r in retry_rows),
                    "next_attempt_at":min((r['next_attempt_at'] for r in retry_rows), default=None)}}

    def evaluation(self):
        # Latest review per message, paired with the exact run the human reviewed.
        with self.engine.connect() as db:
            rows = list(db.execute(select(feedback).order_by(feedback.c.created_at.desc())).mappings())
        latest = {}
        for row in rows:
            latest.setdefault(row["message_id"], dict(row))
        matrix = {actual: {predicted: 0 for predicted in ("clean", "spam", "suspicious", "phishing")}
                  for actual in ("clean", "spam", "suspicious", "phishing")}
        paired = [r for r in latest.values() if r["system_verdict"]]
        for row in paired:
            matrix[row["verdict"]][row["system_verdict"]] += 1
        return {"reviewed_messages": len(latest), "paired_reviews": len(paired), "confusion_matrix": matrix,
                "rows": "human verdict", "columns": "system verdict at review time",
                "false_positives": sum(r["system_verdict"] == "phishing" and r["verdict"] in ("clean", "spam") for r in paired),
                "false_negatives": sum(r["system_verdict"] in ("clean", "spam") and r["verdict"] == "phishing" for r in paired),
                "review_deferrals": sum(r["system_verdict"] == "suspicious" for r in paired)}

    def overview(self):
        today = datetime.now(timezone.utc).date()
        dates = [(today - timedelta(days=i)).isoformat() for i in range(13, -1, -1)]
        daily = {day: {"date": day, "total": 0, **{k: 0 for k in
                 ("clean", "spam", "suspicious", "phishing", "pending", "error")}} for day in dates}
        counts = self.status()["counts"]
        with self.engine.connect() as db:
            reviewed = select(feedback.c.message_id).distinct()
            reviewed_count = db.execute(select(func.count()).select_from(reviewed.subquery())).scalar_one()
            needs_review = db.execute(select(func.count()).select_from(_message_source()).where(
                messages.c.status == "complete", _effective_verdict().in_(["suspicious", "phishing"]),
                messages.c.id.not_in(reviewed))).scalar_one()
            day = func.substr(messages.c.received_at, 1, 10)
            for row in db.execute(select(day.label("day"), messages.c.status, _effective_verdict().label('verdict'), func.count())
                .select_from(_message_source()).where(messages.c.received_at >= dates[0])
                .group_by(day, messages.c.status, _effective_verdict())):
                if row.day in daily:
                    key = row.verdict if row.status == "complete" else "error" if row.status == "error" else "pending"
                    daily[row.day][key] += row[3]
                    daily[row.day]["total"] += row[3]
            recent = [public_message(r) for r in db.execute(_public_select().where(
                messages.c.status == "complete", _effective_verdict().in_(["suspicious", "phishing"]),
                messages.c.id.not_in(reviewed))
                .order_by(messages.c.received_at.desc()).limit(6)).mappings()]
        verdict_counts = {key: counts[key] for key in ("clean", "spam", "suspicious", "phishing")}
        return {"total_messages": sum(counts.values()), "analyzed_messages": sum(verdict_counts.values()),
                "pending_messages": counts["pending"], "error_messages": counts["error"],
                "review_needed": needs_review, "reviewed_messages": reviewed_count,
                "verdict_counts": verdict_counts, "daily": list(daily.values()), "recent_risks": recent}
