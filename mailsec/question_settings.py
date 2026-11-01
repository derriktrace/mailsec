"""Immutable, tenant-scoped question revisions and isolated provider comparisons.

Only wording is configurable. Question identifiers, primitive types, answer keys,
deterministic policy and thresholds remain application code. Test cases are kept
separately from mail analyses and never enqueue work or perform mailbox actions.
"""
from __future__ import annotations

import json
import threading
import time
import weakref
from copy import deepcopy
from dataclasses import fields, replace
from pathlib import Path

from fastapi import HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import JSON, Column, Float, MetaData, String, Table, Text, func, select, update
from sqlalchemy import text as sql_text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from .action_evidence import build_action_evidence
from .action_review import evaluate_action_review
from .decision import configured, decision_client
from .jev import JevError, validate_response
from .jev_sections import combine_evaluations, prepare_evaluations
from .model_setup import initialize as initialize_models
from .model_setup import lock_model_configuration, model_snapshot, read_model_settings
from .provider_consent import PrivacyConsentRequired, privacy_status, require_consent
from .security_cache import digest
from .storage import new_id, now

MAX_BUNDLE_BYTES = 48 * 1024
MAX_TEXT_CHARACTERS = 8192
TEST_BUDGET_SECONDS = 180
TEST_LEASE_SECONDS = 300
TEST_NOTE = ("Provider compatibility and one-case comparison only; this does not establish detection accuracy. "
             "No messages, classifications, labels, queues or security caches were changed. "
             "Existing evidence is a captured snapshot; scans and URL checks are not refreshed.")
DEFAULT_BUNDLES = {name: json.loads(Path(__file__).with_name(filename).read_text())
                   for name, filename in (("primary", "questions.json"), ("actions", "action_questions.json"),
                                          ("authority", "authority_questions.json"))}
metadata = MetaData()
revisions = Table("question_revisions", metadata,
    Column("id", String(32), primary_key=True), Column("tenant", String(160), nullable=False, index=True),
    Column("sha256", String(64), nullable=False), Column("bundles", JSON, nullable=False),
    Column("label", String(120), nullable=False), Column("source", String(30), nullable=False),
    Column("parent_revision_id", String(32)), Column("created_at", String(40), nullable=False))
active_questions = Table("active_question_revisions", metadata,
    Column("tenant", String(160), primary_key=True), Column("revision_id", String(32), nullable=False),
    Column("updated_at", String(40), nullable=False))
activations = Table("question_activations", metadata,
    Column("id", String(32), primary_key=True), Column("tenant", String(160), nullable=False, index=True),
    Column("revision_id", String(32), nullable=False), Column("previous_revision_id", String(32)),
    Column("test_id", String(32)), Column("reason", String(40), nullable=False),
    Column("created_at", String(40), nullable=False))
test_runs = Table("question_test_runs", metadata,
    Column("id", String(32), primary_key=True), Column("tenant", String(160), nullable=False, index=True),
    Column("revision_id", String(32), nullable=False), Column("active_revision_id", String(32), nullable=False),
    Column("candidate_sha256", String(64), nullable=False), Column("provider_fingerprint", String(64), nullable=False),
    Column("provider", JSON, nullable=False), Column("status", String(20), nullable=False),
    Column("created_at", String(40), nullable=False), Column("completed_at", String(40)),
    Column("evidence_sha256", String(64), nullable=False), Column("input_source", String(30), nullable=False),
    Column("results", JSON, nullable=False), Column("usage", JSON, nullable=False), Column("error", Text))
test_lease = Table("question_test_lease", metadata,
    Column("scope", String(30), primary_key=True), Column("test_id", String(32)),
    Column("expires_at", Float, nullable=False))
_initialized = weakref.WeakSet()
_initialize_lock = threading.Lock()


def initialize(store):
    with _initialize_lock:
        if store.engine not in _initialized:
            with store.engine.connect() as db:
                if store.engine.dialect.name == "sqlite":
                    db.exec_driver_sql("BEGIN IMMEDIATE")
                elif store.engine.dialect.name == "postgresql":
                    # Metadata creation must serialize across the API/worker,
                    # whose process-local locks cannot protect each other.
                    db.execute(sql_text("SELECT pg_advisory_xact_lock(6217339011421)"))
                metadata.create_all(db)
                db.commit()
            _initialized.add(store.engine)


def validate_bundles(value):
    """Return a detached exact-schema copy, accepting text edits only."""
    if not isinstance(value, dict) or set(value) != set(DEFAULT_BUNDLES):
        raise ValueError("Provide the primary, actions and authority question bundles")
    for bundle_name, defaults in DEFAULT_BUNDLES.items():
        bundle = value[bundle_name]
        if not isinstance(bundle, dict) or set(bundle) != set(defaults):
            raise ValueError("Question identifiers cannot be added, removed or renamed")
        for name, default in defaults.items():
            question = bundle[name]
            if (not isinstance(question, dict) or set(question) != set(default)
                    or question.get("type") != default["type"]):
                raise ValueError("Question fields and primitive types cannot be changed")
            criteria = question["criteria"]
            if not isinstance(criteria, dict) or set(criteria) != set(default["criteria"]):
                raise ValueError("Allowed answer keys cannot be changed")
            for text in (question["instructions"], *criteria.values()):
                if (not isinstance(text, str) or not text.strip() or len(text) > MAX_TEXT_CHARACTERS
                        or any(ord(c) < 32 and c not in "\t\r\n" for c in text)
                        or any(0xD800 <= ord(c) <= 0xDFFF for c in text)):
                    raise ValueError("Each instruction and criterion must contain 1–8192 valid text characters")
    if len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()) > MAX_BUNDLE_BYTES:
        raise ValueError("The complete question bundle must fit within 48 KiB")
    return deepcopy(value)


def _metadata(row, active_id=None):
    return {key: row[key] for key in ("id", "sha256", "label", "source", "parent_revision_id", "created_at")} | {
        "is_active": row["id"] == active_id}


class QuestionConflict(ValueError):
    pass


def settings_snapshot(settings):
    """Copy configuration values, never runtime handles attached by Gmail setup.

    Account routes attach their Store to Settings for refreshing OAuth config.
    Deep-copying that process state traverses SQLAlchemy engines, modules and
    locks. Only the declared configuration fields belong in a test snapshot.
    Mutable organization/list values still receive independent deep copies.
    """
    return replace(settings, **{field.name: deepcopy(getattr(settings, field.name)) for field in fields(settings)})


class Questions:
    def __init__(self, store, tenant="local"):
        self.store, self.tenant = store, tenant
        initialize(store)

    def _insert(self, table):
        return (pg_insert if self.store.engine.dialect.name == "postgresql" else sqlite_insert)(table)

    def _row(self, db, revision_id):
        row = db.execute(select(revisions).where(revisions.c.tenant == self.tenant,
                                                revisions.c.id == revision_id)).mappings().first()
        if not row:
            raise KeyError("Question revision not found")
        return dict(row)

    def active(self):
        """Read at the beginning of each analysis; no process-local active cache."""
        with self.store.engine.begin() as db:
            revision_id = db.execute(select(active_questions.c.revision_id).where(
                active_questions.c.tenant == self.tenant)).scalar_one_or_none()
            if revision_id is None:
                # Stable per-tenant initial id makes simultaneous first reads
                # idempotent across the API and worker processes.
                revision_id = digest(["shipped-question-defaults-v1", self.tenant, digest(DEFAULT_BUNDLES)])[:32]
                db.execute(self._insert(revisions).values(id=revision_id, tenant=self.tenant,
                    sha256=digest(DEFAULT_BUNDLES), bundles=DEFAULT_BUNDLES, label="Shipped defaults",
                    source="shipped_defaults", parent_revision_id=None, created_at=now()).on_conflict_do_nothing())
                db.execute(self._insert(active_questions).values(tenant=self.tenant,
                    revision_id=revision_id, updated_at=now()).on_conflict_do_nothing())
                revision_id = db.execute(select(active_questions.c.revision_id).where(
                    active_questions.c.tenant == self.tenant)).scalar_one()
            return self._row(db, revision_id)

    def revision(self, revision_id):
        with self.store.engine.connect() as db:
            return self._row(db, revision_id)

    def history(self, limit=100, offset=0):
        active = self.active()
        with self.store.engine.connect() as db:
            rows = db.execute(select(revisions).where(revisions.c.tenant == self.tenant)
                .order_by(revisions.c.created_at.desc(), revisions.c.id).limit(limit).offset(offset)).mappings()
            items = [_metadata(row, active["id"]) for row in rows]
            total = db.execute(select(func.count()).select_from(revisions).where(
                revisions.c.tenant == self.tenant)).scalar_one()
            changes = [dict(row) for row in db.execute(select(activations).where(
                activations.c.tenant == self.tenant).order_by(activations.c.created_at.desc()).limit(100)).mappings()]
        return items, total, changes

    def draft(self, bundles, label, parent_revision_id=None):
        bundles = validate_bundles(bundles)
        label = label.strip()
        if not label or len(label) > 120 or any(ord(c) < 32 for c in label):
            raise ValueError("Give this revision a name of 1–120 characters")
        row = dict(id=new_id(), tenant=self.tenant, sha256=digest(bundles), bundles=bundles,
                   label=label, source="draft", parent_revision_id=parent_revision_id, created_at=now())
        with self.store.engine.begin() as db:
            if parent_revision_id:
                self._row(db, parent_revision_id)
            db.execute(revisions.insert().values(**row))
        return row

    def activate(self, revision_id, expected_active_id, provider_fingerprint, test_id, *, settings=None):
        if settings is not None:
            initialize_models(self.store)
        with self.store.engine.begin() as db:
            if settings is not None:
                lock_model_configuration(db, self.tenant)
                snapshot = settings_snapshot(settings)
                snapshot = read_model_settings(snapshot, db)
                provider_fingerprint = provider_info(snapshot)["fingerprint"]
            row = self._row(db, revision_id)
            test = db.execute(select(test_runs).where(test_runs.c.tenant == self.tenant,
                                                     test_runs.c.id == test_id)).mappings().first()
            if (not test or test["status"] != "complete" or test["revision_id"] != revision_id
                    or test["candidate_sha256"] != row["sha256"]
                    or test["provider_fingerprint"] != provider_fingerprint
                    or test["active_revision_id"] != expected_active_id):
                raise QuestionConflict("Test this saved revision against the current active version with the current provider before activating")
            self._activate(db, revision_id, expected_active_id, test_id, "tested_revision")
        return row

    def _activate(self, db, revision_id, expected_active_id, test_id, reason):
        changed = db.execute(update(active_questions).where(active_questions.c.tenant == self.tenant,
            active_questions.c.revision_id == expected_active_id).values(revision_id=revision_id, updated_at=now()))
        if changed.rowcount != 1:
            raise QuestionConflict("The active questions changed. Reload and test against the new active version")
        db.execute(activations.insert().values(id=new_id(), tenant=self.tenant, revision_id=revision_id,
            previous_revision_id=expected_active_id, test_id=test_id, reason=reason, created_at=now()))

    def restore_defaults(self, expected_active_id):
        row = dict(id=new_id(), tenant=self.tenant, sha256=digest(DEFAULT_BUNDLES), bundles=DEFAULT_BUNDLES,
            label="Restored shipped defaults", source="restored_defaults", parent_revision_id=expected_active_id,
            created_at=now())
        with self.store.engine.begin() as db:
            db.execute(revisions.insert().values(**row))
            self._activate(db, row["id"], expected_active_id, None, "trusted_shipped_defaults")
        return row

    def test(self, test_id):
        self.expire_interrupted_tests()
        with self.store.engine.connect() as db:
            row = db.execute(select(test_runs).where(test_runs.c.tenant == self.tenant,
                                                     test_runs.c.id == test_id)).mappings().first()
        if not row:
            raise KeyError("Question test not found")
        return dict(row) | {"note": TEST_NOTE}

    def tests(self, limit=20):
        self.expire_interrupted_tests()
        with self.store.engine.connect() as db:
            return [dict(row) | {"note": TEST_NOTE} for row in db.execute(select(test_runs).where(
                test_runs.c.tenant == self.tenant).order_by(test_runs.c.created_at.desc()).limit(limit)).mappings()]

    def expire_interrupted_tests(self):
        with self.store.engine.begin() as db:
            lock = db.execute(select(test_lease).where(test_lease.c.scope == "installation")).mappings().first()
            if lock and lock["test_id"] and lock["expires_at"] <= time.time():
                db.execute(update(test_runs).where(test_runs.c.id == lock["test_id"], test_runs.c.status == "running")
                    .values(status="error", completed_at=now(), error="Comparison was interrupted or exceeded its time budget; run a new test"))

    def begin_test(self, candidate, active, provider, evidence, source):
        self.expire_interrupted_tests()
        row = dict(id=new_id(), tenant=self.tenant, revision_id=candidate["id"], active_revision_id=active["id"],
            candidate_sha256=candidate["sha256"], provider_fingerprint=provider["fingerprint"], provider=provider,
            status="running", created_at=now(), completed_at=None, evidence_sha256=digest(evidence),
            input_source=source, results={}, usage={"input_tokens": 0, "output_tokens": 0, "complete": False}, error=None)
        with self.store.engine.begin() as db:
            db.execute(self._insert(test_lease).values(scope="installation", test_id=None, expires_at=0)
                       .on_conflict_do_nothing())
            changed = db.execute(update(test_lease).where(test_lease.c.scope == "installation",
                test_lease.c.expires_at <= time.time()).values(test_id=row["id"], expires_at=time.time() + TEST_LEASE_SECONDS))
            if changed.rowcount != 1:
                raise QuestionConflict("Another question comparison is running. Wait for it to finish")
            db.execute(test_runs.insert().values(**row))
        return row

    def finish_test(self, test_id, results, usage, error=None):
        with self.store.engine.begin() as db:
            # A stale owner cannot turn a timed-out run into an activation gate.
            lock = db.execute(select(test_lease).where(test_lease.c.scope == "installation",
                test_lease.c.test_id == test_id, test_lease.c.expires_at > time.time()).with_for_update()).mappings().first()
            if not lock:
                return
            db.execute(update(test_runs).where(test_runs.c.id == test_id, test_runs.c.status == "running").values(
                status="error" if error else "complete", completed_at=now(), results=results, usage=usage, error=error))
            db.execute(update(test_lease).where(test_lease.c.scope == "installation", test_lease.c.test_id == test_id)
                       .values(test_id=None, expires_at=0))


def provider_snapshot(settings, store):
    """Detach secrets/config before testing; only an opaque fingerprint leaves here."""
    snapshot = model_snapshot(settings, store)
    return snapshot, provider_info(snapshot)


def provider_info(snapshot):
    from .provider_redaction import VERSION as MASKING_VERSION
    secret = snapshot.api_key if snapshot.decision_provider == "jev" else snapshot.decision_api_key
    fingerprint = digest({"provider": snapshot.decision_provider, "model": snapshot.model,
        "base_url": snapshot.decision_base_url, "timeout": snapshot.decision_timeout_seconds, "credential": secret,
        "recipient_address_masking": snapshot.decision_recipient_address_masking,
        "recipient_address_masking_version": MASKING_VERSION})
    info = {"provider": snapshot.decision_provider, "model": snapshot.model, "fingerprint": fingerprint,
        "configured": configured(snapshot), "data_flow": "Selected email evidence is sent to TypeSafe for analysis."
        if snapshot.decision_provider == "jev" else "Selected email evidence is sent to your configured model server."}
    return info


def _comparison_evidence(store, body):
    if body.text is not None:
        if not body.text.strip() or len(body.text.encode()) > 48 * 1024:
            raise ValueError("Provide nonblank text up to 24,000 characters and 48 KiB")
        return {"message": {"subject": "Pasted comparison text", "sender": {}}, "body": body.text,
            "content": {"visible_text": body.text}, "links": [], "attachments": [],
            "inspection": {"status": "not_run", "attachments": [], "coverage": {}},
            "quality": {}, "source_integrity": {"body_and_headers_are_untrusted_email_content": True},
            "test_input": {"scope": "Text only; authentication, attachments, reputation and sender history are not checked."}}, "pasted_text"
    detail = store.detail(body.message_id)
    if not detail:
        raise KeyError("Message not found")
    run = detail["runs"][0] if detail["runs"] else None
    if not run or not run.get("evidence") or run.get("status") != "complete":
        raise ValueError("Choose a message whose latest analysis completed with captured evidence")
    # Explicit top-level source evidence allowlist: never copy message metadata,
    # overrides, feedback, policy, outputs, action ledger or previous answers.
    allowed = {"message", "body", "content", "links", "attachments", "quality", "identity", "authentication",
        "inspection", "url_inspection", "source_integrity", "organization_context", "business_context",
        "content_features", "claim_verification", "findings", "header_evidence", "received"}
    evidence = {key: deepcopy(value) for key, value in run["evidence"].items() if key in allowed}
    # Historical verdicts are not a source of truth for a comparison.
    blocked = {"verdict", "classification", "previous_verdict", "previous_verdicts", "system_verdict", "analyst_override", "feedback",
        "labels", "label_ids", "labelIds", "answers", "output", "policy", "action_review", "model_evidence_coverage"}
    def clean(value):
        if isinstance(value, dict):
            return {key: clean(item) for key, item in value.items() if key not in blocked}
        if isinstance(value, list):
            return [clean(item) for item in value]
        return value
    evidence = clean(evidence)
    evidence["test_input"] = {"scope": "Captured prior evidence only; static scans and URL reputation are not refreshed."}
    if len(json.dumps(evidence, ensure_ascii=True).encode()) > 256 * 1024:
        raise ValueError("Captured evidence is too large for a one-case comparison; paste a bounded text case instead")
    return evidence, "captured_evidence"


def run_comparison(questions, test_id, active, candidate, settings, evidence):
    """A bounded read-only provider workflow, kept outside the analysis pipeline."""
    results, usage = {}, {"input_tokens": 0, "output_tokens": 0, "complete": False}
    deadline = time.monotonic() + TEST_BUDGET_SECONDS
    error = None
    try:
        # Validate both versions' complete evidence fit before any billable call.
        for revision in (active, candidate):
            prepared, coverage = prepare_evaluations(deepcopy(evidence), revision["bundles"]["primary"], settings.model)
            if len(prepared) != 1 or not coverage.get("material_content_complete") or coverage.get("truncated"):
                raise ValueError("Comparison evidence does not fit completely")
        action_state = build_action_evidence(deepcopy(evidence))
        if not action_state["coverage"].get("material_content_complete") or action_state["coverage"].get("truncated"):
            raise ValueError("Comparison action evidence is incomplete")
        require_consent(settings, questions.store)
        client = decision_client(settings, store=questions.store)
        if hasattr(client, 'for_evidence'):
            client = client.for_evidence(evidence)
        # No retry storms for an operator-triggered comparison. Both production
        # adapters cap bytes and validate the entire typed response.
        if hasattr(client, "max_attempts"):
            client.max_attempts = 1
        calls = 0
        def evaluate(state, configured_questions):
            nonlocal calls
            remaining = deadline - time.monotonic()
            if remaining <= 0 or calls >= 6:
                raise JevError("Comparison exceeded its bounded provider budget")
            client.timeout = min(30, remaining)
            calls += 1
            output = client.evaluate(deepcopy(state), questions=deepcopy(configured_questions))
            validate_response(output, configured_questions)
            for key in ("input_tokens", "output_tokens"):
                usage[key] += output["usage"][key]
            if time.monotonic() > deadline:
                raise JevError("Comparison exceeded its bounded provider budget")
            return output
        for name, revision in (("active", active), ("candidate", candidate)):
            bundles = revision["bundles"]
            requests, projection = prepare_evaluations(deepcopy(evidence), bundles["primary"], settings.model)
            if len(requests) != 1 or not projection.get("material_content_complete") or projection.get("truncated"):
                raise ValueError("This case cannot fit completely in a single primary request. Use a smaller complete text case")
            results[name] = {"revision_id": revision["id"], "sha256": revision["sha256"]}
            state, part = requests[0]
            response = evaluate(state, bundles["primary"])
            response["evidence_projection"] = {**part, "state": response.get('provider_request', {}).get('state', state)}
            output = combine_evaluations([response], projection)
            output["decision_provider"] = settings.decision_provider
            output["score_semantics"] = ("provider_probabilities" if settings.decision_provider == "jev"
                                         else "uncalibrated_model_estimates")
            results[name]["primary"] = output
            review = evaluate_action_review(deepcopy(evidence), evaluate, fact_questions=bundles["actions"],
                                            authority_questions=bundles["authority"])
            results[name]["action_review"] = review
            if review["status"] != "complete":
                raise ValueError("Action or authority review was incomplete or failed; this test cannot authorize activation")
            # The same deterministic policy can be inspected, always passive.
            from .protection import decide
            output["action_review"] = review
            policy = decide(output, evidence, replace(settings, enforcement_mode="passive", notifications_enabled=False))
            policy["test_only"] = True
            results[name]["policy"] = policy
        usage["complete"] = True
    except Exception as exc:
        # Provider exceptions can carry raw/private response text; retain only a
        # bounded application-authored diagnostic and class, never str(exc).
        error = ("Comparison could not complete all six validated requests within its budget. "
                 "Check provider availability, request size and captured evidence coverage; no activation was authorized. "
                 f"Failure type: {type(exc).__name__}.")
    questions.finish_test(test_id, results, usage, error)


class DraftBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    bundles: dict
    label: str = Field(min_length=1, max_length=120)
    parent_revision_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{32}$")


class ValidationBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    bundles: dict


class TestBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    revision_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    expected_provider_fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    text: str | None = Field(default=None, max_length=24000)
    message_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{32}$")

    @model_validator(mode="after")
    def one_input(self):
        if (self.text is None) == (self.message_id is None):
            raise ValueError("Choose pasted text or one existing message")
        return self


class ActivationBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    revision_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    expected_active_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    test_id: str = Field(pattern=r"^[a-f0-9]{32}$")


class RestoreBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    expected_active_id: str = Field(pattern=r"^[a-f0-9]{32}$")


def register_question_routes(app, settings, store):
    def service():
        return Questions(store, settings.tenant_id)

    def writable():
        if not settings.app_token or settings.evaluation_mode:
            raise HTTPException(403, "Detection question changes and tests require an authenticated mail workspace")

    def mapped(call):
        try:
            return call()
        except KeyError:
            raise HTTPException(404, "Question revision, test or message not found") from None
        except QuestionConflict as exc:
            raise HTTPException(409, str(exc)) from None
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from None

    @app.get("/api/questions")
    def status(limit: int = Query(100, ge=1, le=100), offset: int = Query(0, ge=0)):
        questions = service()
        active = questions.active()
        history, total, changes = questions.history(limit, offset)
        snapshot, provider = provider_snapshot(settings, store)
        provider['privacy'] = privacy_status(snapshot, store)
        return {"active": active, "defaults": {"sha256": digest(DEFAULT_BUNDLES), "bundles": deepcopy(DEFAULT_BUNDLES)},
            "history": history, "history_total": total, "activations": changes, "provider": provider,
            "writable": bool(settings.app_token) and not settings.evaluation_mode,
            "limits": {"bundle_bytes": MAX_BUNDLE_BYTES, "text_characters": MAX_TEXT_CHARACTERS,
                       "test_text_characters": 24000, "test_budget_seconds": TEST_BUDGET_SECONDS},
            "note": "Activation affects new analyses only. Earlier analyses and pending mailbox actions retain their original context."}

    @app.get("/api/questions/revisions/{revision_id}")
    def revision(revision_id: str):
        return mapped(lambda: service().revision(revision_id))

    @app.post("/api/questions/drafts", status_code=201)
    def save_draft(body: DraftBody):
        writable()
        return mapped(lambda: service().draft(body.bundles, body.label, body.parent_revision_id))

    @app.post("/api/questions/validate")
    def validate(body: ValidationBody):
        writable()
        bundles = mapped(lambda: validate_bundles(body.bundles))
        return {"ok": True, "bundles": bundles, "sha256": digest(bundles)}

    @app.post("/api/questions/activate")
    def activate(body: ActivationBody):
        writable()
        _, provider = provider_snapshot(settings, store)
        return mapped(lambda: service().activate(body.revision_id, body.expected_active_id,
                                                 provider["fingerprint"], body.test_id, settings=settings))

    @app.post("/api/questions/restore-defaults")
    def restore(body: RestoreBody):
        writable()
        result = mapped(lambda: service().restore_defaults(body.expected_active_id))
        return result | {"note": "Shipped defaults restored as a new revision. Version history is preserved; no provider test was required for this trusted baseline."}

    @app.get("/api/questions/tests")
    def list_tests(limit: int = Query(20, ge=1, le=100)):
        return {"tests": service().tests(limit)}

    @app.get("/api/questions/tests/{test_id}")
    def get_test(test_id: str):
        return mapped(lambda: service().test(test_id))

    @app.post("/api/questions/test", status_code=202)
    def compare(body: TestBody):
        writable()
        questions = service()
        snapshot, provider = provider_snapshot(settings, store)
        if body.expected_provider_fingerprint != provider["fingerprint"]:
            raise HTTPException(409, "The decision provider changed. Reload and confirm the current evidence destination before testing")
        try:
            require_consent(snapshot, store)
        except PrivacyConsentRequired as exc:
            raise HTTPException(403, str(exc)) from None
        if not provider["configured"]:
            raise HTTPException(400, "Configure and test a decision provider in Setup first")
        candidate = mapped(lambda: questions.revision(body.revision_id))
        active = questions.active()
        evidence, source = mapped(lambda: _comparison_evidence(store, body))
        record = mapped(lambda: questions.begin_test(candidate, active, provider, evidence, source))
        try:
            threading.Thread(target=run_comparison, args=(questions, record["id"], active, candidate, snapshot, evidence),
                             name="mailsec-question-comparison", daemon=True).start()
        except RuntimeError:
            questions.finish_test(record["id"], {}, record["usage"], "Comparison could not start; run a new test")
            raise HTTPException(503, "Comparison could not start; no provider request was sent") from None
        return record | {"note": TEST_NOTE}
