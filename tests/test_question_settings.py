"""Question settings never change schemas, old analyses or mailbox state."""
import asyncio
import copy
import json
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Barrier, Lock

import httpx
import pytest
from privacy_helpers import authorize_test_provider
from sqlalchemy import func, select, update

from mailsec import question_settings as qs
from mailsec.api import create_app
from mailsec.config import Settings
from mailsec.jev import JevError
from mailsec.pipeline import Pipeline
from mailsec.storage import Store, jobs, messages, runs

TOKEN = "test-question-console-token-" + "a" * 40
HEADERS = {"authorization": "Bearer " + TOKEN}
RAW = b"From: vendor@example.org\r\nSubject: Receipt\r\n\r\nYour order shipped."


def answers(questions):
    result = {}
    for key, question in questions.items():
        if question["type"] == "noul":
            result[key] = {"type": "noul", "noul": 0.01}
        else:
            choice = next(iter(question["criteria"]))
            result[key] = {"type": "choice", "choice": choice, "confidence": 1.0,
                "probabilities": {name: float(name == choice) for name in question["criteria"]}}
    return {"model": "synthetic-test-model", "answers": result, "usage": {"input_tokens": 10, "output_tokens": 5}}


@pytest.fixture
def setup(tmp_path, monkeypatch):
    settings = Settings(database_url=f"sqlite:///{tmp_path}/questions.db", app_token=TOKEN,
                        api_key="synthetic-provider-test-key", require_auth=True)
    store = Store(settings.database_url)
    authorize_test_provider(settings, store)
    calls = []
    class Client:
        provider, model = "jev", "synthetic-test-model"
        timeout, max_attempts = 45, 3
        def evaluate(self, state, questions=None):
            calls.append((copy.deepcopy(state), copy.deepcopy(questions)))
            return answers(questions)
    monkeypatch.setattr(qs, "decision_client", lambda settings, **kwargs: Client())
    yield settings, store, calls, Client
    store.engine.dispose()


def request(app, method, path, **kwargs):
    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost") as client:
            return await client.request(method, path, **kwargs)
    return asyncio.run(run())


def draft(questions, suffix="Test wording"):
    bundles = copy.deepcopy(qs.DEFAULT_BUNDLES)
    bundles["primary"]["verdict"]["instructions"] += " " + suffix
    return questions.draft(bundles, "Test revision", questions.active()["id"])


def completed_test(settings, questions, candidate, evidence=None):
    active = questions.active()
    snapshot, provider = qs.provider_snapshot(settings, questions.store)
    if evidence is None:
        evidence, source = qs._comparison_evidence(questions.store,
            qs.TestBody(expected_provider_fingerprint="0" * 64, revision_id=candidate["id"], text="Your order shipped."))
    else:
        source = "captured_evidence"
    record = questions.begin_test(candidate, active, provider, evidence, source)
    qs.run_comparison(questions, record["id"], active, candidate, snapshot, evidence)
    return questions.test(record["id"])


def test_defaults_and_revision_text_are_detached_and_append_only(setup):
    _, store, _, _ = setup
    questions = qs.Questions(store)
    active = questions.active()
    changed = draft(questions)
    assert questions.active()["id"] == active["id"]
    changed["bundles"]["primary"]["verdict"]["instructions"] = "Mutation after save"
    assert questions.revision(changed["id"])["bundles"] != changed["bundles"]
    active["bundles"]["primary"].clear()
    assert questions.active()["bundles"] == qs.DEFAULT_BUNDLES
    history, total, _ = questions.history()
    assert total == len(history) == 2
    assert "bundles" not in history[0]


@pytest.mark.parametrize("mutation", [
    lambda b: b["primary"].pop("verdict"),
    lambda b: b["primary"]["verdict"].update(type="noul"),
    lambda b: b["primary"]["verdict"]["criteria"].update(safe="Safe"),
    lambda b: b["actions"]["payment_requested"].update(instructions="  "),
    lambda b: b["authority"]["current_request_risk"].update(instructions="x" * 8193),
    lambda b: b["primary"]["verdict"].update(instructions={"untrusted": "object"}),
    lambda b: b["primary"]["verdict"].update(instructions="null\x00byte"),
    lambda b: b["primary"]["verdict"].update(instructions="surrogate\ud800"),
    lambda b: b["primary"]["verdict"].update(threshold=0.1),
    lambda b: b.update(threshold=0.1),
])
def test_fixed_schema_and_nonblank_bounded_text(mutation):
    bundles = copy.deepcopy(qs.DEFAULT_BUNDLES)
    mutation(bundles)
    with pytest.raises(ValueError):
        qs.validate_bundles(bundles)


def test_complete_bundle_bytes_are_bounded():
    bundles = copy.deepcopy(qs.DEFAULT_BUNDLES)
    for question in bundles["primary"].values():
        question["instructions"] = "x" * 8000
    with pytest.raises(ValueError, match="48 KiB"):
        qs.validate_bundles(bundles)


def test_activation_requires_current_provider_test_and_compare_and_swap(setup):
    settings, store, calls, _ = setup
    questions = qs.Questions(store)
    original = questions.active()
    candidate = draft(questions)
    _, provider = qs.provider_snapshot(settings, store)
    with pytest.raises(qs.QuestionConflict):
        questions.activate(candidate["id"], original["id"], provider["fingerprint"], "a" * 32)
    result = completed_test(settings, questions, candidate)
    assert result["status"] == "complete", result
    assert len(calls) == 6
    assert result["usage"] == {"input_tokens": 60, "output_tokens": 30, "complete": True}
    with pytest.raises(qs.QuestionConflict):
        questions.activate(candidate["id"], original["id"], "changed-provider", result["id"])
    questions.activate(candidate["id"], original["id"], provider["fingerprint"], result["id"])
    assert questions.active()["id"] == candidate["id"]
    with pytest.raises(qs.QuestionConflict):
        questions.activate(candidate["id"], original["id"], provider["fingerprint"], result["id"])
    history, _, changes = questions.history()
    assert next(r for r in history if r["id"] == candidate["id"])["is_active"]
    assert changes[0]["test_id"] == result["id"]
    assert all(side["policy"]["mode"] == "passive" and side["policy"]["executed_action"] == "none"
               for side in result["results"].values())


def test_restore_defaults_new_revision_preserves_history_and_cas(setup):
    settings, store, _, _ = setup
    questions = qs.Questions(store)
    original = questions.active()
    candidate = draft(questions)
    result = completed_test(settings, questions, candidate)
    questions.activate(candidate["id"], original["id"], result["provider_fingerprint"], result["id"])
    restored = questions.restore_defaults(candidate["id"])
    assert restored["id"] not in {original["id"], candidate["id"]}
    assert restored["bundles"] == qs.DEFAULT_BUNDLES
    assert restored["source"] == "restored_defaults"
    assert questions.history()[1] == 3
    with pytest.raises(qs.QuestionConflict):
        questions.restore_defaults(candidate["id"])
    assert questions.history()[1] == 3  # transaction rolled back the stale revision
    # A historical revision can be tested and reactivated without overwriting it.
    rollback = completed_test(settings, questions, candidate)
    questions.activate(candidate["id"], restored["id"], rollback["provider_fingerprint"], rollback["id"])
    assert questions.revision(candidate["id"]) == candidate


def test_one_comparison_per_installation_not_per_tenant_and_expired_is_error(setup):
    settings, store, _, _ = setup
    questions = qs.Questions(store)
    candidate, active = draft(questions), questions.active()
    _, provider = qs.provider_snapshot(settings, store)
    record = questions.begin_test(candidate, active, provider, {"body": "Hello"}, "pasted_text")
    other = qs.Questions(store, "another-tenant")
    with pytest.raises(qs.QuestionConflict):
        other.begin_test(other.active(), other.active(), provider, {"body": "Hello"}, "pasted_text")
    with store.engine.begin() as db:
        db.execute(update(qs.test_lease).values(expires_at=time.time() - 1))
    interrupted = questions.test(record["id"])
    assert interrupted["status"] == "error" and "interrupted" in interrupted["error"]
    questions.finish_test(record["id"], {}, {"complete": True})
    assert questions.test(record["id"])["status"] == "error"
    assert other.begin_test(other.active(), other.active(), provider, {}, "pasted_text")


def test_failed_provider_test_preserves_partial_usage_and_never_activates(setup, monkeypatch):
    settings, store, _, Client = setup
    questions = qs.Questions(store)
    candidate = draft(questions)
    class Broken(Client):
        count = 0
        def evaluate(self, state, questions=None):
            self.count += 1
            if self.count == 4:
                raise JevError("private-provider-body-sentinel")
            return super().evaluate(state, questions)
    monkeypatch.setattr(qs, "decision_client", lambda settings, **kwargs: Broken())
    result = completed_test(settings, questions, candidate)
    assert result["status"] == "error"
    assert result["usage"] == {"input_tokens": 30, "output_tokens": 15, "complete": False}
    assert "private-provider-body-sentinel" not in json.dumps(result)
    assert result["results"]["active"]["action_review"]["status"] == "complete"
    with pytest.raises(qs.QuestionConflict):
        questions.activate(candidate["id"], questions.active()["id"], result["provider_fingerprint"], result["id"])


def test_response_validation_no_incomplete_test_gate(setup, monkeypatch):
    settings, store, _, Client = setup
    questions = qs.Questions(store)
    class Invalid(Client):
        def evaluate(self, state, questions=None):
            value = super().evaluate(state, questions)
            value["usage"]["input_tokens"] = True
            return value
    monkeypatch.setattr(qs, "decision_client", lambda settings, **kwargs: Invalid())
    result = completed_test(settings, questions, draft(questions))
    assert result["status"] == "error" and result["usage"]["complete"] is False


def test_text_case_uses_current_local_provider_passive_policy(setup, monkeypatch):
    settings, store, calls, Client = setup
    settings = replace(settings, decision_provider="ollama", decision_base_url="http://localhost:11434",
                       enforcement_mode="auto_quarantine", notifications_enabled=True)
    authorize_test_provider(settings, store)
    snapshots = []
    def factory(snapshot, **kwargs):
        snapshots.append(snapshot)
        # Editing original runtime settings must not change the test snapshot.
        settings.decision_provider = "jev"
        return Client()
    monkeypatch.setattr(qs, "decision_client", factory)
    questions = qs.Questions(store)
    result = completed_test(settings, questions, draft(questions))
    assert result["status"] == "complete"
    assert snapshots[0].decision_provider == "ollama"
    assert result["provider"]["provider"] == "ollama"
    assert result["results"]["candidate"]["primary"]["score_semantics"] == "uncalibrated_model_estimates"
    assert "test_input" in calls[0][0] and "test_input" in calls[3][0]


def test_existing_case_is_captured_source_only_and_cannot_modify_mail(setup):
    settings, store, calls, Client = setup
    pipeline = Pipeline(settings, store=store, jev=Client())
    item = pipeline.ingest(RAW)
    completed = pipeline.process_one()
    store.add_feedback(item["id"], "phishing", "private-review-sentinel", "owner", completed["run_id"], apply_verdict=True)
    with store.engine.begin() as db:
        row = db.execute(select(runs).where(runs.c.id == completed["run_id"])).mappings().one()
        evidence = copy.deepcopy(row["evidence"])
        evidence.update(answers={"secret": "private-answer-sentinel"}, feedback="private-feedback-sentinel")
        evidence["identity"]["previous_verdicts"] = ["private-prior-verdict-sentinel"]
        evidence["message"]["labelIds"] = ["private-label-sentinel"]
        db.execute(update(runs).where(runs.c.id == completed["run_id"]).values(evidence=evidence))
    before = store.detail(item["id"])
    counts = {}
    with store.engine.connect() as db:
        for table in (messages, jobs, runs):
            counts[table.name] = db.execute(select(func.count()).select_from(table)).scalar_one()
    questions = qs.Questions(store)
    candidate = draft(questions)
    case, source = qs._comparison_evidence(store, qs.TestBody(expected_provider_fingerprint="0" * 64, revision_id=candidate["id"], message_id=item["id"]))
    assert source == "captured_evidence"
    result = completed_test(settings, questions, candidate, case)
    assert result["status"] == "complete", result
    transmitted = json.dumps(calls[-6:])
    for marker in ("private-review-sentinel", "private-answer-sentinel", "private-feedback-sentinel",
                   "private-prior-verdict-sentinel", "private-label-sentinel"):
        assert marker not in transmitted
    assert store.detail(item["id"]) == before
    with store.engine.connect() as db:
        for table in (messages, jobs, runs):
            assert db.execute(select(func.count()).select_from(table)).scalar_one() == counts[table.name]


def test_tenant_revision_and_tests_are_not_visible_to_other_tenant(setup):
    settings, store, _, _ = setup
    questions = qs.Questions(store)
    candidate = draft(questions)
    result = completed_test(settings, questions, candidate)
    other = qs.Questions(store, "another-tenant")
    assert other.tests() == []
    for getter, identifier in ((other.revision, candidate["id"]), (other.test, result["id"])):
        with pytest.raises(KeyError):
            getter(identifier)


def test_api_authorization_readonly_and_async_polling(setup, monkeypatch):
    settings, store, calls, _ = setup
    app = create_app(settings, Pipeline(settings, store=store))
    for method, path, body in (("GET", "/api/questions", None), ("POST", "/api/questions/drafts", {}),
                               ("POST", "/api/questions/test", {}), ("POST", "/api/questions/restore-defaults", {})):
        assert request(app, method, path, json=body).status_code == 401
    status = request(app, "GET", "/api/questions", headers=HEADERS).json()
    assert status["writable"] and "synthetic-provider-test-key" not in json.dumps(status)
    response = request(app, "POST", "/api/questions/drafts", headers=HEADERS,
        json={"bundles": status["active"]["bundles"], "label": "API draft", "parent_revision_id": status["active"]["id"]})
    assert response.status_code == 201
    candidate = response.json()
    stale = request(app, "POST", "/api/questions/test", headers=HEADERS, json={
        "revision_id": candidate["id"], "expected_provider_fingerprint": "0" * 64, "text": "Hello"})
    assert stale.status_code == 409 and not calls
    # Capture work rather than racing a real background thread in this test.
    started = []
    class Worker:
        def __init__(self, target, args, **kwargs):
            started.append((target, args))
        def start(self):
            pass
    monkeypatch.setattr(qs.threading, "Thread", Worker)
    response = request(app, "POST", "/api/questions/test", headers=HEADERS,
        json={"revision_id": candidate["id"], "expected_provider_fingerprint": status["provider"]["fingerprint"], "text": "Your order shipped."})
    assert response.status_code == 202 and response.json()["status"] == "running"
    test_id = response.json()["id"]
    assert request(app, "GET", f"/api/questions/tests/{test_id}", headers=HEADERS).json()["status"] == "running"
    target, args = started.pop()
    target(*args)
    assert request(app, "GET", f"/api/questions/tests/{test_id}", headers=HEADERS).json()["status"] == "complete"
    assert len(calls) == 6
    assert request(app, "POST", "/api/questions/activate", headers=HEADERS, json={
        "revision_id": candidate["id"], "expected_active_id": status["active"]["id"], "test_id": test_id}).status_code == 200
    evaluation = create_app(replace(settings, evaluation_mode=True), Pipeline(replace(settings, evaluation_mode=True), store=store))
    for path, body in (("drafts", {"bundles": candidate["bundles"], "label": "No"}),
                       ("test", {"revision_id": candidate["id"], "expected_provider_fingerprint": "0" * 64, "text": "Hello"}),
                       ("restore-defaults", {"expected_active_id": candidate["id"]})):
        assert request(evaluation, "POST", "/api/questions/" + path, headers=HEADERS, json=body).status_code == 403


def test_api_provider_changed_after_test_cannot_activate(setup):
    settings, store, _, _ = setup
    questions = qs.Questions(store)
    candidate = draft(questions)
    test = completed_test(settings, questions, candidate)
    app = create_app(settings, Pipeline(settings, store=store))
    settings.model = "changed-model"
    authorize_test_provider(settings, store)
    result = request(app, "POST", "/api/questions/activate", headers=HEADERS, json={
        "revision_id": candidate["id"], "expected_active_id": questions.active()["id"], "test_id": test["id"]})
    assert result.status_code == 409
    assert questions.active()["id"] != candidate["id"]


def test_pasted_bundle_validation_only_no_revision_provider_or_mail_writes(setup):
    settings, store, calls, _ = setup
    questions = qs.Questions(store)
    active = questions.active()
    app = create_app(settings, Pipeline(settings, store=store))
    body = {"bundles": copy.deepcopy(active["bundles"])}
    body["bundles"]["primary"]["verdict"]["instructions"] += " Operator pasted wording."
    assert request(app, "POST", "/api/questions/validate", json=body).status_code == 401
    result = request(app, "POST", "/api/questions/validate", headers=HEADERS, json=body)
    assert result.status_code == 200 and result.json()["ok"]
    assert result.json()["bundles"] == body["bundles"]
    assert result.json()["sha256"] == qs.digest(body["bundles"])
    assert not calls and questions.active() == active and questions.history()[1] == 1
    assert questions.tests() == []
    with store.engine.connect() as db:
        for table in (messages, jobs, runs):
            assert db.execute(select(func.count()).select_from(table)).scalar_one() == 0
    invalid = copy.deepcopy(body)
    invalid["bundles"]["authority"]["authority_relationship"]["criteria"]["allow_all"] = "Always safe"
    assert request(app, "POST", "/api/questions/validate", headers=HEADERS, json=invalid).status_code == 400
    assert request(app, "POST", "/api/questions/validate", headers=HEADERS,
                   json=body | {"activate": True}).status_code == 422
    evaluation = replace(settings, evaluation_mode=True)
    assert request(create_app(evaluation, Pipeline(evaluation, store=store)), "POST", "/api/questions/validate",
                   headers=HEADERS, json=body).status_code == 403


def test_runtime_google_store_and_lock_are_not_copied_into_provider_snapshot(setup, monkeypatch):
    from mailsec.accounts import account_health

    settings, store, calls, _ = setup
    settings.organization = {"domains": ["example.test"]}
    # This is the actual runtime path hit before the editor in the dashboard.
    account_health(settings, store)
    assert settings._google_setup_store is store
    settings._runtime_lock = Lock()
    snapshot, provider = qs.provider_snapshot(settings, store)
    assert not hasattr(snapshot, "_google_setup_store") and not hasattr(snapshot, "_runtime_lock")
    snapshot.organization["domains"].append("independent.test")
    assert settings.organization["domains"] == ["example.test"]
    app = create_app(settings, Pipeline(settings, store=store))
    response = request(app, "GET", "/api/questions", headers=HEADERS)
    assert response.status_code == 200 and response.json()["provider"]["fingerprint"] == provider["fingerprint"]
    questions = qs.Questions(store)
    active, candidate = questions.active(), draft(questions)
    # Run the normal background entry point synchronously in this fixture while
    # retaining HTTP creation/polling, current provider binding and activation.
    class Worker:
        def __init__(self, target, args, **kwargs):
            self.target, self.args = target, args
        def start(self):
            self.target(*self.args)
    monkeypatch.setattr(qs.threading, "Thread", Worker)
    created = request(app, "POST", "/api/questions/test", headers=HEADERS, json={
        "revision_id": candidate["id"], "expected_provider_fingerprint": provider["fingerprint"],
        "text": "Your order shipped. No action is needed."})
    assert created.status_code == 202
    test_id = created.json()["id"]
    assert request(app, "GET", "/api/questions/tests/" + test_id, headers=HEADERS).json()["status"] == "complete"
    assert len(calls) == 6
    activated = request(app, "POST", "/api/questions/activate", headers=HEADERS, json={
        "revision_id": candidate["id"], "expected_active_id": active["id"], "test_id": test_id})
    assert activated.status_code == 200
    assert questions.active()["id"] == candidate["id"]


def test_oversize_or_incomplete_case_fails_before_provider_calls(setup):
    settings, store, calls, _ = setup
    questions = qs.Questions(store)
    candidate = draft(questions)
    evidence = {"body": "Please see the attachment.", "attachments": [{"filename": "invoice.pdf"}],
                "inspection": {"status": "not_run", "attachments": []}}
    result = completed_test(settings, questions, candidate, evidence)
    assert result["status"] == "error" and not calls
    assert result["usage"]["complete"] is False


def test_first_use_cross_engine_initialization_and_default_race(setup):
    _, store, _, _ = setup
    # Store tables already exist; only the question metadata and default row are
    # concurrently initialized through independent engine instances.
    others = [Store(str(store.engine.url)) for _ in range(4)]
    barrier = Barrier(4)
    def load(other):
        barrier.wait(timeout=10)
        return qs.Questions(other).active()
    try:
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(load, others))
        assert len({row["id"] for row in results}) == 1
        assert qs.Questions(store).history()[1] == 1
    finally:
        for other in others:
            other.engine.dispose()


def test_pipeline_uses_one_bundle_snapshot_then_refreshes_cross_instance(setup):
    settings, store, calls, Client = setup
    settings.action_review_enabled = True
    questions = qs.Questions(store)
    active = questions.active()
    candidate = draft(questions)
    result = completed_test(settings, questions, candidate)
    calls.clear()
    class ActivatingClient(Client):
        def evaluate(self, state, questions=None):
            response = super().evaluate(state, questions)
            if len(calls) == 1:
                qs.Questions(store).activate(candidate["id"], active["id"], result["provider_fingerprint"], result["id"])
            return response
    pipeline = Pipeline(settings, store=store, jev=ActivatingClient())
    item = pipeline.ingest(RAW)
    pipeline.process_one()
    first = store.detail(item["id"])["runs"][0]
    assert first["versions"]["question_revision_id"] == active["id"]
    assert first["versions"]["question_snapshot"]["bundles"] == active["bundles"]
    assert [bundle for _, bundle in calls] == list(active["bundles"].values())
    calls.clear()
    pipeline.jev = Client()
    store.enqueue(item["id"])
    pipeline.process_one()
    second = store.detail(item["id"])["runs"][0]
    assert second["versions"]["question_revision_id"] == candidate["id"]
    assert calls[0][1] == candidate["bundles"]["primary"]
    assert first["versions"]["jev_cache_key"] != second["versions"]["jev_cache_key"]
    assert store.detail(item["id"])["runs"][1] == first


def test_action_only_edit_changes_exact_cache_key(setup):
    settings, store, calls, Client = setup
    pipeline = Pipeline(settings, store=store, jev=Client())
    evidence = {"body": "Your order shipped.", "inspection": {"status": "complete", "attachments": []},
                "url_inspection": {"complete": True, "results": []}}
    one, two = settings.versions(), settings.versions()
    pipeline._evaluate(copy.deepcopy(evidence), one)
    pipeline._evaluate(copy.deepcopy(evidence), two)
    assert two["jev_cache_hit"] and len(calls) == 1
    questions = qs.Questions(store)
    active = questions.active()
    bundles = copy.deepcopy(active["bundles"])
    bundles["actions"]["payment_requested"]["instructions"] += " Current request only."
    candidate = questions.draft(bundles, "Action wording", active["id"])
    result = completed_test(settings, questions, candidate)
    questions.activate(candidate["id"], active["id"], result["provider_fingerprint"], result["id"])
    three = settings.versions()
    pipeline._evaluate(copy.deepcopy(evidence), three)
    assert not three["jev_cache_hit"]
    assert one["jev_cache_key"] != three["jev_cache_key"]
