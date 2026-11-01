"""No email leaves before explicit owner disclosure and saved provider choices."""
import asyncio
import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Event, Lock

import httpx
import pytest
from cryptography.fernet import Fernet
from privacy_helpers import authorize_test_provider
from sqlalchemy import func, select
from test_question_settings import answers

from mailsec import decision, model_setup, question_settings
from mailsec import provider_consent as privacy
from mailsec.api import create_app
from mailsec.config import Settings
from mailsec.decision import decision_client
from mailsec.pipeline import Pipeline
from mailsec.storage import Store, jobs, runs

TOKEN = "synthetic-owner-console-" + "x" * 40
HEADERS = {"authorization": "Bearer " + TOKEN}
RAW = (b"From: vendor@example.test\r\nTo: owner@example.test\r\nCc: family@example.test\r\n"
       b"Subject: Receipt\r\n\r\nYour order shipped. No action is needed.")


def request(app, method, path, **kwargs):
    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost") as client:
            return await client.request(method, path, **kwargs)
    return asyncio.run(run())


@pytest.fixture
def setup(tmp_path, monkeypatch):
    settings = Settings(database_url=f"sqlite:///{tmp_path}/consent.db", api_key="synthetic-provider-credential",
        app_token=TOKEN, token_encryption_key=Fernet.generate_key().decode(), require_auth=True,
        enforcement_mode="auto_quarantine", notifications_enabled=True)
    store, calls = Store(settings.database_url), []
    def provider(req):
        payload = json.loads(req.content)
        calls.append(payload)
        return httpx.Response(200, json=answers(payload["questions"]))
    transport = httpx.MockTransport(provider)
    def factory(settings, **kwargs):
        return decision_client(settings, transport=transport, **kwargs)
    monkeypatch.setattr(model_setup, "decision_client", factory)
    monkeypatch.setattr(question_settings, "decision_client", factory)
    app = create_app(settings, Pipeline(settings, store=store))
    yield settings, store, calls, app, transport
    store.engine.dispose()


def preview(app, provider="jev", base_url=""):
    response = request(app, "POST", "/api/setup/privacy/preview", headers=HEADERS,
                       json={"provider": provider, "base_url": base_url})
    assert response.status_code == 200, response.text
    return response.json()


def accept(app, provider="jev", base_url=""):
    doc = preview(app, provider, base_url)
    response = request(app, "POST", "/api/setup/privacy/accept", headers=HEADERS, json={
        "provider": provider, "base_url": base_url, "disclosure_version": doc["disclosure_version"],
        "disclosure_sha256": doc["disclosure_sha256"], "accepted": True})
    assert response.status_code == 200, response.text
    return response.json()


def save(app, masking=False):
    response = request(app, "POST", "/api/setup/model", headers=HEADERS,
                       json={"provider": "jev", "model": "jev-test", "recipient_address_masking": masking})
    assert response.status_code == 200, response.text
    return response.json()


def test_environment_key_does_not_grant_owner_consent_and_queued_mail_is_preserved(setup):
    settings, store, calls, app, _ = setup
    pipeline = Pipeline(settings, store=store)
    item = pipeline.ingest(RAW)
    before = store.get_message(item["id"])
    assert pipeline.process_one() is None
    assert pipeline.analysis_paused_reason == "awaiting_privacy_consent"
    assert store.get_message(item["id"]) == before
    with store.engine.connect() as db:
        job = db.execute(select(jobs)).mappings().one()
        assert job["status"] == "pending" and job["attempts"] == 0
        assert db.execute(select(func.count()).select_from(runs)).scalar_one() == 0
        assert db.execute(select(func.count()).select_from(privacy.privacy_events)).scalar_one() == 0
    status = request(app, "GET", "/api/setup/model", headers=HEADERS).json()
    assert status["configured"] and status["analysis_paused"]
    assert not status["privacy"]["accepted"] and not status["privacy"]["analysis_allowed"]
    assert not calls


def test_explicit_current_disclosure_hash_and_strict_checkbox_required(setup):
    _, store, calls, app, _ = setup
    doc = preview(app)
    assert doc["third_party"] is True and doc["sends_identifiers"] and not doc["sends_raw_attachments"]
    assert "TypeSafe" in doc["title"] and "third party" in doc["summary"]
    assert {row["title"] for row in doc["sections"]} >= {"Recipient identifiers", "Attachments and local storage"}
    body = {"provider": "jev", "disclosure_version": doc["disclosure_version"],
            "disclosure_sha256": doc["disclosure_sha256"], "accepted": True}
    assert request(app, "POST", "/api/setup/privacy/accept", json=body).status_code == 401
    for change in ({"accepted": False}, {"disclosure_version": "old-version"}, {"disclosure_sha256": "0" * 64}):
        assert request(app, "POST", "/api/setup/privacy/accept", headers=HEADERS,
                       json=body | change).status_code == 409
    for change in ({"accepted": "true"}, {"accepted": 1}, {"grant_all_destinations": True}):
        assert request(app, "POST", "/api/setup/privacy/accept", headers=HEADERS,
                       json=body | change).status_code == 422
    with store.engine.connect() as db:
        assert db.execute(select(func.count()).select_from(privacy.privacy_events)).scalar_one() == 0
    assert not calls


def test_acceptance_only_permits_setup_tests_then_save_commits_masking_and_analysis(setup):
    settings, store, calls, app, transport = setup
    item = Pipeline(settings, store=store).ingest(RAW)
    accepted = accept(app)
    assert accepted["accepted"] and accepted["activation_required"] and not accepted["analysis_allowed"]
    assert not calls  # checking the box did not send a synthetic probe or any mail
    blocked = Pipeline(settings, store=store)
    assert blocked.process_one() is None
    with pytest.raises(privacy.PrivacyConsentRequired):
        decision_client(settings, store=store, transport=transport).evaluate({"body": "private-unmasked"})
    result = request(app, "POST", "/api/setup/model/test", headers=HEADERS,
                     json={"provider": "jev", "model": "jev-test", "recipient_address_masking": True})
    assert result.status_code == 200
    assert len(calls) == 1 and calls[0]["state"]["note"] == "Hello!"
    assert privacy.privacy_status(settings, store)["analysis_allowed"] is False
    saved = save(app, masking=True)
    assert saved["recipient_address_masking"] and not saved["analysis_paused"]
    assert saved["privacy"]["analysis_allowed"]
    settings = model_setup.refresh_model_settings(settings, store)
    pipeline = Pipeline(settings, store=store, jev=decision_client(settings, store=store, transport=transport))
    assert pipeline.process_one()["status"] == "complete"
    assert store.get_message(item["id"])["status"] == "complete"
    submitted = json.dumps(calls[-1])
    assert "owner@example.test" not in submitted and "family@example.test" not in submitted
    assert "recipient-" in submitted


def test_setup_tests_and_save_are_blocked_without_acceptance_before_any_call(setup):
    _, store, calls, app, _ = setup
    for path in ("/api/setup/model/test", "/api/setup/model"):
        response = request(app, "POST", path, headers=HEADERS, json={"provider": "jev", "model": "jev-test"})
        assert response.status_code == 403
    with store.engine.connect() as db:
        assert not db.execute(select(model_setup.model_settings)).first()
    assert not calls


def test_legacy_saved_configuration_is_not_grandfathered_after_acceptance(setup):
    from mailsec.accounts import _encrypt
    from mailsec.storage import now

    settings, store, calls, app, _ = setup
    model_setup.initialize(store)
    with store.engine.begin() as db:
        db.execute(model_setup.model_settings.insert().values(tenant=settings.tenant_id, updated_at=now(),
            encrypted_config=_encrypt(settings, {"provider": "jev", "model": "jev-test", "base_url": "",
                "timeout_seconds": 120, "api_key": settings.api_key})))
    status = accept(app)
    assert status["accepted"] and not status["analysis_allowed"]
    settings = model_setup.refresh_model_settings(settings, store)
    assert not settings.decision_privacy_authorization
    assert not calls


def test_destinations_tenants_and_document_versions_are_independent(setup, monkeypatch):
    settings, store, _, app, _ = setup
    accept(app)
    assert privacy.privacy_status(settings, store)["accepted"]
    other = replace(settings, tenant_id="other-customer")
    assert not privacy.privacy_status(other, store)["accepted"]
    remote = preview(app, "openai_compatible", "https://models.example.test/v1")
    assert not remote["accepted"] and remote["third_party"] is None
    assert "remote" in remote["summary"] and "models.example.test" in remote["destination"]
    monkeypatch.setattr(privacy, "DISCLOSURE_VERSION", "email-sharing-next-version")
    assert not privacy.privacy_status(settings, store)["accepted"]


def test_revocation_and_reacceptance_require_a_new_save_and_history_is_append_only(setup):
    settings, store, _, app, transport = setup
    accept(app)
    save(app)
    configured = model_setup.model_snapshot(settings, store)
    old_client = decision_client(configured, store=store, transport=transport)
    scope = privacy.destination("jev")
    result = request(app, "POST", "/api/setup/privacy/revoke", headers=HEADERS,
                     json={"destination_sha256": scope["destination_sha256"]})
    assert result.status_code == 200 and not result.json()["analysis_allowed"]
    with pytest.raises(privacy.PrivacyConsentRequired):
        old_client.evaluate({"body": "must not leave"})
    renewed = accept(app)
    assert renewed["accepted"] and renewed["activation_required"] and not renewed["analysis_allowed"]
    with pytest.raises(privacy.PrivacyConsentRequired):
        old_client.evaluate({"body": "still must not leave"})
    save(app)
    with store.engine.connect() as db:
        events = list(db.execute(select(privacy.privacy_events).order_by(privacy.privacy_events.c.id)).mappings())
    assert [event["accepted"] for event in events] == [True, False, True]
    assert all(event["actor"] == "authenticated_console" for event in events)
    assert settings.api_key not in json.dumps([dict(event) for event in events])


def test_revoke_during_first_jev_attempt_prevents_retry_request(setup):
    settings, store, _, _, _ = setup
    authorize_test_provider(settings, store)
    calls = []
    def handler(req):
        calls.append(req)
        privacy.PrivacyConsents(store, settings.tenant_id).record(privacy.destination("jev"), False)
        return httpx.Response(429)
    client = decision_client(settings, store=store, transport=httpx.MockTransport(handler))
    client.sleep = lambda _: None
    with pytest.raises(privacy.PrivacyConsentRequired):
        client.evaluate({"body": "synthetic"})
    assert len(calls) == 1


def test_revoke_during_masking_prevents_first_network_request(setup, monkeypatch):
    from mailsec import provider_redaction

    settings, store, calls, _, transport = setup
    settings.decision_recipient_address_masking = True
    authorize_test_provider(settings, store)
    original = provider_redaction.mask_payload
    def transform(*args):
        result = original(*args)
        privacy.PrivacyConsents(store, settings.tenant_id).record(privacy.destination("jev"), False)
        return result
    monkeypatch.setattr(provider_redaction, "mask_payload", transform)
    with pytest.raises(privacy.PrivacyConsentRequired):
        decision_client(settings, store=store, transport=transport).evaluate({"message": {"mailbox": "owner@example.test"}})
    assert not calls


def test_local_destination_rechecks_permission_after_dns(setup, monkeypatch):
    settings, store, calls, _, _ = setup
    settings.decision_provider, settings.decision_base_url = "ollama", "http://localhost:11434"
    authorize_test_provider(settings, store)
    async def resolve(url):
        privacy.PrivacyConsents(store, settings.tenant_id).record(
            privacy.destination(settings.decision_provider, settings.decision_base_url), False)
        return httpx.URL(url), {}, {}
    monkeypatch.setattr(decision, "_pinned_destination", resolve)
    # If the consent callback were absent this fixture would intercept the
    # attempted request, without opening a real socket.
    original = httpx.AsyncClient
    def fake_client(**kwargs):
        kwargs["transport"] = httpx.MockTransport(lambda req: calls.append(req) or httpx.Response(500))
        return original(**kwargs)
    monkeypatch.setattr(httpx, "AsyncClient", fake_client)
    with pytest.raises(privacy.PrivacyConsentRequired):
        decision_client(settings, store=store).evaluate({"body": "synthetic"})
    assert not calls


def test_old_client_cannot_continue_after_saving_a_new_mask_choice(setup):
    settings, store, _, _, _ = setup
    authorize_test_provider(settings, store)
    old = decision_client(settings, store=store, transport=httpx.MockTransport(lambda req: httpx.Response(500)))
    settings.decision_recipient_address_masking = True
    authorize_test_provider(settings, store)
    with pytest.raises(privacy.PrivacyConsentRequired):
        old.evaluate({"body": "old unmasked request"})


def test_revoked_mid_analysis_requeues_without_new_runs_verdict_or_quarantine(setup):
    from mailsec.mailbox_actions import list_actions

    settings, store, _, _, _ = setup
    authorize_test_provider(settings, store)
    revoke = False
    def handler(req):
        value = answers(json.loads(req.content)["questions"])
        if revoke:
            privacy.PrivacyConsents(store, settings.tenant_id).record(privacy.destination("jev"), False)
        return httpx.Response(200, json=value)
    pipeline = Pipeline(settings, store=store, jev=decision_client(settings, store=store,
        transport=httpx.MockTransport(handler)))
    item = pipeline.ingest(RAW)
    assert pipeline.process_one()["status"] == "complete"
    prior = store.detail(item["id"])
    store.enqueue(item["id"])
    revoke = True
    result = pipeline.process_one()
    assert result["status"] == "awaiting_privacy_consent" and result["error"] is None
    after = store.detail(item["id"])
    assert after["runs"] == prior["runs"] and after["message"]["system_verdict"] == prior["message"]["system_verdict"]
    assert after["message"]["status"] == "pending" and list_actions(store) == []
    with store.engine.connect() as db:
        assert db.execute(select(jobs.c.status).where(jobs.c.id == store._enqueue(item["id"]))).scalar_one() == "pending"


def test_question_comparison_cannot_start_until_disclosure_and_model_save(setup):
    _, store, calls, app, _ = setup
    questions = question_settings.Questions(store)
    active = questions.active()
    body = {"revision_id": active["id"], "text": "Synthetic note.",
            "expected_provider_fingerprint": request(app, "GET", "/api/questions", headers=HEADERS).json()["provider"]["fingerprint"]}
    assert request(app, "POST", "/api/questions/test", headers=HEADERS, json=body).status_code == 403
    accept(app)
    assert request(app, "POST", "/api/questions/test", headers=HEADERS, json=body).status_code == 403
    with store.engine.connect() as db:
        assert db.execute(select(func.count()).select_from(question_settings.test_runs)).scalar_one() == 0
    assert not calls


def test_mask_setting_is_persisted_and_changes_question_provider_fingerprint(setup):
    settings, store, _, app, _ = setup
    accept(app)
    save(app, False)
    first = question_settings.provider_snapshot(settings, store)[1]["fingerprint"]
    save(app, True)
    second = question_settings.provider_snapshot(settings, store)[1]["fingerprint"]
    settings = model_setup.model_snapshot(settings, store)
    assert first != second and settings.decision_recipient_address_masking is True
    assert settings.decision_privacy_authorization["recipient_address_masking"] is True


def test_omitting_optional_masking_field_does_not_disable_a_saved_privacy_choice(setup):
    settings, store, _, app, _ = setup
    accept(app)
    save(app, True)
    response = request(app, "POST", "/api/setup/model", headers=HEADERS,
                       json={"provider": "jev", "model": "jev-test"})
    assert response.status_code == 200 and response.json()["recipient_address_masking"] is True
    assert model_setup.model_snapshot(settings, store).decision_recipient_address_masking is True


def test_evaluation_and_tokenless_contexts_cannot_accept_for_an_owner(setup):
    settings, store, _, app, _ = setup
    document = preview(app)
    body = {"provider": "jev", "disclosure_version": document["disclosure_version"],
            "disclosure_sha256": document["disclosure_sha256"], "accepted": True}
    evaluation = replace(settings, evaluation_mode=True)
    assert request(create_app(evaluation, Pipeline(evaluation, store=store)), "POST", "/api/setup/privacy/accept",
                   headers=HEADERS, json=body).status_code == 403
    tokenless = replace(settings, app_token="", require_auth=False)
    assert request(create_app(tokenless, Pipeline(tokenless, store=store)), "POST", "/api/setup/privacy/accept",
                   json=body).status_code == 403


def test_concurrent_model_refresh_returns_whole_snapshots_never_mixed_credentials(setup, monkeypatch):
    settings, store, _, _, _ = setup
    config_a = replace(settings, decision_provider="openai_compatible", decision_base_url="https://model-a.example/v1",
                       decision_api_key="synthetic-key-a", model="model-a")
    authorize_test_provider(config_a, store)
    read_a, release_a = Event(), Event()
    decrypt = model_setup._decrypt
    def delayed_decrypt(snapshot, encrypted):
        value = decrypt(snapshot, encrypted)
        if value["model"] == "model-a":
            read_a.set()
            assert release_a.wait(10)
        return value
    monkeypatch.setattr(model_setup, "_decrypt", delayed_decrypt)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(model_setup.model_snapshot, settings, store)
        assert read_a.wait(10)
        config_b = replace(settings, decision_provider="openai_compatible", decision_base_url="https://model-b.example/v1",
                           decision_api_key="synthetic-key-b", model="model-b")
        authorize_test_provider(config_b, store)
        snapshot_b = model_setup.model_snapshot(settings, store)
        release_a.set()
        snapshot_a = future.result(timeout=10)
    assert (snapshot_a.model, snapshot_a.decision_base_url, snapshot_a.decision_api_key) == (
        "model-a", "https://model-a.example/v1", "synthetic-key-a")
    assert (snapshot_b.model, snapshot_b.decision_base_url, snapshot_b.decision_api_key) == (
        "model-b", "https://model-b.example/v1", "synthetic-key-b")
    assert settings.decision_provider == "jev" and settings.decision_api_key == ""
    sent = []
    def provider(req):
        sent.append(req)
        assert req.url.host == "model-b.example" and req.headers["authorization"] == "Bearer synthetic-key-b"
        assert json.loads(req.content)["model"] == "model-b"
        return httpx.Response(200, json={"choices": [{"finish_reason": "stop", "message": {
            "content": json.dumps({"answers": answers(model_setup.PROBE_QUESTIONS)["answers"]})}}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1}})
    transport = httpx.MockTransport(provider)
    with pytest.raises(privacy.PrivacyConsentRequired):
        decision_client(snapshot_a, store=store, transport=transport).evaluate({"note": "Hello!"}, model_setup.PROBE_QUESTIONS)
    decision_client(snapshot_b, store=store, transport=transport).evaluate({"note": "Hello!"}, model_setup.PROBE_QUESTIONS)
    assert len(sent) == 1


def test_revoke_resolves_current_destination_after_tenant_lock_and_refuses_stale_form(setup, monkeypatch):
    settings, store, _, app, _ = setup
    config_a = replace(settings, decision_provider="ollama", decision_base_url="http://localhost:11434")
    authorize_test_provider(config_a, store)
    scope_a = privacy.destination(config_a.decision_provider, config_a.decision_base_url)
    before_lock, resume = Event(), Event()
    intercept_lock, intercepted = Lock(), False
    original = model_setup.lock_model_configuration
    def delay_first_lock(db, tenant):
        nonlocal intercepted
        with intercept_lock:
            first = not intercepted
            intercepted = True
        if first:
            before_lock.set()
            assert resume.wait(10)
        return original(db, tenant)
    monkeypatch.setattr(model_setup, "lock_model_configuration", delay_first_lock)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(request, app, "POST", "/api/setup/privacy/revoke", headers=HEADERS,
                             json={"destination_sha256": scope_a["destination_sha256"]})
        assert before_lock.wait(10)
        config_b = replace(settings, decision_provider="ollama", decision_base_url="http://localhost:22434")
        authorize_test_provider(config_b, store)
        resume.set()
        response = future.result(timeout=10)
    assert response.status_code == 409
    assert privacy.privacy_status(config_b, store)["analysis_allowed"]
    assert privacy.PrivacyConsents(store, settings.tenant_id).status(scope_a)["accepted"]
    with store.engine.connect() as db:
        assert not db.execute(select(privacy.privacy_events).where(privacy.privacy_events.c.accepted.is_(False))).first()


def test_factory_binds_raw_client_and_guard_from_the_same_detached_configuration(setup, monkeypatch):
    settings, store, _, _, _ = setup
    settings.decision_provider, settings.decision_base_url = "openai_compatible", "https://model-a.example/v1"
    settings.decision_api_key, settings.model = "synthetic-key-a", "model-a"
    authorize_test_provider(settings, store)
    original_endpoint = decision.endpoint
    def interleave_configuration_change(url, provider):
        result = original_endpoint(url, provider)
        settings.decision_base_url = "https://model-b.example/v1"
        settings.decision_api_key = "synthetic-key-b"
        return result
    monkeypatch.setattr(decision, "endpoint", interleave_configuration_change)
    client = decision_client(settings, store=store, transport=httpx.MockTransport(lambda req: httpx.Response(500)))
    assert client._client.url.startswith("https://model-a.example/")
    assert client._client.api_key == client._settings.decision_api_key == "synthetic-key-a"
    assert client._settings.decision_base_url == "https://model-a.example/v1"
    assert settings.decision_base_url == "https://model-b.example/v1"
