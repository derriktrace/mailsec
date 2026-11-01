"""Model onboarding authorization, encrypted persistence and harmless probes."""
import asyncio
from dataclasses import replace

import httpx
import pytest
from cryptography.fernet import Fernet
from privacy_helpers import accept_test_disclosure
from sqlalchemy import select

from mailsec import model_setup
from mailsec.api import create_app
from mailsec.config import Settings
from mailsec.jev import JevError
from mailsec.storage import Store

TOKEN = "test-console-token-" + "a" * 32
HEADERS = {"authorization": "Bearer " + TOKEN}


@pytest.fixture
def setup(tmp_path, monkeypatch):
    settings = Settings(database_url=f"sqlite:///{tmp_path}/mail.db", app_token=TOKEN,
                        token_encryption_key=Fernet.generate_key().decode(), require_auth=True)
    store = Store(settings.database_url)
    accept_test_disclosure(settings, store, provider='ollama', base_url='http://localhost:11434')
    calls = []
    class Probe:
        def evaluate(self, evidence, questions):
            calls.append((evidence, questions))
            return {"model": "probe-model", "usage": {"input_tokens": 10, "output_tokens": 5}, "answers": {
                "kind": {"type": "choice", "choice": "greeting", "confidence": 1,
                         "probabilities": {"greeting": 1, "other": 0}},
                "requests_password": {"type": "noul", "noul": 0}}}
    monkeypatch.setattr(model_setup, "decision_client", lambda settings, **kwargs: Probe())
    return settings, store, calls


def request(app, method, path, **kwargs):
    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost") as client:
            return await client.request(method, path, **kwargs)
    return asyncio.run(run())


def local_configuration(**changes):
    return {"provider": "ollama", "model": "test-model", "base_url": "http://localhost:11434", **changes}


def test_model_setup_requires_console_auth_before_probe_or_secret_save(setup):
    settings, store, calls = setup
    app = create_app(settings)
    for path in ("/api/setup/model", "/api/setup/model/test"):
        response = request(app, "POST", path, json=local_configuration(api_key="private-test-key"))
        assert response.status_code == 401
    assert not calls
    model_setup.initialize(store)
    with store.engine.connect() as db:
        assert not db.execute(select(model_setup.model_settings)).first()


def test_model_configuration_encrypts_key_and_refreshes_worker_settings(setup):
    settings, store, calls = setup
    worker = replace(settings)
    app = create_app(settings)
    response = request(app, "POST", "/api/setup/model", headers=HEADERS,
                       json=local_configuration(api_key="private-test-key"))
    assert response.status_code == 200, response.text
    assert response.json()["key_configured"] and response.json()["configured"]
    assert response.json()["score_semantics"] == "uncalibrated_model_estimates"
    assert not response.json()["model_automatic_quarantine"]
    assert "private-test-key" not in response.text
    with store.engine.connect() as db:
        ciphertext = db.execute(select(model_setup.model_settings.c.encrypted_config)).scalar_one()
    assert "private-test-key" not in ciphertext and "localhost" not in ciphertext
    worker = model_setup.refresh_model_settings(worker, store)
    assert worker.decision_provider == "ollama" and worker.decision_api_key == "private-test-key"
    assert worker.decision_base_url == "http://localhost:11434"
    assert calls == [({"note": "Hello!"}, model_setup.PROBE_QUESTIONS)]


def test_probe_is_explicitly_a_connection_check_and_does_not_save(setup):
    settings, store, calls = setup
    response = request(create_app(settings), "POST", "/api/setup/model/test", headers=HEADERS,
                       json=local_configuration())
    assert response.status_code == 200 and response.json()["ok"]
    assert "not a detection accuracy test" in response.json()["note"]
    assert len(calls) == 1
    with store.engine.connect() as db:
        assert not db.execute(select(model_setup.model_settings)).first()


def test_failed_probe_does_not_replace_configuration_or_return_private_provider_text(setup, monkeypatch):
    settings, store, _ = setup
    app = create_app(settings)
    assert request(app, "POST", "/api/setup/model", headers=HEADERS, json=local_configuration()).status_code == 200
    class Offline:
        def evaluate(self, evidence, questions):
            raise JevError("Decision server could not be reached or timed out; no classification was accepted")
    monkeypatch.setattr(model_setup, "decision_client", lambda settings, **kwargs: Offline())
    response = request(app, "POST", "/api/setup/model", headers=HEADERS,
                       json=local_configuration(model="replacement", api_key="private-test-key"))
    assert response.status_code == 400 and "private-test-key" not in response.text
    assert model_setup.model_status(settings, store)["model"] == "test-model"


def test_invalid_secret_bearing_request_is_not_echoed_in_validation_error(setup):
    settings, _, calls = setup
    response = request(create_app(settings), "POST", "/api/setup/model", headers=HEADERS,
        json=local_configuration(timeout_seconds="private-key-in-invalid-field", api_key={"secret": "private-key"}))
    assert response.status_code == 422 and "private-key" not in response.text
    assert not calls


def test_changing_provider_or_endpoint_does_not_reuse_an_unrelated_key():
    settings = Settings(api_key="paid-provider-key", decision_provider="jev")
    value, candidate = model_setup.candidate(settings, model_setup.ModelConfiguration(**local_configuration()))
    assert value["api_key"] == "" and candidate.decision_api_key == ""
    settings = Settings(decision_provider="openai_compatible", decision_api_key="old-endpoint-key",
                        decision_base_url="https://old.example/v1")
    value, candidate = model_setup.candidate(settings, model_setup.ModelConfiguration(
        provider="openai_compatible", base_url="https://new.example/v1", model="test-model"))
    assert value["api_key"] == "" and candidate.decision_api_key == ""


def test_unchanged_endpoint_can_reuse_key_without_returning_it_in_status(setup):
    settings, store, _ = setup
    app = create_app(settings)
    assert request(app, "POST", "/api/setup/model", headers=HEADERS,
                   json=local_configuration(api_key="private-test-key")).status_code == 200
    response = request(app, "POST", "/api/setup/model", headers=HEADERS,
                       json=local_configuration(model="different-installed-model"))
    assert response.status_code == 200
    configured = model_setup.model_snapshot(settings, store)
    assert configured.decision_api_key == "private-test-key" and "private-test-key" not in response.text
    assert settings.decision_provider == "jev" and settings.decision_api_key == ""
    assert "private-test-key" not in request(app, "GET", "/api/setup/model", headers=HEADERS).text


def test_provider_settings_do_not_cross_tenants_or_evaluation_mode(setup):
    settings, store, _ = setup
    app = create_app(settings)
    assert request(app, "POST", "/api/setup/model", headers=HEADERS, json=local_configuration()).status_code == 200
    separate = replace(settings, tenant_id="different-tenant", decision_provider="jev", model="separate-model")
    separate = model_setup.refresh_model_settings(separate, store)
    assert separate.decision_provider == "jev" and separate.model == "separate-model"
    evaluation = replace(settings, evaluation_mode=True, decision_provider="jev", model="evaluation-model")
    evaluation = model_setup.refresh_model_settings(evaluation, store)
    assert evaluation.decision_provider == "jev" and evaluation.model == "evaluation-model"
