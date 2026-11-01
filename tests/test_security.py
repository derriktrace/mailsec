import asyncio

import httpx
import pytest
from privacy_helpers import authorize_test_provider

from mailsec.api import create_app
from mailsec.config import Settings
from mailsec.demo import samples
from mailsec.jev import QUESTIONS, JevClient, JevError, passive_policy, validate_response
from mailsec.pipeline import Pipeline


def response():
    return {"model": "jev-test", "usage": {"input_tokens": 1, "output_tokens": 1}, "answers": {
        "recommended_security_action": {"type": "choice", "choice": "deliver", "confidence": 1.,
            "probabilities": {"deliver": 1., "junk": 0., "review": 0., "quarantine": 0., "block": 0.}},
        "verdict": {"type": "choice", "choice": "clean", "confidence": .9,
                    "probabilities": {"clean": .9, "spam": .1, "suspicious": 0, "phishing": 0}},
        **{k: {"type": "noul", "noul": 0} for k, q in QUESTIONS.items() if q["type"] == "noul"}}}


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -.1, 1.1, True, "0.2"])
def test_non_probability_provider_values_rejected(value):
    data = response()
    data["answers"]["deceptive_identity"]["noul"] = value
    with pytest.raises(JevError):
        validate_response(data)


def test_provider_retry_budget_and_no_redirect_or_secret_echo():
    calls = []
    def retry(request):
        calls.append(request)
        return httpx.Response(429, headers={"retry-after": "999"}, text="private secret")
    waits = []
    with pytest.raises(JevError, match="HTTP 429"):
        JevClient("private", transport=httpx.MockTransport(retry), sleeper=waits.append).evaluate({})
    assert len(calls) == 3
    assert waits == [15, 15]
    assert all(str(r.url) == "https://api.typesafe.ai/v1/systemone" for r in calls)
    with pytest.raises(JevError, match="HTTP 302"):
        JevClient("private", transport=httpx.MockTransport(lambda r: httpx.Response(302,
            headers={"location": "https://other.invalid"}))).evaluate({})


def test_passive_policy_never_executes_even_high_confidence_phishing():
    data = response()
    data["answers"]["verdict"].update(choice="phishing", confidence=1)
    assert passive_policy(data)["executed_action"] == "none"
    assert passive_policy(data)["recommended_action"] == "quarantine"
    data["answers"]["verdict"]["confidence"] = .2
    assert passive_policy(data)["recommended_action"] == "analyst_review"


def test_console_token_origin_host_and_upload_boundary(tmp_path):
    settings = Settings(database_url=f"sqlite:///{tmp_path / 'security.db'}", app_token="console-secret")
    app = create_app(settings)
    async def check():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://testserver") as client:
            assert (await client.get("/api/status")).status_code == 401
            auth = {"Authorization": "Bearer console-secret"}
            assert (await client.get("/api/status", headers=auth)).status_code == 200
            assert (await client.post("/api/demo", headers={**auth, "Origin": "https://attacker.invalid"})).status_code == 403
            assert (await client.post("/api/demo", headers={**auth, "Origin": "https://testserver"})).status_code == 403
            assert (await client.get("/api/status", headers={**auth, "Origin": "http://testserver:80"})).status_code == 200
            assert (await client.get("/api/status", headers={**auth, "Origin": "null"})).status_code == 403
            assert (await client.get("/api/status", headers={**auth, "host": "attacker.invalid"})).status_code == 400
            assert (await client.post("/api/import", headers={**auth, "Content-Length": "999999999"})).status_code == 413
            result = await client.get("/health")
            assert "frame-ancestors 'none'" in result.headers["content-security-policy"]
            assert result.headers["cache-control"] == "no-store"
    asyncio.run(check())


def test_streaming_limit_precedes_multipart_parser_and_does_not_trust_length(tmp_path):
    settings = Settings(database_url=f"sqlite:///{tmp_path / 'uploads.db'}", app_token="test", max_message_bytes=64)
    app = create_app(settings)

    async def check():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://testserver") as client:
            auth = {"Authorization": "Bearer test"}
            sent = []

            async def oversized():
                for _ in range(10):
                    sent.append(True)
                    yield b"x" * 40000

            for extra in ({}, {"Content-Length": "1"}):
                sent.clear()
                result = await client.post("/api/import", content=oversized(), headers={
                    **auth, **extra, "Content-Type": "multipart/form-data; boundary=x"})
                assert result.status_code == 413
                assert len(sent) == 2  # Rejected before draining the whole stream or parsing multipart.
                assert result.headers["cache-control"] == "no-store"
            result = await client.post("/api/demo", content=b"x" * 65537, headers=auth)
            assert result.status_code == 413
            result = await client.post("/api/demo", content=b"abc", headers={**auth, "Content-Length": "1"})
            assert result.status_code == 400
            for declared in ("-1", "+0", "1, 1", "9" * 5000):
                result = await client.post("/api/demo", headers={**auth, "Content-Length": declared})
                assert result.status_code in {400, 413}
            result = await client.post("/api/demo", content=b"fake-gzip", headers={**auth, "Content-Encoding": "gzip"})
            assert result.status_code == 415
            result = await client.get("/api/status", headers={"Authorization": b"Bearer \xff"})
            assert result.status_code == 401
            assert "frame-ancestors 'none'" in result.headers["content-security-policy"]
            assert (await client.get("/api/messages", headers=auth)).json()["messages"] == []
    asyncio.run(check())


def test_slow_upload_times_out_and_releases_capacity(tmp_path, monkeypatch):
    from mailsec.http_security import ConsoleSecurityMiddleware
    monkeypatch.setattr(ConsoleSecurityMiddleware, "upload_timeout_seconds", 0.01)
    monkeypatch.setattr(ConsoleSecurityMiddleware, "upload_slots", 1)
    app = create_app(Settings(database_url=f"sqlite:///{tmp_path / 'slow.db'}", app_token="test"))

    async def check():
        async def slow():
            yield b"a"
            await asyncio.sleep(10)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://testserver",
                                     headers={"Authorization": "Bearer test"}) as client:
            for _ in range(2):
                result = await client.post("/api/import", content=slow())
                assert result.status_code == 408
            assert (await client.get("/api/status")).status_code == 200
    asyncio.run(check())


def test_invalid_request_does_not_echo_private_input(tmp_path):
    app = create_app(Settings(database_url=f"sqlite:///{tmp_path / 'redaction.db'}", app_token="test"))

    async def check():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://testserver",
                                     headers={"Authorization": "Bearer test"}) as client:
            private = "private-submitted-input-" * 300
            response = await client.post("/api/messages/unknown/feedback", json={"verdict": "clean", "reason": private})
            assert response.status_code == 422
            assert "private-submitted-input" not in response.text
            assert response.json()["errors"] == [{"location": ["body", "reason"], "type": "string_too_long"}]
    asyncio.run(check())


def test_exposed_listener_cannot_use_tokenless_local_demo_defaults(monkeypatch):
    for host in ("0.0.0.0", "::", "192.0.2.1", "mail.example.org"):
        with pytest.raises(ValueError, match="non-loopback listener requires a console token"):
            Settings(bind_host=host)
        Settings(bind_host=host, app_token="x" * 32, allowed_hosts=["mail.example.org"])
    with pytest.raises(ValueError, match="explicit allowed hostnames"):
        Settings(bind_host="0.0.0.0", app_token="x" * 32, allowed_hosts=["*"])
    for host in ("localhost", "127.0.0.1", "::1"):
        Settings(bind_host=host)
    # The CLI override must apply the same boundary as environment configuration.
    from mailsec.cli import main
    monkeypatch.setattr(Settings, "load", lambda: Settings())
    monkeypatch.setattr("sys.argv", ["mailsec", "serve", "--host", "0.0.0.0"])
    with pytest.raises(SystemExit) as error:
        main()
    assert error.value.code == 2


def test_gmail_unparseable_is_retained_as_error_not_a_poll_poison(tmp_path):
    settings = Settings(database_url=f"sqlite:///{tmp_path / 'badmail.db'}", max_message_bytes=10)
    pipeline = Pipeline(settings)
    raw = next(samples())[1]
    item = pipeline.ingest(raw, provider="gmail", provider_message_id="oversize", mailbox="user@example.org")
    assert item["rejected"] is True
    assert pipeline.store.get_message(item["id"])["raw"] == raw
    assert pipeline.store.detail(item["id"])["runs"][0]["status"] == "error"
    assert pipeline.process_one() is None
    assert pipeline.ingest(raw, provider="gmail", provider_message_id="oversize", mailbox="user@example.org")["duplicate"]
    with pytest.raises(ValueError):
        pipeline.ingest(raw, provider="eml")


def test_history_checkpoint_does_not_regress(tmp_path):
    pipeline = Pipeline(Settings(database_url=f"sqlite:///{tmp_path / 'history.db'}"))
    pipeline.store.update_mailbox("user@example.org", history_id="999")
    pipeline.store.update_mailbox("user@example.org", history_id="1000")
    pipeline.store.update_mailbox("user@example.org", history_id="999")
    assert pipeline.store.mailbox_state("user@example.org")["history_id"] == "1000"


def test_overview_counts_only_completed_predictions_and_reviews(tmp_path):
    from mailsec.storage import now
    settings = Settings(database_url=f"sqlite:///{tmp_path / 'overview.db'}")
    fake = response()
    fake["answers"]["verdict"].update(choice="phishing", probabilities={"clean": .1, "spam": 0, "suspicious": 0, "phishing": .9})
    pipeline = Pipeline(settings, jev=JevClient("test", transport=httpx.MockTransport(lambda r: httpx.Response(200, json=fake))))
    authorize_test_provider(settings, pipeline.store)
    raw = next(samples())[1]
    item = pipeline.ingest(raw, received_at=now())
    assert pipeline.store.overview()["pending_messages"] == 1
    pipeline.process_one()
    data = pipeline.store.overview()
    assert data["analyzed_messages"] == 1
    assert data["review_needed"] == 1
    assert data["daily"][-1]["phishing"] == 1
    pipeline.store.add_feedback(item["id"], "clean", "Test correction", "test")
    assert pipeline.store.overview()["review_needed"] == 0
    assert pipeline.store.overview()["reviewed_messages"] == 1
    assert pipeline.store.overview()["recent_risks"] == []


def test_import_without_mailbox_does_not_invent_a_recipient_relationship(tmp_path):
    pipeline = Pipeline(Settings(database_url=f"sqlite:///{tmp_path / 'recipients.db'}"))
    raw = next(samples())[1]
    pipeline.ingest(raw, received_at="2026-09-01T12:00:00Z")
    later = pipeline.ingest(raw.replace(b"order #1842", b"order #1843"), received_at="2026-09-02T12:00:00Z")
    history = pipeline.store.sender_history(pipeline.store.get_message(later["id"]))
    assert history["sender_messages_previous_90d"] == 1
    assert history["recipient_received_from_sender_before"] is None
