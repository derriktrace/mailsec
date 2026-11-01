import asyncio
import base64
import hashlib
import json
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx
import pytest
from cryptography.fernet import Fernet
from fastapi import FastAPI
from sqlalchemy import select, update

from mailsec import accounts as module
from mailsec.accounts import (
    account_health,
    accounts,
    connected_mailboxes,
    gmail_client,
    oauth_states,
    register_account_routes,
)
from mailsec.gmail import MODIFY_SCOPE, READONLY_SCOPE, GmailAuthorizationError
from mailsec.storage import Store


@pytest.fixture
def setup(tmp_path):
    config = tmp_path / "client.json"
    config.write_text(json.dumps({"web": {"client_id": "test-client", "client_secret": "test-secret",
        "redirect_uris": ["http://localhost/oauth/google/callback"]}}))
    settings = SimpleNamespace(google_oauth_client_file=str(config),
        google_oauth_redirect_uri="http://localhost/oauth/google/callback", token_encryption_key=Fernet.generate_key().decode(),
        authorized_mailboxes=["me@example.test", "other@example.test"], google_service_account_file="", mailboxes=[],
        app_token="console-secret", enforcement_mode="auto_quarantine", notifications_enabled=True)
    return settings, Store(f"sqlite:///{tmp_path}/mail.db")


def make_app(settings, store, handler):
    app = FastAPI()
    register_account_routes(app, settings, store, transport=httpx.MockTransport(handler))
    return app


def token_response(scope=MODIFY_SCOPE):
    return {"access_token": "sensitive-access", "refresh_token": "sensitive-refresh", "scope": scope, "expires_in": 3600}


async def begin(client, mailbox="me@example.test"):
    response = await client.post("/api/accounts/connect", json={"mailbox": mailbox},
                                headers={"authorization": "Bearer console-secret"})
    assert response.status_code == 200, response.text
    return parse_qs(urlsplit(response.json()["authorization_url"]).query)


@pytest.mark.parametrize("mailbox", ["relative@gmail.com", "relative@workspace.example"])
def test_personal_and_workspace_oauth_support_monitor_scope(setup, monkeypatch, mailbox):
    settings, store = setup
    settings.authorized_mailboxes = [mailbox]
    def handler(request):
        if request.url.path == "/token":
            return httpx.Response(200, json=token_response(READONLY_SCOPE))
        return httpx.Response(200, json={"emailAddress": mailbox})
    app = make_app(settings, store, handler)
    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost") as client:
            response = await client.post("/api/accounts/connect", json={"mailbox": mailbox, "access_mode": "monitor"},
                                        headers={"authorization": "Bearer console-secret"})
            assert response.status_code == 200
            params = parse_qs(urlsplit(response.json()["authorization_url"]).query)
            assert params["scope"] == [READONLY_SCOPE]
            assert (await callback(client, params)).status_code == 303
    asyncio.run(run())
    assert connected_mailboxes(settings, store) == [mailbox]
    health = account_health(settings, store)["accounts"][0]
    assert health["access_mode"] == "monitor" and not health["can_modify"]
    assert "monitoring only" in module.oauth_write_restriction(store, mailbox)
    with pytest.raises(ValueError, match="monitoring only"):
        with gmail_client(settings, store, mailbox, for_actions=True):
            pytest.fail("Read-only consent cannot construct a writable client")
    # A real client blocks writes even if a caller forgets for_actions=True.
    original = module.GmailClient
    def readonly(*args, **kwargs):
        return original(*args, transport=httpx.MockTransport(lambda request: pytest.fail("No network writes")), **kwargs)
    monkeypatch.setattr(module, "GmailClient", readonly)
    with gmail_client(settings, store, mailbox) as google:
        with pytest.raises(module.GmailError, match="gmail.modify"):
            google.modify_labels("m", add=["q"], remove=["INBOX"])


def test_disconnect_cancels_pending_consent_and_retains_messages(setup):
    settings, store = setup
    app = make_app(settings, store, lambda request: pytest.fail("Disconnect is local"))
    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost") as client:
            params = await begin(client)
            assert (await client.post("/api/accounts/disconnect", json={"mailbox": "me@example.test"})).status_code == 401
            response = await client.post("/api/accounts/disconnect", json={"mailbox": "me@example.test"},
                                        headers={"authorization": "Bearer console-secret"})
            assert response.status_code == 200 and response.json()["retained_messages"]
            assert not response.json()["provider_grant_revoked"]
            assert (await callback(client, params)).status_code == 400
    asyncio.run(run())
    assert connected_mailboxes(settings, store) == []
    assert not account_health(settings, store)["accounts"][0]["connected"]
    with store.engine.connect() as db:
        assert db.execute(select(accounts.c.encrypted_tokens)).scalar_one() == ""


def test_disconnect_during_token_exchange_cannot_resurrect_connection(setup):
    settings, store = setup
    def handler(request):
        if request.url.path == "/token":
            # The local disconnect can happen while Google's exchange is in flight.
            with store.engine.begin() as db:
                db.execute(accounts.insert().values(mailbox="me@example.test", encrypted_tokens="", scopes="",
                    connected_at="disconnected-generation"))
            return httpx.Response(200, json=token_response())
        return httpx.Response(200, json={"emailAddress": "me@example.test"})
    app = make_app(settings, store, handler)
    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost") as client:
            assert (await callback(client, await begin(client))).status_code == 400
    asyncio.run(run())
    assert connected_mailboxes(settings, store) == []


def test_disconnect_stops_inflight_client_and_refresh_persistence(setup, monkeypatch):
    settings, store = setup
    module.initialize(store)
    with store.engine.begin() as db:
        db.execute(accounts.insert().values(mailbox="me@example.test", encrypted_tokens=module._encrypt(settings,
            {"access_token": "test", "refresh_token": "test", "expiry": "2030-01-01T00:00:00"}),
            scopes=MODIFY_SCOPE, connected_at="original"))
    refreshed = []
    original = module.GmailClient
    def factory(*args, **kwargs):
        refreshed.append(kwargs["credentials_updated"])
        return original(*args, transport=httpx.MockTransport(lambda request: pytest.fail("Disconnected request stopped")), **kwargs)
    monkeypatch.setattr(module, "GmailClient", factory)
    with gmail_client(settings, store, "me@example.test") as google:
        with store.engine.begin() as db:
            db.execute(update(accounts).values(encrypted_tokens="", scopes="", connected_at="disconnected"))
        refreshed[0](SimpleNamespace(token="new-token", refresh_token="new-refresh", expiry=None))
        with pytest.raises(module.GmailError, match="disconnected or replaced"):
            google.get_profile()
    with store.engine.connect() as db:
        assert db.execute(select(accounts.c.encrypted_tokens)).scalar_one() == ""


def test_google_setup_is_encrypted_and_other_process_settings_refresh(setup):
    settings, store = setup
    other_process = SimpleNamespace(**vars(settings))
    app = make_app(settings, store, lambda request: pytest.fail("Setup does not contact Google"))
    config = {"web": {"client_id": "family-client", "client_secret": "private-family-secret",
                       "redirect_uris": ["http://localhost/oauth/google/callback"]}}
    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost") as client:
            assert (await client.get("/api/setup/google")).status_code == 401
            response = await client.post("/api/setup/google", json={"client_config": config,
                "mailboxes": ["parent@gmail.com", "relative@workspace.example"]},
                headers={"authorization": "Bearer console-secret"})
            assert response.status_code == 200, response.text
            assert response.json()["configured"] and response.json()["source"] == "wizard"
            assert "private-family-secret" not in response.text
    asyncio.run(run())
    with store.engine.connect() as db:
        ciphertext = db.execute(select(module.google_setup.c.encrypted_config)).scalar_one()
    assert "private-family-secret" not in ciphertext and "parent@gmail.com" not in ciphertext
    assert connected_mailboxes(other_process, store) == []
    assert module.allowed_mailboxes(other_process) == ["parent@gmail.com", "relative@workspace.example"]
    assert module._client_config(other_process)["client_id"] == "family-client"
    assert other_process.initial_query.startswith("-in:sent -in:drafts after:")
    assert "newer_than" not in other_process.initial_query


@pytest.mark.parametrize("history,days", [("new", 0), ("30_days", 30), ("all", None)])
def test_google_setup_history_window_is_fixed_and_survives_process_restart(setup, history, days):
    settings, store = setup
    other_process = SimpleNamespace(**vars(settings))
    config = json.loads(module.Path(settings.google_oauth_client_file).read_text())
    app = make_app(settings, store, lambda request: pytest.fail("Setup does not contact Google"))
    before = datetime.now(UTC).timestamp()
    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost") as client:
            response = await client.post("/api/setup/google", json={"client_config": config,
                "mailboxes": ["relative@gmail.com"], "initial_history": history},
                headers={"authorization": "Bearer console-secret"})
            assert response.status_code == 200, response.text
            return response.json()["initial_query"]
    query = asyncio.run(run())
    if days is None:
        assert query == "-in:sent -in:drafts"
    else:
        epoch = int(query.split("after:")[1])
        assert before - days * 86400 - 1 <= epoch <= datetime.now(UTC).timestamp() - days * 86400
    connected_mailboxes(other_process, store)
    assert other_process.initial_query == query
    account_health(other_process, store)
    assert other_process.initial_query == query


@pytest.mark.parametrize("change", ["client", "remove_mailbox"])
def test_google_setup_cannot_orphan_connected_tokens(setup, change):
    settings, store = setup
    module.initialize(store)
    with store.engine.begin() as db:
        db.execute(accounts.insert().values(mailbox="me@example.test", encrypted_tokens="opaque-active-token",
                                           scopes=MODIFY_SCOPE, connected_at="original"))
    app = make_app(settings, store, lambda request: pytest.fail("Setup does not contact Google"))
    config = json.loads(module.Path(settings.google_oauth_client_file).read_text())
    if change == "client":
        config["web"]["client_id"] = "replacement-client"
    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost") as client:
            response = await client.post("/api/setup/google", json={"client_config": config,
                "mailboxes": ["other@example.test"] if change == "remove_mailbox" else ["me@example.test"]},
                headers={"authorization": "Bearer console-secret"})
            assert response.status_code == 400 and "Disconnect" in response.text
    asyncio.run(run())


async def callback(client, params):
    return await client.get("/oauth/google/callback?" + urlencode({"state": params["state"][0], "code": "single-use-code"}))


def test_oauth_pkce_single_use_encrypts_tokens_and_checks_profile(setup):
    settings, store = setup
    exchanged = []
    def handler(request):
        if request.url.path == "/token":
            exchanged.append(parse_qs(request.content.decode()))
            return httpx.Response(200, json=token_response())
        assert request.headers["authorization"] == "Bearer sensitive-access"
        return httpx.Response(200, json={"emailAddress": "me@example.test", "historyId": "123"})
    app = make_app(settings, store, handler)
    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost") as client:
            params = await begin(client)
            assert params["scope"] == [MODIFY_SCOPE]
            assert params["code_challenge_method"] == ["S256"]
            assert (await callback(client, params)).status_code == 303
            assert (await callback(client, params)).status_code == 400
            return params
    params = asyncio.run(run())
    assert len(exchanged) == 1
    verifier = exchanged[0]["code_verifier"][0]
    assert params["code_challenge"][0] == base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    with store.engine.connect() as db:
        row = db.execute(select(accounts)).mappings().one()
        assert "sensitive-access" not in row["encrypted_tokens"] and "sensitive-refresh" not in row["encrypted_tokens"]
        assert module._decrypt(settings, row["encrypted_tokens"])["refresh_token"] == "sensitive-refresh"
        assert not db.execute(select(oauth_states)).first()
    assert connected_mailboxes(settings, store) == ["me@example.test"]
    assert "sensitive" not in json.dumps(account_health(settings, store))


@pytest.mark.parametrize("problem", ["account", "scope", "refresh", "provider_error"])
def test_callback_rejects_account_mismatch_scope_missing_offline_and_provider_error(setup, problem):
    settings, store = setup
    def handler(request):
        if request.url.path == "/token":
            tokens = token_response(READONLY_SCOPE if problem == "scope" else MODIFY_SCOPE)
            if problem == "refresh":
                tokens.pop("refresh_token")
            if problem == "provider_error":
                return httpx.Response(400, json={"error_description": "sensitive-provider-material"})
            return httpx.Response(200, json=tokens)
        return httpx.Response(200, json={"emailAddress": "other@example.test" if problem == "account" else "me@example.test"})
    app = make_app(settings, store, handler)
    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost") as client:
            response = await callback(client, await begin(client))
            assert response.status_code == 400
            assert "sensitive" not in response.text
    asyncio.run(run())
    assert connected_mailboxes(settings, store) == []


def test_state_bound_to_browser_and_expires(setup):
    settings, store = setup
    def forbidden(request):
        pytest.fail("Invalid state must not contact Google")
    app = make_app(settings, store, forbidden)
    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost") as client:
            params = await begin(client)
            async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://localhost") as stranger:
                assert (await callback(stranger, params)).status_code == 400
            with store.engine.begin() as db:
                db.execute(update(oauth_states).values(expires_at=(datetime.now(UTC) - timedelta(minutes=1)).isoformat()))
            assert (await callback(client, params)).status_code == 400
    asyncio.run(run())


@pytest.mark.parametrize("problem", ["auth", "disallowed", "key", "origin"])
def test_connect_requires_console_auth_allowlist_encryption_and_origin(setup, problem):
    settings, store = setup
    if problem == "key":
        settings.token_encryption_key = ""
    app = make_app(settings, store, lambda request: pytest.fail("Connect only generates an authorization URL"))
    async def run():
        origin = "http://different.test" if problem == "origin" else "http://localhost"
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=origin) as client:
            response = await client.post("/api/accounts/connect", json={"mailbox": "intruder@example.test" if problem == "disallowed" else "me@example.test"},
                headers={"authorization": "Bearer wrong" if problem == "auth" else "Bearer console-secret"})
            assert response.status_code == (401 if problem == "auth" else 400)
    asyncio.run(run())


def test_connected_service_accounts_still_require_explicit_allowlist(setup):
    settings, store = setup
    settings.google_service_account_file = "/configured/only/not-opened.json"
    settings.mailboxes = ["me@example.test", "unexpected@example.test"]
    assert connected_mailboxes(settings, store) == ["me@example.test"]
    health = account_health(settings, store)["accounts"]
    assert health[0]["status"] == "configured_unverified"
    with pytest.raises(ValueError, match="explicitly authorized"):
        with gmail_client(settings, store, "unexpected@example.test"):
            pass


def test_service_account_read_scope_default_and_explicit_action_scope(setup, monkeypatch):
    settings, store = setup
    settings.google_service_account_file = "configured"
    settings.mailboxes = ["me@example.test"]
    seen = []
    @contextmanager
    def fake(path, mailbox, **kw):
        seen.append(kw["scopes"])
        yield object()
    monkeypatch.setattr(module, "GmailClient", fake)
    with gmail_client(settings, store, "me@example.test"):
        pass
    with gmail_client(settings, store, "me@example.test", for_actions=True):
        pass
    assert seen == [[READONLY_SCOPE], [MODIFY_SCOPE]]


def test_invalid_redirect_cleartext_non_loopback_rejected(setup):
    settings, store = setup
    settings.google_oauth_redirect_uri = "http://192.0.2.10/oauth/google/callback"
    with pytest.raises(ValueError, match="HTTPS"):
        module._client_config(settings)


def test_oauth_expired_access_token_refresh_is_encrypted_and_durable(setup, monkeypatch):
    settings, store = setup
    module.initialize(store)
    old = {"access_token": "expired-access", "refresh_token": "sensitive-refresh",
           "expiry": "2020-01-01T00:00:00"}
    with store.engine.begin() as db:
        db.execute(accounts.insert().values(mailbox="me@example.test", encrypted_tokens=module._encrypt(settings, old),
            scopes=MODIFY_SCOPE, connected_at="2026-01-01", updated_at="2026-01-01"))
    requests = []
    def handler(request):
        requests.append(request)
        if request.url.path == "/token":
            body = parse_qs(request.content.decode())
            assert body["grant_type"] == ["refresh_token"]
            assert body["refresh_token"] == ["sensitive-refresh"]
            return httpx.Response(200, json={"access_token": "refreshed-access", "expires_in": 3600,
                                             "token_type": "Bearer", "scope": MODIFY_SCOPE})
        assert request.headers["authorization"] == "Bearer refreshed-access"
        return httpx.Response(200, json={"emailAddress": "me@example.test", "historyId": "123"})
    original = module.GmailClient
    def client(*args, **kwargs):
        return original(*args, transport=httpx.MockTransport(handler), **kwargs)
    monkeypatch.setattr(module, "GmailClient", client)
    with gmail_client(settings, store, "me@example.test") as google:
        assert google.get_profile()["historyId"] == "123"
    assert len(requests) == 2
    with store.engine.connect() as db:
        ciphertext = db.execute(select(accounts.c.encrypted_tokens)).scalar_one()
    assert "refreshed-access" not in ciphertext
    assert module._decrypt(settings, ciphertext)["access_token"] == "refreshed-access"
    settings.token_encryption_key = Fernet.generate_key().decode()
    with pytest.raises(ValueError, match="cannot be decrypted"):
        with gmail_client(settings, store, "me@example.test"):
            pytest.fail("Wrong key must not open a Gmail client")


def test_invalid_grant_refresh_requires_reconnect_without_erasing_saved_state(setup, monkeypatch):
    settings, store = setup
    module.initialize(store)
    original_tokens = module._encrypt(settings, {'access_token': 'expired-access',
        'refresh_token': 'private-refresh-token', 'expiry': '2020-01-01T00:00:00'})
    with store.engine.begin() as db:
        db.execute(accounts.insert().values(mailbox='me@example.test', encrypted_tokens=original_tokens,
            scopes=MODIFY_SCOPE, connected_at='2026-01-01', updated_at='2026-01-01'))
    store.update_mailbox('me@example.test', history_id='123', sync_summary={'complete': True})
    requests = []

    def handler(request):
        requests.append(request)
        assert request.url.path == '/token'
        return httpx.Response(400, json={'error': 'invalid_grant',
            'error_description': 'private-refresh-token and private provider details'})

    original_client = module.GmailClient
    monkeypatch.setattr(module, 'GmailClient', lambda *args, **kwargs:
        original_client(*args, transport=httpx.MockTransport(handler), **kwargs))
    with pytest.raises(GmailAuthorizationError) as error:
        with gmail_client(settings, store, 'me@example.test') as google:
            google.get_profile()
    assert len(requests) == 1
    assert str(error.value) == 'Reconnect Gmail: authorization expired or revoked.'
    with store.engine.connect() as db:
        row = db.execute(select(accounts)).mappings().one()
    assert row['encrypted_tokens'] == original_tokens and row['connected_at'] == '2026-01-01'
    assert row['last_error'] == str(error.value)
    health = account_health(settings, store)
    account = next(item for item in health['accounts'] if item['mailbox'] == 'me@example.test')
    assert account['connected'] and account['status'] == 'attention'
    assert account['last_error'] == str(error.value)
    assert 'private-refresh-token' not in json.dumps(health)
    assert store.mailbox_state('me@example.test')['history_id'] == '123'
    assert store.mailbox_state('me@example.test')['sync_summary'] == {'complete': True}


@pytest.mark.parametrize("cancelled", [False, True])
def test_rate_limit_account_health_recovers_without_reauthorization(setup, monkeypatch, cancelled):
    from mailsec.mailbox_actions import _ActionCancelled
    settings, store = setup
    module.initialize(store)
    with store.engine.begin() as db:
        db.execute(accounts.insert().values(mailbox="me@example.test", encrypted_tokens=module._encrypt(settings,
            {"access_token": "test", "refresh_token": "test", "expiry": "2030-01-01T00:00:00"}),
            scopes=MODIFY_SCOPE, connected_at="2026-01-01", updated_at="2026-01-01"))
    class Client:
        successful_requests = 0
        def __init__(self, *args, **kwargs):
            pass
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
    monkeypatch.setattr(module, "GmailClient", Client)
    with pytest.raises(module.GmailError):
        with gmail_client(settings, store, "me@example.test"):
            raise module.GmailError("quota", 403, reason="userRateLimitExceeded")
    with store.engine.connect() as db:
        error = db.execute(select(accounts.c.last_error)).scalar_one()
    assert "rate-limited" in error and "consent" not in error
    try:
        with gmail_client(settings, store, "me@example.test") as client:
            client.successful_requests = 1
            if cancelled:
                raise _ActionCancelled("Operator paused mailbox changes")
    except _ActionCancelled:
        assert cancelled
    with store.engine.connect() as db:
        row = db.execute(select(accounts.c.last_error, accounts.c.last_verified_at)).mappings().one()
    assert row["last_error"] is None and row["last_verified_at"]


@pytest.mark.parametrize('stage', ['token', 'profile'])
@pytest.mark.parametrize('attack', ['oversized', 'compressed', 'deep_json'])
def test_oauth_callback_bounds_remote_responses_without_storing_credentials(setup, stage, attack):
    settings, store = setup
    calls = []

    class Unreadable(httpx.SyncByteStream):
        def __iter__(self):
            pytest.fail('Oversized or compressed OAuth response must not be consumed')
            yield b''

    def handler(request):
        calls.append(request.url.path)
        assert request.headers['accept-encoding'] == 'identity'
        current = 'token' if request.url.path == '/token' else 'profile'
        if current == stage:
            if attack == 'deep_json':
                return httpx.Response(200, content=b'[' * 4000 + b']' * 4000)
            headers = {'content-length': '1000000'} if attack == 'oversized' else {'content-encoding': 'gzip'}
            return httpx.Response(200, headers=headers, stream=Unreadable())
        return httpx.Response(200, json=token_response())

    app = make_app(settings, store, handler)
    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://localhost') as client:
            response = await callback(client, await begin(client))
            assert response.status_code == 400
            assert 'sensitive-access' not in response.text and 'sensitive-refresh' not in response.text
    asyncio.run(run())
    assert len(calls) == (1 if stage == 'token' else 2)
    assert connected_mailboxes(settings, store) == []
    with store.engine.connect() as db:
        assert db.execute(select(accounts.c.encrypted_tokens)).first() is None
