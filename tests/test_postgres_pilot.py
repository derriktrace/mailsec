"""Additional opt-in PostgreSQL checks, always isolated by pg_store's random schema."""
import asyncio
import json
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import parse_qs, urlsplit

import httpx
from cryptography.fernet import Fernet
from fastapi import FastAPI
from sqlalchemy import event, func, select
from test_mailbox_actions import FakeGmail
from test_migration import migration, source_snapshot
from test_postgres import pg_store as pg_store

from mailsec import accounts as account_module
from mailsec.accounts import accounts, connected_mailboxes, register_account_routes
from mailsec.config import Settings
from mailsec.gmail import MODIFY_SCOPE
from mailsec.mailbox_actions import (
    abandon_notification,
    apply_pending_actions,
    enqueue_action,
    is_notification,
    list_actions,
    notification_delivery_in_progress,
    reconcile_committed_actions,
)
from mailsec.parsing import parse_email
from mailsec.storage import messages, now


def test_postgres_oauth_single_use_callback_and_encrypted_credentials(pg_store, tmp_path):
    config = tmp_path / "client.json"
    config.write_text(json.dumps({"web": {"client_id": "fake-client", "client_secret": "fake-client-secret",
        "redirect_uris": ["http://localhost/oauth/google/callback"]}}))
    settings = Settings(google_oauth_client_file=str(config), google_oauth_redirect_uri="http://localhost/oauth/google/callback",
        token_encryption_key=Fernet.generate_key().decode(), app_token="console-test-token",
        authorized_mailboxes=["me@example.test"])
    exchanges = []
    def handler(request):
        if request.url.path == "/token":
            exchanges.append(request.url.path)
            return httpx.Response(200, json={"access_token": "private-access", "refresh_token": "private-refresh",
                                             "scope": MODIFY_SCOPE, "expires_in": 3600})
        return httpx.Response(200, json={"emailAddress": "me@example.test", "historyId": "123"})
    app = FastAPI()
    register_account_routes(app, settings, pg_store, transport=httpx.MockTransport(handler))
    async def authorize_twice():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://localhost") as client:
            begin = await client.post("/api/accounts/connect", json={"mailbox": "me@example.test"},
                                      headers={"authorization": "Bearer console-test-token"})
            assert begin.status_code == 200
            state = parse_qs(urlsplit(begin.json()["authorization_url"]).query)["state"][0]
            return await asyncio.gather(*[client.get("/oauth/google/callback", params={"state": state, "code": "fake-code"}) for _ in range(2)])
    responses = asyncio.run(authorize_twice())
    assert sorted(response.status_code for response in responses) == [303, 400]
    assert len(exchanges) == 1 and connected_mailboxes(settings, pg_store) == ["me@example.test"]
    with pg_store.engine.connect() as db:
        row = db.execute(select(accounts)).mappings().one()
        assert "private-refresh" not in row["encrypted_tokens"]
        assert account_module._decrypt(settings, row["encrypted_tokens"])["refresh_token"] == "private-refresh"


def test_postgres_action_recovery_concurrency_release_and_uncertain_resolution(pg_store):
    settings = Settings(authorized_mailboxes=["me@example.test"], enforcement_mode="auto_quarantine",
                        notifications_enabled=True, tenant_id="postgres-integration")
    raw = b"From: external@example.test\r\nTo: me@example.test\r\nSubject: Test\r\n\r\nprivate input"
    mid = pg_store.ingest(raw, parse_email(raw), provider="gmail", provider_message_id="provider-id",
                          mailbox="me@example.test")["id"]
    rid = pg_store.finish(pg_store.claim(), {}, {"answers": {"verdict": {"choice": "phishing", "confidence": .99}}},
                          {"eligible_action": "quarantine"}, {}, {}, now())
    assert reconcile_committed_actions(settings, pg_store)["enqueued"] == 1
    assert reconcile_committed_actions(settings, pg_store)["enqueued"] == 0
    client = FakeGmail()
    client.fail_send = True
    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(lambda _: apply_pending_actions(settings, pg_store, client_factory=client.factory), range(3)))
    assert sum(row["applied"] for row in results) == 1
    assert len(client.modified) == len(client.sent) == 1 and client.labels == {"q", "UNREAD"}
    assert not is_notification(pg_store, "me@example.test", "not-confirmed")
    assert notification_delivery_in_progress(pg_store, "me@example.test")
    notification_id = list_actions(pg_store, mid)[0]["notification_id"]
    abandon_notification(pg_store, notification_id)
    assert not notification_delivery_in_progress(pg_store, "me@example.test")
    settings.notifications_enabled = False
    enqueue_action(pg_store, "me@example.test", "provider-id", "release", rid, mid)
    assert apply_pending_actions(settings, pg_store, client_factory=client.factory)["applied"] == 1
    assert "INBOX" in client.labels and "q" not in client.labels and len(client.sent) == 1


def test_postgres_migration_preserves_source_and_rolls_back_late_failure(pg_store, tmp_path):
    source = source_snapshot(tmp_path)
    original_hash = migration.file_digest(source)
    report = migration.migrate(source, pg_store.engine)
    assert report["mode"] == "dry_run" and report["tables"]["messages"]["rows"] == 2
    # Fail after some inserts; PostgreSQL must roll back data and newly-created schema objects.
    statements = []
    def fail_late(conn, cursor, statement, parameters, context, executemany):
        if statement.startswith("INSERT"):
            statements.append(statement)
            if len(statements) == 3:
                raise RuntimeError("synthetic late failure")
    event.listen(pg_store.engine, "before_cursor_execute", fail_late)
    try:
        try:
            migration.migrate(source, pg_store.engine, apply=True, batch_size=1)
            raise AssertionError("Expected injected rollback")
        except RuntimeError as exc:
            assert str(exc) == "synthetic late failure"
    finally:
        event.remove(pg_store.engine, "before_cursor_execute", fail_late)
    with pg_store.engine.connect() as db:
        assert db.execute(select(func.count()).select_from(messages)).scalar_one() == 0
    success = migration.migrate(source, pg_store.engine, apply=True, batch_size=1)
    assert success["destination_verified"] and success["tables"] == report["tables"]
    assert migration.file_digest(source) == original_hash
    try:
        migration.migrate(source, pg_store.engine, apply=True)
        raise AssertionError("Expected nonempty target rejection")
    except migration.MigrationError as exc:
        assert "not empty" in str(exc)


def test_postgres_runtime_control_updates_preserve_concurrent_partial_changes(pg_store):
    from threading import Barrier

    from mailsec.runtime_controls import audit, refresh_controls, update_controls
    tenant = "concurrent-controls"
    settings = Settings(tenant_id=tenant, enforcement_mode="passive", notifications_enabled=False)
    update_controls(settings, pg_store, {"mode": "auto_quarantine"})
    barrier = Barrier(2)
    def change(value):
        # Independent settings objects model distinct API processes with stale local defaults.
        local = Settings(tenant_id=tenant, enforcement_mode="passive", notifications_enabled=False)
        barrier.wait(timeout=10)
        return update_controls(local, pg_store, value)
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(change, [{"mode": "flag_only"}, {"notifications_enabled": True}]))
    fresh = Settings(tenant_id=tenant)
    assert refresh_controls(fresh, pg_store) == {"mode": "flag_only", "notifications_enabled": True}
    with pg_store.engine.connect() as db:
        rows = list(db.execute(select(audit).where(audit.c.tenant == tenant).order_by(audit.c.created_at)).mappings())
    assert len(rows) == 3
    assert rows[1]["before"] == rows[0]["after"] and rows[2]["before"] == rows[1]["after"]
    assert rows[2]["after"] == {"mode": "flag_only", "notifications_enabled": True}
