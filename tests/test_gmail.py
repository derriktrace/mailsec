import base64
from datetime import UTC, datetime

import httpx
import pytest
from google.auth.exceptions import RefreshError

from mailsec.gmail import (
    READONLY_SCOPE,
    GmailAuthorizationError,
    GmailClient,
    GmailError,
    GmailMessageMissing,
    sync_mailbox,
)


class FakeClient:
    mailbox = "analyst@example.test"

    def __init__(self, listing=None, history=None, messages=None):
        self.listing = listing or {None: {}}
        self.histories = history or {None: {"historyId": "101"}}
        self.messages = messages or {}
        self.calls = []

    def get_profile(self):
        self.calls.append(("profile",))
        return {"historyId": "100"}

    def list_messages(self, query="", page_token=None, max_results=100):
        self.calls.append(("list", query, page_token, max_results))
        return self.listing[page_token]

    def history(self, start_history_id, page_token=None):
        self.calls.append(("history", start_history_id, page_token))
        result = self.histories[page_token]
        if isinstance(result, Exception):
            raise result
        return result

    def get_message(self, identifier):
        self.calls.append(("get", identifier))
        result = self.messages.get(identifier, {})
        if isinstance(result, Exception):
            raise result
        return {
            "id": identifier,
            "thread_id": f"t-{identifier}",
            "raw": identifier.encode(),
            "received_at": datetime(2026, 1, 1, tzinfo=UTC),
            "labels": [],
            **result,
        }


def history_page(ids, history_id="110", next_token=None):
    page = {"historyId": history_id, "history": [{"messagesAdded": [{"message": {"id": i}} for i in ids]}]}
    if next_token:
        page["nextPageToken"] = next_token
    return page


def test_initial_pass_paginates_and_captures_boundary_before_enumeration():
    client = FakeClient(
        listing={None: {"messages": [{"id": "a"}], "nextPageToken": "p2"}, "p2": {"messages": [{"id": "b"}]}}
    )
    committed, saved = [], []

    def ingest(raw, **fields):
        assert not saved
        committed.append((raw, fields))
        return fields["provider_message_id"]

    result = sync_mailbox(client, None, ingest, saved.append, "after:2026/01/01", 10)
    assert client.calls[0] == ("profile",)
    assert saved == ["100"]
    assert result["complete"] and result["ingested"] == 2
    assert [r[0] for r in committed] == [b"a", b"b"]
    assert committed[0][1]["provider"] == "gmail"
    assert committed[0][1]["mailbox"] == client.mailbox
    assert committed[0][1]["received_at"].tzinfo is UTC


def test_initial_cap_never_checkpoints_partial_results():
    client = FakeClient(listing={None: {"messages": [{"id": "a"}], "nextPageToken": "p2"}})
    saved = []
    result = sync_mailbox(client, None, lambda *a, **k: True, saved.append, max_initial_messages=1)
    assert not saved
    assert result["truncated"] and not result["complete"]
    assert result["next_page_token"] == "p2"
    assert result["cursor_after"] is None


def test_history_paginates_deduplicates_and_uses_message_added_only():
    first = history_page(["a", "a"], next_token="p2")
    first["history"].append(
        {"messages": [{"id": "ignored"}], "labelsAdded": [{"message": {"id": "ignored"}}]}
    )
    client = FakeClient(history={None: first, "p2": history_page(["a", "b"], "120")})
    imported, saved = [], []
    result = sync_mailbox(client, "99", lambda raw, **k: imported.append(raw), saved.append)
    assert imported == [b"a", b"b"]
    assert saved == ["120"]
    assert result["pages"] == 2
    assert ("history", "99", "p2") in client.calls
    assert all(call[0] != "profile" for call in client.calls)


def test_history_failure_leaves_cursor_unchanged_and_replay_is_idempotent():
    client = FakeClient(
        history={None: history_page(["a"], next_token="p2"), "p2": GmailError("temporary", 503)}
    )
    committed, saved = set(), []

    def ingest(raw, **fields):
        identifier = fields["provider_message_id"]
        if identifier in committed:
            return False
        committed.add(identifier)
        return identifier

    with pytest.raises(GmailError):
        sync_mailbox(client, "90", ingest, saved.append)
    assert saved == [] and committed == {"a"}
    client.histories["p2"] = history_page(["b"], "120")
    result = sync_mailbox(client, "90", ingest, saved.append)
    assert result["duplicates"] == 1 and result["ingested"] == 1
    assert committed == {"a", "b"} and saved == ["120"]


def test_failed_ingest_never_advances_cursor():
    saved = []

    def fail(*args, **kwargs):
        raise RuntimeError("database unavailable")

    with pytest.raises(RuntimeError):
        sync_mailbox(FakeClient(history={None: history_page(["a"])}), "90", fail, saved.append)
    assert saved == []


def test_stale_history_recovers_with_bounded_backfill():
    client = FakeClient(history={None: GmailError("stale", 404)}, listing={None: {"messages": [{"id": "a"}]}})
    saved = []
    result = sync_mailbox(client, "10", lambda *a, **k: True, saved.append)
    assert result["mode"] == "recovery" and result["complete"]
    assert saved == ["100"]
    assert [c[0] for c in client.calls] == ["history", "profile", "list", "get"]


def test_truncated_stale_recovery_does_not_checkpoint():
    client = FakeClient(
        history={None: GmailError("stale", 404)},
        listing={None: {"messages": [{"id": "a"}], "nextPageToken": "more"}},
    )
    saved = []
    result = sync_mailbox(client, "10", lambda *a, **k: True, saved.append, max_initial_messages=1)
    assert result["mode"] == "recovery" and result["cursor_after"] == "10"
    assert result["truncated"] and not saved


def test_non_inbound_skipped_but_archived_spam_and_trash_imported():
    labels = {"sent": ["SENT"], "draft": ["DRAFT"], "spam": ["SPAM"], "trash": ["TRASH"], "archive": []}
    client = FakeClient(
        history={None: history_page(labels)}, messages={i: {"labels": v} for i, v in labels.items()}
    )
    imported = []
    result = sync_mailbox(client, "90", lambda raw, **k: imported.append(raw), lambda c: None)
    assert imported == [b"spam", b"trash", b"archive"]
    assert result["skipped_non_inbound"] == 2


def test_message_deleted_during_sync_counted_without_triggering_recovery():
    client = FakeClient(history={None: history_page(["a", "b"])}, messages={"a": GmailError("gone", 404)})
    saved = []
    result = sync_mailbox(client, "90", lambda *a, **k: True, saved.append)
    assert result["vanished"] == 1 and result["ingested"] == 1
    assert result["mode"] == "incremental" and saved == ["110"]


def test_repeated_page_token_stops_without_checkpoint():
    client = FakeClient(
        history={None: history_page([], next_token="p"), "p": history_page([], next_token="p")}
    )
    saved = []
    with pytest.raises(GmailError, match="repeated"):
        sync_mailbox(client, "90", lambda *a, **k: True, saved.append)
    assert not saved


@pytest.fixture
def client_factory(monkeypatch):
    # No private keys or external requests: exercise real HTTP code and replace
    # only Google's service-account key loader with a credential test double.
    service_account = pytest.importorskip("google.oauth2.service_account")

    class Credentials:
        def with_subject(self, subject):
            assert subject == "analyst@example.test"
            return self

        def before_request(self, request, method, url, headers):
            headers["authorization"] = "Bearer test-token"

    def load(path, scopes):
        assert scopes == [READONLY_SCOPE]
        return Credentials()

    monkeypatch.setattr(service_account.Credentials, "from_service_account_file", load)
    monkeypatch.setattr("mailsec.gmail.time.sleep", lambda seconds: None)
    clients = []

    def make(handler):
        client = GmailClient("unused.json", "analyst@example.test", transport=httpx.MockTransport(handler))
        clients.append(client)
        return client

    yield make
    for client in clients:
        client.close()


def test_client_readonly_raw_decode_and_metadata(client_factory):
    raw = b"From: sender@example.test\r\n\r\nHello \xff"

    def handler(request):
        assert request.method == "GET"
        assert request.url.params["format"] == "raw"
        assert request.headers["authorization"] == "Bearer test-token"
        return httpx.Response(
            200,
            json={
                "id": "a",
                "threadId": "t",
                "raw": base64.urlsafe_b64encode(raw).decode().rstrip("="),
                "internalDate": "1704067200000",
                "labelIds": ["INBOX"],
            },
        )

    message = client_factory(handler).get_message("a")
    assert message["raw"] == raw
    assert message["received_at"] == datetime(2024, 1, 1, tzinfo=UTC)
    assert message["labels"] == ["INBOX"]


def test_client_retries_transient_errors_but_not_permissions(client_factory):
    statuses = iter([429, 503, 200])
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(next(statuses), json={"historyId": "100"})

    assert client_factory(handler).get_profile()["historyId"] == "100"
    assert len(calls) == 3
    with pytest.raises(GmailError) as error:
        client_factory(lambda r: httpx.Response(403, json={"private_body": "redacted"})).get_profile()
    assert error.value.status_code == 403
    assert "redacted" not in str(error.value)


def test_message_label_read_distinguishes_permanently_missing_gmail_message(client_factory):
    calls = []
    def handler(request):
        calls.append(str(request.url))
        return httpx.Response(404, json={"error": {"message": "private provider detail"}})
    with pytest.raises(GmailMessageMissing, match="no longer exists") as error:
        client_factory(handler).message_labels("deleted-id")
    assert error.value.status_code == 404
    assert "private provider detail" not in str(error.value)
    assert len(calls) == 1 and "/messages/deleted-id" in calls[0]


def test_client_retry_count_bounded(client_factory):
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(503)

    with pytest.raises(GmailError):
        client_factory(handler).get_profile()
    assert len(calls) == 4


@pytest.mark.parametrize('failure,requires_consent', [
    (RefreshError('private provider detail', {'error': 'invalid_grant', 'error_description': 'private provider detail'}), True),
    (RefreshError('invalid_grant in private detail', {'error': 'temporarily_unavailable'}, retryable=True), False),
    (RefreshError('invalid_grant in unstructured private detail'), False),
    (RefreshError('private provider detail', {'error': 'invalid_client'}), False),
    (RuntimeError('invalid_grant in private detail'), False),
])
def test_refresh_failure_classification_uses_only_structured_oauth_code(client_factory, failure, requires_consent):
    class Credentials:
        def before_request(self, *args):
            raise failure

    client = client_factory(lambda request: pytest.fail('No Gmail request after failed refresh'))
    client._credentials = Credentials()
    with pytest.raises(GmailError) as error:
        client.get_profile()
    assert isinstance(error.value, GmailAuthorizationError) is requires_consent
    assert 'private' not in str(error.value) and 'invalid_grant' not in str(error.value)
    assert not error.value.rate_limited
    if requires_consent:
        assert str(error.value) == 'Reconnect Gmail: authorization expired or revoked.'


@pytest.mark.parametrize("payload", [[], {"historyId": 123}, {"historyId": "abc"}])
def test_client_rejects_invalid_profile(client_factory, payload):
    with pytest.raises(GmailError):
        client_factory(lambda r: httpx.Response(200, json=payload)).get_profile()


def test_client_rejects_invalid_base64(client_factory):
    with pytest.raises(GmailError):
        client_factory(
            lambda r: httpx.Response(
                200, json={"id": "a", "threadId": "t", "raw": "bad!!", "internalDate": "1"}
            )
        ).get_message("a")


def test_client_list_includes_spam_trash_and_history_uses_specific_change_type(client_factory):
    def handler(request):
        if request.url.path.endswith("messages"):
            assert request.url.params["includeSpamTrash"] == "true"
            assert request.url.params["q"] == "after:2026/01/01"
            assert request.url.params["pageToken"] == "p2"
            return httpx.Response(200, json={"messages": [{"id": "a"}]})
        assert request.url.params["historyTypes"] == "messageAdded"
        return httpx.Response(200, json={"historyId": "110"})

    client = client_factory(handler)
    assert client.list_messages("after:2026/01/01", "p2")["messages"]
    assert client.history("100")["historyId"] == "110"


def test_backfill_resumes_durable_pages_and_preserves_original_history_boundary():
    client = FakeClient(listing={None: {"messages": [{"id": "a"}], "nextPageToken": "p2"},
                                "p2": {"messages": [{"id": "b"}], "nextPageToken": "p3"},
                                "p3": {"messages": [{"id": "c"}]}})
    imported, saved = [], []
    result = sync_mailbox(client, None, lambda raw, **k: imported.append(raw), saved.append, max_initial_messages=1)
    assert result["backfill_resume"]["boundary"] == "100" and not saved
    result = sync_mailbox(client, None, lambda raw, **k: imported.append(raw), saved.append,
                          max_initial_messages=1, resume=result["backfill_resume"])
    assert result["backfill_resume"]["enumerated_total"] == 2 and not saved
    result = sync_mailbox(client, None, lambda raw, **k: imported.append(raw), saved.append,
                          max_initial_messages=1, resume=result["backfill_resume"])
    assert result["complete"] and result["backfill_resume"] is None and saved == ["100"]
    assert imported == [b"a", b"b", b"c"]
    assert len([call for call in client.calls if call[0] == "profile"]) == 1


def test_all_history_default_imports_old_mail_across_folders_then_new_arrivals():
    old_date = datetime(2009, 2, 3, tzinfo=UTC)
    client = FakeClient(
        listing={
            None: {"messages": [{"id": "archive"}, {"id": "spam"}], "nextPageToken": "p2"},
            "p2": {"messages": [{"id": "trash"}, {"id": "self-sent"}], "nextPageToken": "p3"},
            "p3": {"messages": [{"id": "draft"}, {"id": "inbox"}]},
        },
        messages={
            "archive": {"labels": [], "received_at": old_date},
            "spam": {"labels": ["SPAM"], "received_at": old_date},
            "trash": {"labels": ["TRASH"], "received_at": old_date},
            "self-sent": {"labels": ["SENT", "INBOX"]},
            "draft": {"labels": ["DRAFT"]},
            "inbox": {"labels": ["INBOX"]},
        },
        history={None: history_page(["new-during-backfill"], "130")},
    )
    imported, saved = [], []
    resume = None
    skipped = 0
    for index in range(3):
        result = sync_mailbox(
            client, None, lambda raw, **fields: imported.append((raw, fields)), saved.append,
            max_initial_messages=2, resume=resume,
        )
        skipped += result["skipped_non_inbound"]
        resume = result["backfill_resume"]
        assert result["query"] == "-in:sent -in:drafts"
        if index < 2:
            assert not result["complete"] and not saved
    assert saved == ["100"] and result["complete"] and skipped == 2
    assert [item[0] for item in imported] == [b"archive", b"spam", b"trash", b"inbox"]
    assert all(item[1]["received_at"] == old_date for item in imported[:3])
    sync_mailbox(client, saved[-1], lambda raw, **fields: imported.append((raw, fields)), saved.append)
    assert imported[-1][0] == b"new-during-backfill" and saved == ["100", "130"]


def test_backfill_ignores_resume_when_query_or_saved_history_cursor_changes():
    client = FakeClient(listing={None: {"messages": [{"id": "a"}]}})
    resume = {"version": 1, "query": "different", "cursor_before": None,
              "boundary": "90", "page_token": "old", "mode": "initial", "enumerated_total": 2}
    saved = []
    sync_mailbox(client, None, lambda *a, **k: True, saved.append, resume=resume)
    assert saved == ["100"] and client.calls[0] == ("profile",)


def test_expired_backfill_page_restarts_once_without_skipping_unimported_messages():
    client = FakeClient(listing={None: {"messages": [{"id": "a"}]}})
    original = client.list_messages
    def listing(query="", page_token=None, max_results=100):
        if page_token == "expired":
            raise GmailError("page expired", 400)
        return original(query, page_token, max_results)
    client.list_messages = listing
    resume = {"version": 1, "query": "-in:sent -in:drafts", "cursor_before": None,
              "boundary": "90", "page_token": "expired", "mode": "initial", "enumerated_total": 2}
    saved, imported = [], []
    result = sync_mailbox(client, None, lambda raw, **k: imported.append(raw), saved.append, resume=resume)
    assert saved == ["100"] and imported == [b"a"] and "expired" in result["notice"]
