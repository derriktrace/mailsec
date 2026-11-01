import httpx
import pytest

from mailsec.gmail import MODIFY_SCOPE, GmailClient, GmailError


class Credentials:
    def before_request(self, request, method, url, headers):
        headers["authorization"] = "Bearer mock-token"


def client(handler, writable=True):
    return GmailClient("", "me@example.test", credentials=Credentials(),
        scopes=[MODIFY_SCOPE] if writable else None, transport=httpx.MockTransport(handler))


def test_readonly_client_blocks_all_mailbox_writes():
    with client(lambda r: pytest.fail("No HTTP write is permitted"), writable=False) as gmail:
        with pytest.raises(GmailError, match="explicitly configured"):
            gmail.modify_labels("m", add=["q"], remove=["INBOX"])
        with pytest.raises(GmailError, match="explicitly configured"):
            gmail.send_message(b"From: me@example.test\n\nhello")
        with pytest.raises(GmailError, match="explicitly configured"):
            gmail.ensure_label("Mailsec/Review")


def test_send_is_single_attempt_even_for_retryable_provider_status():
    calls = []
    def handler(request):
        calls.append(request)
        return httpx.Response(503, json={"error": "private response"})
    with client(handler) as gmail, pytest.raises(GmailError, match="503"):
        gmail.send_message(b"safe-notification")
    assert len(calls) == 1 and calls[0].url.path.endswith("/messages/send")


def test_send_transport_failure_is_never_retried():
    calls = []
    def handler(request):
        calls.append(request)
        raise httpx.ReadTimeout("timeout", request=request)
    with client(handler) as gmail, pytest.raises(GmailError):
        gmail.send_message(b"safe-notification")
    assert len(calls) == 1


def test_label_create_lost_response_reconciles_exact_existing_name():
    calls = []
    def handler(request):
        calls.append(request)
        if request.method == "POST":
            raise httpx.ReadTimeout("created but response lost", request=request)
        return httpx.Response(200, json={"labels": [] if len(calls) == 1 else
                                         [{"name": "Mailsec/Quarantine", "id": "q"}]})
    with client(handler) as gmail:
        assert gmail.ensure_label("Mailsec/Quarantine") == "q"
    assert [r.method for r in calls] == ["GET", "POST", "GET"]


def test_modify_is_idempotently_retried_and_encodes_provider_id(monkeypatch):
    calls = []
    monkeypatch.setattr("mailsec.gmail.time.sleep", lambda _: None)
    def handler(request):
        calls.append(request)
        return httpx.Response(503 if len(calls) == 1 else 200, json={"id": "m/slash"})
    with client(handler) as gmail:
        assert gmail.modify_labels("m/slash", add=["q"], remove=["INBOX"])["id"] == "m/slash"
    assert len(calls) == 2 and b"m%2Fslash" in calls[0].url.raw_path


def test_write_guard_rechecked_before_each_retry(monkeypatch):
    calls, checks = [], []
    monkeypatch.setattr("mailsec.gmail.time.sleep", lambda _: None)
    def handler(request):
        calls.append(request)
        return httpx.Response(503, json={})
    def guard():
        checks.append(True)
        if len(checks) > 1:
            raise GmailError("Operator paused writes")
    with client(handler) as gmail:
        gmail.write_guard = guard
        with pytest.raises(GmailError, match="Operator paused"):
            gmail.modify_labels("m", add=["q"], remove=["INBOX"])
    assert len(calls) == 1 and len(checks) == 2


@pytest.mark.parametrize('label', ['Mailsec/Clean', 'Mailsec/Spam', 'Mailsec/Suspicious', 'Mailsec/Phishing',
                                   'Mailsec/Review', 'Mailsec/Quarantine'])
def test_real_gmail_client_supports_only_explicit_application_owned_labels(label):
    import json
    calls = []
    def handler(request):
        calls.append(request)
        if request.method == 'GET':
            return httpx.Response(200, json={'labels': []})
        assert json.loads(request.content)['name'] == label
        return httpx.Response(200, json={'id': 'owned-label'})
    with client(handler) as gmail:
        assert gmail.ensure_label(label) == 'owned-label'
    assert [r.method for r in calls] == ['GET', 'POST']


@pytest.mark.parametrize('label', ['INBOX', 'TRASH', 'SPAM', 'Other', 'Mailsec/Arbitrary', 'Mailsec/Clean\n'])
def test_real_gmail_client_refuses_arbitrary_or_system_label_creation(label):
    with client(lambda _: pytest.fail('Unauthorized label creation must not reach Gmail')) as gmail:
        with pytest.raises(ValueError, match='Only Mailsec labels'):
            gmail.ensure_label(label)
