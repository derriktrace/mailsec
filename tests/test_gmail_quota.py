"""Google's documented quota 403 responses must not look like revoked consent."""
import httpx
import pytest

from mailsec import gmail as module
from mailsec.gmail import MODIFY_SCOPE, GmailClient, GmailError


class Credentials:
    def before_request(self, request, method, url, headers):
        headers["authorization"] = "Bearer synthetic"


@pytest.fixture
def make_client(monkeypatch):
    monkeypatch.setattr(module._quota_pacer, "wait", lambda mailbox, units: None)
    monkeypatch.setattr(module.time, "sleep", lambda seconds: None)
    return lambda handler: GmailClient("", "test@example.test", credentials=Credentials(),
        scopes=[MODIFY_SCOPE], transport=httpx.MockTransport(handler))


@pytest.mark.parametrize("reason", ["rateLimitExceeded", "userRateLimitExceeded"])
def test_quota_403_backs_off_and_recovers(make_client, monkeypatch, reason):
    requests, sleeps = [], []
    monkeypatch.setattr(module.time, "sleep", sleeps.append)
    def handler(request):
        requests.append(request)
        if len(requests) < 3:
            return httpx.Response(403, json={"error": {"message": "private-provider-content",
                "errors": [{"reason": reason}]}}, headers={"retry-after": "7"})
        return httpx.Response(200, json={"historyId": "123"})
    with make_client(handler) as client:
        assert client.get_profile()["historyId"] == "123"
        assert client.successful_requests == 1
    assert len(requests) == 3 and sleeps == [7, 10]


@pytest.mark.parametrize("reason", ["insufficientPermissions", "domainPolicy", "private-provider-content"])
def test_permission_403_is_not_retried_or_unsafely_exposed(make_client, reason):
    requests = []
    def handler(request):
        requests.append(request)
        return httpx.Response(403, json={"error": {"message": "private-provider-content",
            "errors": [{"reason": reason}]}})
    with make_client(handler) as client, pytest.raises(GmailError) as caught:
        client.get_profile()
    assert len(requests) == 1 and not caught.value.rate_limited
    assert "private-provider-content" not in str(caught.value)


def test_exhausted_quota_retains_only_known_reason(make_client):
    with make_client(lambda _: httpx.Response(403, json={"error": {
        "errors": [{"reason": "userRateLimitExceeded"}], "message": "private"}})) as client:
        with pytest.raises(GmailError) as caught:
            client.get_profile()
    assert caught.value.status_code == 403
    assert caught.value.reason == "userRateLimitExceeded" and caught.value.rate_limited
    assert "private" not in str(caught.value)


def test_send_stays_single_attempt_on_quota_403(make_client):
    calls = []
    def handler(request):
        calls.append(request)
        return httpx.Response(403, json={"error": {"errors": [{"reason": "rateLimitExceeded"}]}})
    with make_client(handler) as client, pytest.raises(GmailError):
        client.send_message(b"synthetic notification")
    assert len(calls) == 1


def test_current_weighted_budget_is_shared_per_mailbox(monkeypatch):
    clock, sleeps = [0.0], []
    monkeypatch.setattr(module.time, "monotonic", lambda: clock[0])
    def sleep(seconds):
        sleeps.append(seconds)
        clock[0] += seconds
    monkeypatch.setattr(module.time, "sleep", sleep)
    pacer = module._QuotaPacer()
    pacer.wait("first", module._quota_units("GET", "messages/a"))
    pacer.wait("second", module._quota_units("GET", "messages/b"))
    pacer.wait("first", module._quota_units("GET", "messages/c"))
    pacer.wait("first", module._quota_units("GET", "labels"))
    assert sleeps == pytest.approx([.4, .4])
    assert module._quota_units("POST", "messages/send") == 100
    assert module._quota_units("POST", "messages/a/modify") == 5
