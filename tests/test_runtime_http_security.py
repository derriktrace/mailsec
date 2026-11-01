"""Privileged health requests cannot follow redirects, proxies or unlimited bodies."""

import json

import pytest

from mailsec import runtime_http


def connection(monkeypatch, body=b'{}', status=200):
    calls = []

    class Response:
        def read(self, limit):
            calls.append(('read', limit))
            return body[:limit]

    Response.status = status

    class Connection:
        def __init__(self, host, port, timeout):
            calls.append(('connect', host, port, timeout))

        def request(self, method, path, headers):
            calls.append(('request', method, path, headers))

        def getresponse(self):
            return Response()

        def close(self):
            calls.append(('closed',))

    monkeypatch.setattr(runtime_http.http.client, 'HTTPConnection', Connection)
    return calls


def test_health_ignores_proxy_environment_and_only_requests_fixed_loopback(monkeypatch):
    monkeypatch.setenv('HTTP_PROXY', 'http://untrusted.invalid:9999')
    monkeypatch.setenv('ALL_PROXY', 'http://untrusted.invalid:9999')
    calls = connection(monkeypatch, json.dumps({'ready': True}).encode())
    assert runtime_http.local_health(8080) == {'ready': True}
    assert calls[0] == ('connect', '127.0.0.1', 8080, 2)
    assert calls[1] == ('request', 'GET', '/health', {'Host': 'localhost'})
    assert calls[-1] == ('closed',)


@pytest.mark.parametrize('status', [301, 302, 307, 308, 503])
def test_health_never_follows_redirect_or_accepts_unready_status(monkeypatch, status):
    calls = connection(monkeypatch, status=status)
    with pytest.raises(ValueError, match='not ready'):
        runtime_http.local_health(8025)
    assert sum(item[0] == 'connect' for item in calls) == 1
    assert not any(item[0] == 'read' for item in calls)
    assert calls[-1] == ('closed',)


@pytest.mark.parametrize('body', [b'[' + b'0,' * 20000 + b'0]', b'not json', b'null', b'[]'])
def test_health_bounds_response_and_requires_json_object(monkeypatch, body):
    calls = connection(monkeypatch, body=body)
    with pytest.raises(ValueError):
        runtime_http.local_health(8080)
    assert ('read', 16385) in calls and calls[-1] == ('closed',)


def test_health_rejects_unexpected_destination(monkeypatch):
    calls = connection(monkeypatch)
    with pytest.raises(ValueError, match='Unexpected'):
        runtime_http.local_health(9000)
    assert not calls
