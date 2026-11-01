from types import SimpleNamespace

import httpx
import pytest

from mailsec.inspection_client import InspectionClient


@pytest.mark.parametrize('status', [429, 503])
def test_busy_scanner_retries_original_bytes_then_returns_actual_scan(status):
    calls = []
    sleeps = []
    result = {'status': 'complete', 'antivirus': {'status': 'clean'}, 'findings': [], 'urls': []}
    def handler(request):
        calls.append(request.content)
        return httpx.Response(status, headers={'Retry-After': '2'}) if len(calls) < 3 else httpx.Response(200, json=result)
    client = InspectionClient(SimpleNamespace(inspection_url='http://scanner', inspection_timeout_seconds=120),
        transport=httpx.MockTransport(handler), sleeper=sleeps.append, clock=lambda: sum(sleeps))
    assert client.inspect(b'original bytes') == result
    assert calls == [b'original bytes'] * 3 and sleeps == [2, 2]


@pytest.mark.parametrize('header', ['1', '99999', 'nan', 'bad', '-5'])
def test_exhausted_busy_retries_are_bounded_and_never_clean(header):
    sleeps = []
    client = InspectionClient(SimpleNamespace(inspection_url='http://scanner', inspection_timeout_seconds=120),
        transport=httpx.MockTransport(lambda _: httpx.Response(429, headers={'Retry-After': header})),
        sleeper=sleeps.append, clock=lambda: sum(sleeps))
    result = client.inspect(b'email')
    assert result['status'] == result['antivirus']['status'] == 'unavailable'
    assert sum(sleeps) <= 30 and len(sleeps) <= 30


def test_unauthorized_scanner_does_not_retry():
    sleeps = []
    client = InspectionClient(SimpleNamespace(inspection_url='http://scanner', inspection_timeout_seconds=120),
        transport=httpx.MockTransport(lambda _: httpx.Response(401)), sleeper=sleeps.append)
    assert client.inspect(b'email')['status'] == 'unavailable' and not sleeps
