"""Adversarial provider responses and DNS pinning, without real credentials/network."""
import asyncio
import socket

import httpx
import pytest

from mailsec import decision, outbound
from mailsec.gmail import READONLY_SCOPE, GmailClient, GmailError
from mailsec.jev import JevClient, JevError


class Chunks(httpx.SyncByteStream):
    def __init__(self, parts):
        self.parts, self.reads, self.closed = parts, 0, False

    def __iter__(self):
        for part in self.parts:
            self.reads += 1
            yield part

    def close(self):
        self.closed = True


@pytest.mark.parametrize('headers', [{'content-encoding': 'gzip'}, {'content-encoding': 'br'},
    {'content-length': '1000000'}, {'content-length': '-1'}, {'content-length': 'invalid'}])
def test_response_headers_rejected_before_consuming_body(headers):
    stream = Chunks([b'untrusted provider data'])
    with httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(200, headers=headers, stream=stream))) as client:
        with pytest.raises(ValueError):
            outbound.bounded_response(client, 'GET', 'https://provider.example.test/', max_bytes=100, total_seconds=5)
    assert stream.reads == 0 and stream.closed


def test_streamed_response_without_length_is_bounded_and_closed():
    stream = Chunks([b'x' * 6] * 100)
    with httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(200, stream=stream))) as client:
        with pytest.raises(ValueError, match='byte limit'):
            outbound.bounded_response(client, 'GET', 'https://provider.example.test/', max_bytes=10, total_seconds=5)
    assert stream.reads == 2 and stream.closed


def test_drip_feed_cannot_reset_elapsed_response_budget(monkeypatch):
    clock = iter([0, 1, 3, 6, 7])
    monkeypatch.setattr(outbound.time, 'monotonic', lambda: next(clock))
    stream = Chunks([b'x'] * 100)
    with httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(200, stream=stream))) as client:
        with pytest.raises(httpx.ReadTimeout):
            outbound.bounded_response(client, 'GET', 'https://provider.example.test/', max_bytes=100, total_seconds=5)
    assert stream.reads == 3 and stream.closed


def test_small_json_is_read_without_request_secrets_in_returned_response():
    def handler(request):
        assert request.headers['accept-encoding'] == 'identity'
        return httpx.Response(200, json={'ok': True})
    with httpx.Client(transport=httpx.MockTransport(handler)) as client:
        result = outbound.bounded_response(client, 'POST', 'https://provider.example.test/',
            max_bytes=100, total_seconds=5, headers={'Authorization': 'Bearer private-test-token'})
    assert result.json() == {'ok': True}
    with pytest.raises(RuntimeError, match='request instance'):
        _ = result.request


class Credentials:
    token = 'private-test-access-token'
    def before_request(self, request, method, url, headers):
        headers['Authorization'] = 'Bearer ' + self.token


@pytest.mark.parametrize('response', [lambda: httpx.Response(200, headers={'content-length': '3000000'}, stream=Chunks([])),
                                      lambda: httpx.Response(200, headers={'content-encoding': 'gzip'}, stream=Chunks([]))])
def test_gmail_response_caps_fail_closed_with_sanitized_errors(response):
    with GmailClient('', 'owner@example.test', credentials=Credentials(), scopes=[READONLY_SCOPE],
                     transport=httpx.MockTransport(lambda _: response())) as client:
        with pytest.raises(GmailError, match='oversized or unsupported') as error:
            client.get_profile()
    assert 'private-test' not in str(error.value)


@pytest.mark.parametrize('status', [200, 400])
def test_gmail_excessively_nested_json_becomes_a_sanitized_provider_error(status, monkeypatch):
    monkeypatch.setattr('mailsec.gmail._quota_pacer.wait', lambda *args: None)
    nested = b'{"untrusted":' + b'[' * 2000 + b'"private-test"' + b']' * 2000 + b'}'
    with GmailClient('', 'owner@example.test', credentials=Credentials(),
                     transport=httpx.MockTransport(lambda _: httpx.Response(status, content=nested))) as client:
        with pytest.raises(GmailError) as error:
            client.get_profile()
    assert 'private-test' not in str(error.value)
    assert error.value.__cause__ is None


@pytest.mark.parametrize('raw', ['+w==', '/w==', '-/==', '_+==', 'YQ==Yg==', 'Y Q=='])
def test_gmail_raw_requires_exact_urlsafe_alphabet_and_single_padded_value(raw, monkeypatch):
    monkeypatch.setattr('mailsec.gmail._quota_pacer.wait', lambda *args: None)
    payload = {'id': 'synthetic', 'threadId': 'synthetic-thread', 'internalDate': '1', 'raw': raw}
    with GmailClient('', 'owner@example.test', credentials=Credentials(),
                     transport=httpx.MockTransport(lambda _: httpx.Response(200, json=payload))) as client:
        with pytest.raises(GmailError, match='invalid base64url'):
            client.get_message('synthetic')


@pytest.mark.parametrize('raw', ['_w==', '_w', '-w==', '-w'])
def test_gmail_raw_keeps_valid_padded_and_unpadded_base64url(raw, monkeypatch):
    monkeypatch.setattr('mailsec.gmail._quota_pacer.wait', lambda *args: None)
    payload = {'id': 'synthetic', 'threadId': 'synthetic-thread', 'internalDate': '1', 'raw': raw}
    with GmailClient('', 'owner@example.test', credentials=Credentials(),
                     transport=httpx.MockTransport(lambda _: httpx.Response(200, json=payload))) as client:
        assert client.get_message('synthetic')['raw'] == (b'\xff' if raw[0] == '_' else b'\xfb')


@pytest.mark.parametrize('url', ['http://169.254.169.254/token', 'https://attacker.example.test/token',
    'https://oauth2.googleapis.com/token?redirect=attacker', 'https://oauth2.googleapis.com.attacker.test/token'])
def test_google_refresh_refuses_unexpected_token_destination(url):
    with GmailClient('', 'owner@example.test', credentials=Credentials(),
                     transport=httpx.MockTransport(lambda _: pytest.fail('No request may escape'))) as client:
        with pytest.raises(GmailError, match='endpoint'):
            client._auth_request(url, method='POST', body=b'private-refresh-token')


def test_google_refresh_token_body_is_bounded():
    stream = Chunks([b'x' * 40000] * 10)
    with GmailClient('', 'owner@example.test', credentials=Credentials(),
                     transport=httpx.MockTransport(lambda _: httpx.Response(200, stream=stream))) as client:
        with pytest.raises(ValueError, match='byte limit'):
            client._auth_request('https://oauth2.googleapis.com/token', method='POST', body=b'private-test-refresh')
    assert stream.reads == 2 and stream.closed


def test_jev_oversized_response_never_becomes_a_classification():
    calls = []
    def handler(request):
        calls.append(request)
        return httpx.Response(200, headers={'content-length': str(2 * 1024 * 1024)}, stream=Chunks([]))
    with pytest.raises(JevError, match='oversized or unsupported'):
        JevClient('private-test-key', transport=httpx.MockTransport(handler)).evaluate({'body': 'synthetic'})
    assert len(calls) == 1


@pytest.mark.parametrize('address', ['169.254.169.254', '::ffff:169.254.169.254', 'fe80::1', '0.0.0.0',
    '224.0.0.1', '168.63.129.16', '100.100.100.200', '2002:a9fe:a9fe::1',
    '2001:0000:4136:e378:8000:63bf:5601:5601'])
def test_model_dns_alias_cannot_resolve_to_cloud_metadata(monkeypatch, address):
    async def run():
        async def resolve(*args, **kwargs):
            return [(socket.AF_INET6 if ':' in address else socket.AF_INET, socket.SOCK_STREAM, 6, '', (address, 80))]
        monkeypatch.setattr(asyncio.get_running_loop(), 'getaddrinfo', resolve)
        with pytest.raises(JevError, match='allowed network address'):
            await decision._pinned_destination('http://friendly-model.example.test/v1/chat/completions')
    asyncio.run(run())


def test_mixed_dns_answers_reject_the_entire_model_destination(monkeypatch):
    async def run():
        async def resolve(*args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (ip, 80))
                    for ip in ['192.168.20.5', '169.254.169.254']]
        monkeypatch.setattr(asyncio.get_running_loop(), 'getaddrinfo', resolve)
        with pytest.raises(JevError):
            await decision._pinned_destination('http://model.example.test/api/chat')
    asyncio.run(run())


@pytest.mark.parametrize('addresses', [['8.8.8.8'], ['2606:4700:4700::1111'], ['192.168.20.5', '8.8.8.8']])
def test_plain_http_model_cannot_send_email_or_key_to_any_public_dns_answer(monkeypatch, addresses):
    async def run():
        async def resolve(*args, **kwargs):
            return [(socket.AF_INET6 if ':' in ip else socket.AF_INET, socket.SOCK_STREAM, 6, '', (ip, 80))
                    for ip in addresses]
        monkeypatch.setattr(asyncio.get_running_loop(), 'getaddrinfo', resolve)
        with pytest.raises(JevError, match='use HTTPS'):
            await decision._pinned_destination('http://model.example.test/api/chat')
    asyncio.run(run())


@pytest.mark.parametrize('address', ['8.8.8.8', '[2606:4700:4700::1111]'])
def test_literal_public_model_requires_https_during_setup(address):
    with pytest.raises(ValueError, match='use HTTPS'):
        decision.endpoint('http://' + address, 'ollama')
    assert decision.endpoint('https://' + address, 'ollama').endswith('/api/chat')


def test_public_https_model_remains_supported(monkeypatch):
    async def run():
        async def resolve(*args, **kwargs):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('8.8.8.8', 443))]
        monkeypatch.setattr(asyncio.get_running_loop(), 'getaddrinfo', resolve)
        url, headers, extensions = await decision._pinned_destination('https://model.example.test/api/chat')
        assert url.host == '8.8.8.8' and url.scheme == 'https'
        assert headers['Host'] == 'model.example.test'
        assert extensions['sni_hostname'] == 'model.example.test'
    asyncio.run(run())


@pytest.mark.parametrize('address', ['127.0.0.1', '192.168.20.5', '::1'])
def test_model_dns_is_pinned_while_original_host_and_tls_identity_are_preserved(monkeypatch, address):
    async def run():
        calls = []
        async def resolve(host, port, **kwargs):
            calls.append((host, port))
            if len(calls) > 1:
                raise AssertionError('No second DNS lookup may happen')
            return [(socket.AF_INET6 if ':' in address else socket.AF_INET, socket.SOCK_STREAM, 6, '', (address, port))]
        monkeypatch.setattr(asyncio.get_running_loop(), 'getaddrinfo', resolve)
        url, headers, extensions = await decision._pinned_destination('https://model.example.test:8443/v1/chat/completions')
        assert url.host == address and url.port == 8443
        assert headers == {'Host': 'model.example.test:8443'}
        assert extensions == {'sni_hostname': 'model.example.test'}
        assert calls == [('model.example.test', 8443)]
    asyncio.run(run())


@pytest.mark.parametrize('url', ['http://model\n.example.test', 'http://[fe80::1%25eth0]', 'http://168.63.129.16', 'http://100.100.100.200'])
def test_model_control_characters_scoped_hosts_and_metadata_literals_are_rejected(url):
    with pytest.raises(ValueError):
        decision.endpoint(url, 'ollama')


def test_production_model_request_uses_pinned_ip_not_a_second_hostname_lookup(monkeypatch):
    requests = []
    real_client = httpx.AsyncClient
    async def pinned(_):
        return httpx.URL('https://127.0.0.1:8443/api/chat'), {'Host': 'model.example.test:8443'}, {'sni_hostname': 'model.example.test'}
    def handler(request):
        requests.append(request)
        assert request.url.host == '127.0.0.1'
        assert request.headers['host'] == 'model.example.test:8443'
        assert request.extensions['sni_hostname'] == 'model.example.test'
        return httpx.Response(200, content=b'{}')
    def client_factory(**kwargs):
        assert kwargs['trust_env'] is False and kwargs['follow_redirects'] is False
        return real_client(**{**kwargs, 'transport': httpx.MockTransport(handler)})
    monkeypatch.setattr(decision, '_pinned_destination', pinned)
    monkeypatch.setattr(decision.httpx, 'AsyncClient', client_factory)
    client = decision.LocalDecisionClient('ollama', 'https://model.example.test:8443', 'fixture')
    assert asyncio.run(client._response_body({}, {})) == b'{}'
    assert len(requests) == 1


def test_gmail_raw_base64_is_rejected_before_unbounded_decode(monkeypatch):
    from mailsec import gmail
    monkeypatch.setattr(gmail, 'MAX_MESSAGE_BYTES', 10)
    value = {'id': 'message', 'threadId': 'thread', 'raw': 'YQ' * 100, 'internalDate': '1'}
    with GmailClient('', 'owner@example.test', credentials=Credentials(),
                     transport=httpx.MockTransport(lambda _: httpx.Response(200, json=value))) as client:
        with pytest.raises(GmailError, match='import limit'):
            client.get_message('message')


def test_gmail_and_jev_http_clients_disable_inherited_proxy_configuration(monkeypatch):
    real_client = httpx.Client
    seen = []
    def factory(*args, **kwargs):
        seen.append(kwargs.get('trust_env'))
        return real_client(*args, **kwargs)
    monkeypatch.setattr(httpx, 'Client', factory)
    transport = httpx.MockTransport(lambda _: httpx.Response(200, json={'historyId': '1'}))
    with GmailClient('', 'owner@example.test', credentials=Credentials(), transport=transport) as client:
        client.get_profile()
    with pytest.raises(JevError):
        JevClient('synthetic-key', transport=transport, sleeper=lambda _: None).evaluate({})
    assert seen == [False, False]


@pytest.mark.parametrize('provider', ['inspection', 'reputation'])
@pytest.mark.parametrize('attack', ['compressed', 'oversized'])
def test_supplemental_provider_failures_remain_unknown_and_never_clean(tmp_path, provider, attack):
    from types import SimpleNamespace

    from sqlalchemy import create_engine

    from mailsec.inspection_client import InspectionClient, scan_retry_reason
    from mailsec.reputation import ReputationClient
    from mailsec.security_cache import SecurityCache
    stream = Chunks([b'Untrusted body must never be read'])
    headers = {'content-encoding': 'gzip'} if attack == 'compressed' else {'content-length': '10000000'}
    def handler(request):
        assert request.headers['accept-encoding'] == 'identity'
        return httpx.Response(200, stream=stream, headers=headers)
    transport = httpx.MockTransport(handler)
    if provider == 'inspection':
        settings = SimpleNamespace(inspection_url='http://scanner', inspection_timeout_seconds=120)
        result = InspectionClient(settings, transport=transport).inspect(b'Synthetic message')
        assert result['status'] == result['antivirus']['status'] == 'unavailable'
        assert scan_retry_reason(result)
    else:
        settings = SimpleNamespace(organization={}, web_risk_api_key='synthetic-key', url_lookup_monthly_limit=10)
        cache = SecurityCache(create_engine('sqlite:///' + str(tmp_path/'cache.db')))
        result = ReputationClient(settings, cache, transport=transport).check('https://example.test/only-a-query')
        assert result['status'] == 'unavailable' and result['malicious'] is False
    assert stream.reads == 0 and stream.closed


def test_pinned_https_connection_verifies_original_hostname_with_real_tls(tmp_path, monkeypatch):
    """Loopback TLS fixture proves pinning never disables hostname verification."""
    import ssl
    import threading
    from datetime import UTC, datetime, timedelta
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    identity = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'allowed-model.example.test')])
    certificate = (x509.CertificateBuilder().subject_name(identity).issuer_name(identity)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(minutes=1))
        .not_valid_after(datetime.now(UTC) + timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName('allowed-model.example.test')]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(key, hashes.SHA256()))
    cert_path, key_path = tmp_path/'certificate.pem', tmp_path/'private-key.pem'
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                            serialization.NoEncryption()))
    key_path.chmod(0o600)
    requests, names = [], []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass
        def do_POST(self):
            requests.append(self.headers['Host'])
            self.rfile.read(int(self.headers['Content-Length']))
            self.send_response(200)
            self.send_header('Content-Length', '2')
            self.end_headers()
            self.wfile.write(b'{}')

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_path, key_path)
    context.set_servername_callback(lambda _socket, name, _context: names.append(name))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    trust = ssl.create_default_context(cafile=str(cert_path))
    real_client = httpx.AsyncClient
    monkeypatch.setattr(decision.httpx, 'AsyncClient', lambda **kwargs: real_client(**kwargs, verify=trust))

    async def run():
        loop = asyncio.get_running_loop()
        resolve = loop.getaddrinfo
        async def local_names(host, port, **kwargs):
            if host in {'allowed-model.example.test', 'wrong-model.example.test'}:
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', port))]
            return await resolve(host, port, **kwargs)
        monkeypatch.setattr(loop, 'getaddrinfo', local_names)
        port = server.server_address[1]
        good = decision.LocalDecisionClient('ollama', f'https://allowed-model.example.test:{port}', 'fixture', timeout=3)
        assert await good._response_body({}, {}) == b'{}'
        wrong = decision.LocalDecisionClient('ollama', f'https://wrong-model.example.test:{port}', 'fixture', timeout=3)
        with pytest.raises(httpx.ConnectError):
            await wrong._response_body({}, {})
        assert requests == [f'allowed-model.example.test:{port}']
        assert names == ['allowed-model.example.test', 'wrong-model.example.test']
    try:
        asyncio.run(run())
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
