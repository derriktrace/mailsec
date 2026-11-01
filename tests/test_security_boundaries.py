"""Adversarial console and initial-MIME boundaries, using synthetic data only."""

import asyncio
import json
import random

import httpx
import pytest

from mailsec.api import create_app
from mailsec.config import Settings
from mailsec.enrichment import enrich
from mailsec.parsing import MAX_HEADER_CHARS, MAX_HEADERS_PER_PART, MAX_PARSED_PARTS, parse_email
from mailsec.pipeline import Pipeline


def test_every_console_api_route_authenticates_before_handler(tmp_path):
    app = create_app(Settings(database_url=f"sqlite:///{tmp_path / 'auth.db'}", app_token="private"))

    async def check():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://testserver") as client:
            checked = 0
            for route in app.routes:
                if not getattr(route, 'path', '').startswith('/api/'):
                    continue
                path = route.path
                for field in ('mid', 'aid', 'nid'):
                    path = path.replace('{' + field + '}', 'unknown')
                for method in route.methods:
                    for headers in ({}, {'Authorization': 'Bearer incorrect'}):
                        response = await client.request(method, path, headers=headers)
                        assert response.status_code == 401, (method, path, response.status_code)
                    checked += 1
            assert checked >= 25
    asyncio.run(check())


def test_console_rejects_ambiguous_headers_and_sets_https_policy(tmp_path):
    app = create_app(Settings(database_url=f"sqlite:///{tmp_path / 'headers.db'}", app_token="private"))

    async def check():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="https://testserver") as client:
            for headers in ([('Host', 'testserver'), ('Host', 'attacker.invalid')],
                            [('Authorization', 'Bearer private'), ('Authorization', 'Bearer wrong')]):
                result = await client.get('/api/status', headers=headers)
                assert result.status_code == 400
            result = await client.post('/api/demo', content=b'', headers={
                'Authorization': 'Bearer private', 'Transfer-Encoding': 'chunked', 'Content-Length': '0'})
            assert result.status_code == 400
            assert result.headers['strict-transport-security'] == 'max-age=31536000'
            assert result.headers['x-content-type-options'] == 'nosniff'
    asyncio.run(check())


def test_evaluation_root_cannot_forward_anonymous_writes(tmp_path):
    app = create_app(Settings(database_url=f"sqlite:///{tmp_path / 'eval.db'}", app_token='private',
                              evaluation_proxy_url='http://127.0.0.1:9'))

    async def check():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url='http://testserver') as client:
            result = await client.post('/evaluation/', content=b'not forwarded')
            assert result.status_code == 405
            assert (await client.post('/evaluation/api/import')).status_code == 401
    asyncio.run(check())


def test_mime_construction_is_bounded_before_evidence_traversal(tmp_path):
    raw = (b'From: sender@example.invalid\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n' +
           b'--x\r\nContent-Type: text/plain\r\n\r\npart\r\n' * MAX_PARSED_PARTS + b'--x--\r\n')
    with pytest.raises(ValueError, match='MIME structure'):
        parse_email(raw)
    pipeline = Pipeline(Settings(database_url=f"sqlite:///{tmp_path / 'mime.db'}"))
    result = pipeline.ingest(raw, provider='gmail', provider_message_id='synthetic-mime-limit',
                             mailbox='recipient@example.invalid')
    assert result['rejected'] is True
    assert pipeline.store.get_message(result['id'])['raw'] == raw
    assert pipeline.store.detail(result['id'])['runs'][0]['status'] == 'error'


def test_initial_header_count_is_bounded():
    raw = b'X-Field: value\r\n' * (MAX_HEADERS_PER_PART + 1) + b'\r\nmessage'
    with pytest.raises(ValueError, match='header count'):
        parse_email(raw)


def test_oversized_structured_header_is_bounded_and_auth_untrusted():
    raw = (b'From: sender@example.invalid\r\nSubject: ' + b'A' * (MAX_HEADER_CHARS * 2) +
           b'\r\nReceived: from sender.invalid by mx.google.com; date\r\n'
           b'Authentication-Results: mx.google.com; dmarc=pass header.from=example.invalid\r\n\r\nHello')
    evidence = enrich(parse_email(raw, provider='gmail'), {'trusted_authserv_ids': ['mx.google.com']})
    assert evidence['quality']['headers_truncated'] is True
    assert len(evidence['message']['subject']) <= 2000
    assert evidence['authentication']['dmarc'] == 'unknown'


def test_malformed_binary_mail_never_emits_invalid_unicode():
    random_bytes = random.Random(42)
    for _ in range(100):
        raw = b'From: sender@example.invalid\r\nSubject: ' + random_bytes.randbytes(80) + b'\r\n\r\n' + random_bytes.randbytes(200)
        evidence = parse_email(raw)
        json.dumps(evidence, ensure_ascii=False).encode('utf-8')


@pytest.mark.parametrize('header', [b'From', b'To', b'Content-Disposition', b'Content-Type', b'Date', b'Subject'])
def test_malformed_structured_headers_remain_bounded_valid_evidence(header):
    random_bytes = random.Random(81)
    for _ in range(350):
        value = random_bytes.randbytes(random_bytes.randrange(1, 700)).replace(b'\n', b' ')
        raw = b'From: sender@example.invalid\r\n' + header + b': ' + value + b'\r\n\r\nHello'
        evidence = parse_email(raw)
        json.dumps(evidence, ensure_ascii=False).encode('utf-8')
