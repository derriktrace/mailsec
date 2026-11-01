from copy import deepcopy

import httpx
import pytest
from sqlalchemy import create_engine

from mailsec.claim_verification import (
    CACHE_NAMESPACE,
    ENDPOINT,
    MAX_RESPONSE_BYTES,
    MAX_SOURCE_CHARS,
    MISSING_TTL,
    POSITIVE_TTL,
    VERSION,
    ClaimVerificationClient,
    LookupRateLimiter,
    extract_cve_claims,
)
from mailsec.security_cache import SecurityCache


class CacheSpy:
    def __init__(self):
        self.now = 1000
        self.values, self.gets, self.puts = {}, [], []
        self.clock = lambda: self.now

    def get(self, namespace, key):
        self.gets.append((namespace, key))
        result = self.values.get((namespace, tuple(key)))
        return deepcopy(result) if result and result['expires_at'] > self.now else None

    def put(self, namespace, key, value, expires_at):
        self.puts.append((namespace, key, deepcopy(value), expires_at))
        self.values[namespace, tuple(key)] = {'value': deepcopy(value), 'expires_at': expires_at}


def record(cve_id='CVE-2025-1234', description='Example product has a parsing vulnerability.'):
    return {'totalResults': 1, 'vulnerabilities': [{'cve': {
        'id': cve_id, 'published': '2025-02-01T00:00:00.000', 'lastModified': '2025-02-02T00:00:00.000',
        'vulnStatus': 'Analyzed', 'descriptions': [{'lang': 'en', 'value': description}],
    }}]}


def client(cache, handler, **kwargs):
    return ClaimVerificationClient(cache, enabled=True, transport=httpx.MockTransport(handler),
        rate_limiter=LookupRateLimiter(clock=lambda: cache.clock()), **kwargs)


def test_extract_only_visible_body_and_documents_preserves_exact_source_offsets():
    body = ('New patch fixes cve-2025-1234. Read https://attacker.example/patch\n'
            '> prior CVE-2020-1111\nOn Tuesday, someone wrote:\nCVE-2020-2222 old notice')
    document = 'Critical issue CVE-2026-12345 needs a patch.'
    evidence = {'subject': 'CVE-2020-3333', 'body': 'merged CVE-2020-4444', 'content': {
        'visible_text': body, 'hidden_text': 'CVE-2020-5555', 'quoted_text': 'CVE-2020-6666',
        'plain_alternative': 'CVE-2020-7777'}, 'links': [{'raw_url': 'https://evil.example/CVE-2020-8888'}],
        'inspection': {'attachments': [{'evidence_ref': 'part-2', 'text': document,
            'hidden_text': 'CVE-2020-9999', 'quoted_text': 'CVE-2020-1234'}]}}
    original = deepcopy(evidence)
    claims, coverage = extract_cve_claims(evidence)
    assert [claim['cve_id'] for claim in claims] == ['CVE-2025-1234', 'CVE-2026-12345']
    for source, claim in zip((body, document), claims, strict=True):
        item = claim['claims'][0]
        assert source[item['start']:item['end']] == item['literal']
        assert source[item['snippet_start']:item['snippet_end']] == item['snippet']
    assert claims[0]['claims'][0]['source_ref'] == 'content.visible_text'
    assert claims[1]['claims'][0]['evidence_ref'] == 'part-2'
    assert coverage['quoted_lines_excluded'] == 3 and coverage['complete']
    assert evidence == original


def test_distinct_identifiers_occurrences_and_extraction_limits_are_explicit():
    body = ('CVE-2025-1234 ' * 4 + 'CVE-2026-12345 CVE-2024-54321 CVE-2023-4321 '
            'XCVE-2020-1111 CVE-2020-1111X CVE-2020-' + '1' * 100)
    claims, coverage = extract_cve_claims({'content': {'visible_text': body}})
    assert [claim['cve_id'] for claim in claims] == ['CVE-2025-1234', 'CVE-2026-12345', 'CVE-2024-54321']
    assert len(claims[0]['claims']) == 3
    assert coverage['omitted_distinct_cves'] == 1 and coverage['omitted_claim_occurrences'] == 2
    assert not coverage['complete']
    claims, coverage = extract_cve_claims({'body': 'x' * MAX_SOURCE_CHARS + '\nCVE-2025-1234'})
    assert not claims and coverage['source_text_limited']
    assert coverage['source_characters_scanned'] == MAX_SOURCE_CHARS


def test_visible_empty_never_falls_back_to_hidden_legacy_body():
    assert extract_cve_claims({'body': 'CVE-2025-1234', 'content': {'visible_text': ''}})[0] == []
    assert extract_cve_claims({'body': 'CVE-2025-1234', 'content': {'quoted_text': 'CVE-2025-1234'}})[0] == []
    assert extract_cve_claims({'body': 'CVE-2025-1234'})[0][0]['cve_id'] == 'CVE-2025-1234'


def test_disabled_default_never_reads_cache_or_contacts_provider():
    cache = CacheSpy()
    instance = ClaimVerificationClient(cache, transport=httpx.MockTransport(lambda _: pytest.fail('network')))
    result = instance.inspect({'body': 'CVE-2025-1234'})
    assert result['results'][0]['status'] == 'disabled'
    assert not result['enabled'] and not result['coverage']['lookup_complete']
    assert not cache.gets and not cache.puts
    assert 'phishing' not in str(result).lower() and 'malicious' not in result['results'][0]


def test_fixed_endpoint_only_sends_id_and_retains_current_facts_and_claims_separately():
    cache, requests = CacheSpy(), []
    def provider(request):
        requests.append(request)
        assert request.method == 'GET'
        assert str(request.url).split('?')[0] == ENDPOINT
        assert dict(request.url.params) == {'cveId': 'CVE-2025-1234'}
        assert request.extensions['timeout'] == {'connect': 5, 'read': 5, 'write': 5, 'pool': 5}
        assert not request.content
        assert 'private content' not in str(request.url) + str(request.headers)
        return httpx.Response(200, json=record())
    instance = client(cache, provider)
    result = instance.inspect({'content': {'visible_text': 'private content claims CVE-2025-1234 requires this firmware.'},
        'links': [{'raw_url': 'https://attacker.example/CVE-2025-1234'}]})
    row = result['results'][0]
    assert len(requests) == 1 and row['status'] == 'found' and not row['cache_hit']
    assert row['source_url'] == 'https://nvd.nist.gov/vuln/detail/CVE-2025-1234'
    assert row['api_url'] == ENDPOINT + '?cveId=CVE-2025-1234'
    assert row['reference']['descriptions'][0]['text'] == record()['vulnerabilities'][0]['cve']['descriptions'][0]['value']
    assert row['reference']['published_at'] == '2025-02-01T00:00:00.000'
    assert row['reference']['last_modified_at'] == '2025-02-02T00:00:00.000'
    assert row['retrieved_at'] == '1970-01-01T00:16:40+00:00'
    assert row['claims'][0]['snippet'].startswith('private content')
    assert row['expires_at'] == cache.now + POSITIVE_TTL
    assert result['coverage']['complete'] and not result['remote_email_destinations_visited']
    assert 'claims' not in cache.puts[0][2]  # No mailbox content leaks into reusable source-fact cache.
    assert 'contradiction' not in row and 'verdict' not in row


def test_positive_cache_24h_is_cve_version_scoped_and_keeps_original_retrieval_date():
    cache, requests = CacheSpy(), []
    def provider(request):
        requests.append(request)
        return httpx.Response(200, json=record())
    instance = client(cache, provider)
    first = instance.check('cve-2025-1234')
    cache.now += 20
    second = instance.check('CVE-2025-1234')
    assert second['cache_hit'] and len(requests) == 1
    assert first['retrieved_at'] == second['retrieved_at']
    assert cache.gets[0] == (CACHE_NAMESPACE, [VERSION, 'CVE-2025-1234'])
    cache.now += POSITIVE_TTL
    assert not instance.check('CVE-2025-1234')['cache_hit'] and len(requests) == 2


def test_missing_entry_has_one_hour_cache_and_no_negative_security_claim():
    cache = CacheSpy()
    instance = client(cache, lambda _: httpx.Response(200, json={'totalResults': 0, 'vulnerabilities': []}))
    result = instance.check('CVE-2025-1234')
    assert result['status'] == 'not_found' and 'reference' not in result
    assert result['expires_at'] == cache.now + MISSING_TTL
    assert instance.check('CVE-2025-1234')['cache_hit']
    assert 'neither validates nor refutes' in result['reason']


@pytest.mark.parametrize('status', [301, 302, 307, 403, 404, 429, 500])
def test_redirect_and_http_failures_are_neutral_uncached_and_never_followed(status):
    cache, requests = CacheSpy(), []
    def provider(request):
        requests.append(request)
        return httpx.Response(status, headers={'Location': 'https://attacker.example/collect'})
    result = client(cache, provider).check('CVE-2025-1234')
    assert len(requests) == 1 and result['status'] == 'unavailable'
    assert not cache.puts and 'reference' not in result


def test_transport_exception_is_neutral_and_uncached():
    cache = CacheSpy()
    def failure(request):
        raise httpx.ReadTimeout('sensitive diagnostics', request=request)
    result = client(cache, failure).check('CVE-2025-1234')
    assert result['status'] == 'unavailable' and not cache.puts
    assert 'sensitive diagnostics' not in str(result)


@pytest.mark.parametrize('payload', [None, {}, {'totalResults': 0},
    {'totalResults': 1, 'vulnerabilities': []}, record('CVE-2025-9999'),
    {'totalResults': 1, 'vulnerabilities': [{'cve': {'id': 'CVE-2025-1234'}}]}])
def test_invalid_or_mismatched_provider_evidence_never_becomes_a_reference(payload):
    cache = CacheSpy()
    result = client(cache, lambda _: httpx.Response(200, json=payload)).check('CVE-2025-1234')
    assert result['status'] == 'unavailable' and 'reference' not in result and not cache.puts


class Chunks(httpx.SyncByteStream):
    def __init__(self):
        self.reads = 0

    def __iter__(self):
        for _ in range(100):
            self.reads += 1
            yield b' ' * 16384


def test_streamed_response_cap_stops_reading_and_does_not_cache():
    cache, stream = CacheSpy(), Chunks()
    result = client(cache, lambda _: httpx.Response(200, stream=stream)).check('CVE-2025-1234')
    assert result['status'] == 'unavailable' and not cache.puts
    assert stream.reads == MAX_RESPONSE_BYTES // 16384 + 1


def test_declared_oversized_response_is_rejected_before_reading():
    cache, stream = CacheSpy(), Chunks()
    result = client(cache, lambda _: httpx.Response(200, stream=stream,
        headers={'Content-Length': str(MAX_RESPONSE_BYTES + 1)})).check('CVE-2025-1234')
    assert result['status'] == 'unavailable' and stream.reads == 0 and not cache.puts


def test_rate_limiter_shared_across_clients_and_cached_facts_do_not_consume_slot():
    cache = CacheSpy()
    limiter = LookupRateLimiter(limit=1, period=30, clock=cache.clock)
    transport = httpx.MockTransport(lambda request: httpx.Response(200, json=record(request.url.params['cveId'])))
    first = ClaimVerificationClient(cache, enabled=True, transport=transport, rate_limiter=limiter)
    second = ClaimVerificationClient(cache, enabled=True, transport=transport, rate_limiter=limiter)
    assert first.check('CVE-2025-1234')['status'] == 'found'
    assert second.check('CVE-2025-1234')['cache_hit']
    assert second.check('CVE-2025-9999')['status'] == 'rate_limited'
    cache.now += 30
    assert second.check('CVE-2025-9999')['status'] == 'found'


@pytest.mark.parametrize('value', ['https://attacker.example/CVE-2025-1234', 'CVE-2025-1234?x=secret',
    'CVE-2025-1234\n', 'CVE-25-1234', 'CVE-2025-123', 'CVE-2025-' + '1' * 40, None])
def test_check_rejects_nonliteral_identifiers_before_any_lookup(value):
    cache = CacheSpy()
    result = client(cache, lambda _: pytest.fail('network')).check(value)
    assert result['status'] == 'invalid_identifier' and not cache.gets and not cache.puts


def test_actual_security_cache_integration_is_tenant_scoped():
    engine = create_engine('sqlite://')
    requests = []
    def provider(request):
        requests.append(request)
        return httpx.Response(200, json=record())
    a = SecurityCache(engine, 'customer-a', clock=lambda: 1000)
    b = SecurityCache(engine, 'customer-b', clock=lambda: 1000)
    first, second = client(a, provider), client(b, provider)
    assert first.check('CVE-2025-1234')['status'] == 'found'
    assert first.check('CVE-2025-1234')['cache_hit']
    assert not second.check('CVE-2025-1234')['cache_hit']
    assert len(requests) == 2
    engine.dispose()


def test_source_limit_cannot_manufacture_a_different_cve_identifier():
    prefix = ' ' * (MAX_SOURCE_CHARS - len('CVE-2025-1234'))
    claims, coverage = extract_cve_claims({'body': prefix + 'CVE-2025-123456'})
    assert not claims and coverage['source_text_limited']


def test_legacy_merged_body_visibility_gap_is_explicit():
    claims, coverage = extract_cve_claims({'body': 'CVE-2025-1234',
        'content': {'hidden_text': 'hidden alternate'}})
    assert not claims and coverage['source_visibility_unavailable'] and not coverage['complete']


def test_unexpected_compressed_response_is_rejected_before_reading():
    cache, stream = CacheSpy(), Chunks()
    result = client(cache, lambda _: httpx.Response(200, stream=stream,
        headers={'Content-Encoding': 'gzip'})).check('CVE-2025-1234')
    assert result['status'] == 'unavailable' and stream.reads == 0 and not cache.puts


def test_inspect_caps_requests_to_three_distinct_ids():
    cache, requests = CacheSpy(), []
    def provider(request):
        requests.append(request)
        return httpx.Response(200, json=record(request.url.params['cveId']))
    result = client(cache, provider).inspect({'body': 'CVE-2025-1234 CVE-2025-1235 CVE-2025-1236 CVE-2025-1237'})
    assert len(requests) == len(result['results']) == 3
    assert result['coverage']['omitted_distinct_cves'] == 1 and not result['coverage']['complete']
