"""Optional, bounded CVE reference facts. Never fetches an email destination.

A CVE mention is a claim, not a maliciousness signal. This module returns source
facts for a downstream adjudicator; it never declares a contradiction or verdict.
"""
import re
import threading
import time
from collections import deque
from datetime import datetime, timezone

import httpx

from .outbound import bounded_response

VERSION = 'cve-claims-v1'
ENDPOINT = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
CACHE_NAMESPACE = 'cve_facts'
MAX_CVES = 3
MAX_RESPONSE_BYTES = 256 * 1024
MAX_SOURCE_CHARS = 400_000
MAX_ATTACHMENTS = 64
POSITIVE_TTL = 24 * 60 * 60
MISSING_TTL = 60 * 60
_CVE = re.compile(r'\bCVE-[0-9]{4}-[0-9]{4,}\b', re.I)
_QUOTE_START = re.compile(r'^\s*(?:On .{1,400} wrote:|-{2,}\s*(?:Original|Forwarded) Message\s*-{2,})\s*$', re.I)


class LookupRateLimiter:
    """Shared per-process sliding window; never delays the mail worker.

    Use one shared limiter per outbound NVD identity. Multiple processes need a
    shared deployment-level limiter; an NVD 429 is otherwise neutral/unavailable.
    """
    def __init__(self, limit=5, period=30, clock=time.monotonic):
        self.limit, self.period, self.clock = limit, period, clock
        self._requests = deque()
        self._lock = threading.Lock()

    def acquire(self):
        with self._lock:
            now = self.clock()
            while self._requests and self._requests[0] <= now - self.period:
                self._requests.popleft()
            if len(self._requests) >= self.limit:
                return False
            self._requests.append(now)
            return True


_RATE_LIMITER = LookupRateLimiter()


def _sources(evidence):
    content = evidence.get('content', {})
    visible = content.get('visible_text')
    if isinstance(visible, str):
        yield 'content.visible_text', 'current_visible_message', None, visible
    elif not any(content.get(key) for key in ('hidden_text', 'quoted_text', 'plain_alternative')):
        # An old merged body may include hidden/quoted alternatives. Prefer no
        # claim lookup over silently treating these as current visible claims.
        yield 'body', 'legacy_body', None, evidence.get('body', '')
    attachments = evidence.get('inspection', {}).get('attachments', [])
    for index, item in enumerate(attachments[:MAX_ATTACHMENTS]):
        if isinstance(item, dict):
            yield f'inspection.attachments[{index}].text', 'extracted_document_text', item.get('evidence_ref'), item.get('text', '')


def extract_cve_claims(evidence):
    """Return at most three distinct IDs, with bounded exact-source excerpts."""
    claims = {}
    seen = set()
    remaining = MAX_SOURCE_CHARS
    coverage = {'source_characters_scanned': 0, 'source_text_limited': False,
                'omitted_distinct_cves': 0, 'omitted_claim_occurrences': 0,
                'quoted_lines_excluded': 0, 'max_cves': MAX_CVES,
                'source_visibility_unavailable': bool(evidence.get('body')) and
                    not isinstance(evidence.get('content', {}).get('visible_text'), str) and
                    any(evidence.get('content', {}).get(key) for key in ('hidden_text', 'quoted_text', 'plain_alternative')),
                'excluded_sources': ['hidden_text', 'quoted_text', 'plain_alternative', 'headers', 'links']}
    attachments = evidence.get('inspection', {}).get('attachments', [])
    coverage['attachments_omitted'] = max(0, len(attachments) - MAX_ATTACHMENTS)
    for source_ref, role, evidence_ref, original in _sources(evidence):
        if not isinstance(original, str) or not original:
            continue
        text = original[:remaining]
        if len(text) < len(original):
            coverage['source_text_limited'] = True
        remaining -= len(text)
        coverage['source_characters_scanned'] += len(text)
        offset = 0
        for line in text.splitlines(keepends=True):
            if _QUOTE_START.fullmatch(line.rstrip('\r\n')):
                coverage['quoted_lines_excluded'] += len(text[offset:].splitlines())
                break
            if line.lstrip().startswith('>'):
                coverage['quoted_lines_excluded'] += 1
                offset += len(line)
                continue
            for match in _CVE.finditer(line):
                # A malformed, arbitrarily long identifier cannot turn into a
                # provider query or expand the retained evidence without bound.
                if len(match.group()) > 32:
                    coverage['omitted_claim_occurrences'] += 1
                    continue
                end = offset + match.end()
                if end < len(original) and (original[end].isalnum() or original[end] == '_'):
                    # Do not query a prefix created by cutting an identifier at
                    # the source-size limit. The uncut original remains local.
                    continue
                cve_id = match.group().upper()
                if cve_id not in seen:
                    seen.add(cve_id)
                    if len(claims) < MAX_CVES:
                        claims[cve_id] = {'cve_id': cve_id, 'claims': []}
                    else:
                        coverage['omitted_distinct_cves'] += 1
                if cve_id not in claims:
                    continue
                occurrences = claims[cve_id]['claims']
                if len(occurrences) >= 3:
                    coverage['omitted_claim_occurrences'] += 1
                    continue
                start, end = offset + match.start(), offset + match.end()
                snippet_start, snippet_end = max(offset, start - 120), min(offset + len(line), end + 180)
                occurrences.append({'source_ref': source_ref, 'source_role': role,
                    'evidence_ref': evidence_ref, 'literal': original[start:end],
                    'start': start, 'end': end, 'snippet_start': snippet_start, 'snippet_end': snippet_end,
                    'snippet': original[snippet_start:snippet_end]})
            offset += len(line)
    coverage['distinct_cves_found'] = len(seen)
    coverage['complete'] = not (coverage['source_text_limited'] or coverage['attachments_omitted']
        or coverage['omitted_distinct_cves'] or coverage['omitted_claim_occurrences']
        or coverage['source_visibility_unavailable'])
    return list(claims.values()), coverage


def _timestamp(value):
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError('Invalid NVD timestamp')
    datetime.fromisoformat(value.replace('Z', '+00:00'))
    return value


def _reference(data, cve_id):
    if not isinstance(data, dict) or not isinstance(data.get('vulnerabilities'), list):
        raise ValueError('Invalid NVD response')
    records = data['vulnerabilities']
    if not records and data.get('totalResults') == 0:
        return None
    if len(records) != 1 or data.get('totalResults') != 1:
        raise ValueError('Unexpected NVD result count')
    cve = records[0]['cve']
    if cve.get('id') != cve_id:
        raise ValueError('Mismatched NVD identifier')
    descriptions = cve.get('descriptions')
    if not isinstance(descriptions, list) or not descriptions:
        raise ValueError('Missing CVE descriptions')
    retained = []
    limited = False
    for item in descriptions:
        language, value = item.get('lang'), item.get('value')
        if not isinstance(language, str) or not isinstance(value, str) or not value.strip():
            raise ValueError('Invalid CVE description')
        if len(retained) >= 8:
            limited = True
            continue
        limited |= len(value) > 8000
        retained.append({'language': language[:32], 'text': value[:8000]})
    return {'descriptions': retained, 'description_text_limited': limited,
            'published_at': _timestamp(cve.get('published')),
            'last_modified_at': _timestamp(cve.get('lastModified')),
            'vulnerability_status': str(cve.get('vulnStatus', 'unknown'))[:100]}


class ClaimVerificationClient:
    """Optional NVD client using tenant-scoped SecurityCache, disabled by default."""
    def __init__(self, cache, enabled=False, transport=None, rate_limiter=None):
        self.cache, self.enabled, self.transport = cache, enabled, transport
        self.rate_limiter = rate_limiter if rate_limiter is not None else _RATE_LIMITER

    def check(self, cve_id):
        base = {'cve_id': cve_id, 'source': 'nvd', 'status': 'unknown', 'cache_hit': False}
        if not isinstance(cve_id, str) or len(cve_id) > 32 or not _CVE.fullmatch(cve_id):
            return {**base, 'status': 'invalid_identifier', 'reason': 'Only a literal CVE identifier is accepted.'}
        cve_id = cve_id.upper()
        base.update(cve_id=cve_id, source_url='https://nvd.nist.gov/vuln/detail/' + cve_id,
                    api_url=ENDPOINT + '?cveId=' + cve_id)
        if not self.enabled:
            return {**base, 'status': 'disabled', 'reason': 'CVE reference lookup is not enabled.'}
        key = [VERSION, cve_id]
        cached = self.cache.get(CACHE_NAMESPACE, key)
        if cached:
            return {**cached['value'], 'cache_hit': True, 'expires_at': cached['expires_at']}
        if not self.rate_limiter.acquire():
            return {**base, 'status': 'rate_limited', 'reason': 'CVE lookup rate limit reached; claim remains unverified.'}
        try:
            with httpx.Client(timeout=5, follow_redirects=False, trust_env=False, transport=self.transport) as client:
                response = bounded_response(client, 'GET', ENDPOINT, params={'cveId': cve_id},
                    headers={'Accept': 'application/json'}, max_bytes=MAX_RESPONSE_BYTES, total_seconds=5)
                if response.status_code != 200:
                    return {**base, 'status': 'unavailable', 'reason': f'NVD HTTP {response.status_code}; claim remains unverified.'}
                reference = _reference(response.json(), cve_id)
            now = self.cache.clock()
            result = {**base, 'status': 'found' if reference is not None else 'not_found',
                      'retrieved_at': datetime.fromtimestamp(now, timezone.utc).isoformat(),
                      'expires_at': now + (POSITIVE_TTL if reference is not None else MISSING_TTL)}
            if reference is not None:
                result['reference'] = reference
            else:
                result['reason'] = 'No current NVD entry was returned; absence neither validates nor refutes the email claim.'
            self.cache.put(CACHE_NAMESPACE, key, result, result['expires_at'])
            return result
        except (httpx.HTTPError, ValueError, TypeError, KeyError, AttributeError, OverflowError, RecursionError):
            return {**base, 'status': 'unavailable', 'reason': 'CVE lookup failed or returned invalid evidence; claim remains unverified.'}

    def inspect(self, evidence):
        claims, coverage = extract_cve_claims(evidence)
        results = [{**self.check(item['cve_id']), 'claims': item['claims']} for item in claims]
        coverage['lookup_complete'] = all(item['status'] in ('found', 'not_found') for item in results)
        coverage['complete'] &= coverage['lookup_complete']
        return {'version': VERSION, 'enabled': self.enabled, 'results': results, 'coverage': coverage,
                'scope': 'Current NVD reference descriptions only. Compare the source facts with the preserved email claims; '
                         'a CVE mention, missing entry or lookup failure is not a maliciousness finding. '
                         'Current facts may postdate the email; publication, modification and retrieval dates are retained.',
                'remote_email_destinations_visited': False}
