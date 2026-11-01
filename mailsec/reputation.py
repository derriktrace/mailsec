"""Bounded Web Risk lookups. Never visits the supplied URL or strips its query."""
import ipaddress
import re
import socket
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit

import httpx

from .outbound import bounded_response
from .security_cache import digest

ENDPOINT = 'https://webrisk.googleapis.com/v1/uris:search'
THREATS = ('MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE')


def canonical_url(value):
    """Normalize only scheme/host/default port. Preserve path, query AND fragment."""
    if not isinstance(value, str) or len(value) > 8192 or any(ord(c) < 33 for c in value):
        raise ValueError('Invalid URL')
    p = urlsplit(value)
    if p.scheme.lower() not in ('http', 'https') or not p.hostname or p.username is not None or p.password is not None:
        raise ValueError('Unsupported URL')
    host = p.hostname.rstrip('.').encode('idna').decode('ascii').lower()
    if '%' in host:
        raise ValueError('Scoped destination is not submitted externally')
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        addr = None
    if addr is not None:
        if (not addr.is_global or addr.is_reserved or isinstance(addr, ipaddress.IPv6Address)
                and (addr.sixtofour is not None or addr.teredo is not None)):
            raise ValueError('Private or transitional destination is not submitted externally')
        host = '[' + addr.compressed + ']' if addr.version == 6 else str(addr)
    else:
        # Browsers accept legacy IPv4 spellings that ip_address deliberately
        # rejects, such as127.1, octal and hexadecimal. Do not submit ambiguous
        # numeric destinations or consult DNS for arbitrary email link names.
        try:
            socket.inet_aton(host)
        except OSError:
            pass
        else:
            raise ValueError('Ambiguous numeric destination is not submitted externally')
        if (not host or len(host) > 253 or host == 'localhost'
                or host.endswith(('.localhost', '.local', '.internal', '.localdomain', '.home.arpa', '.lan'))
                or '.' not in host):
            raise ValueError('Internal destination') from None
        if (re.fullmatch(r'(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+))*', host)
                or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label)
                       for label in host.split('.'))):
            raise ValueError('Invalid or ambiguous destination')
    port = p.port
    if port and not (p.scheme.lower() == 'https' and port == 443 or p.scheme.lower() == 'http' and port == 80):
        host += ':' + str(port)
    return urlunsplit((p.scheme.lower(), host, p.path or '/', p.query, p.fragment))


class ReputationClient:
    def __init__(self, settings, cache, transport=None):
        self.settings, self.cache, self.transport = settings, cache, transport

    def check(self, value):
        ref = 'url:' + digest(value)
        base = {'evidence_ref':ref, 'source':'google_web_risk', 'status':'unknown', 'malicious':False, 'cache_hit':False}
        try:
            url = canonical_url(value)
        except (ValueError, UnicodeError):
            return {**base, 'reason':'Unsupported, invalid, credential-bearing, or private URL; not submitted.'}
        base['url'] = url
        # Administrator-managed exact URLs; no fuzzy/domain-only inheritance.
        blocked = self.settings.organization.get('blocked_urls', [])
        if url in blocked:
            return {**base, 'source':'local_policy', 'status':'malicious', 'malicious':True, 'threat_types':['ADMIN_BLOCK'], 'expires_at':self.cache.clock()+60}
        key = digest({'url':url, 'threats':THREATS, 'version':'webrisk-v1'})
        cached = self.cache.get('url_reputation', key)
        if cached:
            return {**cached['value'], 'cache_hit':True, 'expires_at':cached['expires_at']}
        if not self.settings.web_risk_api_key:
            return {**base, 'reason':'Web Risk credential is not configured.'}
        if not self.cache.reserve_lookup(self.settings.url_lookup_monthly_limit):
            return {**base, 'status':'budget_exhausted', 'reason':'Monthly URL lookup limit reached; reputation remains unknown.'}
        try:
            with httpx.Client(timeout=5, follow_redirects=False, transport=self.transport, trust_env=False) as client:
                params = [('uri', url)] + [('threatTypes', t) for t in THREATS]
                # API key stays in a header, never in a URL, evidence, or error message.
                r = bounded_response(client, 'GET', ENDPOINT, params=params,
                    headers={'X-Goog-Api-Key':self.settings.web_risk_api_key}, max_bytes=65536, total_seconds=5)
                if r.status_code != 200:
                    return {**base, 'status':'unavailable', 'reason':f'Web Risk HTTP {r.status_code}.'}
                data = r.json()
            if not isinstance(data, dict):
                raise ValueError('Invalid response')
            if not data:
                # Absence on a threat list does not establish safety. Short negative cache.
                result = {**base, 'status':'not_listed', 'checked_at':datetime.now(timezone.utc).isoformat(), 'reason':'No current match on the requested threat lists; not proof of safety.'}
                expiry = self.cache.clock() + 300
            else:
                threat = data['threat']
                kinds = threat['threatTypes']
                if not isinstance(kinds,list) or not kinds or any(t not in THREATS for t in kinds):
                    raise ValueError('Invalid threat list')
                expiry = datetime.fromisoformat(threat['expireTime'].replace('Z','+00:00')).timestamp()
                if expiry <= self.cache.clock():
                    raise ValueError('Expired provider result')
                result = {**base, 'status':'malicious', 'malicious':True, 'threat_types':kinds, 'checked_at':datetime.now(timezone.utc).isoformat()}
            result['expires_at'] = expiry
            self.cache.put('url_reputation', key, result, expiry)
            return result
        except (httpx.HTTPError, ValueError, TypeError, KeyError, OverflowError, RecursionError):
            return {**base, 'status':'unavailable', 'reason':'Reputation lookup failed or returned invalid evidence.'}

    def inspect(self, urls):
        unique = list(dict.fromkeys(u for u in urls if isinstance(u,str)))
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(self.check, unique[:self.settings.max_urls_per_message]))
        if self.settings.web_risk_api_key and results:
            failed = [r for r in results if r['status'] in ('unavailable', 'budget_exhausted')]
            checked = [r for r in results if r['status'] in ('not_listed', 'malicious')]
            if failed or checked:
                self.cache.put('provider_health', 'web_risk',
                    {'status':'unavailable' if failed else 'ready',
                     'reason':failed[0].get('reason') if failed else None}, self.cache.clock() + 86400)
        omitted = max(0,len(unique)-len(results))
        return {'version':'webrisk-v1', 'results':results, 'omitted_urls':omitted,
                'complete':omitted == 0 and all(r['status'] in ('not_listed','malicious') for r in results),
                'remote_pages_visited':False}
