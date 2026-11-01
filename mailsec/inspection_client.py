"""Client for the private scanner; unavailability is explicit, never a clean scan."""
import math
import time

import httpx

from .outbound import bounded_response


def unavailable(reason):
    return {'status':'unavailable','findings':[],'attachments':[],'urls':[],
            'antivirus':{'status':'unavailable'}, 'coverage':{'limitations':[reason]}, 'stats':{}}


class InspectionClient:
    def __init__(self, settings, transport=None, sleeper=time.sleep, clock=time.monotonic):
        self.settings, self.transport = settings, transport
        self.sleep, self.clock = sleeper, clock

    def inspect(self, raw):
        if not self.settings.inspection_url:
            return unavailable('The attachment inspection service is not configured.')
        try:
            with httpx.Client(timeout=self.settings.inspection_timeout_seconds, follow_redirects=False,
                              trust_env=False, transport=self.transport) as client:
                # A bounded scanner has one slot. Backpressure is not a scan result.
                # Retry only explicit busy/unavailable responses; never assume clean
                # on exhaustion. Bound both time and attempts, including bad headers.
                deadline = self.clock() + 30
                for attempt in range(31):
                    delay = None
                    r = bounded_response(client, 'POST', self.settings.inspection_url.rstrip('/')+'/inspect',
                        content=raw, headers={'Content-Type':'application/octet-stream'}, max_bytes=512*1024,
                        total_seconds=self.settings.inspection_timeout_seconds)
                    if r.status_code in (429, 503) and attempt < 30:
                        try:
                            delay = float(r.headers.get('Retry-After', '1'))
                            if not math.isfinite(delay):
                                delay = 1
                        except ValueError:
                            delay = 1
                        delay = min(5, max(1, delay))
                        if self.clock() + delay > deadline:
                            return unavailable(f'Inspection service HTTP {r.status_code}; busy retry budget exhausted.')
                    elif r.status_code != 200:
                        return unavailable(f'Inspection service HTTP {r.status_code}.')
                    if delay is None:
                        break
                    self.sleep(delay)
                result=r.json()
            if result.get('status') not in ('complete','partial','unavailable'):
                raise ValueError('Invalid inspection status')
            if not isinstance(result.get('antivirus'),dict) or not isinstance(result.get('findings'),list):
                raise ValueError('Invalid inspection response')
            if not isinstance(result.get('urls'),list) or len(result['urls'])>500:
                raise ValueError('Invalid extracted URLs')
            return result
        except (httpx.HTTPError, ValueError, TypeError, AttributeError, RecursionError):
            return unavailable('Inspection service failed or returned invalid evidence.')


def scan_retry_reason(inspection):
    """Operational failures must not be accepted as completed scans.

    Content-specific heuristic alerts remain review evidence. Confirmed malware
    is actionable even if other objects could not be scanned.
    """
    av = inspection.get('antivirus', {})
    scans = [av, av.get('raw_message', {})] + [a.get('antivirus', {}) for a in inspection.get('attachments', [])]
    if any(scan.get('status') == 'malicious' for scan in scans):
        return None
    if inspection.get('status') == 'unavailable':
        return 'Inspection service unavailable or busy; automatic retry scheduled.'
    if av.get('status') not in ('clean', 'malicious', 'error', 'stale', 'unavailable'):
        return 'Antivirus returned incomplete status; automatic retry scheduled.'
    for scan in scans:
        status = scan.get('status')
        if status in ('stale', 'unavailable') or (status == 'error' and scan.get('detection_type') != 'heuristic_review'):
            return 'Antivirus could not complete with current signatures; automatic retry scheduled.'
    return None
