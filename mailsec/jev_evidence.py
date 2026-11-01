"""Bound the model view while retaining full evidence for local policy and audit.

Byte budgeting is deliberately conservative: high-entropy tracking URLs can use
far more tokens than ordinary prose. Never silently treat a partial model view
as a complete scan, or let it authorize a semantic-only quarantine.
"""
import json
import re
from copy import deepcopy

VERSION = 'jev-evidence-v5'
# Keep the whole serialized request below the documented 32k-token
# state-plus-longest-question limit even at one token per byte, with margin.
MAX_REQUEST_BYTES = 30_000


def request_size(state, questions, model):
    return len(json.dumps({'model': model, 'state': state, 'questions': questions},
                          ensure_ascii=True).encode())


def _decision_evidence(evidence):
    """Remove audit duplication, never message content or adverse findings.

    Missing scans are represented once, not as dozens of identical warnings.
    Full inputs remain in the append-only run evidence. No sender allowlisting
    or remote URL fetching happens here.
    """
    state = deepcopy(evidence)
    for key in ('schema_version', 'parser_version', 'enrichment_version', 'content_features'):
        state.pop(key, None)
    message = state.get('message', {})
    for key in ('id', 'raw_sha256', 'provider_message_id', 'provider_thread_id',
                'internet_message_id', 'received_at_source'):
        message.pop(key, None)
    auth = state.get('authentication', {})
    auth.pop('transport_headers', None)
    # Imported Authentication-Results are sender-controlled assertions, not
    # verification. Retain the raw assertions in local audit evidence only.
    if auth.pop('unverified_header_assertions', None):
        auth['unverified_assertions_scope'] = ('Unverified authentication header claims are retained in the audit only; '
                                              'they do not establish SPF, DKIM, DMARC, or brand authority.')
    if auth.get('status') == 'receiver_reported':
        auth.pop('receiver_results', None)  # selected per-method results remain
    identity = state.get('identity', {})
    # Earlier model classifications must not become evidence for the next one.
    identity.pop('previous_verdicts', None)
    for key in list(identity):
        if identity[key] is None or identity[key] == [] or identity[key] == {}:
            identity.pop(key)
    for link in state.get('links', []):
        if link.get('normalized_url') == link.get('raw_url'):
            link.pop('normalized_url', None)
        for key in ('reputation', 'scan_status'):
            if link.get(key) in ('unknown', 'not_scanned'):
                link.pop(key, None)
        for key in ('lookalike_hints', 'display_text_brand_claims', 'claimed_brand_domain_matches', 'redirect_chain'):
            if not link.get(key):
                link.pop(key, None)
        for key in ('displayed_domain', 'display_domain_mismatch', 'has_userinfo',
                    'is_shortener', 'is_ip_literal', 'contains_punycode', 'malformed',
                    'final_domain', 'affirmatively_malicious'):
            if not link.get(key):
                link.pop(key, None)
        link.pop('root_domain', None)  # actual host and exact URL remain
        link.pop('scheme', None)  # exact URL includes its scheme
    inspection = state.get('inspection', {})
    for key in ('stats', 'raw_sha256', 'parser_version'):
        inspection.pop(key, None)
    # URLs already represented by complete links need no duplicate scanner list.
    represented = {link.get('raw_url') for link in state.get('links', [])}
    if 'urls' in inspection:
        inspection['urls'] = [url for url in inspection['urls'] if url not in represented]
    reputation = state.get('url_inspection', {})
    groups = {}
    sources = set()
    for result in reputation.get('results', []):
        # Audit/cache identifiers add no destination evidence. Retain status,
        # destination, threat types, expiration and every affirmative finding.
        result.pop('cache_hit', None)
        if result.get('source'):
            sources.add(result['source'])
            if not result.get('malicious'):
                result.pop('source')
        if not result.get('malicious'):
            result.pop('evidence_ref', None)
        reason = result.get('reason')
        if reason:
            groups.setdefault(result.get('status', 'unknown'), set()).add(reason)
            result.pop('reason', None)
    # Missing reputation is neutral and identical for every unassessed URL.
    # Destinations already retained in links need no second per-URL unknown row.
    unassessed = {}
    retained = []
    for result in reputation.get('results', []):
        if (result.get('url') in represented and not result.get('malicious')
                and result.get('status') in ('unknown', 'unavailable', 'not_configured')
                and not result.get('threat_types')):
            status = result.get('status')
            unassessed[status] = unassessed.get(status, 0) + 1
        else:
            retained.append(result)
    if unassessed:
        reputation['results'] = retained
        reputation['unassessed_link_counts'] = unassessed
        reputation['default_link_reputation'] = 'Unknown unless an explicit result states otherwise; not a clean scan.'
    if groups:
        reputation['status_reasons'] = {key: sorted(values) for key, values in groups.items()}
    if sources:
        reputation['sources'] = sorted(sources)
    return state


def prepare_evidence(evidence, questions, model):
    original_bytes = request_size(evidence, questions, model)
    metadata = {'version': VERSION, 'projected': False, 'truncated': False,
                'original_request_bytes': original_bytes, 'request_bytes': original_bytes}
    state = _decision_evidence(evidence)
    if state == evidence and original_bytes <= MAX_REQUEST_BYTES:
        return evidence, metadata

    metadata['projected'] = True
    # Receiver verification and parsed untrusted assertions remain. Raw routing
    # lines/signatures are transport audit material, not additional verification.
    state.get('authentication', {}).pop('transport_headers', None)
    state.pop('content_features', None)
    state.get('inspection', {}).pop('stats', None)
    for link in state.get('links', []):
        if link.get('normalized_url') == link.get('raw_url'):
            link.pop('normalized_url', None)

    # Repeated complete URLs occur in MIME, extracted documents, reputation and
    # body text. Intern exact values; do not strip query/fragment or invent a final
    # destination. References are explicit and every referenced value is included.
    values = {}
    reverse = {}

    def intern(value):
        if isinstance(value, dict):
            return {k: intern(v) for k, v in value.items()}
        if isinstance(value, list):
            return [intern(v) for v in value]
        if isinstance(value, str) and value.lower().startswith(('http://', 'https://')) and not any(c.isspace() for c in value):
            if value not in reverse:
                key = f'url_{len(values)+1}'
                reverse[value] = key
                values[key] = value
            return {'url_ref': reverse[value]}
        return value

    state = intern(state)
    state['confirmed_url_threats'] = [deepcopy(row) for row in state.get('url_inspection', {}).get('results', [])
                                    if row.get('malicious') is True and row.get('status') == 'malicious']
    # Body remains text. Match whole URL tokens, never a prefix of a different
    # destination that may have fallen beyond an upstream extraction limit.
    if isinstance(state.get('body'), str):
        def body_url(match):
            token = match.group()
            url = token.rstrip('.,;!?)')
            if url not in reverse:
                return token
            return f'[url_ref:{reverse[url]}]' + token[len(url):]
        state['body'] = re.sub(r'\bhttps?://[^\s<>"\']+', body_url, state['body'], flags=re.I)
    state['url_values'] = values
    coverage = {'version': VERSION, 'truncated': False, 'omitted_fields': {},
                'note': 'url_ref values resolve through url_values to exact complete destinations. '
                        'Raw transport audit lines and duplicate fields are excluded. '
                        'Any omitted value or unresolved url_ref is unknown, never evidence of safety. '
                        'All original evidence is retained locally.'}
    state['model_evidence_coverage'] = coverage

    def size():
        return request_size(state, questions, model)

    def omitted(path, count):
        coverage['truncated'] = metadata['truncated'] = True
        # Aggregate by field family so attacker-controlled counts cannot make the
        # explanation of omitted data larger than the data itself.
        family = path.split('[')[0].split('.')[0]
        coverage['omitted_fields'][family] = coverage['omitted_fields'].get(family, 0) + count

    # Reduce the largest optional detail first, retaining both ends of long prose
    # and whole destinations. Every real loss is visible to the model and policy.
    while size() > MAX_REQUEST_BYTES:
        candidates = []

        def visit(value, path='', protected=False):
            if isinstance(value, dict):
                for key, item in value.items():
                    child = f'{path}.{key}' if path else key
                    if child == 'model_evidence_coverage':
                        continue
                    protect = protected or child in ('inspection.antivirus', 'source_integrity', 'confirmed_url_threats', 'inspection.findings')
                    if isinstance(item, str) and len(item) > 256 and not protect:
                        candidates.append((len(json.dumps(item)), value, key, child, item))
                    elif isinstance(item, (dict, list)):
                        visit(item, child, protect)
            elif isinstance(value, list):
                for index, item in enumerate(value):
                    child = f'{path}[{index}]'
                    if isinstance(item, str) and len(item) > 256 and not protected:
                        candidates.append((len(json.dumps(item)), value, index, child, item))
                    elif isinstance(item, (dict, list)):
                        visit(item, child, protected)

        visit(state)
        if candidates:
            # Preserve the readable request ahead of audit/detail strings. If it
            # truly cannot fit, shorten it once to the remaining useful budget,
            # rather than repeatedly reducing it to a few dozen characters.
            optional = [item for item in candidates if item[3] != 'body']
            candidates = optional or [item for item in candidates if len(item[4]) > 6000]
        if candidates:
            _, parent, key, path, value = max(candidates, key=lambda item: item[0])
            if path.startswith('url_values.'):
                # A partial URL can look like an unrelated safe destination.
                del parent[key]  # unresolved reference explicitly means unknown in coverage
                omitted(path, len(value))
            else:
                retain = (min(5600, max(512, len(value) - (size() - MAX_REQUEST_BYTES) - 512))
                          if path == 'body' else min(256, max(32, len(value) // 4)))
                parent[key] = value[:retain//2] + '\n[Middle omitted: model context limit]\n' + value[-retain//2:]
                omitted(path, len(value) - retain)
            continue
        # Very many individually short entries can also fill context. Keep the
        # complete policy evidence outside this projection; count all removed rows.
        arrays = []
        def lists(value, path=''):
            if isinstance(value, dict):
                for key, item in value.items():
                    child = f'{path}.{key}' if path else key
                    if child in ('model_evidence_coverage', 'inspection.antivirus', 'source_integrity', 'confirmed_url_threats', 'inspection.findings'):
                        continue
                    if isinstance(item, list) and item:
                        arrays.append((len(json.dumps(item)), value, key, child, item))
                    elif isinstance(item, dict):
                        lists(item, child)
        lists(state)
        if arrays:
            _, parent, key, path, rows = max(arrays, key=lambda item: item[0])
            removed = max(1, len(rows)//2)
            parent[key] = rows[:-removed]
            omitted(path, removed)
            continue
        if state['url_values']:
            # References whose dictionary entry is absent are explicitly unknown.
            # Threat evidence remains in confirmed_url_threats and full local data.
            state['url_values'].pop(next(reversed(state['url_values'])))
            omitted('url_values', 1)
            continue
        if len(state.get('body', '')) > 256:
            value = state['body']
            retain = max(128, len(value) // 2)
            state['body'] = value[:retain//2] + '\n[Middle omitted: model context limit]\n' + value[-retain//2:]
            omitted('body', len(value) - retain)
            continue
        # An adversarially large set of map fields (or administrator configuration)
        # cannot safely fit. Do not send an unbounded request or fabricate a verdict.
        raise ValueError('Core email evidence exceeds the bounded Jev context')

    metadata['request_bytes'] = size()
    metadata['omitted_fields'] = coverage['omitted_fields']
    return state, metadata
