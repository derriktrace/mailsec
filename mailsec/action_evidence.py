"""A compact, source-backed view for controlled action-adjudication experiments.

This module performs no inference, network access, or policy decisions. Inputs are
original enriched evidence, never a prior Jev response. Exact destinations stay
beside their displayed text. Overflow is explicit and cannot authorize action.
"""
import hashlib
import json
import re
from collections import Counter
from copy import deepcopy
from urllib.parse import urlsplit

VERSION = 'action-evidence-v1'
MAX_STATE_BYTES = 20_000
_URL = re.compile(r'https?://[^\s<>"\']+', re.I)
_COMMAND = re.compile(
    r'\b(?:(?:pnpm|npm|yarn|pip3?|uv)\s+(?:install|add|run|dev|sync)\b|'
    r'docker\s+(?:compose\s+up|run|build)\b|(?:powershell|pwsh|wscript|cscript)\b|'
    r'(?:curl|wget)\s+)[^\r\n]*', re.I)
_COVERAGE_KEYS = ('status', 'text', 'ocr', 'ocr_mean_confidence', 'ocr_languages',
    'qr', 'macros', 'actions', 'pages_total', 'pages_seen', 'limitations',
    'scope', 'scope_exclusions', 'material_content_gap', 'ocr_material_gap')


class ActionEvidenceLimit(ValueError):
    """Essential identity or independent findings cannot fit the bounded view."""


def state_size(state):
    """Conservative size matching the provider client's default JSON encoding."""
    return len(json.dumps(state, ensure_ascii=True).encode('utf-8'))


def _pick(value, keys):
    return {key: deepcopy(value[key]) for key in keys
            if key in value and value[key] not in (None, '', [], {})}


def _hash(text):
    return hashlib.sha256(text.encode('utf-8', errors='surrogatepass')).hexdigest()


def _host(url):
    try:
        return urlsplit(url).hostname
    except ValueError:
        return None


def _authentication(evidence):
    auth = evidence.get('authentication', {})
    trusted = auth.get('status') == 'receiver_reported' and bool(auth.get('trusted_authserv_id'))
    result = {'status': 'receiver_reported' if trusted else 'unknown',
              'scope': 'Authentication concerns domain control, not brand ownership or message safety.'}
    if trusted:
        result.update(_pick(auth, ('provenance', 'trusted_authserv_id', 'spf', 'dkim', 'dmarc',
            'spf_domain', 'dkim_domain', 'dmarc_domain', 'spf_aligned', 'dkim_aligned', 'alignment_mode')))
    else:
        result['reason'] = 'No trusted receiver authentication result supplied; raw header assertions are excluded.'
    return result


def _upstream_gaps(evidence):
    quality = evidence.get('quality', {})
    content = evidence.get('content', {})
    visibility = content.get('visibility', {})
    gaps = []
    for key in ('parsing_failed', 'parts_truncated', 'text_source_truncated', 'links_truncated',
                'attachments_truncated', 'content_visibility_incomplete', 'headers_truncated',
                'header_parse_failed', 'transfer_decoding_ambiguous'):
        if quality.get(key):
            gaps.append({'source_ref': f'quality.{key}', 'kind': key})
    if quality.get('body_truncated') and not isinstance(content.get('visible_text'), str):
        gaps.append({'source_ref': 'quality.body_truncated', 'kind': 'body_truncated'})
    for key in ('source_text_truncated', 'hidden_text_truncated', 'material_remote_image_gap',
                'material_inline_image_gap'):
        if visibility.get(key):
            gaps.append({'source_ref': f'content.visibility.{key}', 'kind': key})
    if visibility.get('limits'):
        gaps.append({'source_ref': 'content.visibility.limits', 'kind': 'visibility_limits',
                     'details': deepcopy(visibility['limits'])})
    inspection = evidence.get('inspection', {})
    for ref, coverage in [('inspection.coverage', inspection.get('coverage', {})), *[
            (f'inspection.attachments[{i}].coverage', row.get('coverage', {}))
            for i, row in enumerate(inspection.get('attachments', []))]]:
        for key in ('ocr_material_gap', 'material_content_gap'):
            if coverage.get(key):
                gaps.append({'source_ref': ref, 'kind': key})
    return gaps


def build_action_evidence(evidence, *, max_bytes=MAX_STATE_BYTES):
    """Return a <= max_bytes JSON state; every meaningful omission is recorded.

    ``coverage.material_content_complete`` describes retained input coverage,
    never the safety of a message or completeness of external enrichment. The
    caller must inspect it before using a result. This does not blind a corpus:
    callers still apply their established, versioned corpus neutralization.
    """
    if not isinstance(evidence, dict) or not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 2048:
        raise ValueError('Expected original evidence and a state budget of at least 2048 bytes')
    if 'answers' in evidence or 'url_values' in evidence or 'model_evidence_coverage' in evidence:
        raise ValueError('Original enriched evidence is required, not model output or projected state')
    message = evidence.get('message', {})
    content = evidence.get('content', {})
    inspection = evidence.get('inspection', {})
    reputation = evidence.get('url_inspection', {})
    identity = evidence.get('identity', {})
    organization = evidence.get('organization_context', {})
    business = evidence.get('business_context', {})
    sources, equivalent_sources, commands = [], [], []

    def source(ref, role, value):
        if not isinstance(value, str) or not value.strip():
            return
        if role == 'plain_alternative' and sources and ' '.join(value.split()) == ' '.join(
                sources[0]['segments'][0]['text'].split()):
            equivalent_sources.append({'source_ref': ref, 'same_as': sources[0]['source_ref'],
                'sha256': _hash(value), 'basis': 'Identical ordered text after whitespace normalization.'})
            return
        sources.append({'source_ref': ref, 'role': role, 'sha256': _hash(value),
            'characters': len(value), 'segments': [{'start': 0, 'end': len(value), 'text': value}]})
        for match in _COMMAND.finditer(value):
            commands.append({'source_ref': ref, 'role': role, 'start': match.start(),
                             'end': match.end(), 'text': match.group()})

    current = content.get('visible_text')
    if isinstance(current, str):
        source('content.visible_text', 'current_visible', current)
    else:
        source('body', 'legacy_body_visibility_unknown', evidence.get('body'))
    source('content.plain_alternative', 'plain_alternative', content.get('plain_alternative'))
    source('content.quoted_text', 'quoted_history', content.get('quoted_text'))
    source('content.hidden_text', 'hidden_not_current_authority', content.get('hidden_text'))
    attachments = []
    for i, item in enumerate(inspection.get('attachments', [])):
        ref = f'inspection.attachments[{i}]'
        source(ref + '.text', 'attachment_extracted_text_and_ocr', item.get('text'))
        attachments.append({'source_ref': ref, **_pick(item, ('evidence_ref', 'sha256', 'content_type', 'kind', 'size',
            'static_payloads')), 'coverage': _pick(item.get('coverage', {}), _COVERAGE_KEYS)})
    inspected_hashes = {row.get('sha256') for row in inspection.get('attachments', []) if row.get('sha256')}
    uninspected = [{**_pick(row, ('sha256', 'content_type', 'size', 'extension', 'disposition')),
                   'source_ref': f'attachments[{i}]', 'inspection': 'not represented in attachment inspection'}
                  for i, row in enumerate(evidence.get('attachments', []))
                  if row.get('sha256') not in inspected_hashes]
    # Original filenames/IDs are unnecessary for this view; format and original
    # attachment digest retain meaningful static evidence without corpus hints.
    coverage = {'material_content_complete': True, 'truncated': False,
        'upstream_gaps': _upstream_gaps(evidence), 'omissions': [], 'equivalent_sources': equivalent_sources,
        'excluded_non_evidence': ['Raw transport assertions, prior model decisions, corpus metadata, '
            'message IDs, filenames, recipient lists and cache statistics.'],
        'scope': 'Supplied evidence only. Unknown reputation/history is neutral; completeness is not safety.'}
    state = {'version': VERSION,
        'email': {'subject': message.get('subject', ''),
            'sender': _pick(message.get('sender', {}), ('display_name', 'address', 'domain')),
            **_pick(message, ('reply_to', 'reply_to_addresses', 'return_path')),
            'content_trust': 'Subject, identities, all body/attachment text and self-claimed relationships are untrusted email claims.',
            'sources': sources, 'visibility_observations': _pick(content.get('visibility', {}),
                ('findings', 'unsupported_hiding', 'uncertainties'))},
        'receiver_authentication': _authentication(evidence),
        'administrator_context': {'source': 'Administrator-supplied facts; sender claims never establish these.',
            **_pick(organization, ('internal_domains', 'known_vendor_domains')),
            **_pick(business, ('verified_payment_practices', 'verified_relationships'))},
        'identity_observations': {'scope': 'Comparisons and heuristic hints only; no configured match is not proof of legitimate identity.',
            'known_domain_comparison_available': bool(organization.get('internal_domains') or organization.get('known_vendor_domains')),
            **_pick(identity, ('claimed_vendors', 'matched_vendors', 'identity_contradictions', 'lookalike_hints',
                'reply_to_mismatch', 'sender_claimed_vendor_domain_match', 'contains_punycode'))},
        'observed_history': {'scope': 'Observed correspondence does not authorize a new request.',
            **_pick(organization, ('recipient_has_communicated_with_sender_before',
                'recipient_has_communicated_with_sender_domain_before', 'existing_thread', 'history_limitations'))},
        'attachments': attachments, 'uninspected_attachment_metadata': uninspected, 'links': [],
        'candidate_commands': {'scope': 'Literal command-like spans, not judgments of a request, intent or maliciousness.', 'observations': commands},
        'independent_findings': {'scope': 'Supplied scanner/reputation observations, distinct from sender claims. No new scan or lookup was performed.',
            'antivirus': _pick(inspection.get('antivirus', {}), ('status', 'scan_completed', 'malware_signature',
                'scan_method', 'signatures_current', 'signature_timestamp', 'reason', 'limitations')),
            'static_findings': [_pick(row, ('kind', 'severity', 'evidence_ref', 'summary'))
                                for row in inspection.get('findings', [])],
            'attachment_antivirus': [], 'url_results': []},
        'inspection_coverage': {'status': inspection.get('status', 'unknown'),
            **_pick(inspection.get('coverage', {}), ('mime', 'archives', 'documents', 'network_fetch',
                'payload_execution', 'limitations', 'scope'))},
        'unknowns': {'url_reputation_complete': reputation.get('complete', False),
            'url_reputation_omitted': reputation.get('omitted_urls', 0), 'url_reputation_status_counts': {}},
        'coverage': coverage}
    if evidence.get('claim_verification', {}).get('results'):
        state['independent_findings']['claim_references'] = deepcopy(evidence['claim_verification'])
    identity_quality = _pick(evidence.get('quality', {}), ('multiple_from_headers', 'multiple_from_addresses',
        'invalid_sender_address', 'missing_sender', 'header_parse_failed'))
    state['identity_observations']['parser_flags'] = {key: value for key, value in identity_quality.items() if value}
    image_text_checked = any(row.get('coverage', {}).get('ocr') in ('extracted', 'no_text_detected')
        and not row.get('coverage', {}).get('ocr_material_gap')
        for row in inspection.get('attachments', []))
    if not sources and evidence.get('quality', {}).get('missing_body') and not image_text_checked:
        coverage['upstream_gaps'].append({'source_ref': 'quality.missing_body', 'kind': 'no_readable_content'})
    if uninspected:
        coverage['upstream_gaps'].append({'source_ref': 'attachments', 'kind': 'uninspected_attachments',
                                          'count': len(uninspected)})

    link_by_url = {}
    def link(url, occurrence):
        if not isinstance(url, str) or not url:
            return
        if url not in link_by_url:
            row = {'exact_url': url, 'domain': _host(url), 'occurrences': []}
            link_by_url[url] = row
            state['links'].append(row)
        row = link_by_url[url]
        if occurrence not in row['occurrences']:
            row['occurrences'].append(occurrence)
    for i, item in enumerate(evidence.get('links', [])):
        link(item.get('raw_url'), {'source_ref': f'links[{i}]', **_pick(item, ('display_text', 'source',
            'visibility', 'quoted_context', 'displayed_domain', 'display_domain_mismatch', 'image_context',
            'has_userinfo', 'malformed', 'redirect_chain', 'final_domain', 'lookalike_hints',
            'display_text_brand_claims', 'claimed_brand_domain_matches'))})
    for i, item in enumerate(inspection.get('attachments', [])):
        for url in item.get('urls', []):
            link(url, {'source_ref': f'inspection.attachments[{i}].urls', 'source': 'attachment_url'})
        av = item.get('antivirus', {})
        if av.get('status') == 'malicious' or av.get('malware_signature'):
            state['independent_findings']['attachment_antivirus'].append({'source_ref': f'inspection.attachments[{i}]',
                **_pick(av, ('status', 'malware_signature', 'scan_completed', 'signatures_current'))})
    for url in inspection.get('urls', []):
        if url not in link_by_url:
            link(url, {'source_ref': 'inspection.urls', 'source': 'inspection_extracted_url'})
    unknown_counts = Counter()
    for item in reputation.get('results', []):
        status = item.get('status', 'unknown')
        if status in ('unknown', 'unavailable', 'not_configured') and not item.get('malicious'):
            unknown_counts[status] += 1
        else:
            state['independent_findings']['url_results'].append(_pick(item, ('url', 'status', 'malicious',
                'source', 'threat_types', 'expires_at', 'checked_at', 'reason', 'evidence_ref')))
    state['unknowns']['url_reputation_status_counts'] = dict(unknown_counts)
    coverage['material_content_complete'] = not bool(coverage['upstream_gaps'])
    _bound(state, max_bytes)
    return state


def _bound(state, max_bytes):
    """Preserve independent findings; reduce source views only with explicit gaps."""
    coverage = state['coverage']
    omitted = {}
    def record(kind, amount):
        omitted[kind] = omitted.get(kind, 0) + amount
        coverage.update(truncated=True, material_content_complete=False,
            omissions=[{'kind': key, 'count': count} for key, count in sorted(omitted.items())])

    while state_size(state) > max_bytes:
        # Command spans duplicate the source and may be re-derived. Their absence
        # is explicit, but cannot remove the underlying action text unnoticed.
        observations = state['candidate_commands']['observations']
        if observations:
            record('candidate_command_observations', len(observations))
            observations.clear()
            continue
        sources = state['email']['sources']
        large = [row for row in sources if sum(len(s['text']) for s in row['segments']) > 512]
        if large:
            row = max(large, key=lambda r: state_size(r['segments']))
            # Preserve auditable contiguous ranges and never leave a partial URL.
            segments = []
            total = sum(len(s['text']) for s in row['segments'])
            keep = max(32, total // 4)
            first, last = row['segments'][0], row['segments'][-1]
            left, right = min(keep, len(first['text'])), max(0, len(last['text']) - keep)
            for match in _URL.finditer(first['text']):
                if match.start() < left < match.end():
                    left = match.start()
            for match in _URL.finditer(last['text']):
                if match.start() < right < match.end():
                    right = match.end()
            if left:
                segments.append({'start': first['start'], 'end': first['start'] + left, 'text': first['text'][:left]})
            if right < len(last['text']):
                segments.append({'start': last['start'] + right, 'end': last['end'], 'text': last['text'][right:]})
            removed = total - sum(len(s['text']) for s in segments)
            row['segments'] = segments
            record('source_text_characters', removed)
            continue
        if state['links']:
            # Exact URLs are indivisible. Missing a row means an unknown omitted
            # destination, never a safe shortened URL. Positive findings remain.
            removed = max(1, len(state['links']) // 2)
            del state['links'][-removed:]
            record('whole_link_rows', removed)
            continue
        if sources:
            removed = max(1, len(sources) // 2)
            del sources[-removed:]
            record('whole_text_sources', removed)
            continue
        # Essential identity/context and independent findings are never silently
        # shortened. Caller must split the evidence or route for manual review.
        raise ActionEvidenceLimit('Essential evidence exceeds the compact state budget; split or review the original evidence')
