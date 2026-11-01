"""Bounded, auditable section evaluation when a complete message cannot fit.

Never average away an adverse section. Section confidence remains a local model
judgment, not calibrated whole-message confidence. Multi-section containment is
review-only until separately validated. All full source evidence stays on the run.
"""
import hashlib
import json
import re
from copy import deepcopy

from .jev import JevError
from .jev_evidence import MAX_REQUEST_BYTES, prepare_evidence, request_size

VERSION = 'jev-sections-v3.1'
MAX_SECTIONS = 12
SECTION_BYTES = 7000
OVERLAP_CHARS = 160
_URL = re.compile(r'\bhttps?://[^\s<>"\']+', re.I)
_BLANK_FILLER = re.compile(r'[\u2800\u3164\u115f\u1160\uffa0\u200b\u2060\ufeff\s]{8,}')


def _normalize_padding(text):
    """Remove only long blank-like runs outside complete URL tokens.

    Unicode Hangul/Braille filler runs were making a short request exceed dozens
    of sections. Keep actual letters, punctuation, URLs, and original local
    evidence intact; audit offsets refer explicitly to this normalized view.
    """
    parts, previous, replacements = [], 0, 0
    def normalize(value):
        nonlocal replacements
        def substitute(match):
            nonlocal replacements
            replacements += 1
            return '\n\n' if '\n' in match.group() else ' '
        return _BLANK_FILLER.sub(substitute, value)
    for match in _URL.finditer(text):
        parts.extend((normalize(text[previous:match.start()]), match.group()))
        previous = match.end()
    parts.append(normalize(text[previous:]))
    return ''.join(parts), replacements


def _visible_source(evidence):
    content = evidence.get('content', {})
    # An intentionally empty visible body must not fall back to quoted/hidden
    # or a conflicting plain alternative concatenated into the legacy body.
    return content['visible_text'] if isinstance(content.get('visible_text'), str) else evidence.get('body', '')


def _formatting_equivalent(visible, plain):
    if not isinstance(visible, str) or not isinstance(plain, str) or not visible.strip() or not plain.strip():
        return False
    # Remove only our own presentation wrapper around extracted image alt text;
    # keep every word, URL, punctuation mark and ordering in both alternatives.
    visible = re.sub(r'\[Image description: ([^\]]*)\]', r'\1', visible)
    return ' '.join(visible.split()) == ' '.join(plain.split())


def _interleaved_view(text):
    """An additional diagnostic view, never replacement of multilingual source."""
    if len(text) < 500:
        return None
    runs = re.findall(r'[A-Za-z][\u3040-\u30ff\u3400-\u9fff]{1,40}(?=[A-Za-z])', text)
    if len(runs) < 80 or len(runs) / max(1, len(re.findall('[A-Za-z]', text))) < .4:
        return None
    candidate = re.sub(r'[\u3040-\u30ff\u3400-\u9fff]', '', text)
    return candidate if len(re.findall(r'\b[A-Za-z]{4,}\b', candidate)) >= 30 else None


def _sources(evidence):
    content = evidence.get('content', {})
    current = _visible_source(evidence)
    sources = []
    seen = set()
    def add(name, role, value):
        if not isinstance(value, str) or not value.strip():
            return
        text, replacements = _normalize_padding(value)
        canonical = (role, ' '.join(text.split()))
        if canonical in seen:
            return
        seen.add(canonical)
        sources.append({'source': name, 'role': role, 'text': text,
                        'original_characters': len(value),
                        'original_sha256': hashlib.sha256(value.encode('utf-8', errors='surrogatepass')).hexdigest(),
                        'normalized_padding_runs': replacements})
    add('body', 'current visible message', current)
    plain = content.get('plain_alternative')
    if _formatting_equivalent(current, plain):
        sources[0]['equivalent_sources'] = [{'source': 'content.plain_alternative',
            'method': 'Same ordered text after whitespace and parser image-alt wrapper normalization',
            'original_characters': len(plain), 'original_sha256': hashlib.sha256(plain.encode('utf-8', errors='surrogatepass')).hexdigest()}]
    else:
        add('content.plain_alternative', 'plain MIME alternative; compare with visible HTML', plain)
    for i, a in enumerate(evidence.get('inspection', {}).get('attachments', [])):
        add(f'inspection.attachments[{i}].text', f'attachment text: {a.get("filename", "unnamed")}', a.get('text'))
    # Keep deobfuscation beside original; no assumption that Japanese itself is hostile.
    for source in list(sources):
        candidate = _interleaved_view(source['text'])
        if candidate:
            add(source['source'] + '.diagnostic_view',
                'Derived view removing interleaved CJK noise; verify against preserved original. Not translated text.', candidate)
    add('content.quoted_text', 'quoted history, not necessarily current requested action', content.get('quoted_text'))
    add('content.hidden_text', 'CSS-hidden content; not visible authority for the current message', content.get('hidden_text'))
    return sources


def _pieces(text, budget=SECTION_BYTES):
    start = 0
    while start < len(text):
        low, high = start + 1, min(len(text), start + budget)
        while low < high:
            middle = (low + high + 1) // 2
            if len(json.dumps(text[start:middle], ensure_ascii=True)) <= budget:
                low = middle
            else:
                high = middle - 1
        end = low
        if end < len(text):
            boundary = max(text.rfind('\n', start + (end-start)//2, end),
                           text.rfind(' ', start + (end-start)//2, end))
            if boundary > start:
                end = boundary + 1
        yield start, end, text[start:end]
        if end == len(text):
            break
        start = max(start + 1, end - min(OVERLAP_CHARS, (end-start)//5))


def _compact_duplicates(evidence):
    value = deepcopy(evidence)
    content = value.get('content', {})
    if _formatting_equivalent(content.get('visible_text'), content.get('plain_alternative')):
        value['body'] = content['visible_text']
        content.pop('plain_alternative')
        content['plain_alternative_relation'] = 'Formatting-equivalent ordered text; original MIME alternative remains in local evidence.'
        findings = content.get('visibility', {}).get('findings', [])
        if 'html_plain_alternatives_differ' in findings:
            findings.remove('html_plain_alternatives_differ')
    # Exact image URLs and anchor associations already appear in parser links;
    # retain only unrepresented image rows, without repeating whole URL objects.
    represented_images = {link.get('raw_url') for link in value.get('links', []) if link.get('source') == 'html_img_src'}
    represented_images.update(image.get('src') for link in value.get('links', []) for image in link.get('image_context', []))
    visibility = content.get('visibility', {})
    if 'images' in visibility:
        retained = [image for image in visibility['images'] if image.get('src') not in represented_images]
        if retained:
            visibility['images'] = retained
        else:
            visibility.pop('images')
    # Full body source is already preserved locally and is consumed by _sources.
    # Don't charge the request budget twice for identical parser representations.
    for key in ('visible_text', 'plain_alternative'):
        if content.get(key) and content[key].strip() == value.get('body', '').strip():
            content.pop(key)
    if isinstance(value.get('body'), str):
        value['body'], _ = _normalize_padding(value['body'])
    for key in ('visible_text', 'plain_alternative', 'quoted_text', 'hidden_text'):
        if isinstance(content.get(key), str):
            content[key], _ = _normalize_padding(content[key])
    for item in value.get('inspection', {}).get('attachments', []):
        if isinstance(item.get('text'), str):
            item['text'], _ = _normalize_padding(item['text'])
    return value


def _gap(kind, reason, ref):
    return {'kind': kind, 'reason': reason, 'evidence_ref': ref}


def _upstream_gaps(evidence):
    quality = evidence.get('quality', {})
    visibility = evidence.get('content', {}).get('visibility', {})
    gaps = []
    if (quality.get('text_source_truncated') or quality.get('parts_truncated') or
            visibility.get('source_text_truncated') or 'html_output_limit' in visibility.get('limits', [])):
        gaps.append(_gap('source_content_limit', 'The retained source itself is incomplete; sectioning cannot recover omitted content.', 'content.visibility'))
    if quality.get('body_truncated') and not isinstance(evidence.get('content', {}).get('visible_text'), str):
        gaps.append(_gap('legacy_body_limit', 'Only an already truncated legacy body is available.', 'quality.body_truncated'))
    return gaps


def _whole_link_pieces(rows, budget=SECTION_BYTES):
    """Pack complete rows; never split a query, fragment or displayed destination."""
    batch, start = [], 0
    for index, row in enumerate(rows):
        proposed = batch + [row]
        if batch and len(json.dumps(json.dumps(proposed, ensure_ascii=False), ensure_ascii=True)) > budget:
            yield start, index, json.dumps(batch, ensure_ascii=False)
            batch, start = [], index
        batch.append(row)
    if batch:
        yield start, len(rows), json.dumps(batch, ensure_ascii=False)


def _section_base(evidence, actionable):
    base = deepcopy(evidence)
    base['body'] = ''
    content = base.get('content', {})
    for key in ('visible_text', 'hidden_text', 'quoted_text', 'plain_alternative'):
        content.pop(key, None)
    # Image destinations and anchor associations remain in their link rows.
    content.get('visibility', {}).pop('images', None)
    for item in base.get('inspection', {}).get('attachments', []):
        item.pop('text', None)
    # Parser defaults/hash identifiers duplicate inspector results; meaningful
    # attachment type/filename/behavior and all inspector findings stay present.
    for item in base.get('attachments', []):
        for key in ('sha256', 'content_id', 'scan_status', 'scan_findings'):
            item.pop(key, None)
    visible, _ = _normalize_padding(_visible_source(evidence))
    context_limit = 4000 if len(visible) <= 4000 else 1000
    base['current_message_context'] = {'text': visible[:context_limit], 'is_excerpt': len(visible) > context_limit,
        'note': 'Current visible context only. Missing sections are evaluated separately; do not infer safety from this excerpt.'}
    # Exact links are evaluated in whole rows separately. Repeating eight long
    # tracking tokens in every request would crowd out the current section.
    base['links'] = []
    base['action_link_context'] = {'count': len(actionable),
        'note': 'Summaries only; complete destinations and any additional links are evaluated in action_links sections. A host summary is not a resolved final destination.',
        'examples': [{k: (_link_display_excerpt(link[k]) if k == 'display_text' else link[k])
                      for k in ('display_text', 'source', 'visibility', 'domain',
            'displayed_domain', 'display_domain_mismatch', 'affirmatively_malicious') if k in link}
            for link in actionable[:8]]}
    base.get('inspection', {}).pop('urls', None)
    base['url_inspection'] = {**base.get('url_inspection', {}),
        'results': [r for r in base.get('url_inspection', {}).get('results', []) if r.get('malicious')]}
    return base


def _link_display_excerpt(value, limit=400):
    """Keep a bounded anchor summary; full visible/plain text has its own section.

    One email can wrap its entire newsletter in a single anchor. Repeating that
    prose beside the exact URL must not cause the destination to be omitted.
    """
    if not isinstance(value, str) or len(value) <= limit:
        return value
    half = limit // 2
    return value[:half] + '\n[Link display excerpt; full text in message section]\n' + value[-half:]


def prepare_evaluations(evidence, questions, model):
    compact = _compact_duplicates(evidence)
    state, meta = prepare_evidence(compact, questions, model)
    sources = _sources(evidence)
    source_audit = [{k: v for k, v in source.items() if k != 'text'} | {'characters': len(source['text'])}
                    for source in sources]
    interleaved = any(s['source'].endswith('.diagnostic_view') for s in sources)
    omitted = meta.get('omitted_fields', {})
    link_context_lost = any(k in omitted for k in ('links', 'url_values')) and any(
        x.get('source') not in ('html_img_src', 'html_link_href') and
        x.get('visibility') not in ('hidden', 'noncontent') for x in evidence.get('links', []))
    if not interleaved and not link_context_lost and not any(k in omitted for k in ('body', 'content', 'inspection')):
        upstream = _upstream_gaps(evidence)
        meta = {**meta, 'section_version': VERSION, 'material_content_complete': not upstream,
                'material_gaps': upstream, 'section_count': 1, 'sources': source_audit}
        return [(state, meta)], meta

    links = evidence.get('links', [])
    actionable = [v for v in links if v.get('source') not in ('html_img_src', 'html_link_href')
                  and v.get('visibility') not in ('hidden', 'noncontent')]
    # Inspection can extract a document/QR URL absent from the top-level parser.
    represented = {v.get('raw_url') for v in links}
    actionable += [{'raw_url': url, 'source': 'inspection_url', 'visibility': 'attachment_or_document'}
                   for url in evidence.get('inspection', {}).get('urls', []) if url not in represented]
    base = _section_base(evidence, actionable)
    # Exact actionable destinations are separately sectioned when too many fit.
    link_rows = [{k: (_link_display_excerpt(v.get(k)) if k == 'display_text' else v.get(k))
                  for k in ('raw_url', 'display_text', 'source', 'visibility',
                  'quoted_context', 'domain', 'displayed_domain', 'display_domain_mismatch', 'is_shortener',
                  'normalized_url', 'final_domain', 'redirect_chain', 'reputation', 'affirmatively_malicious',
                  'image_context', 'has_userinfo', 'malformed') if k in v and v[k] not in (None, [], False, '')}
                 for v in actionable]
    for row in link_rows:
        if 'normalized_url' in row and row['normalized_url'] == row.get('raw_url'):
            row.pop('normalized_url')
    if link_rows:
        sources.append({'source': 'action_links', 'role': 'Exact displayed and actual action-link evidence; not a separate message',
                        'text': json.dumps(link_rows, ensure_ascii=False), 'rows': link_rows})
    # One pass per source before additional pieces prevents huge hidden filler
    # from starving all attachment/URL evidence. Source offsets make coverage auditable.
    pieces = [(s, list(_whole_link_pieces(s['rows'])) if 'rows' in s else list(_pieces(s['text']))) for s in sources]
    ordered = []
    for ordinal in range(max((len(parts) for _, parts in pieces), default=0)):
        for source, parts in pieces:
            if ordinal < len(parts):
                ordered.append((source, *parts[ordinal]))
    requests, gaps = [], _upstream_gaps(evidence)
    position = 0
    while position < len(ordered) and len(requests) < MAX_SECTIONS:
        source, start, end, text = ordered[position]
        position += 1
        section = deepcopy(base)
        section['body'] = text
        section['analysis_scope'] = {'source': source['source'], 'role': source['role'],
            'start': start, 'end': end, 'source_characters': len(source['text']),
            'section_index': len(requests), 'section_review': True,
            'offset_basis': 'rows' if 'rows' in source else 'normalized_source_characters',
            'normalized_padding_runs': source.get('normalized_padding_runs', 0),
            'note': 'Judge this evidence section in its source role. Other sections are evaluated separately.'}
        projected, part = prepare_evidence(section, questions, model)
        # URL interning can change representation without losing evidence.
        if part.get('omitted_fields', {}).get('body'):
            if 'rows' not in source and len(text) > 512:
                # Retry smaller contiguous pieces before calling the provider.
                # Text offset coverage stays auditable, without silently retaining
                # only a section's beginning and end.
                middle = len(text) // 2
                overlap = min(OVERLAP_CHARS, middle // 5)
                ordered[position:position] = [(source, start, start + middle + overlap, text[:middle + overlap]),
                                             (source, start + middle - overlap, end, text[middle - overlap:])]
                continue
            if 'rows' in source and end - start > 1:
                middle = start + (end - start) // 2
                ordered[position:position] = [(source, a, b, json.dumps(source['rows'][a:b], ensure_ascii=False))
                                             for a, b in ((start, middle), (middle, end))]
                continue
            gaps.append(_gap('section_text_lost', 'A minimal section or whole destination exceeded the bounded context.', source['source']))
        if any(k in part.get('omitted_fields', {}) for k in ('links', 'url_values')):
            gaps.append(_gap('section_link_context', 'Some shared destination context was omitted.', source['source']))
        if request_size(projected, questions, model) > MAX_REQUEST_BYTES:
            raise JevError('Evidence projection exceeds the bounded provider request limit')
        part.update(section_version=VERSION, source=source['source'], start=start, end=end)
        requests.append((projected, part))
    if position < len(ordered):
        gaps.append(_gap('section_limit', f'At least {len(requests) + len(ordered) - position} sections are needed; the bounded limit is {MAX_SECTIONS}.',
                         'jev.evidence_projection'))
    if not requests:
        return [(state, meta)], {**meta, 'material_content_complete': False,
            'material_gaps': [_gap('missing_semantic_content', 'No readable substantive source remained.', 'body')]}
    meta = {'version': meta['version'], 'section_version': VERSION, 'projected': True,
            'truncated': bool(gaps), 'material_content_complete': not gaps, 'material_gaps': gaps,
            'section_count': len(requests), 'required_sections': len(requests) + len(ordered) - position,
            'original_request_bytes': request_size(evidence, questions, model),
            'request_bytes': max(p['request_bytes'] for _, p in requests),
            'sources': source_audit + ([{'source': 'action_links', 'role': sources[-1]['role'],
                        'characters': len(sources[-1]['text']), 'rows': len(link_rows)}] if link_rows else [])}
    return requests, meta


def combine_evaluations(results, projection):
    """Select an adverse section, retain every response; never fabricate probabilities."""
    priority = {'clean': 0, 'spam': 1, 'suspicious': 2, 'phishing': 3}
    selected = max(range(len(results)), key=lambda i: (
        priority[results[i]['answers']['verdict']['choice']],
        results[i]['answers']['verdict'].get('confidence', 0)))
    output = deepcopy(results[selected])
    output['evidence_projection'] = deepcopy(projection)
    if len(results) > 1:
        output['usage'] = {k: sum(r.get('usage', {}).get(k, 0) for r in results)
                           for k in ('input_tokens', 'output_tokens')}
        output['aggregation'] = {'method': 'max_severity_selected_section', 'review_only': True,
            'count': len(results), 'selected_section': selected,
            'confidence_scope': 'Selected section only; not calibrated whole-message confidence.'}
        output['chunk_evaluations'] = results
    return output
