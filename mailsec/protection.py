"""Deterministic enforcement gates, independent of Jev's recommendation."""
import time

from .security_cache import digest

# Match the existing 0.6 choice-confidence review gate for four outcomes:
# (0.70 - 0.25) / 0.75 == 0.6. This is not calibrated correctness.
PHISHING_VERDICT_THRESHOLD = .70
POLICY_VERSION = 'protection-v4.3'


def material_evidence_gaps(output, evidence):
    """Identify concrete unread or unresolved content, not generic uncertainty.

    Missing reputation, sender history, authentication, model confidence, and
    an ordinary review recommendation do not by themselves make a clean message
    suspicious. These entries describe a missing decision-relevant observation.
    """
    gaps = []
    def add(kind, reason, ref):
        item = {'kind': kind, 'reason': reason, 'evidence_ref': ref}
        if item not in gaps:
            gaps.append(item)
    quality = evidence.get('quality', {})
    projection = (output or {}).get('evidence_projection', {})
    for key, reason in (
        ('parsing_failed', 'The message could not be parsed, so its requested action is unresolved.'),
        ('body_truncated', 'Part of the message body was not read.'),
        ('parts_truncated', 'Some message parts were omitted before analysis.'),
        ('text_source_truncated', 'Part of a text source exceeded the extraction limit and was not read.'),
        ('content_visibility_incomplete', 'The visible message content could not be reconstructed completely.'),
        ('transfer_decoding_ambiguous', 'Malformed message encoding may have omitted or changed content during decoding.'),
    ):
        if quality.get(key):
            if key == 'body_truncated' and projection.get('material_content_complete') is True:
                # The legacy body preview is capped at 40k characters. Full role
                # sources can still be read completely through bounded sections.
                continue
            add(key, reason, f'quality.{key}')
    content = evidence.get('content', {})
    visibility = content.get('visibility', {})
    if visibility.get('source_text_truncated'):
        add('visible_source_truncated', 'Part of the full text source exceeded the extraction limit.',
            'content.visibility.source_text_truncated')
    if visibility.get('material_remote_image_gap'):
        add('remote_image_content_unread', 'The main content or action is in a remote image that was not read.',
            'content.visibility.material_remote_image_gap')
    if visibility.get('material_inline_image_gap'):
        add('inline_image_content_unread', 'The main content or action is in an embedded data image that was not read.',
            'content.visibility.material_inline_image_gap')
    inspection = evidence.get('inspection', {})
    documents = inspection.get('attachments', [])
    has_document_text = any(isinstance(row.get('text'), str) and row['text'].strip() for row in documents)
    image_text_checked = any(row.get('coverage', {}).get('ocr') in ('extracted', 'no_text_detected')
                             and not row.get('coverage', {}).get('ocr_material_gap') for row in documents)
    if quality.get('missing_body') and not str(evidence.get('body') or '').strip() and not (has_document_text or image_text_checked):
        add('message_content_missing', 'No readable message body or document text was available.', 'quality.missing_body')
    for ref, coverage in [('inspection.coverage', inspection.get('coverage', {})), *[
            (row.get('evidence_ref') or f'inspection.attachments[{index}]', row.get('coverage', {}))
            for index, row in enumerate(documents)]]:
        if coverage.get('ocr_material_gap') and (ref != 'inspection.coverage' or not any(
                row.get('coverage', {}).get('ocr_material_gap') for row in documents)):
            add('image_text_unread', 'A substantive image or document page could not be read completely.', ref)
        if coverage.get('material_content_gap') and (ref != 'inspection.coverage' or not any(
                row.get('coverage', {}).get('material_content_gap') for row in documents)):
            add('document_content_unread', 'Important document or attachment content remains unread.', ref)
    if projection.get('material_content_complete') is False:
        details = projection.get('material_gaps', [])
        before = len(gaps)
        for gap in details:
            if isinstance(gap, dict):
                add(gap.get('kind') or 'model_content_omitted',
                    gap.get('reason') or 'Important evidence was not included in the model analysis.',
                    gap.get('evidence_ref') or 'jev.evidence_projection')
        if len(gaps) == before:
            add('model_content_omitted', 'Important evidence was not included in the model analysis.',
                'jev.evidence_projection')
    for finding in inspection.get('findings', []):
        if finding.get('kind') == 'static_download_execute' and finding.get('severity') == 'critical':
            add('unresolved_execution_payload', 'Static inspection found a generated script with download-and-execute behavior; this needs review.',
                finding.get('evidence_ref') or 'inspection.findings')
    return gaps


def decide(output, evidence, settings, *, clock=time.time):
    answers = (output or {}).get('answers', {})
    verdict = answers.get('verdict', {})
    proposed = answers.get('recommended_security_action', {}).get('choice')
    inspection = evidence.get('inspection', {})
    reputation = evidence.get('url_inspection', {})
    refs, reasons = [], []
    hard = False
    url_expiries = []
    av_confirmed = False
    stale_reputation = False
    av = inspection.get('antivirus', {})
    if av.get('status') == 'malicious':
        hard = True
        av_confirmed = True
        refs.append('inspection.antivirus')
        reasons.append('An antivirus signature identified malicious content.')
    for result in reputation.get('results', []):
        if result.get('malicious') is True and result.get('status') == 'malicious':
            expiry = result.get('expires_at', 0)
            if not isinstance(expiry, (int, float)) or expiry <= clock():
                stale_reputation = True
                continue
            url_expiries.append(expiry)
            hard = True
            refs.append(result['evidence_ref'])
            reasons.append('A current reputation or explicit administrator block identifies a malicious URL.')
    phishing = verdict.get('probabilities', {}).get('phishing', 0)
    deceptive = answers.get('deceptive_identity', {}).get('noul', 0)
    sensitive = answers.get('requests_sensitive_action', {}).get('noul', 0)
    anomaly = answers.get('business_context_anomaly', {}).get('noul', 0)
    identity_context = (max(deceptive, anomaly) >= settings.corroboration_threshold
                        and sensitive >= settings.corroboration_threshold)
    # Phishing need not impersonate a brand: direct credential or payment fraud can
    # have strong action/intent evidence. Same-model agreement is not independent proof.
    action_probability = answers.get('recommended_security_action', {}).get('probabilities', {}).get(proposed, 0)
    sensitive_fraud = sensitive >= .95 and action_probability >= .98
    model_evidence_partial = bool((output or {}).get('evidence_projection', {}).get('truncated'))
    unresolved_model_partial = (model_evidence_partial and
        (output or {}).get('evidence_projection', {}).get('material_content_complete') is not True)
    material_gaps = material_evidence_gaps(output, evidence)
    section_review_only = bool((output or {}).get('aggregation', {}).get('review_only'))
    action_review = (output or {}).get('action_review', {})
    action_findings = action_review.get('findings', [])
    # The optional second pass has a smaller context window. When its only
    # limitation is that compact view and the full primary sections were read,
    # its missing answer cannot override the primary clean/spam judgment.
    secondary_budget_only = (action_review.get('status') == 'incomplete'
        and action_review.get('coverage', {}).get('truncated') is True
        and not action_review.get('coverage', {}).get('upstream_gaps')
        and (output or {}).get('evidence_projection', {}).get('material_content_complete') is True)
    action_review_incomplete = (bool(action_review)
        and action_review.get('status') != 'complete' and not secondary_budget_only)
    local_estimates = ((output or {}).get('score_semantics') == 'uncalibrated_model_estimates'
                       or getattr(settings, 'decision_provider', 'jev') != 'jev')
    semantic = (not local_estimates and verdict.get('choice') == 'phishing' and phishing >= settings.quarantine_threshold
                and proposed in ('quarantine', 'block') and (identity_context or sensitive_fraud)
                and not stale_reputation and not model_evidence_partial and not material_gaps and not section_review_only
                and not action_findings and not action_review_incomplete)
    semantic_basis = ('identity_or_established_context' if identity_context else 'sensitive_fraud_agreement') if semantic else None
    if local_estimates:
        reasons.append('Local model scores are uncalibrated estimates. Model-only automatic quarantine is disabled; confirmed scanner detections retain their own policy.')
    if semantic:
        refs += ['jev.verdict.phishing','jev.requests_sensitive_action','jev.recommended_security_action']
        if identity_context:
            refs.append('jev.deceptive_identity' if deceptive >= settings.corroboration_threshold else 'jev.business_context_anomaly')
            reasons.append('High-confidence phishing accompanies a sensitive request and deception or established business-context contradiction.')
        else:
            reasons.append('High phishing, sensitive-action, and protective-action scores agree on credential or financial social engineering; these are same-model scores, not independent proof.')
    # An unconfigured reputation service, a nonmaterial CSS limitation, and a
    # sectioned message are not instructions to label every routine email for
    # review. Material extraction loss and operational failures remain visible.
    operational_scan_failure = (inspection.get('status') not in ('complete', 'partial')
        or inspection.get('antivirus', {}).get('status') in ('error', 'stale', 'unavailable')
        or (bool(getattr(settings, 'web_risk_api_key', None)) and any(
            row.get('status') in ('unavailable', 'budget_exhausted')
            for row in reputation.get('results', []))))
    incomplete = bool(material_gaps) or unresolved_model_partial or stale_reputation or operational_scan_failure
    review_findings = [f for f in inspection.get('findings', [])
                       if f.get('severity') in ('review', 'medium', 'high', 'critical')
                       and (f.get('kind') != 'document_incomplete' or material_gaps)]
    confidence_low = bool(verdict) and verdict.get('confidence',0) < .6
    action = 'none'
    effective = verdict.get('choice', 'suspicious')
    verdict_requires_review = (effective == 'phishing' and not hard
                               and phishing < PHISHING_VERDICT_THRESHOLD)
    verdict_review_basis = 'uncertain_phishing_score' if verdict_requires_review else None
    if verdict_requires_review:
        effective = 'suspicious'
        reasons.append('The model favored phishing, but its score requires an uncertain verdict and human review.')
        refs.append('jev.verdict')
    ambiguous_spam = effective == 'spam' and evidence.get('quality', {}).get('transfer_decoding_ambiguous')
    if (effective == 'clean' or ambiguous_spam) and material_gaps and not hard:
        effective = 'suspicious'
        verdict_requires_review = True
        verdict_review_basis = 'material_evidence_gap'
        reasons.append(f"The readable content received a {verdict.get('choice')} model judgment, but important evidence remains unread or unresolved; review is required.")
        reasons.extend(gap['reason'] for gap in material_gaps)
        refs.extend(gap['evidence_ref'] for gap in material_gaps)
    if effective in ('clean', 'spam') and action_findings and not hard:
        effective = 'suspicious'
        verdict_requires_review = True
        verdict_review_basis = 'action_authority_gap'
        reasons.append('A separate action-and-authority assessment found a consequential request requiring review; the original model verdict is retained.')
        reasons.extend(finding['reason'] for finding in action_findings)
        refs.append('jev.action_review')
    # A review recommendation without a concrete basis is checked by the
    # separate action/authority pass for clean and spam. Its complete absence
    # of findings is not proof of safety, but neither is it a Gmail label cue.
    model_review_needs_flag = (proposed == 'review' and
        (effective in ('phishing', 'suspicious') or bool(material_gaps) or bool(review_findings)
         or not action_review or action_review_incomplete))
    # A low concentration among benign choices is not itself a concrete Gmail
    # review reason once the separate action/authority check completed without a
    # finding. Preserve the score in the run for an analyst, and keep flagging
    # when that extra check was absent or incomplete.
    confidence_needs_flag = (confidence_low and
                             (effective not in ('clean', 'spam') or not action_review or action_review_incomplete))
    if hard or semantic:
        action = 'quarantine'
        if hard:
            effective = 'phishing'
    elif (not output or effective in ('phishing','suspicious') or model_review_needs_flag
          or incomplete or review_findings or confidence_needs_flag
          or action_review_incomplete):
        action = 'flag'
        if incomplete:
            reasons.append('Some inspection evidence is unavailable, incomplete, or expired; review is required.')
            refs.append('inspection.coverage')
        if model_evidence_partial:
            reasons.append('The model received partial evidence because of its context limit; semantic-only automatic quarantine is disabled.')
            refs.append('jev.evidence_projection')
        if section_review_only and verdict.get('choice') in ('phishing', 'suspicious'):
            reasons.append('A section judgment indicates risk; section scores are not calibrated for automatic quarantine of the whole message.')
            refs.append('jev.aggregation')
        if not output:
            reasons.append('Jev analysis failed; the message is not treated as clean.')
        if review_findings:
            refs.extend(f.get('evidence_ref') or f.get('id') for f in review_findings)
            reasons.append('Local document or payload indicators require review.')
        if verdict.get('choice') in ('phishing','suspicious'):
            reasons.append('The model indicates risk below the automatic quarantine gate.')
            refs.append('jev.verdict')
        if model_review_needs_flag:
            reasons.append('Jev recommends human review of unresolved risk.')
            refs.append('jev.recommended_security_action')
        if confidence_needs_flag:
            reasons.append('The verdict confidence is below the review threshold.')
        if action_review_incomplete:
            reasons.append('The additional action-and-authority review was incomplete; no safety conclusion is inferred from the missing stage.')
            refs.append('jev.action_review')
    elif verdict.get('choice') == 'spam':
        reasons.append('Ordinary spam verdict; this pilot does not automatically move marketing mail.')
    else:
        reasons.append('No quarantine or review rule was triggered by available evidence.')
    execution = action
    if settings.enforcement_mode == 'passive':
        execution = 'none'
    elif settings.enforcement_mode == 'flag_only' and action == 'quarantine':
        execution = 'flag'
    # Jev may use reputation evidence: do not assume its semantic answers are independent
    # of that evidence. Bound queued semantic actions and reanalyze when it expires.
    action_expires_at = None
    if not av_confirmed:
        if semantic:
            action_expires_at = min([clock()+300, *url_expiries])
        elif hard:
            action_expires_at = max(url_expiries)
    return {'action_expires_at':action_expires_at, 'action_context_sha256':digest(settings.organization),
            'version':POLICY_VERSION, 'verdict':effective, 'model_verdict':verdict.get('choice'),
            'recommended_action':action, 'eligible_action':execution, 'executed_action':'none',
            'mode':settings.enforcement_mode, 'reasons':list(dict.fromkeys(reasons)),
            'evidence_refs':list(dict.fromkeys(r for r in refs if r)), 'hard_detection':hard,
            'verdict_requires_review':verdict_requires_review, 'phishing_verdict_threshold':PHISHING_VERDICT_THRESHOLD,
            'verdict_review_basis':verdict_review_basis, 'material_evidence_incomplete':bool(material_gaps),
            'action_review_only':bool(action_findings), 'action_review_incomplete':action_review_incomplete,
            'action_review_findings':action_findings,
            'material_evidence_gaps':material_gaps, 'section_review_only':section_review_only,
            'secondary_review_budget_only':secondary_budget_only,
            'semantic_quarantine_gate':semantic, 'semantic_basis':semantic_basis, 'inspection_incomplete':incomplete,
            'model_recommendation':proposed, 'quarantine_semantics':'Gmail label plus removal from Inbox; message remains accessible in All Mail.',
            'policy_fingerprint':digest({'version':POLICY_VERSION,'threshold':settings.quarantine_threshold,
                                        'phishing_verdict_threshold':PHISHING_VERDICT_THRESHOLD,
                                        'corroboration':settings.corroboration_threshold,'mode':settings.enforcement_mode})}
