# Changelog

## 0.4.0-alpha.8 — missing-Gmail-message action handling

- Recognize a 404 when checking the exact Gmail message for a label action as
  a message that no longer exists in the connected mailbox. Cancel the action
  with a clear reason, retain the stored analysis, and do not waste repeated
  provider calls or leave a generic action failure. Pending quarantine notices
  for such a message are skipped before sending.
- Add regression coverage for the Gmail adapter's sanitized 404 distinction and
  durable action cancellation.

## 0.4.0-alpha.7 — targeted Review-label policy refinement (unpublished)

- When a clean or spam decision has complete evidence and the conditional
  action-and-authority review finishes without a finding, low model confidence
  alone no longer adds a Gmail Review label. The score remains visible in the
  analysis. Missing substantive content, incomplete checks, and concrete risk
  findings still trigger review.
- Keep the historical classification replay and its observed coverage limits
  in private operations evidence; it does not establish measured accuracy.

## 0.4.0-alpha.6 — classification and Review label correction (unpublished)

- Refine the default Jev questions around coherent first-party account tasks,
  legitimate claim administrators, hidden/quoted warnings, and unrelated senders
  demanding payment, rewards, or credentials. Keep the existing conditional
  action-and-authority assessment for initial clean/spam judgments.
- Preserve exact action URLs when a long wrapped anchor repeats newsletter text.
  Correct adjacent-sibling CSS visibility handling and distinguish nonmaterial
  HTML rendering uncertainty from unread document content.
- Treat an unconfigured URL reputation service as neutral instead of applying
  Review to every message. Keep operational scanner failures and substantive
  evidence gaps visible and reviewable.
- Reconcile automatic Gmail Review labels after a later completed clean/spam
  analysis no longer calls for them. Never clear a manual correction or touch
  unrelated labels, Inbox placement, Spam, or Trash through this cleanup.
- Compare the revised wording privately with existing risk cases and a separate
  sampled set before activation. This is regression review, not a measured
  accuracy or safety guarantee.

## 0.4.0-alpha.5 — public alpha release preparation (unpublished)

- Correct the disposable CI project name so the single-container build and
  cleanup use an installation name accepted by the installer. Add offline
  consistency checks for the selected project, lookup, and cleanup.
- Refresh the security build and repeat candidate verification against its own
  source and image. Keep earlier immutable candidates and reports as historical
  evidence; prior passing checks do not certify new release bytes.
- Prepare an optional digest-pinned prebuilt-image installation path alongside
  the source-build path. No public registry or repository is assumed, and no
  publication happens from setup or the read-only CI workflow.

## 0.4.0-alpha.4 — explicit analysis data-sharing consent (unpublished)

- Make Jev's transmission of selected email evidence to third-party TypeSafe
  prominent, including mailbox/recipient identities, message content, complete
  links, extracted attachment/OCR/QR text, context, and custom question wording.
- Require explicit owner acceptance for the selected provider/destination and
  disclosure version. Existing installations and environment-supplied keys do
  not grant consent automatically. Acceptance allows only synthetic setup probes;
  queued analyses and comparisons wait for an explicit tested/saved provider and
  masking configuration, checked with a current per-request authorization stamp.
- Add optional recipient masking, off by default, for known mailbox/recipient
  address occurrences in the outbound evidence/questions. Warn that masking can
  reduce accuracy and does not guarantee anonymity; originals/local security
  evidence are retained and third-party sharing acceptance remains required.
- Apply the consent boundary to setup probes, comparisons, and each provider
  request; revocation prevents later requests without pretending sent data can
  be recalled. Retain an audit record and never silently fall back to a provider.
- Document exact outbound evidence, local/remote endpoint distinctions, historical
  and future processing, the separate Google OAuth grant, and the absence of
  upstream retention/training guarantees.

## 0.4.0-alpha.3 — configurable detection questions (unpublished)

- Add an authenticated Detection questions editor for all three decision bundles.
  Instructions and criteria are editable; question IDs, types, and choices remain
  fixed so response validation and deterministic policy retain their contracts.
- Save immutable drafts and version history, compare draft and active questions
  against bounded pasted text or captured message evidence, activate a tested
  revision, and restore shipped defaults without erasing history or rebuilding.
- Copy and paste the complete question bundles as plain text JSON, without file
  import/export. Validate pasted wording before loading it as unsaved edits;
  saving, provider testing, and activation remain separate explicit steps.
- Preserve original analyses and Gmail labels during tests. Capture the chosen
  revision per analysis and bind activation to a completed test with the current
  provider and active baseline.
- Document question tuning, switching hosted/local models, first-run onboarding,
  data flows, recovery, and the manual public alpha release checklist.
- Run the isolated Chromium console suite in CI with Node 22 and add a read-only
  local package/version/documentation readiness checker. CI does not publish.

## 0.4.0-alpha.2 — security hardening

- Confine native parsers to a private job directory, denying access to persistent
  caches, credentials, peer processes, network sockets, and sibling signals.
- Require enabled Linux Landlock ABI6 and seccomp; unsupported hosts report
  unavailable inspection and do not start processing mail with reduced isolation.
- Bound initial MIME allocation, header decoding, provider response sizes, and
  parsing time. Disable inherited proxies and pin approved local-model DNS results.
- Preserve malformed body/attachment transfer-encoding gaps through model review
  and policy enforcement; truncated decoding cannot support a clean disposition.
- Reject ambiguous console request headers and add HTTPS transport policy.
- Fix the Gmail adapter's strict verdict-label allowlist and test real-client
  label/move/undo behavior with synthetic HTTP responses.
- Expand adversarial, browser, dependency, and source-security checks. CI retains
  security reports and the software inventory and blocks high/critical image
  findings even when the package feed reports no available fix.

## 0.4.0-alpha.1 — open-source preparation

- One-container self-host package with supervised service processes, bundled
  PostgreSQL and static scanning, one-command bootstrap, private secrets,
  conservative defaults, backup operations, and deployment documentation.
- Guided setup for decision models, Google OAuth, history selection, and protection.
- Ollama and OpenAI-compatible structured-output adapters, encrypted model settings,
  synthetic connection tests, and explicit local-score quarantine restrictions.
- Personal Gmail and Workspace authorization, read-only/manage scope selection,
  encrypted wizard configuration, disconnect controls, and stale-connection guards.
- Persistent analyst corrections with original model history, explicit Gmail verdict
  labels and optional Inbox removal, conflict-aware undo, and honest read-only controls.
- Worker startup waits for usable antivirus signatures and the inspection service
  before claiming mail, avoiding scan retries caused solely by scanner warm-up.
- Bounded streamed request bodies, exact-origin validation, safe validation errors,
  and refusal of unauthenticated exposed listeners.
- Inherited Linux static-parser restrictions denying networking and cross-process
  inspection, with failed restriction setup stopping document parsing.
- Public source exporter, license/attribution, CI, vulnerability and secret checks.

This alpha does not implement URL reputation activation, multi-user family roles,
MSP isolation, Outlook/IMAP connectors, inline blocking, or attachment execution.
