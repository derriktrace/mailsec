# Architecture and security boundaries

Mailsec is a post-delivery Gmail monitoring application with a web console,
durable jobs, static inspection, structured model assessments, and a separate
mailbox-action policy. The public alpha is one administrative installation. It
does not provide independent family helper roles, MSP tenant isolation, or a
mail gateway that intercepts messages before delivery.

## One container, multiple processes

The self-host command starts one container. Its supervisor manages the following
processes; no separate database, scanner, or worker container is required:

| Process | Responsibility | Access boundary |
| --- | --- | --- |
| API | Console, authenticated setup, review, imports, operator controls | Application credentials, database, loopback inspector, external OAuth/model endpoints |
| Worker | Gmail sync, durable analyses, eligible mailbox actions | Application credentials, database, loopback inspector, Gmail, selected model |
| PostgreSQL | Originals, evidence, jobs, analysis/action history, encrypted credentials | Separate database user and private data directory; authenticated loopback connections |
| Inspector | Bounded static document, image/OCR, QR, archive inspection | Separate user and private inspection directory; no application credential files |
| ClamAV | Antivirus scanning | Scanner user, accepted loopback requests, read-only signatures and private temporary files; outbound connection initiation denied |
| FreshClam | Signature updates | Separate updater user owns signature data and has outbound update access; does not parse submitted mail |

Only the API port is published, bound to host loopback by default. The database,
inspector, and scanner listen inside the container. Application, database,
inspection, and antivirus data have separate ownership. Persistent data lives in
one named volume; the model server and its weights are optional external services.

A small root supervisor initializes owned directories, starts children under their
assigned users, handles termination, and retries the signature updater. A required-service exit stops
the container so the runtime restart policy can recover it. It does not parse
mail or handle console HTTP requests. The container retains the limited capabilities
needed for those tasks; it is not an entirely rootless process tree. A read-only
root filesystem, temporary filesystems, no-new-privileges, and bounded container
resources reduce accidental exposure. Rootless Podman can further limit the
container's host privileges.

**The processes share one container network namespace, filesystem view, resource
budget, and host kernel.** Before reading mail, the static parser installs a Linux
seccomp filter that denies socket operations, `io_uring`, and cross-process memory
inspection. Mandatory Landlock ABI6 restricts it and its OCR/PDF descendants to
read-only public runtime resources and one private job directory. It cannot read
credentials, `/proc`, the persistent inspection cache, or another job, and cannot
signal its HTTP parent or sibling jobs. Failure to install either policy stops
parsing. The inspector HTTP parent owns its HTTP and antivirus connections.
ClamAV has a separate inherited policy: it can serve accepted loopback requests,
read signatures and use its own scratch directory, but cannot initiate outbound
connections, alter signatures, read application state, or signal the updater.
FreshClam uses a different UID and remains able to download signature updates.
Unix permissions protect application secrets from scanner users, and PostgreSQL requires authentication, but these are not
independent container or VM boundaries. The root supervisor and host administrator
can access the persistent state. This packaging is intended for one trusted
operator, not hostile tenants or untrusted extensions. Do not mount the container
engine socket or unrelated host directories into it.

PostgreSQL retains the application's existing transactional queue and action ledger.
Its data belongs on reliable local storage. Backups use PostgreSQL's consistent
dump facility; copying live database files is not a substitute. The bounded static
inspection cache is expendable and is not the source of truth for messages.

## From Gmail to an assessment

1. **Consent and acquisition.** Each allowed mailbox authorizes Google OAuth.
   Personal Gmail and Workspace use the same per-account connector. Workspace
   service-account delegation remains an advanced configuration option. The default
   polls every 30 seconds, with bounded historical pages and resumable checkpoints.
2. **Durable original.** Gmail raw MIME, provider message/thread IDs, mailbox, received
   time, and a content hash are retained. Repeated provider IDs deduplicate. An
   import must be durably committed before its synchronization checkpoint advances.
3. **Parse and inspect.** Bounded MIME parsing extracts identity headers, current
   visible text, plain alternatives, quoted material, actual link targets, and
   attachment metadata. The inspection service scans the original bytes with
   ClamAV and performs supported static extraction and OCR/QR work.
4. **Enrich evidence.** The application derives authentication/identity relationships,
   locally observed sender history, administrator-supplied context, scan findings,
   and available external reference facts. Evidence records its source and limitations.
5. **Assess.** The selected decision provider receives bounded evidence and the
   versioned questions. Oversized content can be evaluated in auditable sections.
   Exact submitted evidence and model output are retained with the run.
6. **Apply policy.** Deterministic application code chooses whether review or
   quarantine is eligible. The model's action recommendation is not an instruction
   to execute a mailbox change.
7. **Record action.** Authorized Gmail changes go through a durable action ledger,
   with current eligibility rechecked before writes. The dashboard distinguishes
   suggested, pending, applied, failed, cancelled, and uncertain outcomes.

An owner's reviewed verdict is a separate persistent override of the displayed
category, not a rewritten model result. Lists and counts use the effective verdict,
while original runs and scan failures remain available. Overrides never enter
subsequent model evidence. Optional manual Gmail labels have their own durable
intent, before-state snapshot, per-message lease, write-permission recheck, and
confirmed outcome. A newer intent supersedes an older pending/retry label action;
undo refuses observed ordering or label-state conflicts. Manual category labeling
clears Review but requires a separate explicit operation to release Quarantine.

Historical import includes incoming archived/spam/trash mail while excluding Sent
and Drafts. The fixed initial cutoff and completed Gmail history cursor are
different pieces of state. Incremental history follows new incoming mail after
backfill. If Gmail expires a history cursor, recovery lists the configured historical
selection and records that limitation; it cannot recover permanently deleted mail.
[Google's synchronization documentation](https://developers.google.com/workspace/gmail/api/guides/sync).

## Authentication evidence and untrusted content

SPF, DKIM, and DMARC evidence is **receiver-reported**. For messages obtained directly
through the Gmail connector, the parser/enricher selects authentication evidence
within the trusted receiving-header boundary and configured authentication service
identity. It distinguishes aligned domains from unrelated passing signatures.
Arbitrary uploaded `.eml` headers do not acquire Gmail provenance simply because
they contain `Authentication-Results: mx.google.com`.

Mailsec does not independently reconstruct historical SMTP delivery, rerun SPF,
cryptographically verify historical DKIM signatures against present DNS, or verify
ARC chains. Authentication establishes control of an authenticated domain, not
ownership of a claimed brand or safety of user-authored content hosted there.

Body text, links, attachments, sender claims, logos, and instructions embedded in
mail are untrusted evidence. They cannot change questions, select model endpoints,
provide credentials, or become asserted scanner results. Analyst feedback and
existing classifications are stored separately from the inference evidence.
Observed sender history is context, not a whitelist or proof of an approved payment
workflow. Evaluation corpora are deliberately separated from live mailbox history.

## Inspection coverage

ClamAV and static inspection address different questions. A clean signature scan
does not prove a document or email is safe. The inspector supports bounded PDF,
Office, HTML, ZIP/TAR/Gzip, image/OCR, and QR work, with explicit findings and coverage
information. Unsupported or encrypted content, extraction limits, timeouts, missing
material images, and incomplete text remain visible limitations.

The application does not execute attachments, detonate malware in a sandbox,
browse email destinations, fetch remote email images, resolve every redirect, or
provide click-time link protection. Local extraction can reveal a URL embedded in a
document or QR code without visiting it. URL reputation / Google Web Risk is
optional and intentionally unconfigured in the public release setup.

## Questions and provider differences

The primary assessment uses nine questions in `mailsec/questions.json`:

| Question | Meaning |
| --- | --- |
| `verdict` | Clean, spam, suspicious, or phishing from supplied evidence |
| `deceptive_identity` | Affirmative contradiction of the sender's claimed identity |
| `requests_sensitive_action` | Actual request exposing secrets, sensitive data, money, or control |
| `hostile_destination_or_payload` | Supplied affirmative malicious destination/payload evidence |
| `business_context_anomaly` | Contradiction of established context or workflow |
| `recommended_security_action` | Model recommendation for delivery, junk, review, quarantine, or block |
| `callback_fraud` | Deceptive phone-based transaction or support pretext |
| `platform_content_abuse` | Deceptive user-authored content delivered through a legitimate platform |
| `execution_or_wallet_fraud` | Deception involving code execution, wallet access, or a deposit |

When enabled and the primary aggregate verdict is clean or spam, the additional
review asks six action questions: software execution, wallet control, payment,
transaction callback, secrets/login, and claimed authority. A second stage asks
about the authority relationship and current-request risk. These stages are enabled
in the self-host Compose configuration. They are conditional, so every email does
not necessarily receive all seventeen questions. Multiple content sections can
also produce more than one primary request.

The authority stage receives validated action estimates with explicit provenance.
It does not receive an answer key or prior verdict as truth. Its findings are
review-only. Agreement among questions from one model is not independent
corroboration.

Jev provides typed judgments and probabilities through its API. Local Ollama and
compatible providers generate the required JSON; their numbers are explicitly
treated as uncalibrated model estimates. Both paths validate responses. Local
scores never authorize semantic-only automatic quarantine. Independently confirmed
scanner detections retain their separate policy. No model score is a measured
accuracy rate, and the release makes no 99% detection claim.

## Question revisions and comparison tests

The copy/paste interface exposes only the three question bundles as plain text
JSON, including any unsaved editor text; it does not include model credentials,
mail evidence, revision identities, or history. A bounded authenticated validation
route checks pasted bundles without provider calls or database persistence. The
browser loads validated wording as unsaved edits; saving, testing, and activation
remain separate operations. There is no question file-import path.

The three shipped JSON bundles are the trusted baseline. The administrative editor
stores immutable draft revisions, an active-revision pointer, and comparison-test
records in PostgreSQL. Only instructions and criteria can change; identifiers,
question types, and allowed answer keys remain fixed because deterministic policy
and response validation depend on them. Revisions are installation-wide, for this
single owner's workspace; they are not per-sender exceptions or a tenant boundary.

A scan captures one coherent question revision for its whole primary/action/authority
assessment. Its exact questions and revision identity remain in the analysis history.
The question content and provider are included in cache identity. Activating a draft
therefore affects future analyses without silently reusing another revision's cached
answer. Running jobs and historical runs are not rewritten.

A comparison evaluates a saved draft and the active baseline against the same bounded
pasted text or a copy of an existing analyzed message's captured evidence. It does
not replay the ingestion/inspection pipeline, visit links, fetch remote images,
modify mailbox state, apply policy, or change the original assessment. Existing
classifications, analyst corrections, and prior model answers are excluded from
message-derived test evidence. Test answers and errors are retained separately.
The comparison exercises all three question bundles; ordinary production action
review remains conditional, so test-call counts differ from a normal email scan.

Activation requires a completed comparison for the exact saved draft and current
provider configuration, plus a check that the active baseline has not changed.
Restoring shipped defaults is an explicit trusted-baseline operation that appends
and activates a revision while preserving all drafts, tests, and history. Comparison
tests and editing require the same administrative token and origin protections as
other console changes. Text, request size, execution time, and concurrency are
bounded. Email content cannot select or edit a revision.

See [the question editing guide](detection-questions.md) for the operator workflow
and the limits of comparing model answers on hand-picked messages.

## Failure handling, caching, and actions

- Missing first-run model configuration leaves queued mail intact. No placeholder
  clean decision is produced.
- Configured scanner outages or stale/unavailable scanning services defer analysis
  into durable retries with backoff and operator attention. Partial extraction or
  heuristic findings are not confused with a transient scanner outage.
- Invalid model responses, refusals, incomplete generation, exhausted retries, or
  failed stages remain explicit errors/incomplete reviews. A failed stage does not
  prove the absence of a malicious request. Model failures may require operator retry.
- Job leases protect against stale workers committing a result. Original messages
  and earlier analyses are retained when a message is replayed.
- Cached assessments include security evidence, questions, provider, actual endpoint,
  model, versions, and policy context. Sender/body resemblance is not permission to
  reuse a clean verdict. Incomplete evidence is not cached as a complete assessment.
- Gmail label additions/removals are idempotent and can be reconciled after a lost
  response. Quota failures back off. Consent, policy, and connection generation are
  rechecked before further requests/writes.
- If Gmail reports that an imported message no longer exists when an action reads
  its current labels, the action is cancelled with that explicit reason instead of
  retrying as an ambiguous failure. The original and analysis remain in Mailsec.
- Notification sends are not blindly retried after an ambiguous outcome, because
  Gmail does not supply an application idempotency key for a send. Uncertain sends
  require reconciliation; polling can pause to prevent notification loops.

Protection defaults to passive with notifications off. Flagging applies a review
label; quarantine applies a quarantine label and removes Inbox. Release restores
Inbox only when Mailsec removed it. Sent/Draft mail is excluded from automatic
changes. Read-only consent blocks writes independently of the selected policy.
Quarantined mail remains accessible in All Mail.

## Data leaving the host

| Destination | Data or purpose |
| --- | --- |
| Google OAuth/Gmail | Authorization, authorized mailbox retrieval, permitted label changes, optional notification sends |
| TypeSafe, when Jev is selected and sharing accepted | Mailbox/recipient and sender identities, selected subject/date/body (including quoted/hidden text), complete URLs with query/fragment, attachment metadata/extracted/OCR/QR text and scan/authentication findings, administrator/history context, and custom questions |
| Configured local/compatible endpoint, after acceptance | The same decision evidence; the administrator determines whether this endpoint is local or remote |
| Antivirus update servers | Signature updates; scanning is performed locally |
| NVD, when claim verification is enabled | Bounded literal CVE identifiers for reference facts; not whole messages |
| Optional URL reputation provider | Original eligible complete URLs, including query/fragment identifiers, if an operator separately configures that adapter; decision-model recipient masking does not apply; unconfigured in this release |

The model evidence is **not anonymized**. Main assessment requests retain the
mailbox and To/Cc/Bcc-derived recipient addresses when present; extra action views
omit some fields but do not undo that main-request disclosure. Raw message/provider
IDs and transport audit headers are removed. Raw `.eml` bytes and binary attachments
are not uploaded; selected extracted/OCR/QR content can be. Google OAuth secrets,
console/database credentials are not message-state inputs. Provider API keys are
sent as authorization to their respective configured provider.

An optional, default-off recipient-masking step replaces known mailbox/recipient
address occurrences in the outbound state and question text while preserving the
original local evidence. It applies to known occurrences in text and URLs too,
records its scope in the sent view, and can reduce accuracy by removing identity
or destination context. It is limited pseudonymization, not general redaction or
an anonymity guarantee; remaining names, signatures, sender details and content
can still identify people. Masking applies only to decision-provider requests; it
does not alter Gmail or the original URLs used by separately configured reputation
services. Google Web Risk, if separately enabled, can receive those complete URLs
including identifiers in query strings or fragments. It remains unconfigured in
this release. Masking does not eliminate the need to accept third-party sharing.

A durable explicit owner acceptance is scoped to the tenant, provider, canonical
destination and version/hash of the disclosure. Acceptance authorizes only
synthetic setup probes. Real analysis and question comparisons additionally need
an explicit tested/saved provider and masking configuration with a matching
authorization stamp. Missing, revoked or stale authorization blocks requests, and
background analysis waits before claiming queued work. Each actual request rechecks the gate and current configuration stamp; saved keys, old installations, mailbox OAuth, cache entries,
and a previous process snapshot do not grant consent. Revocation cannot unsend
an in-flight request. A local inference endpoint has its own acceptance; it can
still be remote or forward data elsewhere. See [data sharing](data-sharing.md) for
operator choices and the absence of upstream retention/training guarantees.

CVE checks are enabled by the self-host Compose configuration. An absent NVD entry
or lookup failure does not by itself prove a scam, and a real CVE does not validate
the sender's requested download. The lookup uses the fixed NVD service, not the
email's destination. Selecting a local model does not disable Google or signature
traffic and does not implicitly disable this reference lookup.

## Stored secrets and operational limits

OAuth tokens and wizard-saved Google/model credentials are encrypted with Fernet
using a key outside PostgreSQL in the application-owned area of the same persistent volume. Browser responses expose configuration status,
not stored secrets. Original mail, extracted evidence, and database backups are
not generally encrypted by the application; use protected storage and encrypted
backups. Keep the matching key in the protected backup so restored credentials
remain usable.

The administrative console token grants access to all imported mail in the
installation. There is no per-family-member visibility boundary or automatic
retention schedule. Disconnect removes current local OAuth tokens and pending
consent; it preserves imported mail and does not revoke Google's grant automatically.

Container health verifies service readiness and current antivirus signatures; it
does not prove that a live worker is making progress. Long Gmail imports and
action batches can also delay the ordinary worker heartbeat. Inspect queue growth,
checkpoints, and completed analyses when diagnosing throughput. Analysis leases
renew separately during long model requests.

The host must remain awake and its container runtime running. Restarts, backups,
restores, upgrades, and provider consent health remain operator responsibilities.
See [self-hosting](self-hosting.md), [Google setup](gmail-setup.md),
[local models](local-models.md), and [security guidance](../SECURITY.md).
