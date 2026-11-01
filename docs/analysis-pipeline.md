# Mailsec: how an email becomes a security decision

Mailsec is a self-hosted, post-delivery email monitor for personal Gmail and
Google Workspace. It imports messages, inspects them locally, asks a chosen
decision model to interpret the evidence, and applies a separate safety policy
before taking any Gmail action. The web console shows the original message,
findings, model judgments, policy decision, and action history so the owner can
review and correct a result.

**In one line:** Gmail → saved original → parsing and local scanning → identity,
link, and context evidence → Jev or a chosen model → conditional action review →
independent safety policy → console and permitted Gmail labels.

## The path of one message

1. **Connect and collect.** The mailbox owner authorizes Google OAuth. Read-only
   access permits monitoring; Manage access also permits approved label and Inbox
   changes. Mailsec can backfill historical incoming mail, including archived,
   Spam, and Trash messages, then poll for new mail. Sent and Draft messages are
   excluded from automatic protection. Mailsec runs after Gmail delivery, so it
   cannot promise to catch a message before someone opens it.
2. **Keep an auditable original.** Mailsec stores the raw message locally with its
   Gmail identifiers, received time, and content hash. Repeated Gmail IDs are
   deduplicated; import checkpoints advance only after storage succeeds. A replay
   adds a new analysis record and preserves the original and earlier results.
3. **Extract what a person could encounter.** A bounded MIME parser separates
   sender and reply-to details, visible HTML text, plain-text alternatives,
   quotations, hidden text, actual link targets, and attachments. These roles
   matter: a warning about a scam, a quoted example, or hidden alternate content
   should not automatically be treated as the current sender's request.
4. **Inspect locally.** ClamAV scans the original message for known malware
   signatures. Static inspection extracts supported PDF, Office, HTML, archive,
   image, OCR, and QR content. It can surface a link inside a document or QR code
   without opening that link. Unsupported or encrypted content and extraction
   limits are recorded as coverage gaps. Mailsec does not execute attachments or
   detonate them in a sandbox.
5. **Build contextual evidence.** Mailsec compares From, Reply-To, Return-Path,
   authenticated domains, and consequential action links. For Gmail imports it
   uses Gmail's receiver-reported SPF, DKIM, and DMARC results from a trusted
   header boundary, including domain alignment. It does not independently rerun
   historical SPF or cryptographically reverify DKIM. Passing authentication
   proves control of the authenticated domain, not ownership of a claimed brand.
   Local sender history and owner-supplied business context are useful context,
   not automatic whitelists. When enabled, a bounded CVE reference lookup checks
   a literal vulnerability ID; a real CVE does not validate an email's proposed
   download. URL reputation is optional and unconfigured in this public alpha;
   unknown reputation is neither a clean result nor proof of a malicious link.
6. **Ask structured questions.** The selected provider is hosted Jev, Ollama, or
   an OpenAI-compatible model endpoint. Mailsec sends bounded, source-labeled
   evidence and versioned questions. The main assessment asks for one of four
   categories—clean, spam, suspicious, or phishing—plus judgments about
   deceptive identity, sensitive requests, hostile destinations or payloads,
   business-context contradictions, callback fraud, abuse of a legitimate
   platform's user content, software or wallet fraud, and a recommended action.
   Long messages can be split into auditable sections so a buried instruction is
   not silently discarded. The question version and exact submitted model view
   are retained with the analysis. The current section combiner preserves the
   highest-risk section for review instead of averaging it away; this can also
   overflag a long, otherwise routine newsletter or receipt when one isolated
   section is ambiguous.
7. **Run a targeted second check.** If the first assessment says clean or spam,
   a conditional action review asks whether the sender actually requests software
   execution, wallet control, payment, a transaction callback, login or secrets,
   and what authority the sender claims. An authority check examines whether a
   consequential request's identity or route is coherent, contradicted, or
   unresolved. A concrete issue can move the effective result to suspicious for
   review. These are extra questions to the same model about the same evidence,
   not independent witnesses, and they do not run as a blanket second vote on
   every suspicious or phishing message.
8. **Apply deterministic safety rules.** Application code, not the model's action
   recommendation alone, sets the effective category and eligible action. A weak
   phishing preference remains suspicious for review. Affirmative malware or a
   current malicious URL finding can support quarantine; model-only quarantine
   requires a much stronger gated combination of phishing, harmful request,
   supported context, complete inspection, and a quarantine recommendation.
   Local model scores are uncalibrated and cannot trigger model-only automatic
   quarantine. Missing material content, scanner outages, or failed model stages
   are never silently converted into a clean judgment.
9. **Show or apply the result.** Clean operational mail is left alone; ordinary
   marketing is classified as spam without automatically moving it. Suspicious
   mail is available for review. In flag mode, Mailsec adds `Mailsec/Review` to
   eligible mail. In automatic-quarantine mode, an eligible message receives
   `Mailsec/Quarantine` and is removed from Inbox while remaining accessible in
   Gmail's All Mail. A read-only connection cannot write labels. The owner can
   correct a category, label or move a message, and undo eligible manual changes.
   A later completed clean/spam replay can clear an earlier *automatic* Review
   label when review is no longer warranted; it respects manual overrides and
   preserves other Gmail labels. Every proposed and attempted Gmail change has a
   durable, reconcilable action record. If a historical message has since been
   permanently removed from Gmail, its stored analysis remains and the Gmail
   action ends with a clear missing-message status.

## What the four categories mean

| Category | Practical meaning |
| --- | --- |
| Clean | Coherent operational or transactional message without affirmative deception or a material unresolved request. |
| Spam | Unsolicited promotion, bulk mail, survey, or solicitation without evidence of fraud or dangerous content. |
| Suspicious | A specific important uncertainty or incomplete evidence calls for a person to check it. Unknown alone is not proof of phishing. |
| Phishing | Affirmative evidence of impersonation, credential or MFA theft, financial fraud, deceptive callback, malicious execution, or another harmful social-engineering mechanism. |

The console keeps the raw model answer, its supporting judgments and probabilities,
local findings, effective policy verdict, evidence gaps, and Gmail action status.
A displayed model percentage is a judgment score, **not a measured chance that
Mailsec is correct**. Owner corrections are stored separately and are not fed back
to the model as an answer key on replay. Questions can be edited, compared against
the active wording, versioned, and restored to shipped defaults without erasing
past analyses.

## Privacy, cost, and scope

With **Jev**, selected email evidence goes to TypeSafe after explicit disclosure
and consent. That can include sender and recipient addresses, subject and body,
quoted or hidden text, complete URLs (including tokens in query strings),
extracted document/OCR/QR text, and scan/context findings. Raw `.eml` bytes and
binary attachments stay on the Mailsec host, but their extracted content can be
sent. Optional recipient-address masking is off by default; it replaces known
recipient addresses in the model view, can reduce detection accuracy, and is not
general anonymization. Ollama or a compatible endpoint receives the same selected
evidence at the configured server; whether that server is truly local depends on
where the operator runs it. A failed provider does not silently fall back to
another one.

Mailsec has no license fee. A previous Jev pilot averaged about **$0.0026 per
message** at then-current input pricing, excluding some retries and
infrastructure; long messages and conditional checks can cost more, and current
pricing must be checked with the provider. Local inference removes hosted model
charges but consumes host hardware. Mailsec is packaged as one Linux amd64
container with the console, worker, database, inspector, and antivirus services;
the optional local model server and its weights run separately.

This alpha is a monitoring and response tool, not an inline mail gateway,
click-time browser protection, an attachment detonation sandbox, a guarantee that
all links are safe, or a proven 99% detector. Google Web Risk is not active in the
public-alpha setup. Real detection-rate claims require a separate, blindly
labeled evaluation that includes both attacks and legitimate mail. The current
installation is intended for one trusted owner; separate helper roles and MSP
tenant isolation are future work.
