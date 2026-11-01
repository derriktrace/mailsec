# Email data sharing and explicit consent

**If you choose Jev, Mailsec sends selected email content and related evidence to
TypeSafe, a third party, for analysis. Recipient and mailbox identifiers can be
included. The evidence is not automatically anonymized. Optional recipient masking reduces
known identifiers and can reduce accuracy; it does not make the content anonymous.** Running Mailsec in your
own container does not keep Jev inference on your server.

This applies to the incoming messages you select for analysis: historical imports,
new mail, retries and replays, and message-based question comparisons. It does not
mean every byte of every mailbox is uploaded. Mailsec constructs bounded evidence
for the messages it analyzes; that evidence can still contain personal, private,
financial, or other sensitive information.

## What Jev can receive

With optional recipient masking **off** (the default), the main assessment
preserves identity and destination details because they help assess impersonation
and scams. Depending on the available message and extracted
content, its request can contain:

| Evidence | Examples |
| --- | --- |
| Mailbox and recipients | The connected mailbox address and To/Cc/Bcc-derived recipient addresses when present in the message |
| Sender and identity | Display name, full sender address, reply-to address(es), return-path, authentication domains/results and identity contradictions |
| Message content | Subject, date, message body, HTML-derived visible text, plain alternatives, quoted history and hidden text extracted from the message |
| Complete destinations | URLs from messages, documents, images or QR codes, retaining query strings and fragments; these can contain tracking identifiers, addresses or access tokens |
| Attachment and scan evidence | Filenames, content types, sizes/hashes, extracted document text, OCR text, QR contents, supported static findings and antivirus results |
| Organization and history context | Administrator-configured domains, vendor/executive relationships, payment practices, and locally observed correspondence/history facts |
| Decision configuration | Your question instructions and criteria, including any private facts you put into custom questions |

Content limits and staged processing mean not every field is present in every
request. The extra action/authority views omit some identifiers, including recipient
lists, but that does **not** anonymize the earlier main assessment. With masking off, full email addresses and identities are not replaced with
pseudonyms. Exact URLs retain their query strings and fragments. The optional
masking described below changes only known recipient-address occurrences in the
model view; it does not generally sanitize destinations or private URL tokens.

Mailsec removes internal/provider message IDs and raw transport audit headers
from the main model view. Earlier verdicts and analyst corrections are not evidence
for a new assessment. These exclusions are not a promise that the remaining text
is anonymous: a body, subject, URL or extracted document may identify a person or
reveal a secret by itself.

## Optional recipient masking

In **Setup walkthrough → Decision model**, the optional checkbox is
**“Mask recipient email addresses before model analysis.”** It is **off by default**
and is an explicit operator choice. It replaces known mailbox and recipient email
addresses in the outbound model view with placeholders consistent within that message's model view. The original-address
mapping is not included in the model request. Replacement
covers occurrences of those known addresses in structured fields and text,
including body/quoted content, extracted document/OCR/QR content, complete URLs,
and question wording that contains them. Common percent-encoded spellings are
handled through up to three encoding rounds. This is not a general decoder:
unrecognized, more deeply encoded, base64 or otherwise obfuscated identifiers can
remain. The sent view records that recipient replacement occurred so the
limitation is auditable.

**Masking can reduce detection accuracy.** Removing recipient identity or changing
a URL containing an address can hide context used to recognize personalization,
relationships, impersonation, and destination inconsistencies. A masked model
answer should not be interpreted as equally reliable without evaluation. Use
representative mail to assess the tradeoff for your own installation.

This is limited pseudonymization, **not guaranteed anonymization or general
personal-data redaction**. It only knows the mailbox/recipient addresses available
to Mailsec. Names, signatures, sender identities, other people's addresses,
postal/contact details, message content, account or order numbers, secrets and
unrecognized identifiers can remain. Someone may still identify a person from the
remaining context. Do not assume a masked email is suitable for public sharing.

Recipient collection and transformation have strict size/resource budgets. If
Mailsec cannot complete masking safely, the model request fails visibly; it does
not fall back to sending an unmasked copy. The original remains available locally
for review and retry after the problem is addressed.

Masking applies only to decision-provider requests. It changes the copy sent to
Jev, Ollama or a compatible model endpoint, including a URL if it contains a known
recipient address. It does not alter the stored original email, captured local
security evidence or Gmail state. Separately configured URL reputation services,
including Google Web Risk, use the original eligible complete URLs; identifiers
in their query strings or fragments can therefore be sent to that service even
when model recipient masking is enabled. Web Risk remains optional and
unconfigured in this release. Full third-party data-sharing acceptance remains
mandatory when masking is enabled: TypeSafe or your configured model endpoint
still receives selected content and context.

## What is not uploaded as a model input

Mailsec does not upload raw `.eml` originals or binary attachment files to Jev.
Those remain on the Mailsec host for local parsing and static scanning. It can
send their **extracted text, OCR/QR content, metadata and scan findings** as listed
above. A locally scanned PDF can therefore contribute private text to a hosted
model request without the PDF file itself being uploaded.

Gmail OAuth refresh/access tokens, Google OAuth client secrets, console tokens
and database passwords are not inserted into the email evidence. The Jev API key
is sent to the fixed TypeSafe API as the normal authorization credential; a chosen
compatible server likewise receives its configured credential when needed.
Credentials are not included by design in question text or the shared message
state. If an email itself contains a password, code, token or other secret, that
content can still appear in its selected analysis evidence.

## Consent before analysis

The console presents a prominent **“Jev shares email evidence with TypeSafe”**
disclosure when Jev is selected. Read the data categories, historical/future scope,
and destination before accepting. The required checkbox is unchecked by default:

> I understand that using Jev sends selected past and future email content and related evidence, including personal or sensitive information, to TypeSafe, a third party. I have permission to analyze these mailboxes.

The explicit button **“Accept the Jev email-sharing disclosure”** allows
**synthetic setup probes only**. Other providers use **“Accept this email-sharing
disclosure.”** It does
**not** resume mail analysis or question comparisons by itself. Finish the full
sequence for an existing or new provider:

1. Review the provider, destination and disclosure; explicitly accept it.
2. Choose whether to enable **Mask recipient email addresses before model analysis**.
3. **Test connection** sends only a synthetic setup note. Select
   **Test, save & allow email analysis →** to commit
   that provider and masking choice for real analysis.

Only the explicit successful save authorizes mail analysis and question comparisons
for that configuration. Pending selected historical and future mail can then
resume automatically. This prevents an acceptance click from starting unmasked
analysis while an unsaved masking choice is still visible in the form.

Acceptance is an explicit administrative action. Selecting a provider, supplying
an API key through a file/environment variable, clicking Google consent, or
running a prior release is not acceptance of this disclosure. Existing
installations need fresh explicit acceptance after this upgrade; they are not
grandfathered in silently. Model processing waits while acceptance is absent, the provider/destination or
disclosure no longer matches, or the configuration has not been explicitly tested
and saved for analysis. A previously stored key alone cannot resume it.

Setup probes require accepted disclosure; real analysis and saved-question
comparisons additionally require the explicitly tested/saved configuration. Each
provider request rechecks that authorization. A setup probe uses synthetic text; a message-based
comparison can send captured private evidence. The operator still reviews which
input a test will use. Saving/pasting questions or validating their schema alone
does not contact the model provider.

Mailsec retains the acceptance/revocation audit record. A changed destination or
updated disclosure requires acceptance for that destination/document and explicit
testing/saving before real analysis resumes. Changing the masking choice also
requires saving the new configuration; an old provider snapshot cannot continue
with the previous masking mode after that change is committed. Accepted
consent does not reconnect Gmail, change its scopes, enable quarantine, or
establish permission from another mailbox owner on its own. Explain the data flow
and obtain permission before connecting someone else's mail.

## Decline or revoke sharing

You can decline rather than enable a provider. **Stop future sharing with this
provider** revokes the selected destination's acceptance. Review a local endpoint as an
alternative if you want inference on hardware you control. Queued messages and
prior analyses remain stored; absence of acceptance does not create clean
classifications or silently select another provider. Mail import can continue
independently of model processing according to its configured Gmail connection.

Revoking sharing prevents later provider requests. A request already sent cannot
be unsent, and revocation cannot recall data held by a provider. It does not erase
mail, prior analyses, comparison history or backups, revoke Google OAuth, undo
Gmail labels, or replace the separate protection controls. Disconnect a mailbox
and adjust protection settings separately when those are your intentions.

Mailsec does not make or enforce promises about TypeSafe's or another provider's
retention periods, model training use, subprocessors, or deletion of previously
received data. Review that provider's current terms and privacy controls directly
before accepting. TypeSafe's [legal documents](https://docs.typesafe.ai/legal)
link to its privacy policy, customer agreement and data processing agreement.
These application controls are not a legal certification.

## Local models and remote compatible servers

Ollama and OpenAI-compatible options send the same selected evidence to the
endpoint you configure. They also require explicit acceptance for their provider
and destination. A server actually running on your controlled hardware can keep
model inference there. An endpoint on another person's machine, a hosted service,
a remote LAN server, or a cloud-routed model is a separate data-sharing decision;
a familiar API format or the word “local” does not establish privacy.

Mailsec does not silently fall back to Jev or another endpoint when a server fails.
Review the model server's own logs, telemetry, retention, and onward cloud routing.
Plain HTTP is allowed only for intentionally private/loopback model destinations;
that traffic is not encrypted merely because it travels on a LAN. Use an endpoint
and network you trust. See [local model setup](local-models.md).

Selecting a local model does not make all Mailsec traffic offline. Google OAuth
and Gmail retrieval still contact Google. Antivirus signatures are downloaded.
When enabled, bounded CVE-reference lookup sends literal CVE identifiers to NVD.
Google URL reputation is optional and remains unconfigured by the public alpha;
separately enabling it can send original eligible complete URLs, including query
strings, fragments and any identifiers they contain, to that service. Decision-model
recipient masking does not cover those separate reputation requests. The
[architecture guide](architecture.md#data-leaving-the-host) lists these boundaries.

## Local storage and access

The administrative console token gives its holder access to all imported mail in
this single-owner installation. There are no independent family-member or helper
roles. Originals, extracted evidence, audit records and backups contain sensitive
data. Model/OAuth credentials saved through setup are encrypted, but mail and
backups are not generally encrypted by the application. Use protected host storage,
restrict console access, and encrypt backups before copying them elsewhere.

Passive protection means no automatic mailbox changes; after acceptance it can
still analyze mail through Jev. It is not a privacy or offline mode. The separate
[Google guide](gmail-setup.md), [question guide](detection-questions.md), and
[self-hosting guide](self-hosting.md) explain connection, comparison and operation
controls.
