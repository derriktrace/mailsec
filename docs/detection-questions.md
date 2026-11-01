# Customize detection questions

Mailsec lets its owner change the wording and criteria used by Jev, Ollama, or an
OpenAI-compatible decision server. Open **Advanced → Detection questions** in the
console. Changes are saved in the database, survive restarts, and need no rebuild.
The same active version applies to every mailbox in this installation.

Start with the shipped defaults. Change a small, explainable rule when you can
identify a pattern of errors, and compare it against both legitimate and malicious
examples. A successful model request is not proof that a question is better.

## What you can edit

The editor groups the full question set into three bundles:

| Bundle | Purpose |
| --- | --- |
| Assessment | Main verdict, identity, sensitive requests, hostile destinations/payloads, business context, and scam patterns |
| Requested actions | Software execution, wallet access, payment, callback, secrets/login, and claimed authority |
| Authority | Whether the requested action's claimed authority is coherent, contradicted, unresolved, or absent |

You can edit each question's **instructions** and each existing **criterion**.
Question IDs, types, and answer keys are read-only: application policy and model
response validation depend on those contracts. The editor validates the complete
three-bundle structure. Individual text fields are limited to 8,192 characters and
the complete submitted bundle to 48 KiB. Keep wording much shorter where possible;
these are safety limits, not a recommended prompt size.

The extra action and authority stages run when the initial assessment says clean
or spam. They check what the message actually asks the reader to do and whether
its claimed authority is supported. A concrete finding can move the effective
result to suspicious; the stage is not an independent witness to a Jev judgment.
It does not run as a blanket second vote on every suspicious or phishing message.
The comparison test exercises all three bundles so you can inspect the changes;
that is not the same number of calls every production email receives.

## Copy and paste question wording

Use **Copy questions** to open plain text containing the complete three-bundle JSON
currently displayed in the editor, including unsaved edits. Select the text and
copy it yourself, or use the dialog's copy button when your browser permits
clipboard access. No file download is required. The text contains only the
question bundles: no mailbox messages, provider settings, API keys, version
history, or comparison results. Review your own wording before sharing it if you
have inserted private facts into a question.

To reuse or externally edit that text:

1. Copy the full JSON, retaining the top-level `primary`, `actions`, and `authority`
   bundles. Edit instructions or criterion text in your preferred plain text editor.
2. Open **Paste questions** in Mailsec and paste the full text. Do not paste a
   screenshot, expected answer, email, partial bundle, or an entire version record.
3. Select **Validate and load draft**. Mailsec validates JSON structure, fixed
   identifiers/types/answer keys, and text/size limits. An invalid paste leaves the
   existing editor content intact. If you already have unsaved edits, the console
   asks before replacing them.
4. Review the loaded wording, give it a useful draft name, and use the ordinary
   **Save draft → Compare with active → Activate tested version** workflow below.

Pasting and validation do not make model calls, save a revision, change the active
questions, or modify mail. Valid text loads as **unsaved edits**, and cannot bypass
the separate test and activation requirements. This is a copy/paste workflow;
Mailsec does not require file import/export for question changes. The copied JSON
is portable between compatible installations with the same question schema. If a
new release changes that schema, validate against that release rather than
removing required fields to force an old bundle through.

## Save and compare a draft

1. Open the active version, or load an older version from **Version history**.
2. Edit only the instructions or criteria you intend to change. Give the draft a
   useful name/note explaining the problem and intended behavior.
3. Select **Save draft**. This creates an immutable saved revision. It does not
   affect scanning. Further edits require saving another draft before testing.
4. Choose **Compare with active**. Supply either pasted text or an already analyzed
   message. The console explains which provider receives the data before you run it.
5. Start the comparison and inspect both columns, the recorded provider/model,
   question revision, and any errors. Check which judgments changed and why the
   revised wording makes sense for the supplied evidence.
6. When satisfied, use **Activate tested version** and confirm the change. New
   analyses use it; previous results and messages remain unchanged.

A comparison makes up to six model requests: the three bundles with the active
questions and the three with the saved draft. This can cost more than one ordinary
email analysis. Each call is limited to 30 seconds with no automatic test retry;
the six-call budget is 180 seconds, with a final in-flight read bounded separately.
Only one comparison may run at once for the installation. Keep the page open to
watch progress or return to the saved test record later.

For pasted **comparison input** (separate from **Paste questions**), use the actual email text and relevant headers you want assessed;
do not add the expected category. Paste is limited to 24,000 characters and 48 KiB.
It is treated as supplied text, not as a new imported email with authenticated
Gmail provenance or a fresh antivirus scan.

For an existing message, the comparison copies the captured evidence from a
completed analysis. It excludes prior classifications, analyst corrections, and
model answers. It does not download the message again or rescan its attachments.
Messages whose captured evidence is incomplete, truncated, or requires multiple
primary content sections are refused rather than silently testing less evidence.
Use a smaller complete example or the normal analysis workflow for those cases.

Tests do **not** update message verdicts, Gmail labels, Inbox/Spam/Trash location,
automatic action queues, sender history, or normal analysis caches. The original
analysis remains intact. The saved test itself contains sensitive evidence and
answers; it belongs in the same protected storage and backups as your mail.

## Activation and version history

Activation requires a completed test of the exact saved draft using the current
provider settings and the currently active baseline. Editing wording after a test,
changing providers/models/endpoints, or another activation invalidates that test
for activation. Run another comparison. This prevents an old or unrelated success
from approving a different change.

Version history retains drafts, activation records, notes, hashes, and comparisons.
To return to earlier custom wording, load that revision, compare it again against
the active questions, and activate it when the comparison completes. Loading or
saving a draft alone never changes production behavior.

**Restore shipped defaults** is a separate confirmation. It creates and activates
a revision of the defaults shipped with this installed release. It preserves all
older versions and test records, and does not erase analyses or Gmail changes.
The trusted shipped baseline does not require a new provider test to restore.
Defaults can differ between Mailsec releases; the recorded revision identifies
what was used. A backup includes the active pointer, revisions, and comparison
history; restoring requires the matching protected backup and encryption keys.

An analysis captures one question version for all its stages. Activation affects
future analyses, not an already running assessment. Old messages are not replayed
automatically. Use the ordinary explicit replay control if you want to obtain a
new analysis; previous runs remain available.

## Tune for evidence, then validate independently

Useful wording clarifies the distinction between deceptive evidence and ordinary
activity. For example, a legitimate service can ask a recipient to sign in or
update payment details. The question should examine the supplied identity,
destination, request, and context together. Urgency alone is not proof of phishing.
A passing SPF/DKIM/DMARC result proves authenticated domain control, not brand
ownership. Unknown enrichment is neutral; a consequential unresolved destination
can still justify review without proving a hostile destination.

Avoid adding sender-specific exceptions, your own domain names, desired answers,
or wording that declares a test example legitimate/malicious. Do not paste a
classifier's existing verdict as evidence. Retain an independent evaluation set
that did not guide your edits. Include legitimate account warnings, invoices,
marketing, real deceptive requests, attachment gaps, and different languages.
Review false positives and missed attacks separately; a set containing only
phishing cannot establish a useful overall accuracy rate.

Compare the same evidence and provider configuration, and record the revision.
One model's supporting answers are related estimates, not independent witnesses.
Repeatedly tuning until a small set is perfect can overfit it. The editor does not
measure production accuracy, train a model, or certify a question set as safe.
For a proposed second pass, compare it with cases it could wrongly escalate as
well as attacks it could catch. A second answer from the same model and evidence
does not automatically justify quarantine or override missing inspection evidence.

## Model choice, privacy, and protection policy

Question tests require current explicit data-sharing acceptance **and** a
provider/masking configuration that was explicitly tested/saved for analysis, as
well as the comparison's input/destination confirmation. Accepting a disclosure
alone only permits synthetic setup probes. Mailbox OAuth or a saved provider
key is not acceptance. Copying/pasting questions and validating their schema do
not invoke the provider. Comparing captured message evidence can send its actual
mailbox/recipient and sender identities, body, exact URLs and extracted content
where present; it is not automatically anonymized. Use synthetic pasted text if
you do not intend to share captured mail for a particular test. Revocation prevents
later comparison requests; a request already sent cannot be recalled. Read
[data sharing and consent](data-sharing.md).

If recipient masking is enabled, known mailbox/recipient address occurrences in
the outgoing evidence and question text are replaced for the model. This changes
its view of the case, can reduce detection accuracy, and does not remove every
personal detail. Original local evidence/question revisions remain available.
Compare configurations deliberately; a masked/unmasked comparison is not purely
a question-wording experiment. Sharing acceptance is required in either mode.

Question changes use the configured provider. With Jev, selected evidence goes to
TypeSafe; with Ollama or a compatible server, it goes to that endpoint. A server on
another machine is not automatically private. See the [local model guide](local-models.md)
for provider switching, endpoint restrictions, and costs.

Editing questions does not relax the separate mailbox-action policy, access mode,
scanner requirements, or local-model restrictions. Local estimated probabilities
still cannot authorize model-only automatic quarantine. Start in monitoring mode
and review effects before enabling automatic actions.

If a test errors, inspect its safe error summary, check provider configuration and
connectivity, shorten overly large wording, or choose complete evidence. A failed
comparison cannot activate a draft. Restore defaults if the active wording causes
unexpected behavior; fixing wording does not require deleting historical results.
