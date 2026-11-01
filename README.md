# Mailsec

**Self-hosted email security for Gmail and Google Workspace, with evidence you can inspect.**

Mailsec reads mail with its owner's consent, scans attachments locally, and asks a
hosted or local decision model to assess phishing and scams. **Using Jev sends
selected email evidence, including recipient/mailbox addresses and message text,
to TypeSafe, a third party. This is not anonymized by default.** The console requires
your explicit acceptance, followed by testing/saving the provider and masking
choice, before enabling email analysis. Its web dashboard
shows the message evidence, assessment, scan coverage, and history of every action.
Keep your existing address and email apps.

Created by **Derrik Trace**. Apache-2.0 licensed. This is `0.4.0-alpha.8`, an early alpha:
use monitoring first and evaluate it on your own mail. No 99% accuracy claim is made.

## Start locally

On Linux with **Landlock ABI 6 or newer enabled** (normally Linux 6.12+), Python
3.10+, and Docker Compose v2 or rootless Podman Compose installed:

```sh
git clone https://github.com/derriktrace/mailsec.git && cd mailsec && ./selfhost.sh
```

The `derriktrace/mailsec` checkout command is for the planned public repository;
it will work only after that repository is published. For an unpublished release
candidate, extract its reviewed source archive and run `./selfhost.sh` there.

Open **http://localhost:8025** and retrieve the private console token with
`./selfhost.sh token`.
The setup walkthrough lets you:

1. Choose **Jev**, **Ollama**, or an **OpenAI-compatible model server**.
2. Review and explicitly accept the selected provider's data-sharing disclosure,
   choose optional recipient masking, then test with a synthetic note and save
   that configuration to enable analysis. Acceptance alone allows setup probes.
3. Upload your Google OAuth client JSON and choose mailbox addresses and initial history.
4. Connect each personal Gmail or Workspace account through Google consent.
5. Choose monitoring, flagging, or reversible quarantine.

The command builds and starts **one Mailsec container** containing the console,
worker, PostgreSQL, static inspector, ClamAV, and signature updater. It does not install Docker/Podman,
create Google credentials, download model weights, or buy API credits. First startup
requires internet access for images, packages, and antivirus signatures. Signature
initialization can take several minutes; scanning waits when the scanner is unavailable.

Cold source builds also compile the native scanners and can take substantial time.
For a prebuilt image, obtain the exact immutable digest and attestation
verification command from this version's GitHub Release notes. The source
checkout intentionally uses a template because the digest is created after the
image is built and signed. Replace the placeholder below with that release's
64-character SHA-256 registry digest:

```sh
./selfhost.sh --image ghcr.io/derriktrace/mailsec@sha256:VERIFIED_64_HEX_DIGEST
```

This pulls the pinned image and starts the same single container without compiling.
The choice persists for later starts; `--build-from-source` explicitly switches
back. Do not run the placeholder command; use the release notes' ready-to-run
command and verification instructions for the actual published image.
See the [installation guide](docs/self-hosting.md) for verification and offline use.

From another device, use an SSH tunnel (replace `user@server` with your host):

```sh
ssh -N -L 8025:127.0.0.1:8025 user@server
```

Then open the same localhost URL on that device. For persistent remote access use
a trusted HTTPS reverse proxy and a matching OAuth callback. Never expose plain
HTTP or the console token to an untrusted network.

[Full self-host guide](docs/self-hosting.md) · [Google setup](docs/gmail-setup.md) ·
[Local model guide](docs/local-models.md) · [Detection question editor](docs/detection-questions.md) ·
[Data sharing and consent](docs/data-sharing.md) · [Plain-English pipeline](docs/analysis-pipeline.md) ·
[Architecture](docs/architecture.md) ·
[Release validation](docs/release-validation.md)

## What it does

- Connects to **free personal Gmail** and **Google Workspace Gmail** via per-account OAuth.
- Imports new mail and optionally historical incoming mail, with resumable checkpoints.
- Preserves original MIME, hashes, evidence, provider/model versions, and analysis history.
- Uses receiving-server SPF/DKIM/DMARC evidence from Gmail's trusted header boundary.
- Runs ClamAV and bounded PDF, Office, HTML, archive, image/OCR, and QR inspection in
  separate processes inside that container. It never executes email attachments or visits message links.
- Evaluates identity, requested actions, deception, destination/payload evidence,
  business contradictions, callback fraud, platform abuse, and execution/wallet scams.
- Supports optional read-only monitoring or Gmail labels and reversible quarantine.
- Lets the owner correct a category while retaining the original assessment, then
  optionally apply a matching Gmail label, move it out of Inbox, or undo a manual change.
- Provides an **Advanced → Detection questions** editor: save drafts, compare them
  with the active questions, activate a tested version, inspect history, and restore
  shipped defaults. Copy/paste all question wording as plain text JSON, with
  validation before it loads as an unsaved draft. Changes persist without rebuilding
  the container.
- Stores action outcomes separately from model recommendations; retries scanner
  outages durably and shows problems instead of presenting a failed scan as clean.
- Supports hosted Jev and local Ollama / compatible servers using the same question
  criteria. Local model estimates are explicitly labeled and cannot authorize
  model-only automatic quarantine.

**Quarantine means applying `Mailsec/Quarantine` and removing `INBOX`.** The message
still exists in Gmail All Mail. Release restores Inbox only if Mailsec removed it.
This is post-delivery monitoring; it cannot guarantee intervention before a click.

URL reputation / Google Web Risk is **optional and outside this release's setup**.
The adapter remains available for existing installations. Without it, reputation
is unknown and coverage gaps remain visible; no lookup is invented.

## Privacy and trust

The dashboard is a **single-owner administrative console**. Anyone with its token
can read imported messages and change settings. There are no separate family helper
roles, per-user access controls, or MSP tenant isolation. Connect loved ones' mail
only with their informed consent and an agreed level of access.

- **Jev:** analyzed past and future mail can send mailbox and recipient addresses
  (To/Cc/Bcc when present), sender/reply-to/return-path identities, subjects, body
  text including quoted/hidden text, complete URLs with query strings/fragments,
  attachment metadata and extracted/OCR/QR text, scan/authentication findings,
  configured organization/history context, and your questions to **TypeSafe**.
  Mailsec sends selected bounded evidence, not raw `.eml` or binary attachments;
  that evidence can still contain private or sensitive information. It is not
  automatically anonymized.
  Optional recipient masking is off by default; it replaces known recipient
  addresses in the model view, can reduce detection accuracy, and does not
  guarantee anonymity or remove all personal information. Consent is still required.
- **Local model:** that evidence goes to the endpoint you configure. An endpoint on
  another machine or a cloud service is not automatically private or local. Each
  provider/destination requires explicit acceptance; choosing a provider, entering
  a key, or authorizing Gmail does not grant that acceptance. Existing installations
  must accept the disclosure and explicitly test/save the selected provider and
  masking mode after upgrading before model processing resumes.
- Review [exact data flows, consent and revocation](docs/data-sharing.md). Passive
  protection mode controls mailbox changes; it does not make hosted inference local.
  Mailsec makes no promise about a provider's retention, training use, or deletion.
- Attachments are inspected on your host. Optional reputation and CVE lookups have
  their own documented external data flows. Separately configured Google URL
  reputation can receive original complete URLs, including identifying query
  strings or fragments; model recipient masking does not cover those requests.
- OAuth tokens and credentials saved by the wizard are encrypted using a key kept
  outside PostgreSQL but in the same protected persistent volume. Mail originals,
  evidence, and backups are sensitive and are
  not generally encrypted by the application. Use encrypted host storage.
- Disconnecting removes locally stored OAuth authorization and stops future access;
  it does not delete previously imported mail. Google grants can also be revoked
  in the account owner's Google Account settings.

## Practical requirements and cost

Use an always-on Linux host. Allow at least 8 GiB of available memory for Mailsec,
plus memory for your OS and any local model. CPU, RAM, and model
requirements depend on the chosen model and mail volume. Linux x86-64 runtime
checks have used rootless Podman and Docker Engine. NAS-specific setup, ARM, and
macOS/Windows Docker Desktop still need platform testing; see the validation record.
The host or Docker Desktop VM must expose Landlock ABI 6+; the inspector refuses to
process mail without its filesystem and process-signal restrictions. Older NAS
kernels require a supported Linux VM or another host. That VM still runs a single
Mailsec container; there is no option to silently disable parser isolation.

Mailsec has no license fee. Hosted model calls, optional external services, storage,
electricity, and hardware can cost money. A previous Jev pilot averaged about
$0.0026 per message using then-current input pricing; this is a workload-specific
estimate, excludes some retries and infrastructure, and is not a promised price.
Local inference avoids hosted inference fees but uses your hardware. The model
server and weights are optional external dependencies; they are not bundled in the
Mailsec container. Importing
many years of mail can be expensive; the walkthrough defaults to 30 days.

## Development and verification

For development outside the container, use Python 3.12+ and install a C compiler,
Python development headers, and PostgreSQL client development headers/tools, with
`pg_config` on your `PATH`, before installing the locked dependencies. The normal
container build supplies its own build prerequisites inside the image.

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements.lock -r requirements-inspection.lock
.venv/bin/pip install -e '.[dev]'
.venv/bin/python -m pytest tests -q
.venv/bin/ruff check mailsec tests scripts
node tests/ui-smoke.mjs
node tests/questions-ui-smoke.mjs
```

Browser checks require Node 22+ and Chromium (`CHROMIUM_PATH` can override its path).
Most tests use synthetic evidence and mocked providers. PostgreSQL, antivirus,
real OAuth, and paid model integration checks have explicit additional setup.
CI is configured for unit/integration checks, isolated Chromium console and
walkthrough tests under Node 22, a complete image build and database-only startup
check, Python/image vulnerability auditing, and secret scanning. The workflow has not been run on a published GitHub repository yet.

Maintainers preparing an unpublished candidate should follow the
[public alpha release checklist](docs/public-alpha-release.md). It distinguishes
local preparation from publishing and records remaining platform checks.

Read [SECURITY.md](SECURITY.md), [CONTRIBUTING.md](CONTRIBUTING.md),
[third-party notices](THIRD_PARTY_NOTICES.md), and the [changelog](CHANGELOG.md).
Model scores are not measured accuracy. Dataset tuning results do not establish
real-world precision or recall, and no system detects every phishing message.
