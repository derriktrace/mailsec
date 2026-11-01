# Self-host Mailsec

Mailsec is an early self-hosted Gmail security application. Both personal Gmail and Google Workspace accounts use explicit, per-mailbox OAuth consent. It monitors mail after delivery; it cannot guarantee interception before a recipient opens a message. Quarantine is a reversible Gmail label plus removal from the inbox, not an inaccessible mail gateway quarantine.

## Start from a release checkout

Requirements: Linux, Python 3.10 or newer for the installer, and either Docker with Compose v2 or rootless Podman with `podman-compose`. Python packages for the application run in containers; no host virtual environment is required. Budget at least 8 GiB of available RAM, preferably a host with 12 GiB or more, and persistent disk space for messages and signatures. The first build downloads images and the first antivirus update can take several minutes. ARM machines and Docker Desktop need separate release testing; the primary target is Linux x86-64.

**The host kernel must provide enabled Landlock ABI 6 or newer**, normally Linux 6.12+
with Landlock enabled in its security-module configuration. A new container image
cannot add a missing host-kernel feature. On an older NAS, use a Linux VM with a
supported kernel or a different host; Mailsec still runs as one container inside
that VM. Docker Desktop's Linux VM must meet the same requirement. The inspector
reports `parser_isolation_unavailable` and keeps mailbox processing stopped when
this requirement is missing. There is no weaker automatic fallback. See the
[Linux Landlock documentation](https://docs.kernel.org/userspace-api/landlock.html)
for host support and ABI details.

The installer checks a local Linux host before building and explains a missing
kernel requirement. The running container checks again, including when Docker
uses a remote host or a desktop VM. A UGREEN DXP4800 Plus has the supported x86-64
processor architecture, but its model name does not establish the installed UGOS
kernel or security-module support. Confirm the kernel check before migrating
mail; this release has not yet been tested on that NAS.

The source build compiles and tests several native components from verified source.
Budget substantially more time and memory for that first build than for later
startup. The alternative prebuilt-image path avoids compiling; it does not remove
the kernel, available-memory, architecture, or persistent-storage requirements.

Obtain and review the source from `derriktrace/mailsec` once published, or from
the versioned source archive supplied by the maintainer. The GitHub command below
works only after that repository is published.

```sh
git clone https://github.com/derriktrace/mailsec.git
cd mailsec
./selfhost.sh
```

This creates a Compose project called `mailsec-selfhost`, builds one image, starts one `mailsec` container, and opens no LAN ports. It does not read the developer pilot's `.env`, `secrets/`, organization configuration, or database. The default address is **http://localhost:8025**. Obtain the private console access token deliberately:

```sh
./selfhost.sh token
```

Paste it into the console login and follow the setup walkthrough. No model API key is required to start the console. Configure an analysis provider before authorizing mailbox processing. A hosted model sends selected message evidence to that provider; a local model keeps that inference on your chosen local endpoint. No model download or paid request happens merely from running the installer.

### Use a verified prebuilt image

When a maintainer provides an image, check the release's supported architecture,
source revision, immutable registry digest, and signature/provenance using the
maintainer identity documented with that release. A SHA-256 digest pins content;
it does not establish who published it. Do not use an image whose publisher or
provenance you do not trust. The registry namespace is
`ghcr.io/derriktrace/mailsec`. Get the exact digest and attestation identity from
the version's GitHub Release notes; they cannot be recorded in this immutable
source checkout before its corresponding image is built.

Only after an image release is verified, replace **VERIFIED_64_HEX_DIGEST** with
the actual published 64-character SHA-256 digest:

```sh
./selfhost.sh --image ghcr.io/derriktrace/mailsec@sha256:VERIFIED_64_HEX_DIGEST
```

The command above is a template and cannot be run with the placeholder. Copy the
ready-to-run command from the release notes and follow its provenance verification
instructions before installing the image.

The installer requires a fully qualified registry reference pinned by a full
64-character SHA-256 digest. Mutable tags such as `latest` are not accepted here.
It saves that reference in the installation's private settings, pulls it, and
starts the one container without a source build. Later `./selfhost.sh` starts
reuse and pull the saved pinned reference. A failed pull stops startup; it does
not silently build or substitute another image.

For deliberately offline startup, use `./selfhost.sh --no-pull` only when that
exact pinned image is already available to the selected container runtime.
Initial antivirus signatures and Gmail/model connections still need their own
network access. Source builds are the default when no image is selected. To
explicitly switch a saved image installation back to the reviewed source:

```sh
./selfhost.sh --build-from-source
```

`--image` and `--build-from-source` cannot be combined. `--no-build` skips a local
source build; it does not select a public image or replace `--no-pull`.
Back up before changing releases. Selecting an image does not migrate an
incompatible database platform, weaken parser isolation, or reset saved protection.

New installations start **passive**, with notifications off. Existing saved protection controls survive restarts and upgrades. Initial Gmail import defaults to the last **30 days of incoming mail**, including archived mail, spam, and trash but excluding sent mail and drafts. Choose new mail, 30 days, or all incoming history in the Gmail setup walkthrough **before connecting**. Terminal setup also supports `--history-days 0` for all history. Changing this after a completed backfill does not rewind the mailbox cursor automatically.

The container includes the API/console, worker, PostgreSQL, static document/QR inspector, ClamAV scanner, and signature updater. No separate Mailsec database or scanner container is required. An optional Ollama or compatible model server is supplied separately by the operator; hosted Jev needs no local model server. Evaluation corpora and model weights are not installed.

On startup the console can become available before scanning is ready. The worker
starts only after the inspector and current antivirus signatures are ready; it does
not claim messages during that warm-up. A ten-minute readiness deadline stops the
container for recovery instead of allowing indefinite hidden startup failure.

The service processes run under separate non-root users. A small supervisor runs as container root with limited capabilities to initialize directories, start children under their assigned users, handle shutdown, and restart failures. Application credentials are in a private application-owned directory; inspection and antivirus processes do not receive them. Database, scanner, and inspector listeners remain internal. The root filesystem is read-only and temporary files use bounded temporary filesystems.

**One container is a simpler installation, not independent service isolation.** These processes share a network namespace, resource budget, and host kernel. The static document parser and its OCR/PDF children deny networking and cross-process inspection through inherited Linux seccomp restrictions. Landlock limits their filesystem access to read-only interpreter, application, and native-tool resources plus a private per-message scratch directory. They cannot access the inspector's persistent cache, application data, other jobs, or peer process memory; signals stay within the parser's own descendants. Parsing stops if either restriction cannot load. The HTTP parent retains full-message and antivirus caching; persistent per-document caching is intentionally unavailable to decoders. The antivirus engine has a separate UID from the signature updater, read-only signature access, private scratch, and a fixed TCP listener; it cannot initiate outbound connections or signal other services. Only the updater and HTTP parent retain their necessary outbound network access. File permissions and database authentication reduce exposure, but a root or kernel compromise can cross those boundaries. This package is for one trusted operator, not hostile tenants.

**Choose and explicitly accept the analysis data destination.** Jev sends selected
email evidence to third-party TypeSafe, including mailbox/recipient addresses,
sender/body text, complete URLs and extracted document/OCR/QR content when present.
It is not anonymized by default. Historical backfill, future mail, retries/replays,
and captured-message comparisons share this boundary. Existing installations must
accept the current disclosure after upgrading, then explicitly test/save the
provider and masking choice. Acceptance alone permits only synthetic setup probes;
mail analysis and question comparisons remain paused until that save. A stored
key or old configuration cannot grant authorization silently.
The setup checkbox **“Mask recipient email addresses before model analysis”** is
off by default, can reduce detection accuracy, and is not a guarantee of anonymity; it does not remove the need to accept sharing.
A local/compatible endpoint has its own destination disclosure and may itself be
remote. See [data sharing and consent](data-sharing.md). Google authorization and
mailbox-action preferences remain separate controls.

**URL reputation / Google Web Risk is intentionally unconfigured.** The release does not require that API or its billing. Missing reputation is a visible evidence limitation and is never reported as a successful URL safety check. It does not, by itself, apply a Review label or make a message suspicious. A configured provider's actual failure remains an operational warning.

## Access from another device

`localhost` refers to the device running the browser. If the server is remote, keep the default loopback binding and create an SSH tunnel from your laptop:

```sh
ssh -N -L 8025:127.0.0.1:8025 your-user@your-server
```

Then open **http://localhost:8025** on the laptop. The OAuth browser redirect reaches the same installation through the tunnel. Keep the tunnel open throughout consent. The background worker continues after the browser/tunnel closes, provided the server and containers keep running.

If port 8025 is occupied, initialize with `./selfhost.sh --port 8125` and use port 8125 consistently in the URL, SSH tunnel, and Google OAuth redirect. The loopback HTTP exception is for localhost only. Do not expose an HTTP bearer-token console on the LAN or Internet.

For persistent remote access, use a domain with a valid HTTPS certificate and a maintained reverse proxy. Keep the application port bound to loopback. Configure the external origin and exact trusted proxy source IP:

```sh
./selfhost.sh configure --non-interactive \
  --public-url https://mailsec.example.com \
  --trusted-proxy-ips ACTUAL_PROXY_SOURCE_IP
./selfhost.sh
```

The proxy must preserve `Host`, send `X-Forwarded-Proto: https`, and overwrite incoming forwarded headers. In a container deployment the source address seen by the API may be the container bridge gateway rather than `127.0.0.1`; determine that address for your runtime. Do not use `*` for trusted proxies. Register `https://mailsec.example.com/oauth/google/callback` in Google and use that origin for both the console and consent. A reverse proxy does not replace console authentication. This alpha uses one operator access token, not separate family-member accounts or an MSP permissions model.

## Gmail authorization

Use the console's Gmail setup steps. If preparing configuration from a terminal instead:

1. Create/select your own Google Cloud project, enable **Gmail API**, and configure Google Auth Platform branding/audience. A personal Gmail account does not require a paid Workspace subscription. Choose an **External** audience to include personal Gmail; an Internal audience is only appropriate for eligible Workspace-only deployments.
2. Create an OAuth client of type **Web application**, named for example **Mailsec Self-Hosted**.
3. Register exactly `http://localhost:8025/oauth/google/callback` for the default tunnel/local installation. Use your selected port or configured HTTPS origin if different.
4. Configure the data-access scopes appropriate to your choice: `https://www.googleapis.com/auth/gmail.readonly` for **Monitor** and `https://www.googleapis.com/auth/gmail.modify` for **Manage**. The connection screen chooses which to request. Manage supports labels/quarantine and includes Google's bundled send capability. Selecting passive policy alone does not narrow an existing Manage grant.
5. Download the client JSON to a private location, then import it with the walkthrough or the installer below. Do not commit it to Git or paste its contents into an issue.
6. Authorize each intended mailbox explicitly. For an External app in Testing, add those accounts as test users. Sign in with each mailbox owner and approve access; a Google Admin session does not automatically authorize another person's inbox.

```sh
./selfhost.sh configure \
  --oauth-client-file /private/path/client_secret.json \
  --mailboxes person@gmail.com,person@example.com
./selfhost.sh
```

The configure command optionally prompts for a Jev key without echoing it. Enter keeps the current key or leaves it empty for provider setup in the GUI. For automation, use `--non-interactive` and an existing key file via `--jev-key-file`; no key value belongs on the command line. Existing database passwords, token-encryption keys, and console tokens are preserved for the same single-container installation. Existing model/OAuth credentials change only when explicitly supplied; normal restarts do not replace them.

Google's External **Testing** mode normally limits refresh tokens for Gmail scopes to seven days. It is suitable for a trial, not unattended long-term protection. Gmail access uses restricted scopes. Evaluate Google's current production verification/security-assessment requirements and applicable personal-use exceptions for your actual deployment; distributing the code does not grant a universal exemption. A broadly offered hosted service or shared OAuth application has additional obligations. Workspace administrators can also restrict third-party OAuth access.

Official references: [Gmail scopes](https://developers.google.com/workspace/gmail/api/auth/scopes), [OAuth token expiration](https://developers.google.com/identity/protocols/oauth2#expiration), and [OAuth verification](https://support.google.com/cloud/answer/13463073).

## Review, correct, and organize messages

Open a message and select **Correct classification**. Choose Clean, Spam,
Suspicious, or Phishing and record your reason. Saving updates the console's
effective category and counts. The original assessment and all runs remain visible;
replaying analysis neither erases the correction nor supplies your correction to
the model as evidence. A correction does not conceal an incomplete or failed scan.

For a connected account with **Manage** access, optionally select **Also apply the
matching Gmail label**. The requested change replaces the four `Mailsec/` verdict
labels and clears `Mailsec/Review`. The separate **Move out of Inbox into this label**
option removes Inbox membership; it is unchecked by default. Mail remains in All
Mail. These are custom labels: `Mailsec/Spam` does not move a message into Gmail's
system Spam folder. You can also organize Gmail without changing the console
category using the separate form in the Actions tab.

**Clean does not release quarantine.** `Mailsec/Quarantine` remains until you use
the explicit release control. Release restores Inbox only when the recorded
quarantine originally removed it. Other Gmail labels remain intact. Automatic
Review/Quarantine labels express a protection action; manual verdict labels express
your chosen category. The console explains when a quarantine still needs release.

Saving a correction and requesting a Gmail change are two recorded operations.
If the latter fails, the console retains the correction and reports that Gmail
queueing was not confirmed. Pending means queued, not applied. Inspect the action
ledger for the actual outcome. Manual label changes remain available in Passive
mode with Manage consent; Monitor consent permits console corrections only.

The latest applicable manual label operation can be undone from its action card.
Undo restores the recorded verdict/review labels and any Inbox membership that
operation removed. It refuses detected newer actions or conflicting Gmail states
rather than overwrite them. Undo does not erase the console correction or model
history. Explicit analyst corrections and outstanding manual organization prevent
automatic policy from immediately reversing the owner's choice.

See [release validation](release-validation.md) for the distinction between tested
mocked Gmail behavior, real runtime checks, and live mailbox validation.

## Adjust detection questions

Open **Advanced → Detection questions** in the console. Edit wording or criteria,
save a named draft, and compare it with the active version using pasted text or a
previously analyzed message. A successful comparison enables activation for that
exact draft and provider; activation affects future analyses. **Version history**
lets you inspect and retest older revisions, and **Restore shipped defaults**
creates a new active baseline without deleting history. No rebuild or container
restart is required. All connected mailboxes in this installation use the active
questions. **Copy questions** and **Paste questions** let you reuse or externally
edit the full three-bundle JSON as plain text. **Validate and load draft** checks a
paste and loads unsaved edits; it makes no model call and does not save or activate.
No question file upload/download is required.

Tests use the configured model provider and can send selected private evidence to
it, with hosted usage charges. They do not relabel mail, change classifications,
rescan attachments, or establish accuracy. Backups include revisions and test data
alongside the sensitive message database. Read the full [question editing guide](detection-questions.md)
before changing detections. To select Jev, Ollama, or a compatible server again,
reopen **Setup walkthrough → Decision model**; see [local models](local-models.md).

## Local model networking

The application is in a container: `localhost` inside it is not the machine running Ollama. The Mailsec container has the `host.docker.internal` host-gateway mapping; rootless Podman also commonly supplies `host.containers.internal`. In the provider walkthrough use the reachable host address, for example `http://host.docker.internal:11434` for a local Ollama server. If that server listens only on host loopback, it may need a restricted bind/proxy so the container can reach it. Permit only the container network in the host firewall; do not expose an unauthenticated inference endpoint publicly. The installer does not alter the host firewall or inference-server binding. Use the walkthrough's connection test before connecting Gmail.

For an OpenAI-compatible endpoint, use the endpoint's documented base URL and a model it actually serves. Compatibility does not imply identical classification accuracy: evaluate a local model on representative mail. Local estimated scores cannot authorize model-only automatic quarantine in this release; confirmed scanner detections have a separate policy.

## Operations and private state

```sh
./selfhost.sh status
./selfhost.sh logs
./selfhost.sh check
./selfhost.sh backup
./selfhost.sh stop
```

Use `--engine docker` or `--engine podman` to choose explicitly. `stop` stops the container and preserves all data. `start` builds the checkout's images and starts them; `--no-build` reuses images already built for that release. An installer exit status of zero confirms Compose accepted startup, not that every external provider is healthy. Check the console's health and scan-retry indicators after startup and after an update. Never count a deferred or failed scan as clean. The container health check verifies supervisor/process presence, database/API readiness, and usable antivirus signatures. It does not prove worker progress: a live worker can still be slow or stalled. Review its heartbeat, mailbox checkpoints, queue counts, and recent analyses in the console. Required-service exit stops the container for the runtime restart policy; the signature updater has bounded retry backoff. A merely unhealthy container is not automatically restarted by Docker's restart policy.

State lives in `.selfhost/` by default. Use `--runtime-dir /private/path/mailsec` consistently for a custom installation. Independent installations need both a separate state directory and a distinct initial `--project-name mailsec-selfhost-NAME`. The project name is saved and cannot be changed in place, because it identifies the persistent data volume. Do not repurpose the pilot's state directory.

The host state directory and its `secrets/` subdirectory are mode `0700`. The entire protected bootstrap directory is mounted for the root supervisor; individual files are not exposed as broadly readable mounts. Bootstrap copies required credentials into application-owned mode `0600` files under the private persistent application directory. The separate organization bootstrap file is mode `0400`, readable only by its host owner and the container supervisor. Do not loosen the enclosing directory permissions or mount the secrets elsewhere. Console tokens, raw mail, database dumps, OAuth credentials, and model keys are private. The database stores encrypted OAuth tokens; the external encryption key must be backed up with the database. Host disk encryption and access control remain the operator's responsibility.

The named data volume is mounted at `/data`. Separate directories hold application secrets and state, PostgreSQL storage, inspection cache, and antivirus signatures. Protect the entire volume. The console token and credential-encryption key are outside PostgreSQL but remain in that same volume; database encryption does not protect against an attacker who can read both the database and keys. Do not attach this volume to another running Mailsec container or share database files over a network filesystem.

## Backup, restore, and upgrades

`./selfhost.sh backup` runs a consistent PostgreSQL custom-format dump and packages it with private settings and encryption keys. By default archives are created inside `.selfhost/backups/`, with owner-only permissions. Inspection caches and antivirus signatures are intentionally omitted because they can be rebuilt. **The archive contains readable mail and credentials; encrypt it before copying it to another host or cloud storage.** Keep an off-host copy and test a restore before relying on it.

Restore into a **fresh installation**, never over a working database. Use the same
release first and only archives you created and trust. The simplest recovery target
is a new host with no existing Mailsec data volume or Compose project of the saved
name. Do not run these commands against a live installation. The commands below
show Docker Compose; replace `docker compose` with `podman-compose` for Podman:

```sh
umask 077
mkdir recovery
tar -xzf /private/path/mailsec-backup.tar.gz -C recovery
# The destination .selfhost must not already exist.
mv recovery/state .selfhost
# Rewrite absolute paths, preserve restored keys, and select database-only startup.
./selfhost.sh configure --non-interactive --database-only
./selfhost.sh
# Wait for the database-only container to be healthy before restoring.
./selfhost.sh status
docker compose --env-file .selfhost/compose.env -f compose.selfhost.yaml \
  -p mailsec-selfhost exec -T mailsec python /opt/mailsec/container_backup.py restore \
  < recovery/database.dump
# Only after a successful restore, enable the console, worker, and scanners.
./selfhost.sh --no-database-only --no-build
```

Use the **saved project name** from `.selfhost/settings.json` in the Compose command
if yours differs. That project must have no existing data volume on the target host.
The restore helper requires database-only mode and an empty database, then runs the
restore as one transaction using the ordinary application database login. It does
not connect as a database superuser and then rely on `SET ROLE`. It refuses to overwrite existing tables; it never uses
`--clean` or drops a database. If the target is nonempty or restore reports an error,
stop and investigate instead of starting the worker or forcing the restore.

Database-only mode starts the bundled database and no console, scanner, or worker.
It is a maintenance setting that persists until explicitly disabled. After restore,
verify connected accounts, data counts, protection settings, provider health, and
a fresh scan. Consent might need to be renewed if a provider revoked it. The restored
protection mode is preserved; review it before enabling normal startup if the backup
had automatic mailbox changes enabled.

A previous multi-container installation has a different runtime format. Do not point the one-container installer at its existing state or volumes; the installer rejects that format. Moving such an installation requires a separately reviewed logical dump/restore and matching keys; follow the [migration guide](migration.md). The one-container start command is not an automatic migration.

Each newly initialized PostgreSQL cluster records its runtime platform. A missing
marker or a glibc/musl mismatch stops startup before PostgreSQL opens the existing
cluster. Never fabricate or edit this marker to bypass the guard. Older alpha
clusters without a marker require a logical backup made with their original image
and restoration into a fresh volume with the new image, retaining the matching
encryption keys. This is particularly important when the image changes between
Debian/glibc and Alpine/musl: the PostgreSQL major version alone does not establish
physical-file compatibility.

Before an upgrade, take a backup, record the current release, and read migration
notes. Reuse the state/project only when the release explicitly supports the
existing physical database platform and schema; otherwise restore into a fresh
installation. Do not assume older application code can read a newer schema.
Rolling back safely may require restoring the pre-upgrade database **and its
matching private state** into a fresh installation. Never run `compose down -v`
as an upgrade step; it deletes the persistent data volume, including messages and keys.

Rootless Podman installations need their user service/session configured to survive logout and host reboot. Choose an appropriate systemd user service/Quadlet and enable lingering only for the account intended to host the service. Docker's daemon must be enabled for reboot startup. `restart: unless-stopped` restarts the exited container while the runtime is available; it does not keep a sleeping laptop or stopped runtime online.
