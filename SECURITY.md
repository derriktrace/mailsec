# Security policy

Mailsec is an early self-hosted release for one trusted operator. It is not an
independently certified security gateway or a multi-tenant hosted service. A clean
classification, antivirus result, or missing reputation match is not a guarantee
that a message is safe. There is no supported claim of 99% real-world accuracy.

## Reporting a vulnerability

Use the repository's **Security → Report a vulnerability** private reporting flow
when it is available. Do not post working credentials, mailbox contents, token
files, database backups, or exploitable details in public issues. If private
reporting is unavailable, open an issue asking the maintainer for a private
contact channel without including the vulnerability or private data. Before the
initial public release the maintainer must enable private vulnerability reporting.

Include the release or commit, affected component, a minimal reproduction using
synthetic messages, expected and observed behavior, and the potential impact.
Please test only systems and mailboxes that you own or are authorized to test.
No response-time guarantee or bug bounty is offered by this policy.

Security fixes target the latest release. Older alpha builds do not have a
separate maintenance branch; upgrade after reviewing release notes and backups.

## Deployment boundary

- Run the console on a private LAN or through a trusted VPN/reverse proxy with
  HTTPS. Do not expose its administration interface directly to the Internet.
  Use an explicit allowed-host list and a generated high-entropy console token.
  Non-loopback listeners reject missing or short tokens. A loopback listener
  placed behind a proxy still needs authentication enabled by its operator.
- The console token grants access to every mailbox and stored message in that
  installation. This is a single-owner administrator credential, not a family
  role or tenant boundary. Give access only to trusted operators with mailbox
  owners' consent. It is kept in browser tab session storage; clear it or close
  the tab when using a shared browser, and rotate it if exposed.
- Protect the host, container runtime, database volumes, backups, and secret
  files. The host administrator can access the data. Containers share the host
  kernel and are not a guarantee against escape.
- Publish only the authenticated API port. Database, inspector, and scanner ports
  must remain internal. Never mount the container engine socket or unrelated host
  directories into Mailsec.
- The single-container package uses separate service users and private data
  directories, but all services share a network namespace, filesystem view,
  resource budget, and kernel. The static MIME/document parser installs an
  inherited Linux seccomp filter before reading mail: socket operations,
  `io_uring`, and cross-process inspection calls are denied, including in its
  OCR/PDF children. Mandatory Landlock ABI 6+ confines filesystem access to public
  read-only runtime resources and one private per-message scratch directory, and
  prevents signals to the inspector parent or sibling jobs. Persistent cache
  access stays in the HTTP parent so an exploited decoder cannot poison later
  cached antivirus results. The parser cannot open application data, sibling
  caches, or `/proc` process-memory paths. Descendants are terminated when their
  job ends, including after normal parser exit. Missing restrictions stop parsing.
  The host needs enabled Landlock ABI 6 or newer (normally Linux 6.12+); older NAS
  kernels need a supported Linux VM or a different host, with no weaker fallback.
  The antivirus engine runs under a different UID from the signature updater.
  It can read signatures and serve its fixed TCP scan listener, but cannot modify
  signatures, signal the updater, initiate network connections, or read application
  data. The updater owns public signatures and retains Internet access; its scratch
  directory remains private. The inspector HTTP parent also retains network access.
  These restrictions are not a
  complete sandbox. Treat a native parser compromise as a potentially
  installation-wide incident. This is weaker isolation than separate restricted
  containers or VMs.
- The startup supervisor runs as container root with limited capabilities so it
  can prepare directories and start/restart children under different users. The
  API, worker, database, inspector, and scanner run under non-root users. Do not
  describe the package as an entirely non-root container. Use rootless container
  hosting where practical; maintain the runtime and host as part of the boundary.
- OAuth token-encryption keys are stored outside the database but in the same
  persistent volume. Keep a protected backup of both the database and matching
  keys; losing the keys prevents reuse of stored authorizations. The included
  backup contains both, so encrypt the archive before off-host storage. Database
  credential encryption does not protect against an attacker reading the whole
  volume, and it does not encrypt message data or backups.
- Do not enable automatic actions until the operator has checked behavior on
  representative mail. Quarantine is a reversible Gmail label and removal from
  Inbox; the message remains accessible through All Mail. Analysis occurs after
  delivery, so a recipient can open a message before analysis finishes.

## Data and model boundary

Emails, headers, HTML, attachments, QR contents, and model output are untrusted.
The console renders message evidence as text and does not load email HTML or
remote message images. The inspection service does bounded static extraction and
antivirus scanning; it does not execute attachments in a browser or sandbox.
The console authenticates before multipart parsing and bounds body size and
upload time, including requests without a trustworthy Content-Length.

**Jev sends selected email evidence to TypeSafe, a third party. This includes
mailbox and recipient addresses when present, full sender/reply identities,
subject/body content, complete URLs, extracted attachment/OCR/QR content,
authentication/scan observations, administrator context, and custom questions.
The evidence is not automatically anonymized.** Raw `.eml` originals and binary
attachments are not uploaded as model inputs; extracted content can nevertheless
contain sensitive personal data or secrets.

Optional recipient masking is off by default. It pseudonymizes known mailbox and
recipient addresses in the outbound model view, including matching occurrences
in text, URLs and questions. It can reduce detection accuracy and does not remove
all identifiers or guarantee anonymity. Original mail and local security evidence
remain intact. Bounded recipient collection/matching fails before dispatch when
it cannot complete safely; no unmasked fallback is allowed. Masking does not
bypass the data-sharing acceptance gate.

Explicit owner acceptance for the selected provider/destination and disclosure
version permits only synthetic setup probes. Mail analysis and question comparisons
remain blocked until the owner explicitly tests/saves the provider and selected
masking configuration. Each subsequent request checks the current configuration
authorization stamp; a stale client cannot continue with an old unmasked setting
after a masked configuration is saved. Existing installations and environment-supplied keys do
not grant acceptance automatically. The gate is checked for each request and
must not be bypassed by a cache hit, background worker, or stale settings snapshot.
Revocation blocks later requests; it cannot recall a request already sent or
provider-held data. Acceptance records are audit data, not permission to change
Gmail protection settings or a substitute for the mailbox owner's permission.
See [data sharing and consent](docs/data-sharing.md) for the exact categories and
local-model distinction. No provider retention, training-use, or deletion promise
is made by Mailsec.

Cloud model providers receive the evidence needed for the configured analysis.
Review provider retention and data-use terms before connecting a mailbox. A local
model option is private only to the extent that its configured endpoint and
deployment are private. Configure only model endpoints you trust; an endpoint
receives email evidence. Model outputs must pass validation and policy gates
before they can influence mailbox changes. Never treat text embedded in an email
as an instruction to the application.

Question copy/paste contains the three bundles only. Validation uses the same
fixed schema and text/size limits as a saved draft, without provider calls,
persistence, or activation. Pasted content remains inert text and loads as
unsaved editor content. Questions can contain facts entered by the owner, so
review their wording before sharing the clipboard text with anyone else.

The authenticated owner can edit question instructions and criteria. Fixed question
IDs, types, and answer keys remain application contracts. Saved revisions are
immutable, and activation requires a completed comparison for the exact draft,
provider configuration, and active baseline. Restoring shipped defaults preserves
history. Comparison tests can transmit selected private evidence to the configured
provider and retain it in protected database records. They do not update messages
or Gmail actions. Editing questions does not change the deterministic action
policy, permission checks, or local-model quarantine restrictions. Evaluate changes
independently: a completed test is not proof of detection accuracy.

Google URL reputation is optional and remains unconfigured in this release.
When separately configured, it may transmit original eligible complete URLs,
including identifiers in query strings or fragments. Decision-provider recipient
masking does not cover those reputation requests. It is not required to run the
application, and absence of reputation evidence must remain visible.

## Maintenance and incident response

Keep application images, the container host, antivirus signatures, and model
configuration current. Review provider/worker health; a running web page alone
does not establish that scanning is healthy. The container readiness check also does not prove a
live worker is making progress; check queue counts, heartbeats, mailbox checkpoints,
and recent analyses. Retry queues preserve unsuccessful
work rather than silently classifying it as safe.

The base image is digest-pinned, Python dependencies are locked, and the ClamAV
source archive and build inputs are version/checksum-pinned. Those pins require deliberate review
and updates; signature downloads do not update the scanner executable. Rebuilding
installs currently available operating-system security updates from the configured
signed repositories. Record the built image digest and installed package versions
when auditing or distributing an image.

CI reports all Trivy image vulnerability counts and fails on every Trivy
high/critical match, including findings without a reported fix. The independent
Grype image report is reviewed separately for each release; its raw matches,
including any high/critical matches, remain visible with image-specific patch
or not-affected dispositions. CI does not automatically gate Grype findings or
validate those dispositions. Other severities and source findings still require
review. A passing gate is not a claim of zero vulnerabilities or proof that a
vulnerable library path cannot be reached. Evaluate scanner matches against the
actual installed component and upstream/vendor advisories; document any
applicability exception narrowly instead of suppressing a whole severity category.

The [initial container review](docs/security-review.md) records the dated image
scan, inspected parser paths, and remaining dependency concerns. It is an alpha
engineering review, not a claim that every reported issue is harmless.

Back up and test restoration before upgrades. Do not publish raw mail, dumps,
screenshots, credentials, or local evaluation reports with the source tree. CI
includes dependency and secret scans, but automated scans cannot prove a release
is free of confidential data or vulnerabilities.

If a credential or host is compromised, stop mailbox actions, revoke affected
Google authorizations and provider keys, rotate console and encryption secrets as
appropriate, preserve private audit records, and reconnect accounts on a trusted
installation. Disconnecting an account does not erase previously imported mail
or backups; operators must apply their own retention and deletion policy.
