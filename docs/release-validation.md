# Release validation

This defines the validation scope for `0.4.0-alpha.8`. See the versioned release's
separate validation assets for exact published source and image identities.
The preceding alpha.5 Fedora deployment was verified separately and is retained
as the rollback image. The earlier `0.4.0-alpha.4` candidate was locally verified on 2026-10-18 with
1,062 passing Python tests, three recorded skips, 161 browser checks, and synthetic
Docker acceptance including consent/masking and question history. Its separate
live upgrade preserved data while leaving model sharing paused for owner consent.
Those are historical results, not a claim that this candidate's refreshed image
and installation changes have already passed those gates. Exact
candidate hashes, current counts/skips, scans, consent/masking checks and outcomes
are recorded alongside each candidate's artifacts after verification. That
separate evidence avoids a self-referential archive hash.

A passing interface check means the control made the intended request and
represented its outcome correctly. It does not establish phishing accuracy,
successful writes to every Gmail account, or compatibility with every NAS.

## Console and provider behavior

| Feature | Evidence | Scope and remaining validation |
| --- | --- | --- |
| Console login, logout, authentication, origin checks, bounded uploads | HTTP security tests and disposable Chromium checks | Synthetic tokens and requests; no claim of a third-party penetration test |
| Dashboard counts, category filters, search, selected message, mobile layouts | Chromium fixtures; storage aggregate tests including persistent analyst overrides | Counts reflect effective categories; scan errors remain visible |
| Message assessment, probabilities, extracted text, evidence, history | Chromium fixtures; parsing and evidence tests | Email HTML, links, and remote content remain inert in the console |
| Analysis data-sharing consent and optional recipient masking | Disclosure/API/client/pipeline tests and isolated browser controls; exact candidate results recorded separately | Fresh explicit acceptance for existing installs, provider/destination/document binding, revocation and per-request checks, all-provider handling, optional default-off masking and accuracy/identity limitations; no implied provider retention promise |
| Detection question copy/paste, drafts, side-by-side test, activation, history, restore defaults | Dedicated revision/API/pipeline tests and isolated Chromium editor suite | Plain text full-bundle copy/paste, validate-only unsaved loading, fixed schema, exact-test/provider/baseline activation, read-only captured evidence, persisted history and explicit error states; record candidate results separately |
| Model setup and connection test | Mock provider/API tests; Chromium wizard; actual CPU Ollama synthetic run | Connection is not an accuracy test. Local run accepted two valid responses and rejected an invalid distribution; no fabricated verdict or normalization |
| Google client setup, import range, Monitor/Manage selection, connect/disconnect | Account/Gmail tests and Chromium wizard; real personal Gmail authorization in Monitor and Manage modes, import, and a user-selected label action | Each mailbox needs its own consent. One successful personal-account action does not prove every organization's authorization policies |
| Historical import, incremental history, duplicate prevention, quota backoff | Mock Gmail tests, database queue tests, real personal Gmail import | Permanently deleted mail and expired provider history cannot be reconstructed |
| Import, demo analysis, replay, retry state | HTTP/pipeline/worker tests and Chromium checks | Synthetic/demo data are distinguished from connected Gmail; replay retains original runs |
| Correct Clean/Spam/Suspicious/Phishing | API/storage/pipeline tests and Chromium controls | Updates console category/counts, retains original automated result, persists replay, and never adds the correction to inference evidence |
| Manual Gmail verdict label, optional move, cancel, undo | Mock Gmail action tests and Chromium controls; user-selected Phishing label confirmed by live Gmail readback, then a separate harmless label/move/undo operation on the final preceding alpha.2 image | Original state and Undo are retained. The selected phishing message was already in Spam and its existing Spam state was preserved. Live checks for this new candidate remain a separate acceptance check. Label change clears Review, preserves Quarantine and unrelated labels; mocked results are not live Gmail proof |
| Read-only and disconnected permission controls | Account/API tests and Chromium checks | Writes are disabled; policy selection alone does not grant permission |
| Automatic flag/quarantine and explicit release | Deterministic policy and mocked Gmail executor tests; Chromium confirmations | Applied outcome requires Gmail confirmation. Local estimated scores cannot authorize model-only quarantine |
| Notification uncertainty and recovery controls | Mock send/reconcile/action tests and Chromium checks | No unattended duplicate resend; actual notification delivery is distinct from mailbox mutation |
| Separate evaluation workspace | Workspace/API and Chromium tests | Synthetic workspace separation; it is not tenant-grade isolation or a second customer product |

Tests use synthetic subjects, addresses, model responses, and Gmail clients unless
explicitly described above as real. Mocked action tests include lost responses,
permission revocation, retries, concurrent workers, newer manual intent, undo
conflicts, and external Spam/Trash/Quarantine changes. The console independently
tests a saved correction followed by Gmail queue failure so partial success is
visible. Pending actions are never displayed as confirmed application.

## Runtime, inspection, and persistence

| Check | Evidence | Scope |
| --- | --- | --- |
| One container with API, worker, PostgreSQL, inspector, antivirus/updater | Actual Linux x86-64 rootless Podman deployment | Separate users, empty supplementary groups, no child capabilities; scanners denied application/bootstrap credentials |
| Actual Docker runtime | Rootless Docker Engine 29.9.1, Compose 5.6.0, preceding immutable alpha.2 image | Native EICAR/seccomp, one synthetic analysis, zero connected accounts, restart, deduplication, and protected backup passed; no real mailbox used |
| Scanner readiness before worker startup | Supervisor tests and feature-image warm-up observation | Worker remained absent during 44 not-ready observations, then started with usable signatures; startup timeout fails visibly rather than claiming mail early |
| Antivirus | Fresh signatures and uncached synthetic EICAR detection in the image | EICAR is a test signature, not a real malware corpus or detection-rate measurement |
| Static PDF, Office, archive, image/OCR, QR inspection | Unit/integration fixtures and native-image probes | Bounded static extraction only; no detonation, browsing, or remote-image fetching |
| Static-parser network restrictions | Actual image socket probes and inherited-process tests | IPv4/IPv6/Unix sockets and socket pairs denied; local files work. HTTP inspector parent retains its required listener. The hardened antivirus accepts its numeric loopback listener but cannot initiate outbound connections |
| Service failure, restart, shutdown, persistent queue | Required-worker kill/restart, graceful stop, synthetic queued item and marker | Runtime restart policy tested; a merely unhealthy Docker container is not automatically restarted |
| Database correctness | Isolated PostgreSQL concurrency/lease/checkpoint tests | Test schemas are disposable; never point tests at a personal mailbox database |
| Backup and restore | Actual synthetic database-only restore with matching key | Original marker/message preserved; nonempty target and normal-runtime restore refused |
| Previous deployment migration | Actual PostgreSQL logical migration rehearsal, all public-table counts and canonical row hashes compared | Original keys recovered encrypted configuration. This does not authorize a live cutover or reuse an old snapshot after later writes |
| Source privacy and supply chain | Explicit export allowlist, private-marker scan, Gitleaks, manifest hashes; image vulnerability review | No personal messages, credentials, old state, or private pilot configuration belong in the public archive |

See [the image security review](security-review.md) for the baseline image review,
remaining native dependency findings, applicability assessment, and limitations.
Image scans report residual findings; the release makes no zero-vulnerability claim.

## Platforms and release gates

Linux x86-64 on Fedora with rootless Podman and actual rootless Docker Engine has
been exercised. The prior immutable alpha.2 image's evidence is a baseline;
this candidate's exact frozen-source build and checks must be recorded in its own
validation report. Do not re-scope a prior image's security dispositions to a new
image digest without repeating the applicable checks.
NAS installation, ARM, macOS/Windows Docker Desktop, public
registry publication, and a GitHub-hosted CI run are not established by the local
checks. The installer requires Compose, Python 3.10+, sufficient memory, persistent
local storage, and an always-running container engine; a NAS must meet those
requirements rather than merely advertise container support.

Before distributing a candidate: follow the [public alpha checklist](public-alpha-release.md), run the exported Python suite with inspection
dependencies installed, record every skip, run both browser suites, verify question-revision persistence, inspect the
container and current vulnerability report, verify backup recovery, and scan the
exact archive source for private material. Record artifact hashes separately from
the archive being hashed. Repeat relevant checks after further changes.

Safe Browsing/Web Risk activation, inline protection, a 99–100% accuracy claim,
family helper roles, MSP isolation, and Microsoft 365/IMAP are outside this alpha.
