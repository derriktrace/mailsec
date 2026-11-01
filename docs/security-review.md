# Security hardening and alpha.8 review scope

An earlier unpublished `0.4.0-alpha.8` candidate, before the GitHub publication
metadata and guide updates, has local source and image validation. Its source
archive SHA-256 is
`1846944fe9c81e21699d1bf10f1014c639e61cbed6f8e92c82350265886f054b`;
its built Linux amd64 image config is
`sha256:b4c380049d4bc33a6cab5e7d00bd932d33413fab89b2096040b378f13eb17d5b`.
That exported source passed 1,079 Python tests with 21 skips, plus Ruff, a local
consistency check, Gitleaks, and private-marker checks. The exact image became
healthy in a disposable single-container installation and detected raw and
attached EICAR test signatures. These checks do not measure phishing accuracy.

Trivy reported zero vulnerability matches and zero secrets for that exact image
with its locally available database. An independent Grype scan reported 20 raw
matches, including one Critical and five High. The candidate's retained
dispositions mark 15 as fixed by verified source patches and five as not affected
by the tested execution paths. The Critical GLib match concerns a GIO D-Bus API
not called by the application or linked by tested scanner executables; the five
High Tesseract matches concern fixes in the pinned upstream source revision.
These are scoped assessments, not a claim that the image has zero risk. Raw
reports, patch provenance, SBOM, and unsigned image-scoped VEX are retained with
that private candidate's `security-evidence/`. This checkout's final image needs
its own identity, scans, and dispositions in release validation assets; the older
image's results must not be reassigned to a new build. Hosted GitHub CI, image
signing, a fresh registry pull, and the target NAS are not yet verified.

The alpha.5 findings and hardening details below are historical background. They
do not replace the exact alpha.8 evidence.

The `0.4.0-alpha.2` baseline and subsequent `0.4.0-alpha.4` consent/masking candidate
were reviewed on 2026-10-18. The unpublished `0.4.0-alpha.5` candidate refreshes
the security build and prepares digest-pinned image installation. Its exact
source/image checks and raw reports are recorded separately with that candidate.
Earlier scans and dispositions are not silently re-scoped to
a new image. This is an engineering review
and reproducible security test record, not a certification or a guarantee against
unknown vulnerabilities. The final image identity, raw scans, software inventory,
and test results belong in the validation files beside the distributed archive.
A scan of a development image is not evidence for different distributed bytes.

## Dependency remediation

The previous Debian candidate reported 560 OS package/advisory matches, including
1 critical and 91 high matches. Merely updating that distribution left known
native-library problems. Merely switching distributions also proved insufficient:
the alternative vendor feed omitted upstream XML advisories.

The alpha.5 build uses digest-pinned Python 3.12.16 on Alpine 3.24, current signed
runtime packages, and checksum-verified source builds of libxml2 2.15.4,
PostgreSQL 18.6, Tesseract's pinned upstream revision
`565e3bd72a0ecc4814ccffbda3f17afcb40d75ef` (reporting 5.5.3), and ClamAV 1.4.6.
The OCR revision contains eight additional upstream security fixes; its eight
targeted regression executables run during the build, alongside the XML and
antivirus upstream suites. Native packages retain real APK metadata
and identify the local source build; no package database is deleted or renamed
to hide a finding.

Pillow, cryptography, and Psycopg's C extension are built against the shared
patched TIFF, OpenSSL, and libpq libraries. The build verifies the libraries
actually loaded by Python, cryptography, Pillow, and Psycopg. It rejects the
old binary Psycopg adapter and mismatched or older crypto/TIFF dependencies.
Image-build compilers, Rust tooling, and pip are absent from the runtime.
See [native provenance](../deploy/native/README.md) for exact versions, source
hashes, build recipes, preserved licenses, and corresponding source locations.

ClamAV's locked Rust graph updates rand 0.9.2 to 0.9.3. Its Cisco OneNote parser
fork receives a source backport for CVE-2026-46671, preserving the existing API.
Four Rust regression cases cover ordinary entries, traversal/absolute/Windows
paths, and escaping versus internal symlinks. A scanner relying only on the
unchanged upstream version may still match that advisory. Retain the raw match,
the exact patch/source evidence, and a narrow patched-status statement; do not
silence the package or represent a fork as an unmodified newer upstream release.

The pinned CPython standard library receives PSF fixes for IMAP/POP command
injection (CVE-2025-15366 and CVE-2025-15367) and cookie JavaScript injection
(CVE-2026-6019), plus the upstream response-framing grammar fix and follow-up for
`http.client` (CVE-2026-103995). Whole-file input/output and upstream-patch hashes
guard all four changed modules; checks exercise them without a network.
The interpreter reports its real 3.12.16 upstream version. The alpha.4 image used
3.12.15; its scans and tested digest remain historical. The Python update does
not make an earlier image's vulnerability review apply to the new one.

BusyBox retains all 44 Alpine distribution patches, the distribution config and
all 304 applets. A narrow CVE-2025-60876 backport rejects raw URL control bytes,
spaces and DEL before initial/proxy requests or redirected requests are sent.
Compiled-executable tests cover unsafe bytes, valid percent-encoded URLs and
redirects. The corresponding sources, config and recipes accompany the rebuilt
BusyBox, shell-provider and HTTPS-helper packages. Unchanged upstream versions
can produce version-only scanner matches; each disposition must be scoped to
the exact patched image, with the raw finding and source evidence preserved.

## Application and process boundaries

| Boundary reviewed | Change and verification |
| --- | --- |
| Initial email parsing | MIME object allocation and header counts are capped before evidence traversal; expensive structured headers are bounded before decoding. Lazy transfer-decoding defects are collected after both body and attachment decoding, and encoded header words are validated before decoding. Ambiguous base64 creates a material content gap: a model's clean or spam result requires review, and cannot authorize semantic quarantine. Valid wrapped base64 and unrelated MIME defects do not create this transfer gap. Image-focused HTML with unread embedded data images retains a material content gap; small decorations are neutral, and no embedded URI is executed or fetched. Untrusted image dimensions are bounded before integer conversion. Rejected Gmail originals remain retained with an error, never a clean verdict. Generated malformed-header tests cover six header families. |
| Console access | Every registered console API route is tested without credentials and with an invalid bearer token. Host/origin checks, streaming byte/time/concurrency limits, ambiguous-header rejection, safe validation errors, CSP, and HTTPS transport policy are exercised. |
| Proxy trust | Installer and supervisor reject wildcard components and whole-address-space CIDRs; arbitrary proxy headers cannot become trusted through a mixed list. |
| Model data sharing | Explicit owner acceptance binds the selected provider/canonical destination and disclosure version/hash; existing keys or older installs cannot auto-grant consent. Acceptance permits only synthetic setup probes; real analysis/comparisons wait for an explicit tested/saved provider and masking configuration. Queued processing waits, requests recheck consent and the current configuration stamp, revocation blocks later calls without claiming to recall in-flight data. Default-off known-recipient pseudonymization warns of accuracy loss and remaining identifiers; mandatory sharing disclosure remains. |
| Detection question changes | Only authenticated owners can save immutable wording-only drafts. Exact schema validation preserves IDs/types/choices. Activation binds a completed test to the saved draft, active baseline, and current provider; comparison evidence excludes prior classifications and does not queue mailbox actions. Bounded comparison leases, provider requests, and compare-and-swap activation prevent stale or overlapping changes. Restore-defaults appends a trusted-baseline revision without deleting history. |
| Browser rendering | Hostile sender names, subjects, bodies, and audit text remain inert text. Isolated Chromium checks record unexpected external requests, script dialogs, and CSP/runtime errors. |
| Document decoder | Mandatory seccomp and Landlock restrict filesystem access to public read-only runtime resources and private per-job scratch. Persistent caches, secrets, peer memory, and sibling jobs are inaccessible. |
| Peer availability | Parser and antivirus cannot signal peers, change peer resource limits/scheduling, create new namespaces, or escape their process group. Own resource limits and OCR-child termination still work. Restrictions survive child execution. |
| Antivirus | Clamd uses UID10002 with read-only signatures, private scratch, and no outbound connection initiation. Freshclam uses separate UID10005 and owns signature updates. Benign, raw EICAR, and archive EICAR probes verify scanning still works. |
| Cache integrity | Decoders receive no persistent cache handle. Only the trusted inspector parent owns message/AV cache operations. A new security epoch invalidates older message, document, and attachment AV entries. |
| Backups and migration | Dump, restore, and restored-row verification connect initially as the ordinary database owner. RESET ROLE cannot recover a superuser session. Restore requires an empty maintenance target; temporary password files remain private and are removed. |
| Database platform changes | Unknown or incompatible physical clusters are refused before PostgreSQL starts. Debian/glibc to Alpine/musl requires logical dump/restore into a fresh volume with matching encryption keys. |
| Provider connections | Environment proxies and redirects are disabled. Fixed-provider replies are bounded before decompression/JSON parsing. Custom model endpoints receive a strict whole-request deadline, DNS-answer validation, and pinned connections retaining original TLS hostname verification. |
| Model endpoint privacy | Internet endpoints require HTTPS. HTTP remains available for explicit private/loopback model servers. Metadata aliases, ambiguous numeric hosts, IPv6 transition routes, and mixed private/public HTTP DNS answers are rejected. |
| Optional reputation privacy | Known internal/private/scoped and alternate numeric URL spellings are withheld without resolving or visiting the email destination. Public path, query, and fragment remain intact when a lookup is explicitly configured. This review does not activate that provider. |
| Gmail writes | Authorization is rechecked at execution. Real adapter tests cover the six application-owned labels, read-only refusal, move semantics, conflict-aware undo, and stale action suppression. Automatic policy remains separate from explicit operator actions. |

All services use separate unprivileged identities, empty supplementary groups,
and no child capabilities. The supervisor retains only the capabilities required
for private storage initialization, identity changes, and service supervision.
The root filesystem is read-only, privilege gains are disabled, temporary storage
and process counts are bounded, and internal database/scanner ports are not
published. No Docker socket or host filesystem is mounted into the application.

## Verification and release gates

The release record must include full dependency scans from Trivy and an independent
scanner, the retained Rust dependency graph and native inventory, Python advisory
checks, all-severity source findings, a secret scan of the sanitized export, and
checksums of the source/image archives. Findings are not removed simply because
no package fix is reported. CI blocks every Trivy high/critical image match and
high-confidence medium/high source finding, retains its raw Trivy report and SBOM,
and runs regression tests against a disposable PostgreSQL database. The independent
Grype report and exact-image patch/not-affected dispositions are manual release
evidence; CI does not gate Grype matches or verify those dispositions automatically.

The exact-image acceptance also checks native image/PDF OCR and QR extraction,
EICAR scanning, filesystem/network/peer confinement, startup gating, synthetic
end-to-end analysis, correction history, restart persistence, duplicate handling,
and protected backup/restore. Synthetic protocol fixtures establish integration
behavior; they do not establish model accuracy. Tests on an earlier image or
mock Gmail responses are identified separately from final-image or live checks.

## Deployment requirements and remaining boundaries

Enabled Linux Landlock ABI6 or newer is mandatory, normally requiring Linux6.12+
and a compatible container seccomp profile. Unsupported hosts report unavailable
inspection and preserve queued work rather than weakening isolation. A new image
cannot upgrade a NAS kernel. The installer checks a local Linux host before
building; the container checks again on its actual host/VM. A UGREEN DXP4800 Plus
has the intended CPU architecture, but its installed UGOS/kernel must be checked.
NAS-specific installation and ARM support need their own validation.

All processes still share one container network namespace, resource budget, and
host kernel. Confinement reduces the impact of a native decoder compromise;
unknown kernel bugs, a compromised supervisor, or a trusted operator's access can
cross those boundaries. Email and analysis reside in the private data volume;
backups include sensitive email and matching encryption keys and must be protected.
This release is for a trusted operator, not mutually hostile tenants.

Fixed Google/Jev/NVD destinations have TLS verification, socket timeouts, byte
caps, and elapsed checks per raw body chunk. Custom model servers additionally
have cancellable whole-request deadlines. Lexical URL privacy checks cannot
identify every private service behind a public-looking split-DNS name; Mailsec
intentionally does not resolve arbitrary email destinations merely to classify
that distinction. Gmail acts after delivery, and no scanner or model result
proves an email safe. No 99–100% detection-accuracy claim is made.

Repeat the scans, upstream advisory review, and actual-image tests whenever the
base image, native library, confinement policy, dependency lock, or parser changes.
See [the security policy](../SECURITY.md) for incident handling and deployment scope.
