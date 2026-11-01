# Native dependency provenance

The supported self-host image uses the digest-pinned official Python 3.12 Alpine
3.24 base in `Dockerfile.selfhost`. Python is 3.12.16. Signed Alpine repositories
supply runtime packages and security updates during each rebuild. The build keeps
APK package metadata; it does not remove package databases or suppress advisories.

The native source manifest pins exact HTTPS URLs, sizes and SHA-256 hashes. The
builder compiles upstream libxml2 2.15.4, PostgreSQL 18.6, Tesseract 5.5.3 plus pinned upstream security fixes and
ClamAV 1.4.6. The database and antivirus link libxml2 2.15.4. No old-ABI alias is
used. These programs are registered as local APK packages with version suffix
`-r100` and a description identifying the Mailsec source build; they are not
represented as signed Alpine vendor builds. Both their package versions and the
upstream source inputs remain available to inventory tools.

ClamAV's actual Cargo.lock graph receives a compatible dependency update: rand 0.9.2 becomes
0.9.3 to address GHSA-cq8v-f236-94qc. `patch_clamav_rand.py` verifies the replacement
crate, updates the lock entry and vendor checksums, and the scanner compiles with
its offline vendored dependencies. The final Cargo.lock is retained at
`/usr/share/mailsec-native/clamav/Cargo.lock`. Nested example/test lock files in
vendored crates are not the built ClamAV dependency graph.

Cisco's `onenote_parser` 0.3.1 fork also receives a source backport for
CVE-2026-46671. Its notebook filesystem helper now rejects path traversal,
absolute/Windows paths, invalid filename characters and existing symlink escapes
before opening referenced sections. The buffer API used by ClamAV is unchanged.
The original version remains 0.3.1; this does not pretend to be upstream 1.1.1.
`patches.json` records the upstream fix URL/hash, adaptation and modification
hashes. Four Rust regressions execute the exact policy module during the build.
A source-version scanner may still report this advisory; that finding requires
this specific patch evidence, never a blanket ignore rule.

Tesseract is built from upstream commit
`565e3bd72a0ecc4814ccffbda3f17afcb40d75ef`, whose version file still says 5.5.3.
That exact revision contains all eight fixes for CVE-2026-88047 through
CVE-2026-88054. The original upstream patches and their hashes are retained as
evidence; they are already included in this source and are not applied twice.
Eight security-test executables run during compilation, covering the affected
model deserialization paths. No upstream 5.5.4 release is claimed. Version-only
scanner findings must be evaluated against this explicit source revision.

ClamAV's numeric loopback listener additionally skips musl's `AI_ADDRCONFIG`
connectivity probes. The address remains fixed to 127.0.0.1 and uses numeric-only
resolution. All other upstream bind behavior is unchanged, and outbound-connect
denial stays enforced. The source hash and full modification recipe are retained
in `patches.json` and `patch_clamav_loopback.py`.

BusyBox is rebuilt from the pinned Alpine 1.37.0-r31 source recipe, all 44
distribution patches and its unchanged configuration, with an additional fix for
CVE-2025-60876. Initial/proxy URLs and absolute/relative redirect targets reject
raw control bytes, spaces and DEL before creating an HTTP request; percent-encoded
URLs continue to work. The rebuilt executable is tested against a local HTTP
server, and all 304 original applets must remain present. Its busybox,
busybox-binsh and ssl_client packages use the documented local revision r100.
All 56 source inputs and the complete modification/build recipe accompany the
image. This is an actual source fix, not removal of a command symlink.

The pinned CPython 3.12.16 standard library also receives exact PSF fixes for
CVE-2025-15366 (IMAP command injection), CVE-2025-15367 (POP command injection),
CVE-2026-6019 (JavaScript cookie output), and CVE-2026-103995 (HTTP response
framing), including its upstream optional-whitespace compatibility follow-up.
Original-file, upstream-patch and
resulting-file hashes must match before the build succeeds. The helper removes
stale bytecode and runs 97 offline behavior cases against the four installed modules.
Its version remains 3.12.16, and `python-stdlib-patches.json` records the actual
modified source hashes in the final image.

The XML upstream regression suite and ClamAV upstream tests run during the build.
Tesseract retains the English, Portuguese and Spanish 4.1.0 language models.
Training utilities, on-access host scanning and mail-server milter integration are
not Mailsec features and are not built. File OCR, image/PDF inspection, antivirus
stream scanning, archive scanning, database backup/restore, and SQL XML support
remain present. The three traineddata files are themselves installed unchanged.

Pillow, cryptography and the Psycopg C extension are built from pinned Python
versions against the updated shared TIFF, OpenSSL and libpq libraries. This
avoids private older copies inside binary wheels. The runtime contains no build
compiler, Rust toolchain, pip, or image-build credentials.

For the source-built components, original compressed archives (including ClamAV's
vendored Rust sources), the replacement rand crate, the full source manifest and
build/modification scripts accompany the binaries under `/usr/share/mailsec-native`.
Their source archives contain upstream license notices. Language-model notices
and licenses are available from their pinned upstream release. Other Alpine
packages retain their original licenses and their corresponding source recipes
are in the [Alpine aports repository](https://gitlab.alpinelinux.org/alpine/aports).
A downstream image publisher remains responsible for providing corresponding
source for any additional GPL/LGPL components it distributes.

Changing libc from an earlier Debian image to Alpine requires a logical PostgreSQL
dump/restore into a fresh volume. Never attach an existing Debian database volume
directly to this image. Follow the migration procedure and keep the old volume.

A zero result from a distro vulnerability feed is not proof that upstream native
libraries have no flaws. Review upstream advisories and the retained source graph
as well as the complete image scan. Rebuild and recheck these explicit pins when
upstream releases security fixes; do not silence a finding by renaming a package.
