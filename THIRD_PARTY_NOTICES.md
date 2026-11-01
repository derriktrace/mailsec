# Third-party components

The Apache-2.0 license covers original Mailsec source. Dependencies, base images,
model weights, and optional datasets keep their own licenses. This source release
does not include user mail, OAuth clients, API keys, model weights, or phishing corpora.

| Component | Role | License / source |
| --- | --- | --- |
| Python | Runtime | [Python licensing](https://docs.python.org/3/license.html) |
| FastAPI, Starlette, Uvicorn, HTTPX, Pydantic | API and validation | MIT / BSD licenses in installed distributions |
| SQLAlchemy, Psycopg, PostgreSQL | Persistence | MIT, LGPL, and [PostgreSQL license](https://www.postgresql.org/about/licence/) respectively |
| cryptography, Google auth libraries | Encrypted credentials and OAuth | Apache-2.0 / BSD; see installed distribution notices |
| ClamAV 1.4.6 | Local antivirus | GPL-2.0-only; checksum-verified source build with rand 0.9.3 patch; [corresponding upstream source](https://github.com/Cisco-Talos/clamav/tree/clamav-1.4.6) |
| libxml2 2.15.4 | Antivirus and database XML parsing | MIT; [upstream source](https://gitlab.gnome.org/GNOME/libxml2) |
| Poppler utilities | PDF rendering for OCR | GPL; [upstream source](https://poppler.freedesktop.org/) |
| Tesseract 5.5.3 and 4.1.0 language data | OCR | Apache-2.0; [engine source](https://github.com/tesseract-ocr/tesseract), [language models](https://github.com/tesseract-ocr/tessdata/tree/4.1.0) |
| pypdf, Pillow, zxing-cpp, defusedxml, oletools and dependencies | Static document/image inspection | Licenses retained in installed distributions; locked versions in `requirements-inspection.lock` |
| Alpine packages | Container operating system | Package-specific licenses and [corresponding source recipes](https://gitlab.alpinelinux.org/alpine/aports) |
| tldextract public suffix snapshot | Domain normalization | Library and Public Suffix List retain their own notices |

Images are built from the documented Dockerfiles and pinned Python package lists.
The one-container package bundles separate programs communicating over HTTP/TCP.
Signed Alpine repositories supply the operating-system packages. XML, PostgreSQL,
antivirus and OCR are compiled from the exact upstream source inputs recorded in
[the native source manifest](deploy/native/sources.lock.json). The image retains
their original compressed source archives, the patched rand crate, complete build
and modification scripts, and ClamAV's final dependency lock under
`/usr/share/mailsec-native`. Source-built packages retain real name/version/license
metadata in the APK database. Their `-r100` suffix identifies Mailsec's build,
rather than an official Alpine package revision. The rebuilt Psycopg C extension's
source archive is included as well. See [native build provenance](deploy/native/README.md)
for the exact build, patch and source locations.

Inspect the built image for exact package versions and retained notices. Publishing a combined
container image requires retaining dependency notices and fulfilling applicable
source-distribution obligations, particularly GPL/LGPL components; publishing this
repository's Apache-2.0 source does not relicense those components.

Hosted providers have separate service terms. A local model's weight license is
independent of the server software and Mailsec; the operator supplies that model.
The optional Phishing Pot evaluation support does not ship its corpus or claim its
messages are verified ground truth. Obtain any evaluation dataset directly from its
publisher and comply with its license and privacy restrictions.

The bundled Cisco `onenote_parser` 0.3.1 fork (MPL-2.0) has a Mailsec backport of
CVE-2026-46671 from upstream commit
[c9267b2](https://github.com/msiemens/onenote.rs/commit/c9267b2c96e2542be7e7b557d67318e81b733585).
The original source remains in the ClamAV archive; the complete modification
recipe, adapted MPL-2.0 path-policy source and checksums are in `deploy/native/`
and `scripts/patch_clamav_onenote.py`, and accompany the image binaries.

Tesseract uses pinned upstream revision
`565e3bd72a0ecc4814ccffbda3f17afcb40d75ef` (Apache-2.0), containing the eight
CVE-2026-88047 through CVE-2026-88054 fixes. Its exact source archive, upstream
patches, hashes and build recipe accompany the binaries. Its upstream version
remains 5.5.3; no unreleased version number is fabricated.

BusyBox 1.37.0 is rebuilt with the complete pinned Alpine 1.37.0-r31 configuration
and all 44 distribution patches, plus the Mailsec CVE-2025-60876 URL-validation
backport (GPL-2.0-only). The original archive, source/configuration, distribution
patches, ssl_client source, modification scripts and hashes accompany the image
in `/usr/share/mailsec-native/sources/busybox` and `build-tools`.

The CPython 3.12.16 standard library includes PSF upstream backports for
CVE-2025-15366, CVE-2025-15367, CVE-2026-6019 and CVE-2026-103995 (including
the HTTP response framing follow-up). The original upstream patches,
complete modification recipe and exact original/resulting hashes are retained
under `deploy/native/` and accompany the image. Python's license remains PSF-2.0.
