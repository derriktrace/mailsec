# Public alpha preparation and release checklist

This is the maintainer checklist for `0.4.0-alpha.8`. Local preparation does not
publish anything. The intended GitHub owner is `derriktrace`, and the planned
repository and registry locations are `derriktrace/mailsec` and
`ghcr.io/derriktrace/mailsec`. Their availability, a registry image digest, and a
signing identity have not been established by this source checkout. The regular
CI does not publish. A separate guarded workflow can publish an image only after
an explicit maintainer dispatch on `main` and a successful exact-commit CI run;
it has not been run on GitHub. Creating a release/tag remains a separate action.

## Audience and promises

The first alpha targets technical self-hosters on supported Linux x86-64 systems.
They can connect their own or consenting loved ones' personal Gmail/Workspace
mailboxes to one administrative console. It is post-delivery monitoring, with
optional reversible Gmail labels/quarantine. It is not a gateway, an independent
family-member permission system, or an MSP product.

Require enabled Landlock ABI 6+, Compose, Python 3.10+ for the installer, roughly
8 GiB of available RAM, protected persistent storage, and an always-running host.
A NAS advertising Docker support is insufficient. UGREEN and other NAS models,
ARM, and Docker Desktop remain unverified until tested on those exact platforms.
Do not weaken inspection isolation to expand the support matrix. An older NAS can
host a supported Linux VM if its hardware and virtualization support allow it.

The model server is optional and external. Users supply Google OAuth credentials
and, if selecting Jev, their own provider key. Before model requests they must
explicitly accept the provider/destination disclosure. Self-hosting the application
does not keep Jev analysis on that host; recipient identities and content can go
to TypeSafe. See [data sharing](data-sharing.md). Google authorization/testing-mode
limitations are explained in the [Google guide](gmail-setup.md). URL reputation /
Safe Browsing activation is excluded. Never advertise 99% detection or imply that
model confidence measures accuracy. Explain monitoring-first defaults and the
limits of static scanning in the release notes.

## Local source checks

From a reviewed source tree, use a disposable environment and database:

```sh
python3 scripts/check_public_alpha.py
ruff check --no-cache mailsec tests scripts
python -m pytest -q -m 'not live'
node tests/ui-smoke.mjs
node tests/questions-ui-smoke.mjs
```

The readiness checker is read-only and local-only: it checks package/runtime/image
version consistency, required source files, local documentation links, and an
export manifest if present. It does not run tests, scan dependencies, contact any
service, initialize Git, build/start containers, touch a mailbox, or prove release
safety. Node 22+ and Chromium are required for the browser suite. Set
`CHROMIUM_PATH` if needed. Configure PostgreSQL tests only against a disposable
database; never reuse a personal installation's database or credentials.

Record the complete test count, every skip and its reason, browser report, and
source-security findings. Run dependency audits and a redacted secret scan against
the exact selected source. Retain raw findings and describe applicability; do not
hide findings or alter package metadata to make scanner counts look better.
The GitHub workflow also runs these classes of checks, but its existence does not
establish a successful hosted run. A successful local run is not a hosted CI result.

## Create an unpublished source candidate

Use the allowlisted exporter rather than copying this development directory. It
omits live runtime state, private pilot files, mail corpora, credentials, and prior
release outputs; it also refuses symlinks, binary sources, credential patterns,
and missing required files. Gitleaks must be installed locally. Keep a private
marker file of deployment identities outside the exported tree.

```sh
python3 scripts/export_release.py --help
```

Supply a **new, nonexistent destination** for each candidate and use the private
marker check. Read the printed archive hash and verify the archive and
`RELEASE_MANIFEST.json` independently. Rerun relevant checks against the exported
tree, not only the private working source. The exporter neither initializes a
repository nor uploads anything. Keep validation reports next to the archive,
separate from the archive being hashed, so evidence cannot self-reference its hash.

Never initialize a public repository from an old private deployment or its Git
history. Begin with the reviewed export, inspect every selected file and tracked
history, and keep `.selfhost*`, mail, tokens, backups, screenshots of actual mail,
and any identity-specific evaluation inputs private. Synthetic fixtures should be
clearly marked. Retain Derrik Trace's authorship in package metadata, NOTICE, and
README, Apache-2.0 licensing, and all third-party/source-license notices.

## Build and verify the exact container locally

Build only from the exported source and tag it with the candidate's version.
Record the actual immutable image/config identity and source archive SHA-256.
Keep build provenance, the source manifest, native corresponding sources, SBOM,
raw vulnerability/secret scans, and scoped dispositions. Findings tied to a prior
image digest do not automatically apply to a new image. Regenerate the image's
attestations; do not copy an earlier image's VEX as if it scanned this candidate.

Use an isolated state directory, project name, and port, with no private mailbox
credentials initially. Verify one container, actual healthcheck, startup scanner
readiness, benign/static OCR/QR/PDF fixtures and uncached EICAR, strict process/
filesystem/network denial, synthetic analysis, restart persistence, duplicate
prevention, and backup/restore with matching keys. The frozen source's test run
and a preceding image's run are different evidence; identify both precisely.

Also exercise the prebuilt-image installer with a fully qualified immutable
registry digest: pull/start without compilation, saved-reference reuse, refusal
of mutable tags or malformed digests, visible pull failure without source
fallback, deliberate `--no-pull` startup from an already available exact image,
and explicit `--build-from-source` switching. Use synthetic state and the same
kernel/isolation requirements. No registry name is hardcoded before ownership is
chosen. A local archive test does not establish a successful fresh public pull.

On an explicitly authorized test mailbox, verify real OAuth refresh, historical
and incremental import, one harmless label/move operation, readback, and exact
undo. Retain original state, avoid sending notifications during acceptance, and
preserve unrelated labels and Spam/Trash state. A mocked Gmail test is not live
write proof. Do not migrate an existing mailbox simply to run a public release
check. Follow [migration](migration.md) for any separately authorized upgrade.

Verify data-sharing disclosure and the consent boundary before a release: new
install and upgrade without acceptance must make no provider calls; neither a
saved/environment key nor Google OAuth can auto-grant. Acceptance alone must
allow synthetic setup probes without resuming mail/comparisons; only explicit
tested/saved provider and masking settings can enable them. Check provider/destination/
document binding, probe and comparison gates, per-request revocation, retained
history and a visible resume path. Test both Jev and local/compatible destinations.
Verify the default-off recipient masking option, replacement of known addresses in
body/extracted content/URLs/questions, unchanged original/local evidence, and
prominent accuracy and remaining-identifier warnings. Accepting sharing must still
be required when masking is enabled. Record exact candidate results separately.

Test the question editor end to end: plain text copy of all three bundles without
mail/provider/history data, valid/invalid paste validation, unchanged content on
paste failure, unsaved edits after validation with no provider call or persistence,
immutable draft, rejected schema/choice changes, active/draft comparison with synthetic input, error handling, activation
only for the exact tested draft/provider/baseline, history, restore-defaults,
restart persistence, and a subsequent new analysis using the selected revision.
Confirm tests did not change message verdicts or Gmail state.

## Documentation and publication gates

Before approving public publication:

- Have someone follow the exported installation guide on a fresh supported host
  without private development context. Confirm the first-run walkthrough, model
  switching, Google setup, import bounds, passive defaults, diagnostics, and token
  retrieval. Record the host/kernel/runtime and any unresolved friction.
- Review [self-hosting](self-hosting.md), [Gmail setup](gmail-setup.md),
  [local models](local-models.md), [data sharing](data-sharing.md), [question editing](detection-questions.md),
  [architecture](architecture.md), [migration](migration.md),
  [validation](release-validation.md), [security](../SECURITY.md), and
  [contributing](../CONTRIBUTING.md). Verify documentation links in the export.
- Confirm that `derriktrace/mailsec` and `ghcr.io/derriktrace/mailsec` are the
  actual repository and registry namespace. Enable GitHub private vulnerability
  reporting and set an accurate project description/topics. Review authorship
  and license notices before publishing.
- Keep the initial public image limited to an architecture that was actually
  checked. Put the exact published digest, ready-to-run install command, and
  attestation verification identity in the versioned GitHub Release notes. The
  source checkout deliberately keeps a digest template to avoid changing the
  image's input after its digest is known. Keep source-build instructions available.
- Run hosted CI on the exact repository revision before calling it passed. Require
  the Python, browser, dependency, source-security, secret, and container gates.
- When publication is separately approved, publish a versioned prerelease and
  immutable image digest, not just a mutable `latest` tag. Add the real repository
  and revision OCI labels, SBOM/provenance, checksums, source/corresponding-source
  links, supported architecture, and explicit alpha limitations. Sign the image
  and checksum/provenance artifacts with the chosen maintainer identity; publish
  verification instructions naming that exact identity. A checksum alone does
  not authenticate its publisher.
- Confirm a fresh pull/import works, then announce only measured behavior and
  tested platforms. Keep a rollback/migration policy and a place for sanitized bug
  reports. Do not upload real mail when asking for detection feedback.

A local Docker save archive can be imported privately before a registry exists.
Keep its checksum beside it and verify the loaded image's identity. This is a
local delivery format, not proof of a published or signed container image.
No checklist step authorizes publication automatically.
