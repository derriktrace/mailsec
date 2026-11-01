# Contributing

Start with a focused issue or pull request describing the concrete behavior you
want to improve. Security reports follow [SECURITY.md](SECURITY.md). Use synthetic
or properly sanitized fixtures; do not attach personal mailbox exports, actual
OAuth clients, API keys, screenshots of private mail, or customer data.

## Local development

Python 3.12 on Linux is the initial tested runtime. Static-parser process tests
also require the system `libseccomp.so.2` library (`libseccomp2` on Debian/Ubuntu,
`libseccomp` on Fedora); the container installs it. Building the Psycopg extension
also requires a C compiler, Python development headers and PostgreSQL client
development files (`gcc python3-dev libpq-dev` on Debian/Ubuntu). Parser security
tests require enabled Landlock ABI6 or newer. From the source root:

```sh
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.lock -r requirements-inspection.lock
python -m pip install --no-deps -e .
python -m pip install 'pytest>=8,<10' 'ruff>=0.11,<1'
pytest -q -m 'not live'
ruff check mailsec tests scripts
node --check mailsec/static/app.js
node --check mailsec/static/onboarding.js
node --check mailsec/static/question-editor.js
node tests/ui-smoke.mjs
node tests/questions-ui-smoke.mjs
python scripts/check_public_alpha.py
```

The browser suite requires Node 22+ and a Chromium-based executable; set
`CHROMIUM_PATH` if it is not `/usr/bin/chromium-browser`. All browser data are
synthetic and its API fixture blocks actual provider or Gmail access. GitHub CI
uses Node 22 and the Ubuntu runner's Chrome for the same suite.

The ordinary tests use temporary SQLite databases and mocked providers. They do
not require Gmail authorization or a paid model API key. PostgreSQL tests are
opt-in locally: set `MAILSEC_TEST_POSTGRES_URL` to a disposable PostgreSQL database
with permission to create schemas. They isolate each test in a random schema and
remove that schema afterward. Never point tests at the production database.

Tests that need a real ClamAV daemon or a paid model call require their explicit
opt-in settings. Keep those settings off during routine development. The GitHub
workflow uses a disposable PostgreSQL service and never receives mailbox or model
credentials. A separate job builds the complete Docker image, verifies a single
database-only container, and rejects high/critical image vulnerabilities
with a checksum-verified Trivy release. All severity counts, including unfixed
findings, remain visible in its job summary. Full scanning readiness, restoration, and
mailbox authorization still need explicit integration testing.

## Review expectations

- Explain the user-visible change, its safety implications, and the meaningful
  checks you ran. Add a regression test when changing security boundaries,
  ingestion cursors, action idempotency, evidence handling, or detection policy.
- Keep previously imported originals and audit history intact. Schema changes
  must be compatible with documented backup and upgrade procedures. Question
  revisions and test results are audit data: never overwrite history. Preserve
  fixed IDs/types/answer keys and the exact-tested-draft activation guard.
- Keep datasets, expected labels, prior verdicts, and analyst feedback out of
  model inputs during blind evaluation. Report precision, recall, false positives,
  abstentions, and coverage separately; an apparent perfect score on a tuning
  set is not a production accuracy claim.
- Treat authenticated sender domains as evidence of domain control, not proof
  of affiliation with a brand. Missing enrichment is not proof of maliciousness.
  Do not fix false positives by adding private customer or personal allowlists.
- Keep email content inert in the UI. Do not introduce `innerHTML`, remote email
  images, automatic URL visits, or client-side handling of provider secrets.
- Preserve service-user separation, private file permissions, internal listeners,
  and strict resource limits. Do not claim that processes in one container have
  independent network or container boundaries. Any new provider
  integration needs explicit consent, bounded requests, safe error reporting,
  reconnect behavior, and tests for partial failures.
- Preserve explicit model data-sharing acceptance and its audit. A provider key,
  Google OAuth, an old release, or an environment variable must never auto-grant
  sharing. New request paths must enforce current destination/document acceptance
  before network activity; revocation and the selected masking mode must apply
  coherently to subsequent calls. Test upgrades and stale concurrent settings.
  Recipient masking is limited pseudonymization, not an anonymity promise.
- Update both dependency constraints and resolved lock files intentionally.
  Run dependency audits and the relevant tests after updating a dependency.
- For native updates, review [the source manifest](deploy/native/sources.lock.json)
  and [build provenance](deploy/native/README.md). Verify upstream advisories,
  corresponding sources, real package metadata and the final Cargo dependency
  graph as well as distro scan output. Never make an audit appear clean by
  removing package metadata, renaming a vulnerable dependency, or hiding an
  unresolved finding.
- Attribute third-party code, datasets, and assets and retain their applicable
  notices. State substantial AI assistance honestly in the contribution description.

## Release checks

Run the tests, dependency audits, and Gitleaks against the exact source to be
published. CI pins third-party actions to reviewed commit SHAs, runs with read-only
repository permission, and does not publish images or deploy automatically.
Keep publication, image signing, release notes, and license/attribution review as
explicit maintainer steps. A source export is not evidence that personal Gmail
consent, container startup, restoration, or real-world detection has been tested;
record those results separately.


The [public alpha release checklist](docs/public-alpha-release.md) describes the
local-only readiness check, allowlisted export, exact-artifact verification,
registry/signing preparation, and publication gates. It deliberately does not
create a repository, tag a release remotely, upload an image, or choose an account
for the maintainer. Do not add an automatic publish trigger to the CI workflow.
