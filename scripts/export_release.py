#!/usr/bin/env python3
"""Export an allowlisted public source tree without touching a running installation.

This never initializes Git, uploads files, deploys, or copies local configuration.
The default export also requires a local Gitleaks executable. Supply private
markers in a local file (one address/domain/host per line) to reject deployment
identities without embedding those identities in public source.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 20 * 1024 * 1024
REQUIRED_FILES = (
    'README.md', 'LICENSE', 'NOTICE', 'THIRD_PARTY_NOTICES.md', 'CHANGELOG.md',
    'SECURITY.md', 'CONTRIBUTING.md', 'pyproject.toml', 'requirements.lock',
    'requirements-inspection.lock', 'Dockerfile.selfhost',
    '.dockerignore', 'selfhost.sh', 'compose.selfhost.yaml',
    '.github/workflows/ci.yml', '.github/workflows/publish-alpha-image.yml', '.github/dependabot.yml',
    'docs/self-hosting.md', 'docs/architecture.md', 'docs/analysis-pipeline.md', 'docs/gmail-setup.md', 'docs/local-models.md', 'docs/migration.md',
    'docs/security-review.md', 'docs/release-validation.md', 'docs/detection-questions.md',
    'docs/public-alpha-release.md', 'docs/data-sharing.md',
    'deploy/selfhost/organization.example.yaml',
    'deploy/selfhost/clamd.conf', 'deploy/selfhost/freshclam.conf', 'deploy/selfhost/postgresql.conf',
    'deploy/selfhost/postgres-archive-key.asc',
    'deploy/native/sources.lock.json', 'deploy/native/README.md', 'deploy/native/onenote_path_policy.rs', 'deploy/native/patches.json', 'deploy/native/busybox.lock.json',
    'deploy/native/patches/CVE-2025-15366.patch', 'deploy/native/patches/CVE-2025-15367.patch',
    'deploy/native/patches/CVE-2026-6019.patch',
    'deploy/native/patches/CVE-2026-103995.patch',
    'deploy/native/patches/CVE-2026-103995-followup.patch',
    'deploy/native/patches/CVE-2026-88047.patch',
    'deploy/native/patches/CVE-2026-88048.patch',
    'deploy/native/patches/CVE-2026-88049.patch',
    'deploy/native/patches/CVE-2026-88050.patch',
    'deploy/native/patches/CVE-2026-88051.patch',
    'deploy/native/patches/CVE-2026-88052.patch',
    'deploy/native/patches/CVE-2026-88053.patch',
    'deploy/native/patches/CVE-2026-88054.patch',

    'scripts/setup_selfhost.py', 'scripts/export_release.py', 'scripts/check_public_alpha.py',
    'scripts/build_busybox.sh', 'scripts/patch_busybox_wget.py', 'scripts/check_busybox_wget.py',
    'scripts/fetch_native.py', 'scripts/patch_clamav_rand.py', 'scripts/patch_clamav_onenote.py', 'scripts/patch_clamav_loopback.py', 'scripts/build_native.sh', 'scripts/native_inventory.py', 'scripts/patch_python_stdlib.py',
    'scripts/container_runtime.py', 'scripts/container_health.py', 'scripts/container_backup.py',
    'scripts/migrate_sqlite.py', 'scripts/migrate_selfhost.py', 'scripts/action_counterexamples.py', 'scripts/publish_evidence_regression.py',
    'mailsec/__init__.py', 'mailsec/questions.json', 'mailsec/action_questions.json',
    'mailsec/authority_questions.json', 'mailsec/static/index.html', 'mailsec/static/app.js',
    'mailsec/static/onboarding.js', 'mailsec/static/question-editor.js', 'mailsec/static/style.css', 'tests/ui-smoke.mjs', 'tests/questions-ui-smoke.mjs', 'tests/privacy_helpers.py',
    'tests/fixtures/account_alert_cases.json', 'tests/fixtures/action_counterexamples/inputs.json',
    'tests/fixtures/action_counterexamples/expectations.json',
    'samples/banking-change.eml', 'samples/legitimate-code.eml', 'samples/marketing.eml',
    'samples/mfa-theft.eml', 'samples/receipt.eml', 'samples/unknown-login.eml',
)
# These tests exercise obsolete private-pilot TLS and split-container backup scripts.
EXCLUDED_TESTS = {'test_tls_bootstrap.py', 'test_backup_script.py'}
EXECUTABLES = {'selfhost.sh', 'scripts/export_release.py', 'scripts/setup_selfhost.py'}
PUBLIC_GITIGNORE = '''.venv/
.env
.env.*
!.env.example
.selfhost/
.selfhost-*/
.migration*
secrets/
data/
backups/
organization.yaml
*.db
*.db-*
*.dump
*.partial
*.pem
*.key
*.crt
*.p12
*.pfx
*.mbox
__pycache__/
.pytest_cache/
.ruff_cache/
*.egg-info/
build/
dist/
release/
release-staging/
*.tar.gz
'''
PUBLIC_ENV_EXAMPLE = '''# The self-host setup wizard writes private runtime configuration under .selfhost/.
# Start with ./selfhost.sh; do not copy credentials into source-controlled files.
# Prefer the console setup wizard for Gmail and model-provider configuration.
# Personal Gmail and Workspace accounts each require the owner's OAuth consent.
MAILSEC_ENFORCEMENT_MODE=passive
MAILSEC_NOTIFICATIONS_ENABLED=false
MAILSEC_REQUIRE_AUTH=true
MAILSEC_BIND_HOST=127.0.0.1
MAILSEC_ALLOWED_HOSTS=localhost,127.0.0.1
MAILSEC_PUBLIC_BASE_URL=http://localhost:8025
GOOGLE_OAUTH_REDIRECT_URI=http://localhost:8025/oauth/google/callback
MAILSEC_INITIAL_QUERY=-in:sent -in:drafts
MAILSEC_DECISION_PROVIDER=jev
# Optional model choices: jev, ollama, openai_compatible.
# Configure endpoint/model and keys in the console; do not commit key values.
# Google URL reputation is optional and is not configured by this example.
'''
CREDENTIAL_PATTERNS = {
    'google_api_key': re.compile(rb'AIza[0-9A-Za-z_-]{35}'),
    'google_oauth_client_secret': re.compile(rb'GOCSPX-[0-9A-Za-z_-]{20,}'),
    'github_access_token': re.compile(rb'(?:gh[pousr]_[0-9A-Za-z]{36,}|github_pat_[0-9A-Za-z_]{60,})'),
    'aws_access_key': re.compile(rb'(?:AKIA|ASIA)[0-9A-Z]{16}'),
    'private_key': re.compile(rb'-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----'),
    'provider_secret_key': re.compile(rb'\bsk-(?:proj-)?[0-9A-Za-z_-]{32,}'),
}


class ReleaseError(ValueError):
    """Safe message containing paths or rule names, never matching file contents."""


def read_regular(root: Path, name: str) -> bytes:
    path = root / name
    for parent in (path, *path.parents):
        if parent == root:
            break
        if parent.is_symlink():
            raise ReleaseError(f'Symbolic link is not exportable: {name}')
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_NONBLOCK', 0))
    except OSError:
        raise ReleaseError(f'Required source file is unavailable: {name}') from None
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ReleaseError(f'Expected a regular source file: {name}')
        if info.st_size > MAX_FILE_BYTES:
            raise ReleaseError(f'Source file exceeds release size limit: {name}')
        content = stream.read(MAX_FILE_BYTES + 1)
        if len(content) > MAX_FILE_BYTES:
            raise ReleaseError(f'Source file exceeds release size limit: {name}')
    try:
        content.decode('utf-8')
    except UnicodeDecodeError:
        raise ReleaseError(f'Unexpected binary source file: {name}') from None
    if b'\x00' in content:
        raise ReleaseError(f'Unexpected binary source file: {name}')
    return content


def scan_content(name: str, content: bytes, private_markers: tuple[bytes, ...]):
    for rule, pattern in CREDENTIAL_PATTERNS.items():
        if pattern.search(content):
            raise ReleaseError(f'Credential pattern ({rule}) found in {name}; value redacted')
    lowered = content.lower()
    if any(marker in lowered for marker in private_markers):
        raise ReleaseError(f'Private deployment marker found in {name}; value redacted')


def collect_files(source: Path, private_markers: tuple[bytes, ...] = ()) -> dict[str, bytes]:
    names = set(REQUIRED_FILES)
    for name in ('mailsec', 'tests'):
        directory = source / name
        if directory.is_symlink():
            raise ReleaseError(f'Symbolic source directory is not exportable: {name}')
        for path in directory.rglob('*'):
            relative = path.relative_to(source)
            if '__pycache__' in relative.parts:
                continue
            if path.is_symlink():
                raise ReleaseError(f'Symbolic link is not exportable: {relative.as_posix()}')
            if name == 'mailsec' and path.suffix == '.py':
                names.add(relative.as_posix())
            elif (name == 'tests' and path.parent == directory and path.name.startswith('test_')
                  and path.suffix == '.py' and path.name not in EXCLUDED_TESTS):
                names.add(relative.as_posix())
    files = {}
    for name in sorted(names):
        content = read_regular(source, name)
        if name.startswith('samples/') and b'X-Mailsec-Synthetic: true' not in content:
            raise ReleaseError(f'Only explicitly synthetic sample mail may be exported: {name}')
        scan_content(name, content, private_markers)
        files[name] = content
    # Never copy an existing default Dockerfile/compose, .env example, gitignore, or org file
    # from a private deployment. These are public release-specific replacements.
    files['compose.yaml'] = files['compose.selfhost.yaml']
    files['Dockerfile'] = files['Dockerfile.selfhost']
    files['.gitignore'] = PUBLIC_GITIGNORE.encode()
    files['.env.example'] = PUBLIC_ENV_EXAMPLE.encode()
    if sum(map(len, files.values())) > MAX_TOTAL_BYTES:
        raise ReleaseError('Selected source exceeds the total release size limit')
    return files


def scan_gitleaks(stage: Path, executable: str):
    with tempfile.TemporaryDirectory(prefix='mailsec-release-scan-') as directory:
        report = Path(directory) / 'report.json'
        try:
            result = subprocess.run([
                executable, 'dir', str(stage), '--redact', '--no-banner',
                '--report-format', 'json', '--report-path', str(report),
            ], capture_output=True, timeout=120, check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise ReleaseError('External secret scanner could not complete; no release archive created') from None
        if result.returncode:
            raise ReleaseError('External secret scanner rejected the staged tree; no release archive created')


def export_release(source: Path, destination: Path, *, private_markers=(), gitleaks: str | None = None):
    if source.is_symlink():
        raise ReleaseError('Source root must not be a symbolic link')
    source = source.resolve()
    destination = destination.absolute()
    archive = destination.with_name(destination.name + '.tar.gz')
    if destination.exists() or destination.is_symlink() or archive.exists() or archive.is_symlink():
        raise ReleaseError('Release destination or archive already exists; choose a new path')
    if not destination.parent.is_dir():
        raise ReleaseError('Release destination parent must already exist')
    executable = gitleaks or shutil.which('gitleaks')
    if not executable:
        raise ReleaseError('Install Gitleaks or provide --gitleaks; no unscanned archive will be created')
    markers = tuple(value.lower() for value in private_markers if value)
    files = collect_files(source, markers)
    with tempfile.TemporaryDirectory(prefix='.mailsec-export-', dir=destination.parent) as directory:
        stage = Path(directory) / destination.name
        stage.mkdir(mode=0o700)
        for name, content in files.items():
            target = stage / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
            target.chmod(0o755 if name in EXECUTABLES else 0o644)
        scan_gitleaks(stage, executable)
        manifest = {
            'format': 1,
            'purpose': 'Sanitized source export; no upload, deployment, or accuracy claim',
            'checks': {'credential_patterns': 'passed', 'private_marker_count': len(markers), 'gitleaks': 'passed'},
            'files': [{'path': name, 'sha256': hashlib.sha256(content).hexdigest(), 'bytes': len(content)}
                      for name, content in sorted(files.items())],
        }
        files['RELEASE_MANIFEST.json'] = (json.dumps(manifest, indent=2) + '\n').encode()
        (stage / 'RELEASE_MANIFEST.json').write_bytes(files['RELEASE_MANIFEST.json'])
        # All validation finishes before any final destination is created.
        os.rename(stage, destination)
    descriptor = os.open(archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, 'wb') as output:
            with gzip.GzipFile(filename='', fileobj=output, mode='wb', mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode='w') as bundle:
                    for name, content in sorted(files.items()):
                        info = tarfile.TarInfo(destination.name + '/' + name)
                        info.size = len(content)
                        info.mode = 0o755 if name in EXECUTABLES else 0o644
                        info.uid = info.gid = info.mtime = 0
                        info.uname = info.gname = ''
                        bundle.addfile(info, io.BytesIO(content))
    except BaseException:
        archive.unlink(missing_ok=True)
        raise
    return {'files': len(files), 'bytes': sum(map(len, files.values())),
            'staging_directory': str(destination), 'archive': str(archive),
            'archive_sha256': hashlib.sha256(archive.read_bytes()).hexdigest(), 'gitleaks': 'passed'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=ROOT)
    parser.add_argument('--output', type=Path, required=True, help='New directory; also produces PATH.tar.gz')
    parser.add_argument('--private-markers-file', type=Path, help='Local UTF-8 file, one private address/domain/host per line')
    parser.add_argument('--gitleaks', help='Path to the locally installed Gitleaks executable')
    args = parser.parse_args()
    try:
        markers = []
        if args.private_markers_file:
            with args.private_markers_file.open('rb') as stream:
                content = stream.read(65537)
            if len(content) > 65536:
                raise ReleaseError('Private marker file exceeds size limit')
            markers = [line.strip() for line in content.splitlines() if line.strip() and not line.startswith(b'#')]
            if any(len(value) < 4 for value in markers):
                raise ReleaseError('Private markers must contain at least four bytes')
        result = export_release(args.source, args.output, private_markers=markers, gitleaks=args.gitleaks)
    except ReleaseError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except OSError:
        print('Release export failed during a filesystem operation; no existing deployment was changed', file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
