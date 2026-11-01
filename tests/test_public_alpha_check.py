"""The offline release checker detects drift and never changes a candidate tree."""
import ast
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/check_public_alpha.py'
EXPORT_AST = ast.parse((ROOT / 'scripts/export_release.py').read_text())
REQUIRED = ast.literal_eval(next(node.value for node in EXPORT_AST.body
    if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == 'REQUIRED_FILES'
                                         for target in node.targets)))


@pytest.fixture
def candidate(tmp_path):
    for name in (*REQUIRED, 'mailsec/config.py', 'mailsec/api.py'):
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('Public source fixture\n')
    (tmp_path / 'pyproject.toml').write_text('[project]\nversion = "0.4.0a5"\n')
    (tmp_path / 'mailsec/config.py').write_text('VERSIONS = {"engine": "0.4.0-alpha.5"}\n')
    (tmp_path / 'mailsec/api.py').write_text('app = FastAPI(version="0.4.0-alpha.5")\n')
    (tmp_path / 'compose.selfhost.yaml').write_text('image: localhost/mailsec-selfhost:0.4.0-alpha.5\n')
    (tmp_path / 'Dockerfile.selfhost').write_text('LABEL org.opencontainers.image.version="0.4.0-alpha.5"\n')
    (tmp_path / 'README.md').write_text('# Mailsec 0.4.0-alpha.5\n[Guide](docs/detection-questions.md)\n')
    (tmp_path / 'CHANGELOG.md').write_text('# 0.4.0-alpha.5\n')
    (tmp_path / '.github/workflows/ci.yml').write_text('''permissions:
  contents: read
image: localhost/mailsec-selfhost:0.4.0-alpha.5
node-version: '22'
run: node tests/ui-smoke.mjs
run: node tests/questions-ui-smoke.mjs
run: ./selfhost.sh --project-name mailsec-selfhost-ci --database-only
run: docker ps -aq --filter label=com.docker.compose.project=mailsec-selfhost-ci
run: docker compose -p mailsec-selfhost-ci down --volumes --remove-orphans
''')
    return tmp_path


def run(candidate, *options):
    result = subprocess.run([sys.executable, str(SCRIPT), '--source', str(candidate), *options],
                            capture_output=True, text=True, timeout=10, check=False)
    return result.returncode, json.loads(result.stdout)


def add_manifest(candidate):
    files = [{'path': path.relative_to(candidate).as_posix(), 'bytes': path.stat().st_size,
              'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
             for path in sorted(candidate.rglob('*')) if path.is_file()]
    (candidate / 'RELEASE_MANIFEST.json').write_text(json.dumps({'checks': {'gitleaks': 'passed'}, 'files': files}))


def test_offline_checker_accepts_consistent_source_and_writes_nothing(candidate):
    before = {path.relative_to(candidate): path.read_bytes() for path in candidate.rglob('*') if path.is_file()}
    code, report = run(candidate)
    assert code == 0 and report['ok'] and report['checks_passed'] >= 10
    assert report['version'] == '0.4.0-alpha.5'
    assert before == {path.relative_to(candidate): path.read_bytes()
                      for path in candidate.rglob('*') if path.is_file()}


@pytest.mark.parametrize(('name', 'replacement', 'reason'), [
    ('mailsec/config.py', 'VERSIONS={"engine":"0.4.0-alpha.2"}', 'runtime engine matches package version'),
    ('compose.selfhost.yaml', 'image: localhost/mailsec-selfhost:0.4.0-alpha.2', 'Compose image matches package version'),
    ('README.md', '# 0.4.0-alpha.5\n[Missing](docs/no-guide.md)', 'all local Markdown link targets exist within source'),
    ('README.md', '# 0.4.0-alpha.5\n[Escape](../private.md)', 'all local Markdown link targets exist within source'),
    ('.github/workflows/ci.yml', 'run: docker push private.invalid/image', 'CI does not publish containers or releases'),
])
def test_offline_checker_detects_drift(candidate, name, replacement, reason):
    (candidate / name).write_text(replacement)
    code, report = run(candidate)
    assert code == 1 and not report['ok'] and reason in report['failures']


def test_ci_rejects_a_project_name_the_installer_will_refuse(candidate):
    path = candidate / '.github/workflows/ci.yml'
    path.write_text(path.read_text().replace('mailsec-selfhost-ci', 'mailsec-ci'))
    code, report = run(candidate)
    assert code == 1 and 'CI project name is accepted by the installer' in report['failures']


@pytest.mark.parametrize('part', ['lookup', 'cleanup'])
def test_ci_rejects_container_lookup_or_cleanup_for_another_project(candidate, part):
    path = candidate / '.github/workflows/ci.yml'
    old = ('label=com.docker.compose.project=mailsec-selfhost-ci' if part == 'lookup'
           else '-p mailsec-selfhost-ci down')
    path.write_text(path.read_text().replace(old, old.replace('selfhost-ci', 'selfhost-other')))
    code, report = run(candidate)
    assert code == 1 and 'CI container lookup and cleanup use the installed project' in report['failures']


def test_export_manifest_is_required_on_request_and_verified(candidate):
    assert run(candidate, '--require-manifest')[0] == 1
    add_manifest(candidate)
    assert run(candidate, '--require-manifest')[0] == 0
    (candidate / 'mailsec/config.py').write_text('VERSIONS={"engine":"0.4.0-alpha.5"}\n# drift\n')
    code, report = run(candidate, '--require-manifest')
    assert code == 1 and 'export manifest entries match all required source bytes' in report['failures']


@pytest.mark.parametrize('kind', ['duplicate', 'missing', 'traversal'])
def test_export_manifest_rejects_ambiguous_or_incomplete_records(candidate, kind):
    add_manifest(candidate)
    path = candidate / 'RELEASE_MANIFEST.json'
    manifest = json.loads(path.read_text())
    if kind == 'duplicate':
        manifest['files'].append(manifest['files'][0])
    elif kind == 'missing':
        manifest['files'] = [entry for entry in manifest['files'] if entry['path'] != 'README.md']
    else:
        manifest['files'].append({'path': '../private', 'bytes': 0, 'sha256': '0' * 64})
    path.write_text(json.dumps(manifest))
    assert run(candidate, '--require-manifest')[0] == 1


def test_unsafe_file_error_is_redacted(candidate):
    path = candidate / 'README.md'
    path.unlink()
    path.symlink_to(candidate.parent / 'private-secret-file')
    code, report = run(candidate)
    assert code == 1 and 'private-secret-file' not in json.dumps(report)


def test_export_manifest_rejects_unlisted_source_but_ignores_test_caches(candidate):
    add_manifest(candidate)
    cache = candidate / 'tests/__pycache__/cached.pyc'
    cache.parent.mkdir()
    cache.write_bytes(b'generated test cache')
    assert run(candidate, '--require-manifest')[0] == 0
    (candidate / 'mailsec/unlisted.py').write_text('Unexpected source')
    assert run(candidate, '--require-manifest')[0] == 1
