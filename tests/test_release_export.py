"""Publication boundaries: only selected source survives and failures publish nothing."""
import importlib.util
import json
import tarfile
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location('release_export', Path(__file__).parents[1] / 'scripts/export_release.py')
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)


@pytest.fixture
def source(tmp_path):
    root = tmp_path / 'private-workspace'
    root.mkdir()
    for name in release.REQUIRED_FILES:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('X-Mailsec-Synthetic: true\n\nSynthetic example\n' if name.startswith('samples/') else 'Public source fixture\n')
    for name in ('secrets/key', 'data/mail.db', 'backups/mail.dump', '.env.local', 'organization.yaml',
                 'compose.yaml', 'Dockerfile', 'start.sh', 'docs/private-review.md', 'tests/live-readonly-ui.mjs',
                 'tests/test_tls_bootstrap.py', 'scripts/prepare_pilot.py', 'Dockerfile.inspection',
                 'Dockerfile.antivirus', 'deploy/clamd.conf', 'deploy/freshclam.conf',
                 'scripts/backup.sh', 'tests/test_backup_script.py'):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('DO NOT EXPORT: private fixture contents\n')
    (root / 'mailsec/new_component.py').write_text('"""New application module."""\n')
    (root / 'tests/test_new_component.py').write_text('def test_example(): assert True\n')
    return root


def allow_mock_scan(monkeypatch):
    seen = []
    monkeypatch.setattr(release, 'scan_gitleaks', lambda stage, executable: seen.append(stage))
    return seen


def test_export_excludes_private_state_and_preserves_public_tests(source, tmp_path, monkeypatch):
    scans = allow_mock_scan(monkeypatch)
    destination = tmp_path / 'public-source'
    result = release.export_release(source, destination, gitleaks='mock-scanner')
    assert len(scans) == 1
    assert (destination / 'compose.yaml').read_bytes() == (source / 'compose.selfhost.yaml').read_bytes()
    assert (destination / 'Dockerfile').read_bytes() == (source / 'Dockerfile.selfhost').read_bytes()
    assert (destination / '.env.example').read_text() == release.PUBLIC_ENV_EXAMPLE
    assert '.selfhost/' in (destination / '.gitignore').read_text()
    assert (destination / 'mailsec/new_component.py').is_file()
    assert (destination / 'tests/test_new_component.py').is_file()
    assert (destination / 'tests/privacy_helpers.py').read_bytes() == (source / 'tests/privacy_helpers.py').read_bytes()
    for name in ('secrets', 'data', 'backups', '.env.local', 'organization.yaml', 'start.sh',
                 'docs/private-review.md', 'tests/live-readonly-ui.mjs', 'tests/test_tls_bootstrap.py',
                 'scripts/prepare_pilot.py', 'Dockerfile.inspection', 'Dockerfile.antivirus',
                 'deploy/clamd.conf', 'deploy/freshclam.conf', 'scripts/backup.sh', 'tests/test_backup_script.py'):
        assert not (destination / name).exists()
    manifest = json.loads((destination / 'RELEASE_MANIFEST.json').read_text())
    assert manifest['checks']['gitleaks'] == 'passed'
    assert str(source) not in json.dumps(manifest)
    with tarfile.open(result['archive']) as archive:
        members = archive.getmembers()
        assert len(members) == result['files']
        assert all(member.isfile() and member.uid == member.gid == member.mtime == 0 for member in members)
        assert all(member.name.startswith('public-source/') for member in members)
        assert archive.getmember('public-source/selfhost.sh').mode == 0o755
        assert all(b'DO NOT EXPORT' not in archive.extractfile(member).read() for member in members)


@pytest.mark.parametrize('kind', ['symlink', 'oversize', 'binary', 'credential', 'private_marker', 'non_synthetic_mail'])
def test_preflight_rejects_unsafe_selected_files_without_creating_output(source, tmp_path, monkeypatch, kind):
    allow_mock_scan(monkeypatch)
    target = source / 'mailsec/new_component.py'
    markers = ()
    if kind == 'symlink':
        target.unlink()
        target.symlink_to(source / 'secrets/key')
    elif kind == 'oversize':
        monkeypatch.setattr(release, 'MAX_FILE_BYTES', 64)
        target.write_bytes(b'x' * 65)
    elif kind == 'binary':
        target.write_bytes(b'\x00binary')
    elif kind == 'credential':
        # Deliberately assembled invalid fixture, not a live credential.
        target.write_text('token = "' + 'AIza' + 'Q' * 35 + '"\n')
    elif kind == 'private_marker':
        target.write_text('owner = "private-person@private.invalid"\n')
        markers = (b'private-person@private.invalid',)
    else:
        (source / 'samples/receipt.eml').write_text('From: private-person@private.invalid\n\nReal email\n')
    destination = tmp_path / 'public-source'
    with pytest.raises(release.ReleaseError) as error:
        release.export_release(source, destination, private_markers=markers, gitleaks='mock-scanner')
    assert 'private-person@private.invalid' not in str(error.value)
    assert 'Q' * 35 not in str(error.value)
    assert not destination.exists() and not destination.with_suffix('.tar.gz').exists()


def test_secret_scanner_failure_publishes_nothing_and_does_not_echo_scanner_output(source, tmp_path, monkeypatch):
    class Result:
        returncode = 1
        stdout = b'private scanner finding'
        stderr = b'private scanner finding'
    monkeypatch.setattr(release.subprocess, 'run', lambda *args, **kwargs: Result())
    destination = tmp_path / 'public-source'
    with pytest.raises(release.ReleaseError) as error:
        release.export_release(source, destination, gitleaks='mock-scanner')
    assert 'private scanner finding' not in str(error.value)
    assert not destination.exists() and not destination.with_suffix('.tar.gz').exists()


def test_existing_destination_and_missing_required_source_are_not_overwritten(source, tmp_path, monkeypatch):
    allow_mock_scan(monkeypatch)
    destination = tmp_path / 'public-source'
    destination.mkdir()
    (destination / 'keep').write_text('preserve')
    with pytest.raises(release.ReleaseError, match='already exists'):
        release.export_release(source, destination, gitleaks='mock-scanner')
    assert (destination / 'keep').read_text() == 'preserve'
    (source / 'LICENSE').unlink()
    with pytest.raises(release.ReleaseError, match='LICENSE'):
        release.export_release(source, tmp_path / 'second-export', gitleaks='mock-scanner')
    assert not (tmp_path / 'second-export').exists()
