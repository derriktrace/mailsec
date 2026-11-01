"""The production image and supported 3.12 development stdlib are exercised offline."""
import hashlib
import importlib.util
import shutil
import sysconfig
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('patch_python_stdlib', ROOT / 'scripts/patch_python_stdlib.py')
patcher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(patcher)
PATCH_DIR = ROOT / 'deploy/native/patches'


@pytest.fixture
def copied_stdlib(tmp_path):
    installed = Path(sysconfig.get_path('stdlib'))
    target = tmp_path / 'stdlib'
    for name, spec in patcher.PATCHES.items():
        content = (installed / name).read_bytes()
        if patcher.digest(content) not in {spec['original'], spec['patched_sha256']}:
            pytest.skip('This integration check targets the pinned CPython 3.12 image stdlib')
        path = target / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    return target


def test_psf_patches_are_exact_pinned_artifacts():
    for spec in patcher.PATCHES.values():
        content = (PATCH_DIR / (spec['advisory'] + '.patch')).read_bytes()
        assert hashlib.sha256(content).hexdigest() == spec['patch_sha256']
        assert content.startswith(('From ' + spec['commit'] + ' ').encode())
        if 'followup_commit' in spec:
            followup = (PATCH_DIR / (spec['advisory'] + '-followup.patch')).read_bytes()
            assert hashlib.sha256(followup).hexdigest() == spec['followup_patch_sha256']
            assert followup.startswith(('From ' + spec['followup_commit'] + ' ').encode())


def test_actual_stdlib_security_regressions(copied_stdlib):
    first = next(iter(patcher.PATCHES))
    if patcher.digest((copied_stdlib / first).read_bytes()) == patcher.PATCHES[first]['original']:
        report = patcher.patch(copied_stdlib, PATCH_DIR)
        assert len(report['files']) == 4
    result = patcher.verify(copied_stdlib)
    assert sum(result.values()) == 97
    for name, spec in patcher.PATCHES.items():
        assert patcher.digest((copied_stdlib / name).read_bytes()) == spec['patched_sha256']


@pytest.mark.parametrize('name', list(patcher.PATCHES))
def test_changed_base_source_refused(name):
    with pytest.raises(ValueError, match='Unexpected original'):
        patcher.transform(name, b'# changed upstream base\n')


def test_tampered_upstream_patch_refused_before_writes(tmp_path, copied_stdlib):
    patches = tmp_path / 'patches'
    patches.mkdir()
    for spec in patcher.PATCHES.values():
        shutil.copyfile(PATCH_DIR / (spec['advisory'] + '.patch'), patches / (spec['advisory'] + '.patch'))
        if 'followup_commit' in spec:
            filename = spec['advisory'] + '-followup.patch'
            shutil.copyfile(PATCH_DIR / filename, patches / filename)
    (patches / 'CVE-2025-15366.patch').write_bytes(b'changed')
    before = {name: (copied_stdlib / name).read_bytes() for name in patcher.PATCHES}
    with pytest.raises(ValueError, match='upstream PSF patch checksum'):
        patcher.patch(copied_stdlib, patches)
    assert before == {name: (copied_stdlib / name).read_bytes() for name in patcher.PATCHES}


def test_symlink_source_refused(tmp_path):
    root = tmp_path / 'root'
    root.mkdir()
    outside = tmp_path / 'outside.py'
    outside.write_text('original')
    source = root / 'imaplib.py'
    source.symlink_to(outside)
    with pytest.raises(ValueError, match='confined regular'):
        patcher.regular_file(source, root)
    assert outside.read_text() == 'original'


def test_verification_rejects_unknown_installed_sources(tmp_path):
    (tmp_path / 'imaplib.py').write_text('unknown = True\n')
    with pytest.raises(ValueError, match='backport checksum'):
        patcher.verify(tmp_path)


def test_context_match_must_be_unique():
    with pytest.raises(ValueError, match='source context'):
        patcher.replace_once('repeat repeat', 'repeat', 'replacement')


def test_behavioral_gate_does_not_use_optimizable_assert():
    with pytest.raises(AssertionError, match='gate still active'):
        patcher.require(False, 'gate still active')
