"""Source/build integrity gates, complementary to the executable loopback test."""
import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/patch_busybox_wget.py'
spec = importlib.util.spec_from_file_location('busybox_patch', SCRIPT)
patcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(patcher)


def inputs(tmp_path):
    manifest = json.loads((ROOT / 'deploy/native/busybox.lock.json').read_text())
    directory = tmp_path / 'inputs'
    directory.mkdir()
    for name, entry in manifest.items():
        value = ('synthetic source bytes for ' + name).encode()
        (directory / name).write_bytes(value)
        entry.update(bytes=len(value), sha256=hashlib.sha256(value).hexdigest(),
                     sha512=hashlib.sha512(value).hexdigest())
    path = tmp_path / 'manifest.json'
    path.write_text(json.dumps(manifest))
    return path, directory, manifest


def test_manifest_verifies_all_bytes_and_exact_patch_order(tmp_path):
    manifest, directory, entries = inputs(tmp_path)
    assert patcher.verified_patch_names(manifest, directory) == [name for name in entries if name.endswith('.patch')]
    target = directory / 'busyboxconfig'
    target.write_bytes(target.read_bytes() + b'changed')
    with pytest.raises(ValueError, match='size'):
        patcher.verified_patch_names(manifest, directory)


def test_same_size_source_tampering_fails_hash_gate(tmp_path):
    manifest, directory, _ = inputs(tmp_path)
    target = directory / 'ssl_client.c'
    target.write_bytes(b'x' * target.stat().st_size)
    with pytest.raises(ValueError, match='hash'):
        patcher.verified_patch_names(manifest, directory)


@pytest.mark.parametrize('optimized', [False, True])
def test_reordered_patch_manifest_rejected_even_with_python_optimization(tmp_path, optimized):
    manifest, directory, entries = inputs(tmp_path)
    names = list(entries)
    patches = [index for index, name in enumerate(names) if name.endswith('.patch')]
    left, right = patches[:2]
    names[left], names[right] = names[right], names[left]
    manifest.write_text(json.dumps({name: entries[name] for name in names}))
    command = [sys.executable, *(['-O'] if optimized else []), str(SCRIPT), '--patch-list', str(manifest), str(directory)]
    result = subprocess.run(command, capture_output=True, text=True, timeout=10)
    assert result.returncode != 0 and 'patch order' in result.stderr
    assert result.stdout == ''


def test_patch_refuses_hash_tampered_source_without_mutation(tmp_path):
    source = tmp_path / 'networking/wget.c'
    source.parent.mkdir()
    source.write_text(patcher.BEFORE + patcher.REDIRECT_BEFORE)
    original = source.read_bytes()
    with pytest.raises(ValueError, match='pinned Alpine'):
        patcher.patch(tmp_path)
    assert source.read_bytes() == original


def test_patch_refuses_missing_or_duplicate_context_without_mutation(tmp_path, monkeypatch):
    source = tmp_path / 'networking/wget.c'
    source.parent.mkdir()
    for text in (patcher.BEFORE, patcher.BEFORE * 2 + patcher.REDIRECT_BEFORE):
        source.write_text(text)
        original = source.read_bytes()
        monkeypatch.setattr(patcher, 'EXPECTED_SHA256', hashlib.sha256(original).hexdigest())
        with pytest.raises(ValueError, match='context'):
            patcher.patch(tmp_path)
        assert source.read_bytes() == original
