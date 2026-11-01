"""Use rand 0.9.3 for GHSA-cq8v-f236-94qc in ClamAV's actual locked graph.

The upstream ClamAV release contains a complete vendor directory. Replace only
the compatible rand crate, update its Cargo lock/checksums, and compile offline.
Other crates' example/test Cargo.lock files are not the application's graph.
The original release archive, replacement crate and this script ship in the
image's corresponding-source directory.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import sys
import tarfile
from pathlib import Path

RAND_SHA256 = '7ec095654a25171c2124e9e3393a930bddbffdc939556c914957a4c3e0a87166'
OLD_ENTRY = '''name = "rand"
version = "0.9.2"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "6db2770f06117d490610c7488547d543617b21bfa07796d7a12f6f1bd53850d1"'''
NEW_ENTRY = OLD_ENTRY.replace('0.9.2', '0.9.3').replace(
    '6db2770f06117d490610c7488547d543617b21bfa07796d7a12f6f1bd53850d1', RAND_SHA256)


def patch(source: Path, crate: Path) -> None:
    if hashlib.sha256(crate.read_bytes()).hexdigest() != RAND_SHA256:
        raise ValueError('Unexpected rand source')
    lockfile = source / 'Cargo.lock'
    original = lockfile.read_text()
    if original.count(OLD_ENTRY) != 1:
        raise ValueError('Unexpected ClamAV dependency graph')
    vendor = source / '.cargo/vendor'
    with tarfile.open(crate) as archive:
        if any(not member.name.startswith('rand-0.9.3/') for member in archive.getmembers()):
            raise ValueError('Unexpected crate structure')
        archive.extractall(vendor, filter='data')
    replacement = vendor / 'rand-0.9.3'
    checksums = {path.relative_to(replacement).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                 for path in replacement.rglob('*') if path.is_file()}
    (replacement / '.cargo-checksum.json').write_text(json.dumps({'files': checksums, 'package': RAND_SHA256}))
    shutil.rmtree(vendor / 'rand')
    replacement.rename(vendor / 'rand')
    lockfile.write_text(original.replace(OLD_ENTRY, NEW_ENTRY))


if __name__ == '__main__':
    patch(Path(sys.argv[1]), Path(sys.argv[2]))
