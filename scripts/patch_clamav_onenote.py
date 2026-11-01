"""Backport CVE-2026-46671 without changing Cisco's onenote_parser 0.3.1 API.

The affected notebook filesystem API remains present, but validates entry paths
before touching referenced files. ClamAV's buffer API is unchanged. The original
archive, this modification recipe and the tested path policy accompany the image.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ORIGINAL_SHA256 = 'cf28ce92e7fdbbbbbe5ea4864a1e587bb9b66c54f7851072008deb0b6c6456d8'
OLD_MAP = '''            .map(|name| {
                let mut file = base_dir.to_path_buf();
                file.push(name);

                file
            })'''
NEW_MAP = '''            .map(|name| path_policy::resolve_entry_path(base_dir, name).map_err(Into::into))
            .collect::<Result<Vec<_>>>()?
            .into_iter()'''


def patch(source: Path, policy: Path) -> None:
    vendor = source / '.cargo/vendor/onenote_parser'
    module = vendor / 'src/onenote/mod.rs'
    original = module.read_bytes()
    if hashlib.sha256(original).hexdigest() != ORIGINAL_SHA256:
        raise ValueError('Unexpected original OneNote parser source')
    text = original.decode()
    if text.count(OLD_MAP) != 1:
        raise ValueError('Unexpected notebook path traversal implementation')
    module.write_text(text.replace('pub(crate) mod content;', 'mod path_policy;\npub(crate) mod content;').replace(OLD_MAP, NEW_MAP))
    target_policy = vendor / 'src/onenote/path_policy.rs'
    target_policy.write_bytes(policy.read_bytes())
    checksum_path = vendor / '.cargo-checksum.json'
    checksums = json.loads(checksum_path.read_text())
    for path in (module, target_policy):
        checksums['files'][path.relative_to(vendor).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    checksum_path.write_text(json.dumps(checksums, sort_keys=True))


if __name__ == '__main__':
    patch(Path(sys.argv[1]), Path(sys.argv[2]))
