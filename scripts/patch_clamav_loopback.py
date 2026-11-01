"""Keep clamd's numeric local bind compatible with its outbound-network denial.

musl AI_ADDRCONFIG probes socket connectivity even for a literal address. Only
Mailsec's fixed 127.0.0.1 listener bypasses that probe; other addresses retain the
upstream behavior. This changes no scanner verdicts or permitted network calls.
"""
from __future__ import annotations

import hashlib
import sys
from pathlib import Path

ORIGINAL_SHA256 = '4c3d3a0c38babaee2d191945b257cec0af9fa4f52b588c251c5525f3afe2766f'
OLD = '''#ifdef AI_ADDRCONFIG
    hints.ai_flags |= AI_ADDRCONFIG;
#endif'''
NEW = '''    /* Numeric loopback needs no DNS or musl connectivity probe. */
    if (ipaddr && strcmp(ipaddr, "127.0.0.1") == 0) {
        hints.ai_family = AF_INET;
        hints.ai_flags |= AI_NUMERICHOST | AI_NUMERICSERV;
    } else {
#ifdef AI_ADDRCONFIG
        hints.ai_flags |= AI_ADDRCONFIG;
#endif
    }'''


def patch(source: Path) -> None:
    path = source / 'clamd/tcpserver.c'
    original = path.read_bytes()
    if hashlib.sha256(original).hexdigest() != ORIGINAL_SHA256:
        raise ValueError('Unexpected original ClamAV TCP listener source')
    text = original.decode()
    if text.count(OLD) != 1:
        raise ValueError('Unexpected ClamAV listener flags')
    path.write_text(text.replace(OLD, NEW))


if __name__ == '__main__':
    patch(Path(sys.argv[1]))
