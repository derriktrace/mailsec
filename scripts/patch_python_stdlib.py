"""Apply audited PSF security fixes to the pinned CPython 3.12 stdlib.

No interpreter version is changed. Whole-file and upstream-patch hashes make a
future base-image change fail closed rather than silently misapply a backport.
The IMAP and HTTP hunk placements adapt the upstream branch context without
changing the security logic. Run only in an image build or
against an isolated copy, never as a host-system installer.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import io
import json
import os
import re
import stat
import sys
from pathlib import Path

PATCHES = {
    'imaplib.py': {
        'advisory': 'CVE-2025-15366',
        'commit': '71926d943c05bde79bd2a866933103541d91b6a2',
        'original': 'ab3d485f7ee89deaf132533cd135888326be3c92a88ede79a16fa4c0e4709632',
        'patch_sha256': 'ef3e6ea1e797e4376bbcb7a3e53c3d6ffd8f3e1975ed5bfc9c42b9045b018ea6',
        'patched_sha256': '095bed01d8fd1a488c2382ae6ad87caaa017e1c3ba570c50cea59bcc33096299',
    },
    'poplib.py': {
        'advisory': 'CVE-2025-15367',
        'commit': 'b234a2b67539f787e191d2ef19a7cbdce32874e7',
        'original': 'e1596878e408b1702dea74ca55f13b367f93b12fd9950fc62f70d8e7b47fce83',
        'patch_sha256': '606aa1bd8124cb0d777744dfe1a89d1ba983638115372cc508f4ed4a154f3abf',
        'patched_sha256': 'd61b5c998036b0c0a947e8d587a24bd55890dde6bcd990a3aeae479fed493931',
    },
    'http/cookies.py': {
        'advisory': 'CVE-2026-6019',
        'commit': '76b3923d688c0efc580658476c5f525ec8735104',
        'original': '6387f676095ae5374943eff99fbcd2d9c681172c00209fadf54c311cf7228149',
        'patch_sha256': '83800265bb9cb0bc16eb5bd1b6582d926654a1e1483d073b47e29b4576f9313c',
        'patched_sha256': 'e98b941e6084e00f6bda5971178d714a4102189d2849c1c81bebddb088ef9f51',
    },
    'http/client.py': {
        'advisory': 'CVE-2026-103995',
        'commit': '2eb2af805c156ca52b316bb4ced5e0ab3971d0ae',
        'original': 'c2c0694155837d72fc710a4138e5d1e53ae1a652b117a2e23a5b1b0db527a0f9',
        'patch_sha256': '1f8d0ef8eb56798b2c8c98b47f449ce8f6f89af3c44729e143168f840a103b85',
        'patched_sha256': '49c6ad24d743d0c4b4535a639b96bea18310ee23e0f3f38bf24f3b28903525d0',
        'followup_commit': '9f52b443c002cccfb54bda0706a9276b6b4a109d',
        'followup_patch_sha256': '62e99aa3d79c55847bb9c600a66c4e922390dfc1eeba41ee0fe2be3e14b2ea09',
    },
}


def digest(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def replace_once(source: str, before: str, after: str) -> str:
    if source.count(before) != 1:
        raise ValueError('Unexpected CPython source context')
    return source.replace(before, after)


def transform(name: str, original: bytes) -> bytes:
    if digest(original) != PATCHES[name]['original']:
        raise ValueError(f'Unexpected original CPython source: {name}')
    source = original.decode('utf-8')
    if name == 'imaplib.py':
        anchor = "_Untagged_status = br'\\* (?P<data>\\d+) (?P<type>[A-Z-]+)( (?P<data2>.*))?'\n"
        source = replace_once(source, anchor, anchor +
            '# Only NUL, CR and LF are unsafe (they cannot be represented even in\n'
            '# a quoted string); other control characters are sent quoted.\n'
            "_control_chars = re.compile(b'[\\x00\\r\\n]')\n")
        source = replace_once(source,
            "                arg = bytes(arg, self._encoding)\n            data = data + b' ' + arg",
            '                arg = bytes(arg, self._encoding)\n'
            '            if _control_chars.search(arg):\n'
            '                raise ValueError("NUL, CR and LF not allowed in commands")\n'
            "            data = data + b' ' + arg")
    elif name == 'poplib.py':
        source = replace_once(source,
            '        line = bytes(line, self.encoding)\n        self._putline(line)',
            '        line = bytes(line, self.encoding)\n'
            "        if re.search(b'[\\x00-\\x1F\\x7F]', line):\n"
            "            raise ValueError('Control characters not allowed in commands')\n"
            '        self._putline(line)')
    elif name == 'http/cookies.py':
        source = replace_once(source, '    def js_output(self, attrs=None):\n        # Print javascript\n',
            '    def js_output(self, attrs=None):\n        import base64\n        # Print javascript\n')
        source = replace_once(source,
            '            raise CookieError("Control characters are not allowed in cookies")\n        return """',
            '            raise CookieError("Control characters are not allowed in cookies")\n'
            '        # Base64-encode value to avoid template\n'
            '        # injection in cookie values.\n'
            '        output_encoded = base64.b64encode(output_string.encode(\'utf-8\')).decode("ascii")\n'
            '        return """')
        source = replace_once(source, r'document.cookie = \"%s\";', r'document.cookie = atob(\"%s\");')
        source = replace_once(source, '''(output_string.replace('"', r'\\"'))''', '(output_encoded,)')
    else:
        anchor = "_contains_disallowed_method_pchar_re = re.compile('[\\x00-\\x1f]')\n"
        source = replace_once(source, anchor, anchor +
            "\n# RFC 9112: Content-Length = 1*DIGIT and chunk-size = 1*HEXDIG.\n"
            '# int() is more permissive, so we match against the grammar before calling it.\n'
            "_is_legal_content_length = re.compile(r'[0-9]+').fullmatch\n"
            "_is_legal_chunk_size = re.compile(rb'[0-9a-fA-F]+').fullmatch\n")
        source = replace_once(source,
            '        length = self.headers.get("content-length")\n'
            '        if length and not self.chunked:\n'
            '            try:\n'
            '                self.length = int(length)\n'
            '            except ValueError:\n'
            '                self.length = None\n'
            '            else:\n'
            '                if self.length < 0:  # ignore nonsensical negative lengths\n'
            '                    self.length = None\n',
            '        length = self.headers.get("content-length")\n'
            '        if length is not None:\n'
            '            # RFC 9112, section 5.1: optional whitespace (SP / HTAB) around\n'
            '            # the field value is not part of the value.\n'
            "            length = length.strip(' \\t')\n"
            '        if length and not self.chunked and _is_legal_content_length(length):\n'
            '            self.length = int(length)\n')
        source = replace_once(source,
            '            line = line[:i] # strip chunk-extensions\n'
            '        try:\n'
            '            return int(line, 16)\n',
            '            line = line[:i] # strip chunk-extensions\n'
            '        line = line.rstrip()\n'
            '        try:\n'
            '            if not _is_legal_chunk_size(line):\n'
            '                raise ValueError("invalid chunk size")\n'
            '            return int(line, 16)\n')
    compile(source, name, 'exec')
    changed = source.encode('utf-8')
    if digest(changed) != PATCHES[name]['patched_sha256']:
        raise ValueError('Unexpected patched CPython source checksum')
    return changed


def regular_file(path: Path, root: Path) -> bytes:
    if path.is_symlink() or not stat.S_ISREG(path.stat().st_mode) or not path.resolve().is_relative_to(root.resolve()):
        raise ValueError('Expected a confined regular source file')
    return path.read_bytes()


def patch(stdlib: Path, patch_dir: Path) -> dict:
    pending = []
    report = {'component': 'CPython', 'upstream_version': '3.12.16', 'files': {}}
    # Validate every input before writing any target; a changed base fails build.
    for name, spec in PATCHES.items():
        upstream = patch_dir / (spec['advisory'] + '.patch')
        if digest(regular_file(upstream, patch_dir)) != spec['patch_sha256']:
            raise ValueError('Unexpected upstream PSF patch checksum')
        if 'followup_commit' in spec:
            followup = patch_dir / (spec['advisory'] + '-followup.patch')
            if digest(regular_file(followup, patch_dir)) != spec['followup_patch_sha256']:
                raise ValueError('Unexpected upstream PSF follow-up patch checksum')
        path = stdlib / name
        cache = path.parent / '__pycache__'
        if cache.is_symlink():
            raise ValueError('Unexpected symbolic bytecode-cache directory')
        original = regular_file(path, stdlib)
        changed = transform(name, original)
        pending.append((path, changed))
        report['files'][name] = {**spec, 'patched_sha256': digest(changed),
            'upstream_patch_url': f"https://github.com/python/cpython/commit/{spec['commit']}.patch"}
    for path, changed in pending:
        temporary = path.with_name('.' + path.name + '.mailsec-patch')
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_NOFOLLOW', 0), 0o644)
        try:
            with os.fdopen(fd, 'wb') as stream:
                stream.write(changed)
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)
        for cached in (path.parent / '__pycache__').glob(path.stem + '.*.pyc'):
            cached.unlink()
    return report


def load_module(stdlib: Path, name: str):
    spec = importlib.util.spec_from_file_location('_mailsec_verify_' + name.replace('/', '_'), stdlib / name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def verify(stdlib: Path) -> dict:
    """Network-free regressions exercise actual installed/copied patched code."""
    for name, spec in PATCHES.items():
        if digest(regular_file(stdlib / name, stdlib)) != spec['patched_sha256']:
            raise ValueError('Installed CPython backport checksum does not match')
    imap, pop, cookies, http = [load_module(stdlib, name) for name in PATCHES]
    sent = []
    client = object.__new__(imap.IMAP4)
    client.state, client.literal, client.untagged_responses = 'AUTH', None, {}
    client.is_readonly, client._encoding, client.debug = False, 'utf-8', 0
    client._new_tag = lambda: b'A001'
    client._log = lambda *args: None
    client.send = sent.append
    for control in '\0\r\n':
        for value in ['name' + control + 'NOOP', ('name' + control + 'NOOP').encode()]:
            try:
                client._command('SELECT', value)
            except ValueError:
                pass
            else:
                raise AssertionError('IMAP control character reached command sender')
            require(not sent, 'Rejected IMAP input reached command sender')
    for value in ['"Inbox"', '"name\tvalue"', b'"name\x01value"']:
        client._command('SELECT', value)
    require(len(sent) == 3, 'Valid IMAP command compatibility regressed')
    sent.clear()
    client = object.__new__(pop.POP3)
    client._debugging, client.encoding, client._putline = 0, 'utf-8', sent.append
    for number in [*range(32), 127]:
        for prefix in ['USER ', 'PASS ']:
            try:
                client._putcmd(prefix + 'name' + chr(number) + 'QUIT')
            except ValueError:
                pass
            else:
                raise AssertionError('POP control character reached command sender')
            require(not sent, 'Rejected POP input reached command sender')
    client._putcmd('USER ordinary')
    client._putcmd('PASS unicode-\u00e9')
    require(sent == [b'USER ordinary', 'PASS unicode-\u00e9'.encode()], 'Valid POP command compatibility regressed')
    for payload in ['ordinary', '</script><img src=x onerror=alert(1)>', '"; alert(1); //', '\u00e9']:
        morsel = cookies.Morsel()
        morsel.set('session', payload, payload)
        output = morsel.js_output()
        encoded = re.search(r'document\.cookie = atob\("([A-Za-z0-9+/=]+)"\);', output)
        require(bool(encoded) and base64.b64decode(encoded[1], validate=True).decode() == morsel.OutputString(),
                'Cookie output round trip or encoded JavaScript contract failed')
        require(output.count('</script>') == 1, 'Cookie value escaped the JavaScript wrapper')
    morsel = cookies.Morsel()
    morsel.set('session', 'ordinary', 'ordinary')
    morsel._coded_value = 'bad\nvalue'
    try:
        morsel.js_output()
    except cookies.CookieError:
        pass
    else:
        raise AssertionError('Cookie control-character guard regressed')

    class FakeSocket:
        def __init__(self, data):
            self.data = data

        def makefile(self, mode):
            return io.BytesIO(self.data)

    def response(headers, body):
        value = http.HTTPResponse(FakeSocket(b'HTTP/1.1 200 OK\r\n' + headers + b'\r\n\r\n' + body), method='GET')
        value.begin()
        return value

    for length in (b'+5', b'5_0', b'5 0'):
        value = response(b'Content-Length: ' + length, b'Hello\r\n')
        require(value.length is None and value.read() == b'Hello\r\n', 'Malformed HTTP content length framed a body')
        value.close()
    for length in (b'7 ', b'7\t', b'7 \t ', b' 7 '):
        value = response(b'Content-Length: ' + length, b'Hello\r\nextra')
        require(value.length == 7 and value.read() == b'Hello\r\n' and value.isclosed(),
                'HTTP optional whitespace compatibility regressed')
        value.close()
    for size in (b'-5', b'+5', b'0x5', b'1_f', b' 5'):
        value = response(b'Transfer-Encoding: chunked', size + b'\r\nHELLO\r\n0\r\n\r\n')
        try:
            value.read()
        except http.IncompleteRead:
            require(value.isclosed(), 'Malformed HTTP chunk did not close the connection')
        else:
            raise AssertionError('Malformed HTTP chunk size was accepted')
        value.close()
    for size in (b'5', b'5;name=value', b'5 '):
        value = response(b'Transfer-Encoding: chunked', size + b'\r\nHELLO\r\n0\r\n\r\n')
        require(value.read() == b'HELLO' and value.isclosed(), 'Valid HTTP chunk compatibility regressed')
        value.close()
    return {'imap_control_cases': 6, 'imap_valid_cases': 3, 'pop_control_cases': 66,
            'pop_valid_cases': 2, 'cookie_roundtrips': 4, 'cookie_control_case': 1,
            'http_malformed_lengths': 3, 'http_optional_whitespace': 4,
            'http_malformed_chunks': 5, 'http_valid_chunks': 3}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('stdlib', type=Path)
    parser.add_argument('patch_dir', type=Path)
    parser.add_argument('report', type=Path)
    args = parser.parse_args()
    sys.dont_write_bytecode = True
    result = patch(args.stdlib, args.patch_dir)
    result['regressions'] = verify(args.stdlib)
    args.report.write_text(json.dumps(result, indent=2) + '\n')
    print('Four hash-verified CPython security backports applied; 97 regression cases passed.')


if __name__ == '__main__':
    main()
