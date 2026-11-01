"""Narrow request-target validation for BusyBox1.37.0 after pinned Alpine patches."""
import hashlib
import json
import re
import sys
from pathlib import Path

EXPECTED_SHA256 = 'f86e80bd88a2fe78e92903d91844aed8c78dce2048a0586672e445c52f46c6b7'
PATCH_ORDER_SHA256 = '767694ca2a8946c32f6323ce63232272f029b9ba6e1c9bb3eea92b9514bdee2e'
BEFORE = '''static void parse_url(const char *src_url, struct host_info *h)
{
\tchar *url, *p, *sp;

\tfree(h->allocated);
'''
AFTER = '''static void validate_url(const char *src_url)
{
\tconst unsigned char *c;

\t/* Mailsec: raw HTTP delimiters must never become request-target bytes.
\t * Apply before parsing every initial, proxy, or redirected URL. Encoded
\t * bytes remain encoded; ordinary RFC percent-encoded URLs still work.
\t */
\tfor (c = (const unsigned char *)src_url; *c; c++) {
\t\tif (*c <= 0x20 || *c == 0x7f)
\t\t\tbb_error_msg_and_die("invalid control character or space in URL");
\t}
}

static void parse_url(const char *src_url, struct host_info *h)
{
\tchar *url, *p, *sp;

\tvalidate_url(src_url);

\tfree(h->allocated);
'''
REDIRECT_BEFORE = '''\t\t\tif (key == KEY_location && status >= 300) {
\t\t\t\tif (--redir_limit == 0)
'''
REDIRECT_AFTER = '''\t\t\tif (key == KEY_location && status >= 300) {
\t\t\t\t/* Relative redirects bypass parse_url; validate those too. */
\t\t\t\tvalidate_url(str);
\t\t\t\tif (--redir_limit == 0)
'''


def verified_patch_names(manifest, directory):
    entries = json.loads(Path(manifest).read_text())
    names = [name for name in entries if name.endswith('.patch')]
    if (len(names) != 44 or hashlib.sha256('\n'.join(names).encode()).hexdigest() != PATCH_ORDER_SHA256):
        raise ValueError('BusyBox manifest does not preserve the pinned Alpine patch order')
    for name, entry in entries.items():
        if not re.fullmatch(r'[A-Za-z0-9_.-]+', name) or name in ('.', '..'):
            raise ValueError('BusyBox manifest contains an unsafe source filename')
        target = Path(directory) / name
        if target.is_symlink() or not target.is_file() or target.stat().st_size != entry['bytes']:
            raise ValueError('BusyBox source size or file type differs from the manifest')
        value = target.read_bytes()
        if (hashlib.sha256(value).hexdigest() != entry['sha256']
                or hashlib.sha512(value).hexdigest() != entry['sha512']):
            raise ValueError('BusyBox source hash differs from the manifest')
    return names


def patch(root):
    target = Path(root) / 'networking/wget.c'
    source = target.read_bytes()
    if hashlib.sha256(source).hexdigest() != EXPECTED_SHA256:
        raise ValueError('BusyBox source differs from the pinned Alpine patch sequence')
    text = source.decode()
    if text.count(BEFORE) != 1 or text.count(REDIRECT_BEFORE) != 1:
        raise ValueError('BusyBox URL validation patch context does not match exactly')
    target.write_text(text.replace(BEFORE, AFTER).replace(REDIRECT_BEFORE, REDIRECT_AFTER))


if __name__ == '__main__':
    if len(sys.argv) == 4 and sys.argv[1] == '--patch-list':
        print('\n'.join(verified_patch_names(sys.argv[2], sys.argv[3])))
    elif len(sys.argv) == 2:
        patch(sys.argv[1])
    else:
        raise ValueError('Expected a source directory or --patch-list manifest inputs')
