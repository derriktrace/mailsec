"""Fetch checksum-pinned native build inputs; never execute downloaded scripts."""
from __future__ import annotations

import hashlib
import http.client
import json
import ssl
import sys
import time
from pathlib import Path
from urllib.parse import urljoin, urlsplit


def download(url: str, destination: Path, maximum: int) -> tuple[str, int]:
    """Build-time public-source fetch: TLS only, no proxies or credentials."""
    digest = hashlib.sha256()
    size = 0
    deadline = time.monotonic() + 300
    for _ in range(6):
        parts = urlsplit(url)
        if (parts.scheme != 'https' or not parts.hostname or parts.username or parts.password
                or parts.port not in (None, 443)):
            raise ValueError('Native sources require credential-free HTTPS URLs')
        connection = http.client.HTTPSConnection(parts.hostname, timeout=90, context=ssl.create_default_context())
        try:
            path = parts.path or '/'
            if parts.query:
                path += '?' + parts.query
            connection.request('GET', path, headers={'Accept-Encoding': 'identity'})
            response = connection.getresponse()
            if response.status in (301, 302, 303, 307, 308):
                location = response.getheader('Location')
                if not location:
                    raise ValueError('Native source redirect has no location')
                url = urljoin(url, location)
                continue
            if response.status != 200 or response.getheader('Content-Encoding', 'identity') != 'identity':
                raise ValueError('Unexpected native source response')
            with destination.open('wb') as output:
                while chunk := response.read(1024 * 1024):
                    size += len(chunk)
                    if size > maximum or time.monotonic() > deadline:
                        raise ValueError('Native source exceeded its pinned bounds')
                    digest.update(chunk)
                    output.write(chunk)
            return digest.hexdigest(), size
        finally:
            connection.close()
    raise ValueError('Too many native source redirects')


def fetch(manifest: Path, destination: Path) -> None:
    entries = json.loads(manifest.read_text())
    destination.mkdir(parents=True, exist_ok=True)
    for name, entry in entries.items():
        if Path(name).name != name or not entry['url'].startswith('https://'):
            raise ValueError('Invalid native source manifest')
        target = destination / name
        expected_size = entry['bytes']
        if target.is_file() and hashlib.sha256(target.read_bytes()).hexdigest() == entry['sha256']:
            continue
        temporary = destination / (name + '.partial')
        for attempt in range(3):
            try:
                digest, size = download(entry['url'], temporary, expected_size)
                if size != expected_size or digest != entry['sha256']:
                    raise ValueError('Native source checksum mismatch')
                temporary.replace(target)
                break
            except (OSError, ValueError):
                temporary.unlink(missing_ok=True)
                if attempt == 2:
                    raise
                time.sleep(attempt + 1)


if __name__ == '__main__':
    fetch(Path(sys.argv[1]), Path(sys.argv[2]))
