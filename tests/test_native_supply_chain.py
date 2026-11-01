import hashlib
import io
import json

import pytest

from scripts import fetch_native
from scripts.patch_clamav_rand import patch


class Response(io.BytesIO):
    def __init__(self, body=b'', status=200, headers=None):
        super().__init__(body)
        self.status = status
        self.headers = headers or {}

    def getheader(self, name, default=None):
        return self.headers.get(name, default)


def connection_factory(monkeypatch, responses):
    hosts = []

    class Connection:
        def __init__(self, host, **kwargs):
            hosts.append(host)

        def request(self, method, path, headers):
            assert method == 'GET'
            assert headers['Accept-Encoding'] == 'identity'

        def getresponse(self):
            return responses.pop(0)

        def close(self):
            pass

    monkeypatch.setattr(fetch_native.http.client, 'HTTPSConnection', Connection)
    return hosts


@pytest.mark.parametrize('url', ['http://example.org/source', 'file:///etc/passwd',
                                 'https://user:password@example.org/source', 'https://example.org:8443/source'])
def test_native_source_never_uses_unsafe_transport(tmp_path, monkeypatch, url):
    hosts = connection_factory(monkeypatch, [])
    with pytest.raises(ValueError, match='HTTPS'):
        fetch_native.download(url, tmp_path / 'source', 3)
    assert not hosts


def test_native_https_redirect_cannot_downgrade(tmp_path, monkeypatch):
    hosts = connection_factory(monkeypatch, [Response(status=302, headers={'Location': 'http://example.org/data'})])
    with pytest.raises(ValueError, match='HTTPS'):
        fetch_native.download('https://example.org/source', tmp_path / 'source', 3)
    assert hosts == ['example.org']


@pytest.mark.parametrize('response', [Response(b'too large'), Response(b'abc', headers={'Content-Encoding': 'gzip'})])
def test_native_source_rejects_oversize_and_compression(tmp_path, monkeypatch, response):
    connection_factory(monkeypatch, [response])
    with pytest.raises(ValueError):
        fetch_native.download('https://example.org/source', tmp_path / 'source', 3)


def test_native_source_checksum_failure_is_never_committed(tmp_path, monkeypatch):
    connection_factory(monkeypatch, [Response(b'bad') for _ in range(3)])
    monkeypatch.setattr(fetch_native.time, 'sleep', lambda _: None)
    manifest = tmp_path / 'manifest.json'
    manifest.write_text(json.dumps({'source.tar.gz': {'url': 'https://example.org/source', 'bytes': 3,
                                                    'sha256': hashlib.sha256(b'yes').hexdigest()}}))
    with pytest.raises(ValueError, match='checksum'):
        fetch_native.fetch(manifest, tmp_path / 'downloads')
    assert not list((tmp_path / 'downloads').iterdir())


def test_native_source_redirect_limit(tmp_path, monkeypatch):
    connection_factory(monkeypatch, [Response(status=302, headers={'Location': '/again'}) for _ in range(6)])
    with pytest.raises(ValueError, match='Too many'):
        fetch_native.download('https://example.org/source', tmp_path / 'source', 3)


def test_modified_crate_rejected_before_source_tree_is_changed(tmp_path):
    crate = tmp_path / 'rand.crate'
    crate.write_bytes(b'modified')
    with pytest.raises(ValueError, match='Unexpected rand'):
        patch(tmp_path / 'source', crate)
    assert not (tmp_path / 'source').exists()


def test_onenote_backport_rejects_unexpected_original_without_mutation(tmp_path):
    from scripts.patch_clamav_onenote import patch as patch_onenote

    source = tmp_path / 'source'
    module = source / '.cargo/vendor/onenote_parser/src/onenote/mod.rs'
    module.parent.mkdir(parents=True)
    module.write_text('unexpected upstream revision')
    with pytest.raises(ValueError, match='Unexpected original'):
        patch_onenote(source, tmp_path / 'policy.rs')
    assert module.read_text() == 'unexpected upstream revision'
    assert not (module.parent / 'path_policy.rs').exists()


def test_native_patch_provenance_matches_shipped_modifications():
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    manifest = json.loads((root / 'deploy/native/patches.json').read_text())
    for entry in manifest['patches']:
        for name, digest in entry['files'].items():
            assert hashlib.sha256((root / name).read_bytes()).hexdigest() == digest
