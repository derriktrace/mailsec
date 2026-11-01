"""Record and verify the libraries actually loaded by the finished image."""
from __future__ import annotations

import json
import re
import sqlite3
import ssl
import subprocess
import sys
import xml.parsers.expat
from pathlib import Path

import psycopg
from cryptography.hazmat.backends.openssl.backend import backend
from PIL import features


def version_tuple(text: str) -> tuple[int, ...]:
    match = re.search(r'\b(\d+)\.(\d+)\.(\d+)\b', text)
    if not match:
        raise ValueError('Cannot verify native library version')
    return tuple(map(int, match.groups()))


def inventory() -> dict:
    image_formats = {name: features.check(name) for name in ('jpg', 'jpg_2000', 'webp', 'avif', 'zlib', 'libtiff')}
    crypto_ssl = backend.openssl_version_text()
    tiff = features.version_codec('libtiff')
    if (sys.version_info < (3, 12, 15) or version_tuple(ssl.OPENSSL_VERSION) < (3, 5, 9)
            or crypto_ssl != ssl.OPENSSL_VERSION or not tiff or version_tuple(tiff) < (4, 7, 2)
            or not all(image_formats.values()) or psycopg.pq.__impl__ != 'c' or psycopg.pq.version() < 180006):
        raise ValueError('Runtime library verification failed')
    programs = {
        'postgresql': ['/usr/lib/postgresql/18/bin/postgres', '--version'],
        'clamav': ['/usr/bin/clamscan', '--version'],
        'tesseract': ['/usr/bin/tesseract', '--version'],
        'ocr_languages': ['/usr/bin/tesseract', '--list-langs'],
        'poppler': ['/usr/bin/pdftoppm', '-v'],
        'libxml2': ['/usr/bin/xmllint', '--version'],
    }
    native = {}
    for name, command in programs.items():
        completed = subprocess.run(command, capture_output=True, timeout=15, check=True)
        native[name] = (completed.stdout + completed.stderr).decode('utf-8', 'replace').strip()
    if not all(language in native['ocr_languages'].splitlines() for language in ('eng', 'por', 'spa')):
        raise ValueError('Required OCR language files are unavailable')
    return {'python': sys.version, 'openssl': ssl.OPENSSL_VERSION,
            'cryptography_openssl': crypto_ssl, 'sqlite': sqlite3.sqlite_version,
            'expat': xml.parsers.expat.EXPAT_VERSION, 'pillow_tiff': tiff,
            'pillow_features': image_formats,
            'psycopg_implementation': psycopg.pq.__impl__, 'libpq_version': psycopg.pq.version(),
            'native_programs': native}


if __name__ == '__main__':
    Path(sys.argv[1]).write_text(json.dumps(inventory(), indent=2) + '\n')
