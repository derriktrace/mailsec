"""Private tenant-scoped metadata cache; original bytes are never persisted."""

import hashlib
import json
import os
import sqlite3
import time
from pathlib import Path

from . import PARSER_VERSION


def cache_key(tenant, kind, content_hash, engine, signature, parameters=None):
    return hashlib.sha256(json.dumps([tenant, kind, content_hash, engine, signature,
                                     PARSER_VERSION, parameters], sort_keys=True).encode()).hexdigest()


class Cache:
    def __init__(self, path, ttl=86400, max_entries=10000, max_bytes=128 * 1024 * 1024):
        self.path, self.ttl, self.max_entries, self.max_bytes = str(path), ttl, max_entries, max_bytes
        parent = Path(path).parent
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.close(descriptor)
        os.chmod(path, 0o600)
        with self._connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS cache (key TEXT PRIMARY KEY, created REAL, value TEXT)")

    def _connect(self):
        return sqlite3.connect(self.path, timeout=5)

    def get(self, key):
        try:
            with self._connect() as db:
                row = db.execute("SELECT value,created FROM cache WHERE key=?", (key,)).fetchone()
            if row is None or row[1] + self.ttl < time.time():
                return None
            return json.loads(row[0])
        except (sqlite3.Error, ValueError):
            return None

    def put(self, key, value):
        encoded = json.dumps(value, ensure_ascii=True)
        if len(encoded) > 2 * 1024 * 1024:
            return
        try:
            with self._connect() as db:
                db.execute("INSERT OR REPLACE INTO cache VALUES (?,?,?)", (key, time.time(), encoded))
                db.execute("DELETE FROM cache WHERE created < ?", (time.time() - self.ttl,))
                db.execute("DELETE FROM cache WHERE key IN (SELECT key FROM cache ORDER BY created DESC LIMIT -1 OFFSET ?)",
                           (self.max_entries,))
                db.execute("DELETE FROM cache WHERE key IN (SELECT key FROM "
                           "(SELECT key, SUM(LENGTH(value)) OVER (ORDER BY created DESC, key) AS cumulative FROM cache) "
                           "WHERE cumulative > ?)", (self.max_bytes,))
        except sqlite3.Error:
            pass  # A full/unavailable cache never converts an inspection failure into clean.
