"""The decoder only receives its own job; durable cache ownership stays outside it."""

import json
import signal
from pathlib import Path

from mailsec.inspection import service
from mailsec.inspection.settings import InspectionSettings


def test_parser_ignores_private_cache_identity_and_kills_descendants_on_success(monkeypatch):
    captured = {}
    killed = []

    class Process:
        pid = 12345
        returncode = 0

        def __init__(self, command, **kwargs):
            captured.update(kwargs)
            assert 'INSPECTION_WORKER_CACHE' not in kwargs['env']
            assert 'private-cache' not in json.dumps(kwargs['env'])
            scratch = Path(kwargs['env']['INSPECTION_WORKER_SCRATCH'])
            assert scratch.is_dir() and scratch.stat().st_mode & 0o777 == 0o700
            assert kwargs['env']['TMPDIR'] == str(scratch)
            assert kwargs['env']['HOME'] == str(scratch)
            kwargs['stdout'].write(b'{"status":"complete","attachments":[]}')

        def communicate(self, **kwargs):
            return None, None

    monkeypatch.setattr(service.subprocess, 'Popen', Process)
    monkeypatch.setattr(service.os, 'killpg', lambda pid, sig: killed.append((pid, sig)))
    result = service.run_parser(b'From: test@example.org\n\nSynthetic', InspectionSettings(),
                                {'path': '/private-cache', 'tenant': 'private-customer'})
    assert result['status'] == 'complete'
    assert killed == [(12345, signal.SIGKILL)]
    assert not Path(captured['env']['INSPECTION_WORKER_SCRATCH']).exists()


def test_direct_decoder_never_opens_provided_persistent_cache(tmp_path):
    from mailsec.inspection.worker import inspect_message

    cache = tmp_path / 'victim.sqlite3'
    cache.write_bytes(b'private-cache-must-remain-untouched')
    before = cache.read_bytes()
    result = inspect_message(b'From: test@example.org\n\nSynthetic', InspectionSettings().parser_limits(),
                             {'path': str(cache), 'ttl': 1, 'max_entries': 10})
    assert result['status'] == 'complete'
    assert cache.read_bytes() == before


def test_security_epoch_rejects_every_pre_confinement_cache_kind(tmp_path, monkeypatch):
    from mailsec.inspection import PARSER_VERSION, cache

    assert PARSER_VERSION.startswith('inspection-v2.')
    persistent = cache.Cache(tmp_path / 'old-cache.sqlite3')
    for kind in ('message', 'document', 'attachment'):
        with monkeypatch.context() as previous:
            previous.setattr(cache, 'PARSER_VERSION', 'inspection-v1.previous-release')
            old = cache.cache_key('same-tenant', kind, 'same-content', 'same-engine', 'same-signatures')
            persistent.put(old, {'status': 'clean', 'untrusted_previous_result': True})
        current = cache.cache_key('same-tenant', kind, 'same-content', 'same-engine', 'same-signatures')
        assert old != current
        assert persistent.get(current) is None
