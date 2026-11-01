"""Queued mail must not be claimed during antivirus startup or missing coverage."""
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('startup_runtime', ROOT / 'scripts/container_runtime.py')
runtime = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runtime)

READY = {'status': 'ready', 'antivirus': {'status': 'ready', 'signatures_current': True}}


@pytest.mark.parametrize('payload', [
    None, [], {}, {'status': 'ready'},
    {'status': 'starting', 'antivirus': READY['antivirus']},
    {'status': 'ready', 'antivirus': None},
    {'status': 'ready', 'antivirus': {'status': 'unavailable', 'signatures_current': True}},
    {'status': 'ready', 'antivirus': {'status': 'ready', 'signatures_current': False}},
    {'status': 'ready', 'antivirus': {'status': 'ready', 'signatures_current': 'true'}},
])
def test_uncertain_unavailable_or_stale_scanner_never_starts_worker(monkeypatch, payload):
    supervisor = runtime.Supervisor()
    supervisor.worker_start_deadline = 100
    monkeypatch.setattr(runtime.time, 'monotonic', lambda: 1)
    monkeypatch.setattr(runtime, 'local_health', lambda *a, **kw: payload)
    monkeypatch.setattr(supervisor, 'start', lambda *a: pytest.fail('mailbox worker must remain stopped'))
    supervisor.start_worker_when_ready()


def test_scanner_connection_failure_retries_probe_without_starting_worker(monkeypatch):
    supervisor = runtime.Supervisor()
    supervisor.worker_start_deadline = 100
    now = [1]
    calls = []
    monkeypatch.setattr(runtime.time, 'monotonic', lambda: now[0])

    def unavailable(*args, **kwargs):
        calls.append(kwargs)
        raise OSError('scanner still starting')

    monkeypatch.setattr(runtime, 'local_health', unavailable)
    monkeypatch.setattr(supervisor, 'start', lambda *a: pytest.fail('mailbox worker must remain stopped'))
    supervisor.start_worker_when_ready()
    now[0] = 2
    supervisor.start_worker_when_ready()
    assert len(calls) == 1 and calls[0]['timeout'] == 2
    now[0] = 3
    supervisor.start_worker_when_ready()
    assert len(calls) == 2


def test_ready_current_scanner_starts_worker_once_but_shutdown_and_maintenance_do_not(monkeypatch):
    supervisor = runtime.Supervisor()
    supervisor.worker_start_deadline = 100
    monkeypatch.setattr(runtime.time, 'monotonic', lambda: 1)
    monkeypatch.setattr(runtime, 'local_health', lambda *a, **kw: READY)
    started = []

    def start(name, command, uid, kind):
        started.append((name, command, uid, kind))
        supervisor.children[name] = object()

    monkeypatch.setattr(supervisor, 'start', start)
    supervisor.stopping = True
    supervisor.start_worker_when_ready()
    supervisor.stopping = False
    supervisor.database_only = True
    supervisor.start_worker_when_ready()
    assert started == []
    supervisor.database_only = False
    supervisor.start_worker_when_ready()
    supervisor.start_worker_when_ready()
    assert len(started) == 1 and started[0][0] == 'worker'
    assert started[0][2:] == (runtime.APP_UID, 'app')


@pytest.mark.parametrize('becomes_ready', [True, False])
def test_supervision_keeps_console_open_while_waiting_then_starts_or_fails_bounded(monkeypatch, tmp_path, becomes_ready):
    """Exercise actual run ordering without a database, provider, or mailbox."""
    supervisor = runtime.Supervisor()
    clock = [0.0]
    events = []
    states = []
    scanner_probes = []
    monkeypatch.setattr(runtime, 'DATA', tmp_path)
    monkeypatch.setattr(runtime, 'SCANNER_STARTUP_TIMEOUT_SECONDS', 6)
    (tmp_path / 'antivirus').mkdir()
    (tmp_path / 'antivirus/main.cvd').write_bytes(b'fixture')
    monkeypatch.setattr(runtime, 'prepare', lambda: 'private-fixture-password')
    monkeypatch.setattr(runtime, 'run_as', lambda *a, **kw: None)
    monkeypatch.setattr(runtime.time, 'monotonic', lambda: clock[0])
    monkeypatch.setattr(runtime.time, 'sleep', lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    monkeypatch.setattr(supervisor, 'reap', lambda: None)

    class Process:
        pid = 123

        def poll(self):
            return None

    def start(name, *_):
        events.append((name, clock[0]))
        supervisor.children[name] = Process()

    def status():
        states.append(set(supervisor.children))
        if 'worker' in supervisor.children:
            supervisor.stopping = True

    def open_health(port, **_):
        if port == 8025:
            return {'status': 'ok'}
        scanner_probes.append(clock[0])
        return READY if becomes_ready and clock[0] >= 4 else {'status': 'starting'}

    monkeypatch.setattr(supervisor, 'start', start)
    monkeypatch.setattr(supervisor, 'postgres', lambda _: start('postgres'))
    monkeypatch.setattr(supervisor, 'write_status', status)
    monkeypatch.setattr(supervisor, 'shutdown', lambda: events.append(('shutdown', clock[0])))
    monkeypatch.setattr(runtime, 'local_health', open_health)
    result = supervisor.run()
    assert any({'api', 'clamd', 'freshclam', 'inspector'} <= state and 'worker' not in state for state in states)
    if becomes_ready:
        assert result == 0
        assert ('worker', 4.0) in events
        assert next(t for name, t in events if name == 'clamd') < 4
    else:
        assert result == 1
        assert not any(name == 'worker' for name, _ in events)
        assert ('shutdown', 6.0) in events
    assert scanner_probes == [0.0, 2.0, 4.0]
