"""One-container security/lifecycle boundaries, without accessing real installations."""
import importlib.util
import json
import os
import signal
import stat
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'scripts' / (name + '.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


runtime = module('container_runtime')
health = module('container_health')
backup = module('container_backup')


def test_scanner_and_database_environments_never_receive_application_secrets():
    inherited = {'MAILSEC_APP_TOKEN': 'secret-console', 'GOOGLE_OAUTH_CLIENT_FILE': '/secret-google',
                 'TYPESAFE_API_KEY': 'secret-model', 'WEB_RISK_API_KEY': 'secret-url',
                 'AWS_SECRET_ACCESS_KEY': 'secret-cloud', 'LD_PRELOAD': '/untrusted.so',
                 'MAILSEC_DATABASE_ONLY': 'true', 'MAILSEC_WORKSPACE_NAME': 'Home'}
    for name in ('inspector', 'av', 'updater', 'postgres'):
        values = runtime.service_env(name, inherited)
        assert not any('secret-' in value for value in values.values())
        assert not set(inherited) & set(values)
    app = runtime.service_env('app', inherited)
    assert app['MAILSEC_WORKSPACE_NAME'] == 'Home'
    assert app['MAILSEC_APP_TOKEN_FILE'] == '/data/app/secrets/console-token'
    assert 'LD_PRELOAD' not in app and 'AWS_SECRET_ACCESS_KEY' not in app
    assert 'MAILSEC_DATABASE_ONLY' not in app
    assert runtime.UPDATER_UID != runtime.AV_UID
    assert runtime.service_env('av', inherited)['HOME'] == '/tmp/mailsec-av'
    assert runtime.service_env('updater', inherited)['HOME'] == '/data/antivirus'


@pytest.mark.parametrize('value', ['*', '127.0.0.1,*', '*,::1', '', 'proxy.example.test',
                                  '127.0.0.1,', '0.0.0.0/0', '::/0'])
def test_direct_container_environment_cannot_enable_wildcard_proxy_trust(value):
    with pytest.raises(ValueError):
        runtime.trusted_proxies(value)


def test_direct_container_proxy_configuration_accepts_explicit_addresses():
    assert runtime.trusted_proxies('127.0.0.1, ::1, 192.0.2.16/28') == '127.0.0.1,::1,192.0.2.16/28'


def isolated_prepare(monkeypatch, tmp_path):
    for name in ('DATA', 'BOOTSTRAP', 'RUN_DIR', 'TMP_DIR'):
        path = tmp_path / name.lower()
        path.mkdir(mode=0o700)
        monkeypatch.setattr(runtime, name, path)
    monkeypatch.setattr(runtime, 'ORGANIZATION_BOOTSTRAP', tmp_path / 'optional-org')
    default = tmp_path / 'default-org'
    default.write_text('organization: {}\n')
    monkeypatch.setattr(runtime, 'ORGANIZATION_DEFAULT', default)
    monkeypatch.setattr(runtime.os, 'chown', lambda *a, **kw: None)
    monkeypatch.setattr(runtime.os, 'fchown', lambda *a, **kw: None)


def test_bootstrap_preserves_generated_credentials_and_refuses_encryption_key_replacement(tmp_path, monkeypatch):
    isolated_prepare(monkeypatch, tmp_path)
    runtime.prepare()
    folder = runtime.DATA / 'app/secrets'
    before = {p.name: p.read_bytes() for p in folder.iterdir()}
    runtime.prepare()
    assert before == {p.name: p.read_bytes() for p in folder.iterdir()}
    assert all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in folder.iterdir())
    for name in ('app', 'app/secrets', 'inspection', 'postgres'):
        assert stat.S_IMODE((runtime.DATA / name).stat().st_mode) == 0o700
    (runtime.BOOTSTRAP / 'token-encryption-key').write_text('different-key')
    with pytest.raises(ValueError, match='Encryption key mismatch'):
        runtime.prepare()
    assert (folder / 'token-encryption-key').read_bytes() == before['token-encryption-key']


def test_runtime_rejects_public_bootstrap_or_symlinked_private_files(tmp_path, monkeypatch):
    isolated_prepare(monkeypatch, tmp_path)
    runtime.BOOTSTRAP.chmod(0o755)
    with pytest.raises(ValueError, match='private'):
        runtime.prepare()
    runtime.BOOTSTRAP.chmod(0o700)
    victim = tmp_path / 'victim'
    victim.write_text('unchanged')
    (runtime.BOOTSTRAP / 'postgres-password').symlink_to(victim)
    with pytest.raises(ValueError, match='regular'):
        runtime.prepare()
    assert victim.read_text() == 'unchanged'
    target = tmp_path / 'target'
    target.symlink_to(victim)
    with pytest.raises(ValueError, match='symbolic'):
        runtime.write_private(target, 'overwrite', os.getuid())
    assert victim.read_text() == 'unchanged'


def test_supervisor_graceful_stop_delivers_signal_to_child(tmp_path, monkeypatch):
    monkeypatch.setattr(runtime, 'STATE', tmp_path / 'status.json')
    monkeypatch.setattr(runtime, 'demote', lambda uid: None)
    marker = tmp_path / 'stopped'
    ready = tmp_path / 'ready'
    code = ('import signal,time,pathlib,sys; '
            f'signal.signal(signal.SIGTERM,lambda *_:(pathlib.Path({str(marker)!r}).write_text("graceful"),sys.exit(0))); '
            f'pathlib.Path({str(ready)!r}).write_text("ready"); time.sleep(30)')
    supervisor = runtime.Supervisor()
    process = supervisor.start('worker', [sys.executable, '-c', code], os.getuid(), 'app')
    try:
        deadline = time.monotonic() + 5
        while not ready.exists() and time.monotonic() < deadline:
            time.sleep(.01)
        assert ready.exists()
        supervisor.shutdown()
        assert process.returncode == 0
        assert marker.read_text() == 'graceful'
        assert json.loads((tmp_path / 'status.json').read_text())['stopping']
    finally:
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()


def test_health_rejects_dead_worker_or_stale_supervisor_before_external_checks(tmp_path, monkeypatch):
    path = tmp_path / 'state'
    monkeypatch.setattr(health, 'STATE', path)
    path.write_text(json.dumps({'stopping':False,'updated_at':time.time(),'database_only':False,
                               'services':{'postgres':{'running':True,'pid':os.getpid()}}}))
    with pytest.raises(ValueError, match='not running'):
        health.health()
    path.write_text(json.dumps({'stopping':False,'updated_at':time.time()-60,'database_only':True,'services':{}}))
    with pytest.raises(ValueError, match='stale'):
        health.health()


def test_health_rejects_unavailable_parser_isolation_even_with_current_antivirus(tmp_path, monkeypatch):
    path = tmp_path / 'state'
    path.write_text(json.dumps({'stopping': False, 'updated_at': time.time(), 'database_only': False,
                               'services': {name: {'running': True, 'pid': os.getpid()}
                                            for name in ('postgres', 'api', 'worker', 'inspector', 'clamd', 'freshclam')}}))
    monkeypatch.setattr(health, 'STATE', path)
    monkeypatch.setattr(health.subprocess, 'run', lambda *args, **kwargs: type('Ready', (), {'returncode': 0})())
    monkeypatch.setattr(health, 'local_health', lambda port, **kwargs: {
        'status': 'parser_isolation_unavailable', 'antivirus': {'status': 'ready', 'signatures_current': True}})
    with pytest.raises(ValueError, match='Inspection is not ready'):
        health.health()


def test_restore_refuses_running_application_and_nonempty_database(tmp_path, monkeypatch):
    path = tmp_path / 'status'
    path.write_text(json.dumps({'database_only':False,'services':{'postgres':{},'worker':{}}}))
    monkeypatch.setattr(backup, 'STATE', path)
    monkeypatch.setattr(backup, 'restore_password', lambda: 'x' * 48)
    monkeypatch.setattr(backup.sys, 'argv', ['backup', 'restore'])
    with pytest.raises(ValueError, match='database-only'):
        backup.main()
    path.write_text(json.dumps({'database_only':True,'services':{'postgres':{}}}))
    for name in ('setgroups', 'setgid', 'setuid'):
        monkeypatch.setattr(backup.os, name, lambda value: None)
    monkeypatch.setattr(backup.subprocess, 'check_output', lambda *a, **kw: b'1')
    monkeypatch.setattr(backup.subprocess, 'call', lambda *a, **kw: pytest.fail('must not restore'))
    with pytest.raises(ValueError, match='not empty'):
        backup.main()


def test_restore_empty_database_uses_single_transaction_and_unprivileged_role(tmp_path, monkeypatch):
    path = tmp_path / 'status'
    path.write_text(json.dumps({'database_only':True,'services':{'postgres':{}}}))
    monkeypatch.setattr(backup, 'STATE', path)
    monkeypatch.setattr(backup, 'TEMP_DIR', str(tmp_path))
    monkeypatch.setattr(backup, 'restore_password', lambda: 'x' * 48)
    monkeypatch.setattr(backup.sys, 'argv', ['backup', 'restore'])
    for name in ('setgroups', 'setgid', 'setuid'):
        monkeypatch.setattr(backup.os, name, lambda value: None)
    monkeypatch.setattr(backup.subprocess, 'check_output', lambda *a, **kw: b'0')
    calls=[]
    passfiles = []

    def restore(command, **kwargs):
        calls.append(command)
        private = Path(kwargs['env']['PGPASSFILE'])
        passfiles.append(private)
        assert stat.S_IMODE(private.stat().st_mode) == 0o600
        assert private.read_text() == '127.0.0.1:5432:mailsec:mailsec:' + 'x' * 48 + '\n'
        assert 'x' * 48 not in repr(command) + repr(kwargs['env'])
        return 0

    monkeypatch.setattr(backup.subprocess, 'call', restore)
    assert backup.main() == 0
    assert '--single-transaction' in calls[0]
    assert '--exit-on-error' in calls[0]
    assert '--role=mailsec' in calls[0]
    assert calls[0][calls[0].index('-U') + 1] == 'mailsec'
    assert calls[0][calls[0].index('-h') + 1] == '127.0.0.1'
    assert all(not path.exists() for path in passfiles)


def test_restore_verification_never_queries_as_postgres(tmp_path, monkeypatch):
    state = tmp_path / 'status'
    state.write_text(json.dumps({'database_only': True, 'services': {'postgres': {}}}))
    monkeypatch.setattr(backup, 'STATE', state)
    monkeypatch.setattr(backup, 'TEMP_DIR', str(tmp_path))
    monkeypatch.setattr(backup, 'restore_password', lambda: 'x' * 48)
    monkeypatch.setattr(backup.sys, 'argv', ['backup', 'verify-query'])
    for name in ('setgroups', 'setgid', 'setuid'):
        monkeypatch.setattr(backup.os, name, lambda value: None)
    calls = []
    monkeypatch.setattr(backup.subprocess, 'check_output', lambda *a, **kw: pytest.fail('No superuser query'))
    monkeypatch.setattr(backup.subprocess, 'call', lambda command, **kwargs: calls.append(command) or 0)
    assert backup.main() == 0
    assert calls[0][0].endswith('/psql') and '-X' in calls[0] and '-w' in calls[0]
    assert calls[0][calls[0].index('-U') + 1] == 'mailsec'
    assert not list(tmp_path.glob('restore-*'))


def test_regular_backup_cannot_execute_data_serialization_as_superuser(tmp_path, monkeypatch):
    monkeypatch.setattr(backup, 'TEMP_DIR', str(tmp_path))
    monkeypatch.setattr(backup, 'restore_password', lambda: 'x' * 48)
    monkeypatch.setattr(backup.sys, 'argv', ['backup'])
    for name in ('setgroups', 'setgid', 'setuid'):
        monkeypatch.setattr(backup.os, name, lambda value: None)
    calls = []
    private_paths = []

    def dump(command, **kwargs):
        calls.append(command)
        private = Path(kwargs['env']['PGPASSFILE'])
        private_paths.append(private)
        assert stat.S_IMODE(private.stat().st_mode) == 0o600
        assert 'x' * 48 not in repr(command) + repr(kwargs['env'])
        return 0

    monkeypatch.setattr(backup.subprocess, 'check_output', lambda *a, **kw: pytest.fail('No superuser query'))
    monkeypatch.setattr(backup.subprocess, 'call', dump)
    assert backup.main() == 0
    assert calls[0][0].endswith('/pg_dump')
    assert calls[0][calls[0].index('-U') + 1] == 'mailsec'
    assert all(not path.exists() for path in private_paths)


@pytest.mark.parametrize('marker', [None, 'postgres18-glibc-v1', 'unrecognized-platform'])
def test_existing_cluster_requires_matching_runtime_platform_before_postgres_start(tmp_path, monkeypatch, marker, capsys):
    monkeypatch.setattr(runtime, 'DATA', tmp_path)
    monkeypatch.setattr(runtime, 'database_platform', lambda: 'postgres18-musl-v1')
    folder = tmp_path / 'postgres'
    folder.mkdir()
    (folder / 'PG_VERSION').write_text('18\n')
    if marker:
        (folder / runtime.DATABASE_PLATFORM_MARKER).write_text(marker)
    before = {path.name: path.read_bytes() for path in folder.iterdir()}
    monkeypatch.setattr(runtime, 'run_as', lambda *a, **kw: pytest.fail('Must not start initialization or SQL'))
    supervisor = runtime.Supervisor()
    monkeypatch.setattr(supervisor, 'start', lambda *a, **kw: pytest.fail('Must not start incompatible cluster'))
    with pytest.raises(ValueError, match='Logical database migration'):
        supervisor.postgres('x' * 48)
    assert before == {path.name: path.read_bytes() for path in folder.iterdir()}
    assert 'NEW volume' in capsys.readouterr().err


def test_matching_cluster_platform_and_bounded_configuration_reads(tmp_path):
    marker = tmp_path / runtime.DATABASE_PLATFORM_MARKER
    marker.write_text('postgres18-musl-v1\n')
    runtime.validate_database_platform(tmp_path, 'postgres18-musl-v1')
    oversized = tmp_path / 'oversized'
    oversized.write_bytes(b'x' * (1024 * 1024 + 1))
    with pytest.raises(ValueError, match='size limit'):
        runtime.regular_read(oversized)


@pytest.mark.parametrize('content', [b'private-invalid-credential-\xff', b'x' * 300, b'bad;SQL'])
def test_restore_malformed_credentials_never_echo_their_contents(tmp_path, monkeypatch, content):
    password = tmp_path / 'credential'
    password.write_bytes(content)
    password.chmod(0o600)
    monkeypatch.setattr(backup, 'PASSWORD_FILE', str(password))
    with pytest.raises(ValueError, match='Invalid restore database credential file') as error:
        backup.restore_password()
    assert 'private-invalid' not in str(error.value)


def test_restore_refuses_special_files_without_waiting_for_fifo_writer(tmp_path, monkeypatch):
    password = tmp_path / 'credential'
    os.mkfifo(password, mode=0o600)
    monkeypatch.setattr(backup, 'PASSWORD_FILE', str(password))
    with pytest.raises(ValueError, match='private regular'):
        backup.restore_password()
