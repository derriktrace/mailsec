"""One-container supervisor. No email parsing or network control API runs as root.

Only the web/worker processes can read app credentials. PostgreSQL, static
inspection, and antivirus have different UIDs and private persistent directories.
Unexpected required-process death stops the container so its restart policy can
recover the durable queue. The updater retries with bounded exponential backoff.
"""
from __future__ import annotations

import base64
import ctypes
import ipaddress
import json
import os
import re
import secrets
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path

from mailsec.runtime_http import local_health

APP_UID, AV_UID, INSPECTOR_UID, DB_UID = 10001, 10002, 10003, 10004
UPDATER_UID = 10005
PG_BIN = '/usr/lib/postgresql/18/bin/'
DATA = Path('/data')
STATE = Path('/run/mailsec-supervisor.json')
BOOTSTRAP = Path('/run/bootstrap-private')
ORGANIZATION_BOOTSTRAP = Path('/run/bootstrap-organization.yaml')
ORGANIZATION_DEFAULT = Path('/app/organization.yaml')
RUN_DIR = Path('/run')
TMP_DIR = Path('/tmp')
BASE_ENV = {'PATH': '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8', 'TZ': 'UTC',
            'PYTHONUNBUFFERED': '1', 'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONNOUSERSITE': '1'}
APP_PREFIXES = ('MAILSEC_', 'TYPESAFE_', 'GOOGLE_OAUTH_', 'WEB_RISK_')
SCANNER_STARTUP_TIMEOUT_SECONDS = 600
DATABASE_PLATFORM_MARKER = '.mailsec-database-platform'


def trusted_proxies(value):
    entries = [entry.strip() for entry in value.split(',')]
    if not entries or len(value) > 1024:
        raise ValueError('Specify explicit trusted proxy IP addresses or restricted networks')
    for entry in entries:
        try:
            network = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            raise ValueError('Specify explicit trusted proxy IP addresses or restricted networks') from None
        if network.prefixlen == 0:
            raise ValueError('Trusting every proxy source is not supported')
    return ','.join(entries)


def database_platform():
    """Physical PostgreSQL files must not cross the glibc/musl image boundary."""
    if Path('/etc/alpine-release').is_file():
        return 'postgres18-musl-v1'
    try:
        if os.confstr('CS_GNU_LIBC_VERSION'):
            return 'postgres18-glibc-v1'
    except (ValueError, OSError):
        pass
    raise RuntimeError('Unsupported PostgreSQL runtime platform')


def validate_database_platform(folder, expected):
    marker = folder / DATABASE_PLATFORM_MARKER
    if not marker.exists() or regular_read(marker).decode().strip() != expected:
        print('Database platform is unknown or incompatible. Do not reuse this physical database volume. '
              'Use the previous image to create a logical backup, initialize a NEW volume with this image, '
              'then restore the backup with its matching encryption keys. Existing data was not changed.',
              file=sys.stderr, flush=True)
        raise ValueError('Logical database migration is required')


def private_directory(path, uid, mode=0o700):
    path = Path(path)
    if path.is_symlink():
        raise ValueError('Refusing a symbolic link in runtime directories')
    path.mkdir(parents=False, exist_ok=True, mode=mode)
    if not path.is_dir():
        raise ValueError('Runtime path is not a directory')
    # CHOWN suffices without retaining FOWNER: configure as owner, then hand off.
    os.chown(path, 0, 0, follow_symlinks=False)
    path.chmod(mode)
    os.chown(path, uid, uid, follow_symlinks=False)


def regular_read(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise ValueError('Expected a regular runtime configuration file')
    # Verify the opened inode, not just its earlier pathname; a raced symlink or
    # oversized persistent configuration must not trick the root supervisor.
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError('Expected a regular runtime configuration file')
        value = stream.read(1024 * 1024 + 1)
        if len(value) > 1024 * 1024:
            raise ValueError('Runtime configuration exceeds its size limit')
        return value


def write_private(path, value, uid):
    path = Path(path)
    if path.is_symlink():
        raise ValueError('Refusing a symbolic link in runtime configuration')
    content = value.encode() if isinstance(value, str) else value
    temporary = path.parent / ('.' + path.name + '.' + secrets.token_hex(8))
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchown(stream.fileno(), uid, uid)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def service_env(kind, inherited=None):
    inherited = os.environ if inherited is None else inherited
    environment = dict(BASE_ENV)
    homes = {'app': '/data/app', 'inspector': '/data/inspection', 'av': '/tmp/mailsec-av',
             'updater': '/data/antivirus', 'postgres': '/data/postgres'}
    temp = {'app': '/tmp/mailsec-app', 'inspector': '/tmp/mailsec-inspector', 'av': '/tmp/mailsec-av',
            'updater': '/tmp/mailsec-updater', 'postgres': '/tmp/mailsec-postgres'}
    environment.update(HOME=homes[kind], TMPDIR=temp[kind])
    if kind == 'app':
        environment.update({key: value for key, value in inherited.items() if key.startswith(APP_PREFIXES)})
        environment.update(MAILSEC_DATABASE_URL_FILE='/data/app/secrets/database-url',
                           TYPESAFE_API_KEY_FILE='/data/app/secrets/jev-key',
                           MAILSEC_APP_TOKEN_FILE='/data/app/secrets/console-token',
                           MAILSEC_TOKEN_ENCRYPTION_KEY_FILE='/data/app/secrets/token-encryption-key',
                           GOOGLE_OAUTH_CLIENT_FILE='/data/app/secrets/google-oauth-client.json',
                           MAILSEC_ORG_CONFIG='/data/app/organization.yaml',
                           MAILSEC_INSPECTION_URL='http://127.0.0.1:8080')
        # The supervisor's maintenance controls are never application settings.
        environment.pop('MAILSEC_DATABASE_ONLY', None)
    elif kind == 'inspector':
        environment.update(INSPECTION_CLAMD_HOST='127.0.0.1', INSPECTION_REQUEST_TIMEOUT_SECONDS='90',
                           INSPECTION_TENANT_ID='selfhost', INSPECTION_CACHE_PATH='/data/inspection/cache.sqlite3')
    return environment


def demote(uid):
    def apply():
        os.setgroups([])
        os.setgid(uid)
        os.setuid(uid)
        # Antivirus signatures are public data and must be readable by the
        # separately confined engine. Updater scratch remains a private0700 dir.
        os.umask(0o022 if uid == UPDATER_UID else 0o077)
        # Best effort before exec; normal exec may reset this flag. Separate
        # service UIDs/private paths are the persistent isolation boundary.
        ctypes.CDLL(None, use_errno=True).prctl(4, 0, 0, 0, 0)  # PR_SET_DUMPABLE=0
    return apply


def run_as(command, uid, environment, **kwargs):
    return subprocess.run(command, env=environment, preexec_fn=demote(uid), check=True, **kwargs)


def prepare():
    os.umask(0o077)
    private_directory(DATA, 0, 0o755)
    for name, uid, mode in [('app', APP_UID, 0o700), ('inspection', INSPECTOR_UID, 0o700),
                            ('antivirus', UPDATER_UID, 0o755), ('postgres', DB_UID, 0o700)]:
        private_directory(DATA / name, uid, mode)
    private_directory(DATA / 'app/secrets', APP_UID)
    private_directory(RUN_DIR / 'mailsec-postgres', DB_UID)
    for name, uid in [('app', APP_UID), ('inspector', INSPECTOR_UID), ('av', AV_UID),
                      ('updater', UPDATER_UID), ('postgres', DB_UID)]:
        private_directory(TMP_DIR / ('mailsec-' + name), uid)
    if BOOTSTRAP.exists() and (BOOTSTRAP.is_symlink() or BOOTSTRAP.stat().st_mode & 0o077):
        raise ValueError('Bootstrap secrets directory must be private (0700)')
    values = {'console-token': secrets.token_urlsafe(48),
              'token-encryption-key': base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(),
              'postgres-password': secrets.token_urlsafe(36), 'jev-key': '', 'google-oauth-client.json': '{}'}
    folder = DATA / 'app/secrets'
    for name, generated in values.items():
        path = folder / name
        current = regular_read(path) if path.exists() or path.is_symlink() else None
        source = BOOTSTRAP / name
        supplied = regular_read(source) if source.exists() or source.is_symlink() else None
        if name == 'token-encryption-key' and current is not None and supplied is not None and current != supplied:
            raise ValueError('Encryption key mismatch: restore the matching original key; refusing to overwrite it')
        write_private(path, supplied if supplied is not None else current if current is not None else generated, APP_UID)
    password = regular_read(folder / 'postgres-password').decode().strip()
    if not re.fullmatch(r'[A-Za-z0-9_-]{32,}', password):
        raise ValueError('Invalid database password file')
    write_private(folder / 'database-url', 'postgresql+psycopg://mailsec:' + password + '@127.0.0.1:5432/mailsec', APP_UID)
    source = ORGANIZATION_BOOTSTRAP
    current = DATA / 'app/organization.yaml'
    organization = regular_read(source) if source.exists() else regular_read(current) if current.exists() else regular_read(ORGANIZATION_DEFAULT)
    write_private(current, organization, APP_UID)
    return password


class Supervisor:
    def __init__(self, database_only=False):
        self.database_only = database_only
        self.children = {}
        self.stopping = False
        self.updater_failures = 0
        self.updater_restart_at = 0
        self.worker_start_deadline = None
        self.worker_probe_at = 0

    def start(self, name, command, uid, kind):
        if self.stopping:
            raise RuntimeError('Shutdown requested')
        process = subprocess.Popen(command, env=service_env(kind), preexec_fn=demote(uid), start_new_session=True)
        self.children[name] = process
        print('Started service: ' + name, flush=True)
        return process

    def write_status(self):
        data = {'updated_at': time.time(), 'database_only': self.database_only, 'stopping': self.stopping,
                'startup_phase': ('maintenance' if self.database_only else
                                  'running' if 'worker' in self.children else 'waiting_for_scanner'),
                'services': {name: {'pid': process.pid, 'running': process.poll() is None}
                             for name, process in self.children.items()}}
        temporary = STATE.with_suffix('.new')
        temporary.write_text(json.dumps(data))
        temporary.chmod(0o644)
        temporary.replace(STATE)

    @staticmethod
    def signal_group(process, sig):
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            pass

    def shutdown(self):
        self.stopping = True
        self.write_status()
        # Stop accepting imports and let current work finish while DB/scanners live.
        front = [self.children[name] for name in ('api', 'worker') if name in self.children]
        for process in front:
            self.signal_group(process, signal.SIGTERM)
        deadline = time.monotonic() + 80
        while any(process.poll() is None for process in front) and time.monotonic() < deadline:
            time.sleep(.2)
        for process in front:
            self.signal_group(process, signal.SIGKILL)
        others = [(name, process) for name, process in self.children.items() if name not in ('api', 'worker')]
        for name, process in others:
            # PostgreSQL fast shutdown rolls back active transactions and checkpoints.
            self.signal_group(process, signal.SIGINT if name == 'postgres' else signal.SIGTERM)
        deadline = time.monotonic() + 15
        while any(process.poll() is None for _, process in others) and time.monotonic() < deadline:
            time.sleep(.2)
        for _, process in others:
            self.signal_group(process, signal.SIGKILL)
        for process in self.children.values():
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
        self.reap()

    def reap(self):
        # poll() first records direct-child exits; then reap adopted grandchildren.
        for process in self.children.values():
            process.poll()
        try:
            while os.waitpid(-1, os.WNOHANG)[0]:
                pass
        except ChildProcessError:
            pass

    def wait_database(self):
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline and not self.stopping:
            if self.children['postgres'].poll() is not None:
                raise RuntimeError('PostgreSQL exited during startup')
            result = subprocess.run([PG_BIN + 'pg_isready', '-h', '/run/mailsec-postgres', '-U', 'postgres'],
                                    env=service_env('postgres'), preexec_fn=demote(DB_UID),
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if result.returncode == 0:
                return
            time.sleep(.25)
        raise RuntimeError('PostgreSQL did not become ready')

    def postgres(self, password):
        folder = DATA / 'postgres'
        version = folder / 'PG_VERSION'
        platform = database_platform()
        if not version.exists():
            if any(folder.iterdir()):
                raise ValueError('Database directory is nonempty without PG_VERSION; restore a complete backup')
            run_as([PG_BIN + 'initdb', '-D', str(folder), '-U', 'postgres', '--encoding=UTF8',
                    '--locale=C.UTF-8', '--auth-local=peer', '--auth-host=scram-sha-256'], DB_UID, service_env('postgres'))
            write_private(folder / DATABASE_PLATFORM_MARKER, platform + '\n', DB_UID)
        else:
            validate_database_platform(folder, platform)
        if regular_read(version).strip() != b'18':
            raise ValueError('This release requires PostgreSQL18 data; use a supported logical migration')
        self.start('postgres', [PG_BIN + 'postgres', '-D', str(folder), '-c', 'config_file=/etc/mailsec/postgresql.conf'], DB_UID, 'postgres')
        self.wait_database()
        # The password is validated token text and supplied only on stdin, never argv/logs.
        sql = ("SELECT 'CREATE ROLE mailsec LOGIN' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname='mailsec')\\gexec\n"
               "ALTER ROLE mailsec PASSWORD '" + password + "';\n"
               "SELECT 'CREATE DATABASE mailsec OWNER mailsec' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname='mailsec')\\gexec\n")
        run_as([PG_BIN + 'psql', '-h', '/run/mailsec-postgres', '-U', 'postgres', '-d', 'postgres', '-v', 'ON_ERROR_STOP=1'],
               DB_UID, service_env('postgres'), input=sql, text=True, stdout=subprocess.DEVNULL)

    def start_worker_when_ready(self):
        """Leave queued mail untouched until inspection and current AV are ready."""
        if self.database_only or self.stopping or 'worker' in self.children:
            return
        now = time.monotonic()
        if self.worker_start_deadline is None or now >= self.worker_start_deadline:
            raise RuntimeError('Antivirus did not become ready within the startup deadline')
        if now < self.worker_probe_at:
            return
        self.worker_probe_at = now + 2
        try:
            status = local_health(8080, timeout=2)
            if not isinstance(status, dict):
                return
            antivirus = status.get('antivirus', {})
            if (not isinstance(antivirus, dict) or status.get('status') != 'ready'
                    or antivirus.get('status') != 'ready' or antivirus.get('signatures_current') is not True):
                return
        except (OSError, ValueError):
            return
        if not self.stopping:
            self.start('worker', [sys.executable, '-m', 'mailsec.worker'], APP_UID, 'app')

    def run(self):
        failure = False
        started_at = time.monotonic()
        phase = 'private storage initialization'
        try:
            proxy_ips = trusted_proxies(os.getenv('MAILSEC_TRUSTED_PROXY_IPS', '127.0.0.1'))
            password = prepare()
            phase = 'PostgreSQL initialization'
            self.postgres(password)
            del password
            if not self.database_only:
                phase = 'application startup'
                # Serial schema setup before API and worker overlap.
                run_as([sys.executable, '-c', 'from mailsec.api import create_app; create_app()'], APP_UID, service_env('app'))
                self.start('freshclam', ['freshclam', '--daemon', '--foreground', '--config-file=/etc/mailsec/freshclam.conf'], UPDATER_UID, 'updater')
                self.start('inspector', [sys.executable, '-m', 'uvicorn', 'mailsec.inspection.api:create_app', '--factory', '--host', '127.0.0.1', '--port', '8080', '--no-access-log'], INSPECTOR_UID, 'inspector')
                self.start('api', [sys.executable, '-m', 'uvicorn', 'mailsec.api:create_app', '--factory', '--host', '0.0.0.0', '--port', '8025', '--no-access-log', '--proxy-headers', '--forwarded-allow-ips', proxy_ips], APP_UID, 'app')
                deadline = time.monotonic() + 60
                while time.monotonic() < deadline and not self.stopping:
                    if self.children['api'].poll() is not None:
                        raise RuntimeError('Console exited during startup')
                    try:
                        local_health(8025, timeout=2)
                        break
                    except (OSError, ValueError):
                        pass
                    time.sleep(.25)
                else:
                    raise RuntimeError('Console did not become ready')
                # First signature installation and clamd loading can take minutes.
                # Keep the console available but do not claim jobs or repeatedly
                # create scan failures while those services initialize.
                self.worker_start_deadline = time.monotonic() + SCANNER_STARTUP_TIMEOUT_SECONDS
                print('Waiting for current antivirus signatures before starting mailbox processing', flush=True)
            phase = 'service supervision'
            while not self.stopping:
                if not self.database_only and 'clamd' not in self.children and any((DATA / 'antivirus' / name).is_file() for name in ('main.cvd', 'main.cld')):
                    self.start('clamd', [sys.executable, '-m', 'mailsec.inspection.clam_policy'], AV_UID, 'av')
                for name, process in list(self.children.items()):
                    if process.poll() is not None:
                        self.signal_group(process, signal.SIGKILL)
                        if name == 'freshclam':
                            self.updater_failures += 1
                            delay = min(60, 2 ** min(self.updater_failures, 6))
                            self.updater_restart_at = time.monotonic() + delay
                            del self.children[name]
                            print('Signature updater exited; retrying in ' + str(delay) + ' seconds', flush=True)
                        else:
                            print('Required service exited: ' + name + '; stopping container for recovery', flush=True)
                            raise RuntimeError('Required service exited')
                if not self.database_only and 'freshclam' not in self.children and time.monotonic() >= self.updater_restart_at:
                    self.start('freshclam', ['freshclam', '--daemon', '--foreground', '--config-file=/etc/mailsec/freshclam.conf'], UPDATER_UID, 'updater')
                self.start_worker_when_ready()
                self.reap()
                self.write_status()
                time.sleep(.5)
        except Exception as exc:
            # Do not print exception values that could contain operator configuration.
            print('Container failure during ' + phase + ' (' + type(exc).__name__ + '); check service logs', file=sys.stderr, flush=True)
            failure = True
        finally:
            self.shutdown()
        if failure:
            # Some runtimes restart failed containers immediately; bound that loop.
            time.sleep(max(0, 10 - (time.monotonic() - started_at)))
        return 1 if failure else 0


def main():
    if os.geteuid() != 0:
        print('The supervisor must start as container root to separate service UIDs; services run unprivileged.', file=sys.stderr)
        return 1
    supervisor = Supervisor(os.getenv('MAILSEC_DATABASE_ONLY', 'false').lower() == 'true')
    def stop(*_):
        supervisor.stopping = True
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    return supervisor.run()


if __name__ == '__main__':
    raise SystemExit(main())
