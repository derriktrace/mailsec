"""Backup/restore with bundled PostgreSQL; restore is restricted to empty maintenance DBs."""
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

PG = '/usr/lib/postgresql/18/bin/'
ENV = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}
STATE = Path('/run/mailsec-supervisor.json')
TEMP_DIR = '/tmp/mailsec-postgres'
PASSWORD_FILE = '/data/app/secrets/postgres-password'


def restore_password():
    descriptor = os.open(PASSWORD_FILE, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            raise ValueError('Restore requires a private regular database credential file')
        value = stream.read(257)
    if len(value) > 256:
        raise ValueError('Invalid restore database credential file')
    try:
        password = value.decode('ascii').strip()
    except UnicodeError:
        raise ValueError('Invalid restore database credential file') from None
    if not re.fullmatch(r'[A-Za-z0-9_-]{32,128}', password):
        raise ValueError('Invalid restore database credential file')
    return password


def main():
    restore = sys.argv[1:] == ['restore']
    verify = sys.argv[1:] == ['verify-query']
    if sys.argv[1:] and not (restore or verify):
        raise ValueError('Expected no argument (backup), restore or verify-query')
    if restore or verify:
        state = json.loads(STATE.read_text())
        if not state['database_only'] or set(state['services']) != {'postgres'}:
            raise ValueError('Restore requires database-only maintenance mode')
    # Dumping rows can execute a user-defined type's output function too. Every
    # data operation logs in as the ordinary owner, never a superuser session.
    password = restore_password()
    os.setgroups([])
    os.setgid(10004)
    os.setuid(10004)
    if restore:
        count = subprocess.check_output([PG + 'psql', '-X', '-w', '-h', '/run/mailsec-postgres', '-U', 'postgres', '-d', 'mailsec', '-At', '-c',
            "SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%' AND c.relkind IN ('r','p','v','m','S','f')"], env=ENV).strip()
        if count != b'0':
            raise ValueError('Restore target is not empty; no data was changed')
        # Connect as the ordinary login from the start. SET ROLE from a postgres
        # session alone is not a boundary: a crafted dump can RESET ROLE.
        command = [PG + 'pg_restore', '-h', '127.0.0.1', '-U', 'mailsec', '-d', 'mailsec',
                   '--single-transaction', '--exit-on-error', '--no-owner', '--no-acl', '--role=mailsec']
    elif verify:
        # Row serialization can invoke restored functions/types; verification
        # must never inspect a restored database under a superuser session.
        command = [PG + 'psql', '-X', '-w', '-qAt', '-h', '127.0.0.1', '-U', 'mailsec', '-d', 'mailsec',
                   '-v', 'ON_ERROR_STOP=1']
    else:
        command = [PG + 'pg_dump', '-h', '127.0.0.1', '-U', 'mailsec', '-d', 'mailsec',
                   '--format=custom', '--no-owner', '--no-acl']
    with tempfile.TemporaryDirectory(prefix='database-', dir=TEMP_DIR) as folder:
        passfile = Path(folder) / 'pgpass'
        descriptor = os.open(passfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'w') as output:
            output.write('127.0.0.1:5432:mailsec:mailsec:' + password + '\n')
        del password
        return subprocess.call(command, env={**ENV, 'PGPASSFILE': str(passfile)})


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except ValueError as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from None
