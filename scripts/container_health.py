"""Container health checks, with no credentials in output or HTTP requests."""
import json
import os
import subprocess
import time
from pathlib import Path

from mailsec.runtime_http import local_health

STATE = Path('/run/mailsec-supervisor.json')


def postgres_identity():
    os.setgroups([])
    os.setgid(10004)
    os.setuid(10004)


def health():
    status = json.loads(STATE.read_text())
    if status['stopping'] or time.time() - status['updated_at'] > 30:
        raise ValueError('Supervisor stopped or stale')
    expected = {'postgres'} if status['database_only'] else {'postgres', 'api', 'worker', 'inspector', 'clamd', 'freshclam'}
    for name in expected:
        item = status['services'].get(name, {})
        if not item.get('running'):
            raise ValueError('Required service is not running')
        os.kill(item['pid'], 0)
    result = subprocess.run(['/usr/lib/postgresql/18/bin/pg_isready', '-h', '/run/mailsec-postgres', '-U', 'postgres'],
                            env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}, preexec_fn=postgres_identity,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
    if result.returncode:
        raise ValueError('Database is not ready')
    if not status['database_only']:
        local_health(8025, timeout=2)
        result = local_health(8080, timeout=3)
        antivirus = result.get('antivirus', {})
        if (result.get('status') != 'ready' or not isinstance(antivirus, dict) or antivirus.get('status') != 'ready'
                or antivirus.get('signatures_current') is not True):
            raise ValueError('Inspection is not ready or antivirus signatures are stale')
    return True


if __name__ == '__main__':
    try:
        health()
    except Exception:
        print('Mailsec is starting or a required service is unhealthy; inspect container logs and console health.')
        raise SystemExit(1) from None
