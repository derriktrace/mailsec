"""Real isolated child proves antivirus can serve scans but cannot initiate egress."""

import os
import select
import socket
import subprocess
import sys
import tempfile


def test_clamd_policy_serves_tcp_but_protects_signatures_peers_and_network(tmp_path):
    signatures = tmp_path / 'public-signatures'
    signatures.mkdir()
    database = signatures / 'synthetic.cvd'
    database.write_text('public signed signatures')
    private = tmp_path / 'private-other-service'
    private.write_text('private credential')
    # Baseline permissions deliberately allow this UID to write the fixture.
    # The confinement must enforce read-only independently of Unix ownership.
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        port = reservation.getsockname()[1]
    with tempfile.TemporaryDirectory(prefix='mailsec-av-', dir=tmp_path) as scratch:
        code = '''
import errno,os,socket,sys
from pathlib import Path
from mailsec.inspection.process_policy import restrict_parser,_restrict_filesystem
restrict_parser(tcp_server=True)
_restrict_filesystem(SCRATCH,prefix='mailsec-av-',readonly=(SIGNATURES,),tcp_port=PORT)
def denied(call):
    try: call()
    except OSError as error: assert error.errno in (errno.EPERM,errno.EACCES),error
    else: raise AssertionError('Antivirus escaped confinement')
assert Path(DATABASE).read_text()=='public signed signatures'
denied(lambda:Path(DATABASE).write_text('poisoned'))
denied(lambda:Path(PRIVATE).read_text())
denied(lambda:os.kill(PARENT,0))
denied(lambda:os.setsid())
with socket.socket() as outgoing:
    denied(lambda:outgoing.connect(('127.0.0.1',PORT)))
with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as outgoing:
    denied(lambda:outgoing.sendto(b'private-data',('127.0.0.1',PORT)))
with socket.socket() as server:
    server.bind(('127.0.0.1',PORT))
    server.listen(1)
    server.settimeout(5)
    print('ready',flush=True)
    connection,_=server.accept()
    with connection:
        assert connection.recv(16)==b'PING'
        connection.sendall(b'PONG')
Path(SCRATCH,'own-output').write_text('allowed')
'''
        values = {'SCRATCH': repr(scratch), 'SIGNATURES': repr(str(signatures)), 'PORT': str(port),
                  'DATABASE': repr(str(database)), 'PRIVATE': repr(str(private)), 'PARENT': str(os.getpid())}
        for name, value in values.items():
            code = code.replace(name, value)
        child = subprocess.Popen([sys.executable, '-c', code], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            assert select.select([child.stdout], [], [], 10)[0], 'Confined listener did not start'
            ready = child.stdout.readline()
            if ready != b'ready\n':
                _, error = child.communicate(timeout=3)
                raise AssertionError(error.decode())
            with socket.create_connection(('127.0.0.1', port), timeout=3) as client:
                client.sendall(b'PING')
                assert client.recv(16) == b'PONG'
            _, error = child.communicate(timeout=5)
            assert child.returncode == 0, error.decode()
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
    assert database.read_text() == 'public signed signatures'
