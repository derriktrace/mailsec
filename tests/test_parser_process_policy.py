"""Exercise restrictions in disposable children; never constrain the test runner."""

import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from mailsec.inspection.process_policy import restrict_parser


@pytest.mark.skipif(sys.platform != 'linux', reason='The self-host runtime targets Linux')
def test_parser_denies_network_including_exec_children_but_allows_local_work():
    probe = '''
import errno, socket, tempfile
for family in (socket.AF_INET, socket.AF_INET6, socket.AF_UNIX):
    try:
        socket.socket(family)
    except OSError as exc:
        assert exc.errno == errno.EPERM, exc
    else:
        raise AssertionError('Parser opened a network socket')
try:
    socket.socketpair()
except OSError as exc:
    assert exc.errno == errno.EPERM, exc
else:
    raise AssertionError('Parser opened a socket pair')
with tempfile.TemporaryFile() as output:
    output.write(b'local-work')
    output.seek(0)
    assert output.read() == b'local-work'
'''
    code = ('from mailsec.inspection.process_policy import restrict_parser; '
            'import socket,subprocess,sys; socket.socket().close(); restrict_parser(); '
            + 'exec(' + repr(probe) + '); '
            + 'subprocess.run([sys.executable,"-c",' + repr(probe) + '],check=True)')
    completed = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, timeout=15)
    assert completed.returncode == 0, completed.stderr


def test_parser_restriction_failure_is_not_silently_ignored(monkeypatch):
    def unavailable(*args, **kwargs):
        raise OSError('Missing required policy library')
    monkeypatch.setattr('mailsec.inspection.process_policy.ctypes.CDLL', unavailable)
    with pytest.raises(OSError, match='Missing required policy library'):
        restrict_parser()


def test_worker_stops_before_reading_mime_when_policy_cannot_load(monkeypatch):
    from mailsec.inspection import worker

    def unavailable():
        raise RuntimeError('Cannot activate parser syscall restriction')
    monkeypatch.setattr('mailsec.inspection.process_policy.restrict_parser', unavailable)
    monkeypatch.delenv('INSPECTION_WORKER_LIMITS', raising=False)
    with pytest.raises(RuntimeError, match='Cannot activate'):
        worker.main()
    assert 'INSPECTION_WORKER_LIMITS' not in os.environ


@pytest.mark.skipif(sys.platform != 'linux', reason='The self-host runtime targets Linux')
def test_parser_filesystem_cannot_read_poison_or_truncate_sibling_cache_including_exec(tmp_path):
    victim = tmp_path / 'private-cache.sqlite3'
    victim.write_text('private other-message and antivirus data')
    # The same UID and ordinary Unix permissions permit these operations before
    # confinement. This reproduces the native-decoder/cache trust-boundary gap.
    victim.chmod(0o600)
    with tempfile.TemporaryDirectory(prefix='mailsec-parser-', dir=tmp_path) as scratch:
        Path(scratch, 'escape').symlink_to(victim)
        probe = '''
import errno,os,tempfile
from pathlib import Path
victim=Path(VICTIM)
def denied(operation):
    try:
        operation()
    except OSError as exc:
        assert exc.errno in (errno.EACCES,errno.EPERM,errno.EXDEV),exc
    else:
        raise AssertionError('Protected sibling data was accessible')
denied(lambda:victim.read_bytes())
denied(lambda:victim.write_bytes(b'poisoned antivirus result'))
denied(lambda:victim.unlink())
denied(lambda:os.truncate(victim,0))
denied(lambda:os.chmod(victim,0o777))
denied(lambda:Path(SCRATCH,'escape').read_bytes())
denied(lambda:os.open('/proc/'+str(PARENT)+'/mem',os.O_RDONLY))
denied(lambda:os.kill(PARENT,0))
denied(lambda:os.setsid())
denied(lambda:os.setpgid(0,0))
import ctypes
libc=ctypes.CDLL(None,use_errno=True)
libc.syscall.restype=ctypes.c_long
seccomp=ctypes.CDLL('libseccomp.so.2')
seccomp.seccomp_syscall_resolve_name.argtypes=[ctypes.c_char_p]
for name,args,expected in (
    (b'clone3',(0,0),errno.ENOSYS),
    (b'unshare',(0x10000000,),errno.EPERM),
    (b'setns',(-1,0),errno.EPERM),
):
    result=libc.syscall(seccomp.seccomp_syscall_resolve_name(name),*args)
    assert result==-1 and ctypes.get_errno()==expected,(name,result,ctypes.get_errno())
result=libc.syscall(seccomp.seccomp_syscall_resolve_name(b'clone'),0x10000000|17,0,0,0,0)
if result==0:
    os._exit(99)
if result>0:
    os.waitpid(result,0)
assert result==-1 and ctypes.get_errno()==errno.EPERM,('clone namespace escaped',result)
with tempfile.TemporaryDirectory(dir=SCRATCH) as work:
    own=Path(work,'native-output')
    own.write_text('allowed temporary result')
    assert own.read_text()=='allowed temporary result'
'''.replace('VICTIM', repr(str(victim))).replace('SCRATCH', repr(scratch)).replace('PARENT', str(os.getpid()))
        code = ('from mailsec.inspection.process_policy import restrict_parser,restrict_filesystem; '
                'import subprocess,sys; restrict_parser(); restrict_filesystem(' + repr(scratch) + '); '
                'exec(' + repr(probe) + '); '
                'child=subprocess.Popen([sys.executable,"-c","import time; time.sleep(30)"]); '
                'child.terminate(); assert child.wait(timeout=3)<0; '
                'subprocess.run([sys.executable,"-c",' + repr(probe) + '],check=True)')
        completed = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, timeout=15)
        assert completed.returncode == 0, completed.stderr
    assert victim.read_text() == 'private other-message and antivirus data'
    assert victim.stat().st_mode & 0o777 == 0o600


def test_filesystem_confinement_refuses_old_or_disabled_landlock(tmp_path, monkeypatch):
    from mailsec.inspection import process_policy

    class Call:
        def __call__(self, *args):
            return 2

    class Library:
        syscall = Call()
        seccomp_syscall_resolve_name = Call()

    monkeypatch.setattr(process_policy.ctypes, 'CDLL', lambda *a, **kw: Library())
    with tempfile.TemporaryDirectory(prefix='mailsec-parser-', dir=tmp_path) as scratch:
        with pytest.raises(RuntimeError, match='Landlock ABI6'):
            process_policy.restrict_filesystem(scratch)


def test_filesystem_confinement_rejects_shared_or_symlinked_scratch(tmp_path, monkeypatch):
    from mailsec.inspection.process_policy import restrict_filesystem

    # Validation tests must never reach a real irreversible policy installation,
    # even if another test changed the process umask or a filesystem default.
    monkeypatch.setattr('mailsec.inspection.process_policy.ctypes.CDLL',
                        lambda *a, **kw: pytest.fail('Invalid scratch reached policy installation'))
    with pytest.raises(ValueError, match='private per-job'):
        restrict_filesystem(tmp_path)
    scratch = tmp_path / 'mailsec-parser-public'
    scratch.mkdir(mode=0o755)
    scratch.chmod(0o755)
    with pytest.raises(ValueError, match='private per-job'):
        restrict_filesystem(scratch)
    scratch.chmod(0o700)
    link = tmp_path / 'mailsec-parser-linked'
    link.symlink_to(scratch)
    with pytest.raises(ValueError, match='private per-job'):
        restrict_filesystem(link)
