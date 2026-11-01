"""Containment tests run in a disposable harness, never target the test runner."""

import json
import subprocess
import sys

import pytest


@pytest.mark.parametrize('antivirus', [False, True])
def test_confined_native_process_cannot_change_peer_limits_or_scheduling(antivirus):
    child = '''
import errno, os, resource, sys
from mailsec.inspection.process_policy import restrict_parser, _restrict_filesystem
peer = int(sys.argv[1])
scratch = sys.argv[2]
restrict_parser(tcp_server=ANTIVIRUS)
_restrict_filesystem(scratch, prefix='mailsec-parser-')
def denied(call):
    try:
        call()
    except OSError as error:
        assert error.errno == errno.EPERM, error
    else:
        raise AssertionError('Native process modified a peer resource')
limits = resource.getrlimit(resource.RLIMIT_NOFILE)
resource.setrlimit(resource.RLIMIT_NOFILE, limits)
assert resource.prlimit(0, resource.RLIMIT_NOFILE) == limits
denied(lambda: resource.prlimit(peer, resource.RLIMIT_NOFILE, (16, 16)))
denied(lambda: os.setpriority(os.PRIO_PROCESS, peer, 19))
denied(lambda: os.sched_setaffinity(peer, os.sched_getaffinity(0)))
# musl's scheduler wrappers can return ENOSYS without invoking the kernel for
# another PID. Probe the actual syscalls so this tests seccomp on either libc.
import ctypes
libc = ctypes.CDLL(None, use_errno=True)
libc.syscall.restype = ctypes.c_long
seccomp = ctypes.CDLL('libseccomp.so.2')
seccomp.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
def direct(name, *args):
    number = seccomp.seccomp_syscall_resolve_name(name)
    assert number >= 0, name
    result = libc.syscall(number, *args)
    if result < 0:
        raise OSError(ctypes.get_errno(), 'direct syscall')
    return result
parameter = ctypes.c_int(0)
denied(lambda: direct(b'sched_setscheduler', peer, 0, ctypes.byref(parameter)))
denied(lambda: direct(b'sched_setparam', peer, ctypes.byref(parameter)))
denied(lambda: direct(b'sched_setattr', peer, 0, 0))
denied(lambda: direct(b'ioprio_set', 1, peer, 0))
print('peer limits and scheduling protected')
'''.replace('ANTIVIRUS', repr(antivirus))
    # If a regression allows changing the parent's RLIMIT, only this short-lived
    # harness is affected. The pytest process is never a syscall target.
    harness = '''
import os, resource, subprocess, sys, tempfile
before = resource.getrlimit(resource.RLIMIT_NOFILE)
with tempfile.TemporaryDirectory(prefix='mailsec-parser-') as scratch:
    child = subprocess.run([sys.executable, '-c', CHILD, str(os.getpid()), scratch],
                           capture_output=True, text=True, timeout=10)
assert resource.getrlimit(resource.RLIMIT_NOFILE) == before, 'Peer limits changed'
assert child.returncode == 0, child.stderr
print(child.stdout, end='')
'''.replace('CHILD', repr(child))
    result = subprocess.run([sys.executable, '-c', harness], capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, json.dumps({'stdout': result.stdout, 'stderr': result.stderr})
    assert 'peer limits and scheduling protected' in result.stdout
