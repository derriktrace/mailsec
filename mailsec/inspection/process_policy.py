"""Deny network and cross-process inspection in the static parser and its children.

This is a defense in depth for native document decoders, not a complete sandbox.
The parent inspector owns HTTP/ClamAV connections; the parser receives only pipes.
Apply before reading untrusted MIME. Failure must stop parsing, never fall back.
"""

import ctypes
import errno
import os
import sys
from pathlib import Path

DENIED_SYSCALLS = (
    'socket', 'socketpair', 'connect', 'bind', 'listen', 'accept', 'accept4',
    'sendto', 'sendmsg', 'sendmmsg', 'recvfrom', 'recvmsg', 'recvmmsg',
    'io_uring_setup', 'io_uring_enter', 'io_uring_register',
    'ptrace', 'process_vm_readv', 'process_vm_writev', 'pidfd_getfd',
    # Every descendant must remain in the job's process group so the trusted
    # parent can terminate the entire job on timeout or normal parser exit.
    'setsid', 'setpgid', 'unshare', 'setns',
    # Same-UID peers must not lose scheduling resources through a compromised
    # decoder. Landlock's signal scope does not mediate these operations.
    'setpriority', 'ioprio_set', 'sched_setaffinity', 'sched_setscheduler',
    'sched_setparam', 'sched_setattr',
    # Landlock does not mediate these pathname metadata operations. A parser
    # must not chmod a sibling cache or alter its metadata without opening it.
    'chmod', 'fchmod', 'fchmodat', 'fchmodat2', 'chown', 'fchown', 'lchown', 'fchownat',
    'setxattr', 'lsetxattr', 'fsetxattr', 'removexattr', 'lremovexattr', 'fremovexattr',
    'utime', 'utimes', 'futimesat', 'utimensat',
)


def landlock_abi():
    """Read support without restricting this (possibly HTTP-parent) process."""
    if sys.platform != 'linux':
        raise RuntimeError('Static parser filesystem restrictions require Linux')
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    lib = ctypes.CDLL('libseccomp.so.2', use_errno=True)
    lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    lib.seccomp_syscall_resolve_name.restype = ctypes.c_int
    number = lib.seccomp_syscall_resolve_name(b'landlock_create_ruleset')
    if number < 0:
        raise RuntimeError('Landlock syscall identifiers are unavailable')
    result = libc.syscall(number, None, 0, 1)
    if result < 0:
        raise OSError(ctypes.get_errno(), 'Landlock is unavailable or disabled')
    return result


def isolation_status():
    try:
        abi = landlock_abi()
    except (OSError, RuntimeError):
        abi = None
    return {'status': 'ready' if abi is not None and abi >= 6 else 'unavailable',
            'landlock_abi': abi, 'minimum_landlock_abi': 6,
            'peer_signals_isolated': abi is not None and abi >= 6}


def restrict_filesystem(scratch_directory):
    """Confine decoding to public runtime resources and one private scratch dir.

    Requires Landlock ABI6 (Linux6.12+, enabled by the host). There is no fallback:
    earlier ABIs cannot isolate signals from the same-UID HTTP parent. Readable package paths
    exclude /data, /proc, other jobs and the inspector's persistent cache.
    """
    _restrict_filesystem(scratch_directory, prefix='mailsec-parser-')


def restrict_clamd_filesystem(scratch_directory):
    _restrict_filesystem(scratch_directory, prefix='mailsec-av',
                         readonly=('/data/antivirus', '/etc/mailsec/clamd.conf'), tcp_port=3310)


def _restrict_filesystem(scratch_directory, *, prefix, readonly=(), tcp_port=None):
    if sys.platform != 'linux':
        raise RuntimeError('Static parser filesystem restrictions require Linux')
    scratch = Path(scratch_directory)
    if (not scratch.is_absolute() or scratch.is_symlink() or not scratch.is_dir()
            or scratch.stat().st_uid != os.getuid() or scratch.stat().st_mode & 0o077
            or not scratch.name.startswith(prefix)):
        raise ValueError('Parser scratch directory must be a private per-job directory')
    scratch = scratch.resolve(strict=True)
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    lib = ctypes.CDLL('libseccomp.so.2', use_errno=True)
    lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    lib.seccomp_syscall_resolve_name.restype = ctypes.c_int
    calls = [lib.seccomp_syscall_resolve_name(name) for name in
             (b'landlock_create_ruleset', b'landlock_add_rule', b'landlock_restrict_self')]
    if any(number < 0 for number in calls):
        raise RuntimeError('Landlock syscall identifiers are unavailable')
    create, add, restrict = calls
    abi = libc.syscall(create, None, 0, 1)  # LANDLOCK_CREATE_RULESET_VERSION
    if abi < 6:
        raise RuntimeError('Static inspection requires enabled Landlock ABI6 or newer')

    class Ruleset(ctypes.Structure):
        _fields_ = [('handled_access_fs', ctypes.c_uint64), ('handled_access_net', ctypes.c_uint64),
                    ('scoped', ctypes.c_uint64)]

    class PathRule(ctypes.Structure):
        _pack_ = 1
        _fields_ = [('allowed_access', ctypes.c_uint64), ('parent_fd', ctypes.c_int32)]

    class PortRule(ctypes.Structure):
        _fields_ = [('allowed_access', ctypes.c_uint64), ('port', ctypes.c_uint64)]

    handled = (1 << 15) - 1  # All filesystem operations through ABI3, including truncate.
    if abi >= 5:
        handled |= 1 << 15  # Device ioctls denied, except explicitly granted devices.
    if abi >= 9:
        handled |= 1 << 16  # Pathname Unix socket access (also denied by seccomp).
    # Signals cannot reach the HTTP parent or another message job, even though
    # they share a UID. Descendants within this job still support timeout kills.
    attributes = Ruleset(handled, 3 if tcp_port else 0, 3)
    size = ctypes.sizeof(attributes)
    descriptor = libc.syscall(create, ctypes.byref(attributes), size, 0)
    if descriptor < 0:
        raise OSError(ctypes.get_errno(), 'Cannot create parser filesystem policy')
    read_file, read_dir, execute, write_file = 1 << 2, 1 << 3, 1, 1 << 1

    def allow(path, permissions):
        path = Path(path)
        if not path.exists():
            return
        handle = os.open(path, os.O_PATH | os.O_CLOEXEC)
        try:
            rule = PathRule(permissions, handle)
            if libc.syscall(add, descriptor, 1, ctypes.byref(rule), 0) < 0:
                raise OSError(ctypes.get_errno(), 'Cannot add parser filesystem rule')
        finally:
            os.close(handle)

    try:
        roots = {Path('/usr'), Path('/lib'), Path('/lib64'), Path('/bin'),
                 Path(sys.prefix), Path(sys.base_prefix), Path(__file__).resolve().parent.parent,
                 Path('/etc/fonts')}
        for path in roots:
            allow(path, read_file | read_dir | execute)
        for path in ('/etc/ld.so.cache', '/etc/localtime', '/dev/urandom', '/dev/random'):
            allow(path, read_file)
        for path in readonly:
            allow(path, read_file | (read_dir if Path(path).is_dir() else 0))
        allow('/dev/null', read_file | write_file)
        # No executable, device, socket, FIFO or symlink creation in scratch.
        writable = read_file | read_dir | write_file | sum(1 << bit for bit in (4, 5, 7, 8, 13, 14))
        allow(scratch, writable)
        if tcp_port:
            # The antivirus engine serves only this local port. No outbound TCP
            # connect is granted; seccomp additionally excludes non-TCP egress.
            rule = PortRule(1, tcp_port)  # LANDLOCK_ACCESS_NET_BIND_TCP
            if libc.syscall(add, descriptor, 2, ctypes.byref(rule), 0) < 0:
                raise OSError(ctypes.get_errno(), 'Cannot add antivirus listener policy')
        if libc.prctl(38, 1, 0, 0, 0) != 0 or libc.syscall(restrict, descriptor, 0) < 0:
            raise OSError(ctypes.get_errno(), 'Cannot activate parser filesystem policy')
    finally:
        os.close(descriptor)


def restrict_parser(*, tcp_server=False):
    """Install an inherited Linux seccomp policy, requiring no extra capability."""
    if sys.platform != 'linux':
        raise RuntimeError('Static parser process restrictions require Linux')
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    libc.prctl.restype = ctypes.c_int
    seccomp = ctypes.CDLL('libseccomp.so.2', use_errno=True)
    seccomp.seccomp_init.argtypes = [ctypes.c_uint32]
    seccomp.seccomp_init.restype = ctypes.c_void_p
    seccomp.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    seccomp.seccomp_syscall_resolve_name.restype = ctypes.c_int
    seccomp.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]
    seccomp.seccomp_rule_add.restype = ctypes.c_int
    seccomp.seccomp_load.argtypes = [ctypes.c_void_p]
    seccomp.seccomp_load.restype = ctypes.c_int
    seccomp.seccomp_release.argtypes = [ctypes.c_void_p]
    seccomp.seccomp_release.restype = None

    # no_new_privs makes the restriction irrevocable across fork/exec, including
    # pdftoppm and tesseract. Disable core/process dumps after this process's exec.
    if libc.prctl(38, 1, 0, 0, 0) != 0 or libc.prctl(4, 0, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), 'Cannot restrict parser process')
    context = seccomp.seccomp_init(0x7FFF0000)  # SCMP_ACT_ALLOW
    if not context:
        raise RuntimeError('Cannot create parser syscall policy')
    try:
        allowed_for_server = {'socket', 'bind', 'listen', 'accept', 'accept4', 'sendto', 'recvfrom',
                              'recvmsg', 'recvmmsg'}
        for name in DENIED_SYSCALLS:
            if tcp_server and name in allowed_for_server:
                continue
            number = seccomp.seccomp_syscall_resolve_name(name.encode('ascii'))
            # libseccomp recognizes native and multiplexed syscall identifiers.
            if number == -1:
                raise RuntimeError('Parser syscall policy is unsupported')
            result = seccomp.seccomp_rule_add(context, 0x00050000 | errno.EPERM, number, 0)
            if result < 0:
                raise OSError(-result, 'Cannot install parser syscall restriction')
        # clone3 stores flags behind a pointer, which seccomp cannot inspect.
        # ENOSYS permits libc's ordinary-thread fallback to classic clone.
        number = seccomp.seccomp_syscall_resolve_name(b'clone3')
        if number == -1:
            raise RuntimeError('Parser clone policy is unsupported')
        result = seccomp.seccomp_rule_add(context, 0x00050000 | errno.ENOSYS, number, 0)
        if result < 0:
            raise OSError(-result, 'Cannot restrict clone3')

        class Argument(ctypes.Structure):
            _fields_ = [('arg', ctypes.c_uint), ('op', ctypes.c_int),
                        ('datum_a', ctypes.c_uint64), ('datum_b', ctypes.c_uint64)]

        # prlimit64 can change a same-UID HTTP parent's limits without sending
        # a signal. PID0 preserves normal resource.setrlimit() for this process;
        # explicit PID targets are unnecessary and could address a peer.
        number = seccomp.seccomp_syscall_resolve_name(b'prlimit64')
        if number == -1:
            raise RuntimeError('Parser resource-limit policy is unsupported')
        condition = Argument(0, 1, 0, 0)  # SCMP_CMP_NE, target PID != 0.
        result = seccomp.seccomp_rule_add(context, 0x00050000 | errno.EPERM, number, 1, condition)
        if result < 0:
            raise OSError(-result, 'Cannot restrict cross-process resource limits')

        if tcp_server:
            # Only IPv4 TCP sockets are needed for the fixed loopback listener.
            # send()/recv() use sendto()/recvfrom() on some ABIs; a NULL
            # destination permits replies on accepted sockets, never new egress.
            conditions = [(b'socket', Argument(0, 1, 2, 0)),  # SCMP_CMP_NE, AF_INET
                          (b'sendto', Argument(4, 1, 0, 0))]
            for name, condition in conditions:
                number = seccomp.seccomp_syscall_resolve_name(name)
                if number == -1:
                    raise RuntimeError('Antivirus socket policy is unsupported')
                result = seccomp.seccomp_rule_add(context, 0x00050000 | errno.EPERM, number, 1, condition)
                if result < 0:
                    raise OSError(-result, 'Cannot restrict antivirus socket use')

        number = seccomp.seccomp_syscall_resolve_name(b'clone')
        if number == -1:
            raise RuntimeError('Parser clone policy is unsupported')
        # The supported x86-64/ARM64 ABIs carry clone flags in argument0.
        for flag in (0x00000080, 0x00020000, 0x02000000, 0x04000000,
                     0x08000000, 0x10000000, 0x20000000, 0x40000000):
            condition = Argument(0, 7, flag, flag)  # SCMP_CMP_MASKED_EQ; CLONE_NEW* only.
            result = seccomp.seccomp_rule_add(context, 0x00050000 | errno.EPERM, number, 1, condition)
            if result < 0:
                raise OSError(-result, 'Cannot restrict parser namespace creation')
        result = seccomp.seccomp_load(context)
        if result < 0:
            raise OSError(-result, 'Cannot activate parser syscall restriction')
    finally:
        seccomp.seccomp_release(context)
