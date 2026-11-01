"""Constrain the native antivirus engine before it reads signatures or email."""

import os
import shutil

from .process_policy import restrict_clamd_filesystem, restrict_parser


def main():
    binary = shutil.which('clamd', path='/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin')
    if not binary:
        raise RuntimeError('Antivirus executable is unavailable')
    restrict_parser(tcp_server=True)
    restrict_clamd_filesystem('/tmp/mailsec-av')
    os.execv(binary, [binary, '--config-file=/etc/mailsec/clamd.conf'])


if __name__ == '__main__':
    main()
