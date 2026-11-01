#!/usr/bin/env bash
set -euo pipefail
umask 077
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
if ! command -v python3 >/dev/null; then
  printf '%s\n' 'Install Python 3.10+ and Docker Compose v2 or rootless Podman with podman-compose.' >&2
  exit 1
fi
exec python3 scripts/setup_selfhost.py "$@"
