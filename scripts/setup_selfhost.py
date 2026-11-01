#!/usr/bin/env python3
"""Prepare an isolated self-host installation using only Python's standard library.

Never imports the application or reads the pilot's environment/configuration. No
credentials are passed to child processes as command arguments or printed.
"""
from __future__ import annotations

import argparse
import base64
import ctypes
import getpass
import hashlib
import ipaddress
import json
import os
import platform
import re
import secrets
import shutil
import subprocess
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
MARKER = ".mailsec-selfhost"
MARKER_CONTENT = "Mailsec single-container state v2\n"
DEFAULTS = {
    "image": "",
    "database_only": False,
    "port": 8025,
    "public_url": "http://localhost:8025",
    "authorized_mailboxes": [],
    "history_days": 30,
    "history_cutoff_epoch": None,
    "workspace_name": "Mail workspace",
    "trusted_proxy_ips": "127.0.0.1",
    "project_name": "mailsec-selfhost",
}


def check_host_isolation():
    """Fail early on an unsupported local Linux host, before compiling the image.

    The container still checks its own kernel/LSM: a remote Docker context or
    Docker Desktop VM may use a different kernel from the installer machine.
    """
    remote = any(os.environ.get(name) for name in ('DOCKER_CONTEXT', 'CONTAINER_HOST'))
    docker_host = os.environ.get('DOCKER_HOST', '')
    if (sys.platform != 'linux' or remote or docker_host and not docker_host.startswith('unix://')
            or platform.machine().lower() not in {'x86_64', 'amd64', 'aarch64', 'arm64'}):
        return
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    # Linux x86-64 and ARM64 use syscall444 for landlock_create_ruleset.
    abi = libc.syscall(444, None, 0, 1)  # LANDLOCK_CREATE_RULESET_VERSION
    if abi < 6:
        raise ValueError('This host lacks enabled Landlock ABI6, required for protected email scanning. '
                         'Use Linux6.12+ with Landlock enabled, or run Mailsec inside a supported Linux VM. '
                         'No image was built or service started. A container cannot upgrade the NAS kernel.')


def write_file(path: Path, value: str | bytes, *, mode: int, replace: bool = False):
    """Write private files without following a pre-existing symlink."""
    if path.is_symlink():
        raise ValueError(f"Refusing a symbolic link at {path.name}")
    if path.exists() and not replace:
        if not path.is_file():
            raise ValueError(f"Expected a regular file at {path.name}")
        return
    content = value.encode() if isinstance(value, str) else value
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    temporary = path.parent / ("." + path.name + "." + secrets.token_hex(8))
    fd = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), mode)
        if not replace and path.exists():
            raise ValueError(f"File appeared during setup: {path.name}; rerun setup")
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def private_directory(path: Path):
    if path.is_symlink():
        raise ValueError(f"Refusing a symbolic link at {path.name}")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not path.is_dir() or path.stat().st_uid != os.getuid():
        raise ValueError(f"The current user must own {path}")
    path.chmod(0o700)


def validate_mailboxes(value: str | list[str]) -> list[str]:
    addresses = value.split(",") if isinstance(value, str) else value
    result = []
    for address in addresses:
        address = address.strip().lower()
        if not address:
            continue
        if len(address) > 320 or not re.fullmatch(r"[A-Za-z0-9.!#$%&*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z0-9-]+", address):
            raise ValueError("Authorized mailboxes must be complete email addresses separated by commas")
        if address not in result:
            result.append(address)
    return result


def validate_settings(config: dict) -> dict:
    image = config.setdefault("image", "")
    if not isinstance(image, str) or image and not re.fullmatch(
        r"[a-z0-9]+(?:[.-][a-z0-9]+)*(?::[0-9]{1,5})?/"
        r"(?:[a-z0-9]+(?:[._-][a-z0-9]+)*/)*[a-z0-9]+(?:[._-][a-z0-9]+)*"
        r"@sha256:[a-f0-9]{64}", image
    ):
        raise ValueError("Image must be a complete registry/repository@sha256:<64 lowercase hex> reference; mutable tags are not accepted")
    if not re.fullmatch(r"mailsec-selfhost(?:-[a-z0-9][a-z0-9_-]*)?", config["project_name"]):
        raise ValueError("Project name must be mailsec-selfhost or mailsec-selfhost-<name>")
    if type(config.get("database_only")) is not bool:
        raise ValueError("Database-only mode must be true or false")
    if type(config.get("port")) is not int or not 1024 <= config["port"] <= 65535:
        raise ValueError("Port must be between 1024 and 65535")
    if type(config.get("history_days")) is not int or not 0 <= config["history_days"] <= 36500:
        raise ValueError("History days must be 0 (all history) or between 1 and 36500")
    if config.get("history_cutoff_epoch") is not None and (
            type(config["history_cutoff_epoch"]) is not int or config["history_cutoff_epoch"] < 0):
        raise ValueError("Historical cutoff must be a positive epoch timestamp")
    config["authorized_mailboxes"] = validate_mailboxes(config["authorized_mailboxes"])
    url = urlsplit(config["public_url"])
    if (not url.hostname or url.username or url.password or url.query or url.fragment
            or url.path not in {"", "/"} or url.scheme not in {"http", "https"}):
        raise ValueError("Public URL must be an HTTP(S) origin without a path, credentials, query, or fragment")
    if url.scheme == "http" and url.hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise ValueError("HTTP is allowed only on loopback; use an SSH tunnel or HTTPS reverse proxy")
    if url.scheme == "http" and (url.port or 80) != config["port"]:
        raise ValueError("The loopback public URL port must match the configured listening port")
    config["public_url"] = config["public_url"].rstrip("/")
    if not isinstance(config["workspace_name"], str) or not 1 <= len(config["workspace_name"]) <= 120:
        raise ValueError("Workspace name must be between 1 and 120 characters")
    for value in (config["public_url"], config["workspace_name"], config["trusted_proxy_ips"]):
        if not isinstance(value, str) or any(character in value for character in "\r\n\x00'"):
            raise ValueError("Configuration values cannot contain newlines, NUL, or single quotes")
    for entry in config['trusted_proxy_ips'].split(','):
        try:
            network = ipaddress.ip_network(entry.strip(), strict=False)
        except ValueError:
            raise ValueError('Trusted proxies must be explicit IP addresses or CIDRs; wildcards are not allowed') from None
        if network.prefixlen == 0:
            raise ValueError('Trusted proxies cannot include an entire IPv4 or IPv6 address space')
    return config


def validate_oauth(data: str, redirect_uri: str) -> str:
    try:
        document = json.loads(data)
        web = document["web"]
        if not all(isinstance(web.get(key), str) and web[key] for key in ("client_id", "client_secret")):
            raise ValueError()
        if redirect_uri not in web.get("redirect_uris", []):
            raise ValueError("OAuth JSON must authorize the exact callback URL: " + redirect_uri)
    except (TypeError, KeyError, json.JSONDecodeError) as exc:
        raise ValueError("Use the downloaded Google OAuth Web application client JSON") from exc
    return json.dumps(document, indent=2) + "\n"


def build_revision(root: Path, inputs: list[str]) -> str:
    """Compose implementations need a config change to notice rebuilt image tags."""
    digest = hashlib.sha256()
    for source in sorted(inputs):
        entry = root / source
        paths = sorted(entry.rglob("*")) if entry.is_dir() else [entry]
        for path in paths:
            if not path.is_file() or path.suffix == ".pyc" or "__pycache__" in path.parts:
                continue
            digest.update(str(path.relative_to(root)).encode() + b"\0" + path.read_bytes() + b"\0")
    return digest.hexdigest()


def prepare(root: Path, state: Path, args: argparse.Namespace, *, interactive: bool = False) -> dict:
    """Idempotently initialize only the dedicated, marked installation directory."""
    if state.is_symlink():
        raise ValueError("The state directory must not be a symbolic link")
    state = state.absolute()
    if state.exists() and not (state / MARKER).is_file() and any(state.iterdir()):
        raise ValueError("State directory is not an empty directory or an existing Mailsec self-host installation")
    if any(character in str(state) for character in "\r\n\x00'"):
        raise ValueError("Use a state directory without newlines or single quotes")
    if (state / MARKER).exists() and (state / MARKER).read_text() != MARKER_CONTENT:
        raise ValueError("Legacy six-service installation: use its saved Compose file; migrate into a new single-container state directory")
    private_directory(state)
    write_file(state / MARKER, MARKER_CONTENT, mode=0o600)
    private_directory(state / "secrets")
    settings_path = state / "settings.json"
    if settings_path.is_symlink():
        raise ValueError("Settings file must not be a symbolic link")
    config = dict(DEFAULTS)
    if settings_path.exists():
        config.update(json.loads(settings_path.read_text()))
        if args.project_name and args.project_name != config["project_name"]:
            raise ValueError("Changing an existing installation's Compose project would select a different database; use a new state directory")
    previous_history_days = config["history_days"]
    for name in DEFAULTS:
        supplied = getattr(args, name, None)
        if supplied is not None:
            config[name] = supplied
    if getattr(args, "build_from_source", False):
        config["image"] = ""
    if getattr(args, "port", None) is not None and getattr(args, "public_url", None) is None:
        previous = urlsplit(config["public_url"])
        if previous.scheme == "http" and previous.hostname in {"localhost", "127.0.0.1", "::1"}:
            config["public_url"] = f"http://localhost:{config['port']}"
    if interactive:
        entered = input("Authorized Gmail addresses, comma separated [keep current / empty]: ").strip()
        if entered:
            config["authorized_mailboxes"] = entered
    config = validate_settings(config)
    if not config["history_days"]:
        config["history_cutoff_epoch"] = None
    elif config["history_days"] != previous_history_days or config["history_cutoff_epoch"] is None:
        # A fixed cutoff keeps pagination stable even when a large backfill spans
        # days. Restarting must not silently shrink the requested history window.
        config["history_cutoff_epoch"] = max(0, int(datetime.now(timezone.utc).timestamp()) - config["history_days"] * 86400)
    redirect_uri = config["public_url"] + "/oauth/google/callback"
    key_path = getattr(args, "jev_key_file", None)
    jev_key = Path(key_path).expanduser().read_text().strip() if key_path else None
    if interactive and not key_path:
        jev_key = getpass.getpass("Jev API key [Enter to keep current or configure a provider in the GUI]: ").strip() or None
    if jev_key is not None and (not jev_key or any(char.isspace() for char in jev_key)):
        raise ValueError("Jev API key must be a nonempty token without whitespace")
    oauth_path = getattr(args, "oauth_client_file", None)
    if interactive and not oauth_path:
        oauth_path = input("Google OAuth Web client JSON path [Enter to keep current / set up later]: ").strip() or None
    oauth = validate_oauth(Path(oauth_path).expanduser().read_text(), redirect_uri) if oauth_path else None
    secret_dir = state / "secrets"
    # The whole host directory is mounted read-only and remains 0700. PID1 alone
    # copies these inputs into private per-service paths with explicit ownership;
    # sibling scanner UIDs cannot traverse the bootstrap directory.
    write_file(secret_dir / "postgres-password", secrets.token_urlsafe(36), mode=0o444)
    password_path = secret_dir / "postgres-password"
    if password_path.is_symlink():
        raise ValueError("Postgres password must not be a symbolic link")
    password = password_path.read_text().strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]{32,}", password):
        raise ValueError("Existing database password is invalid; restore the original installation secrets")
    write_file(secret_dir / "database-url", f"postgresql+psycopg://mailsec:{password}@127.0.0.1:5432/mailsec", mode=0o444)
    write_file(secret_dir / "console-token", secrets.token_urlsafe(48), mode=0o444)
    write_file(secret_dir / "token-encryption-key", base64.urlsafe_b64encode(secrets.token_bytes(32)), mode=0o444)
    write_file(secret_dir / "jev-key", jev_key or "", mode=0o444, replace=jev_key is not None)
    write_file(secret_dir / "google-oauth-client.json", oauth or "{}\n", mode=0o444, replace=oauth is not None)
    write_file(state / "organization.yaml", (root / "deploy/selfhost/organization.example.yaml").read_bytes(), mode=0o400)
    (state / "organization.yaml").chmod(0o400)
    write_file(settings_path, json.dumps(config, indent=2) + "\n", mode=0o600, replace=True)
    hostname = urlsplit(config["public_url"]).hostname
    revision = hashlib.sha256()
    for name in ("google-oauth-client.json", "jev-key", "console-token", "token-encryption-key"):
        revision.update(name.encode() + b"\0" + (secret_dir / name).read_bytes() + b"\0")
    values = {
        "MAILSEC_IMAGE": config["image"],
        "MAILSEC_STATE_DIR": str(state),
        "MAILSEC_DATABASE_ONLY": str(config["database_only"]).lower(),
        "MAILSEC_PORT": str(config["port"]),
        "MAILSEC_PUBLIC_BASE_URL": config["public_url"],
        "GOOGLE_OAUTH_REDIRECT_URI": redirect_uri,
        "MAILSEC_ALLOWED_HOSTS": ",".join(dict.fromkeys(["localhost", "127.0.0.1", hostname])),
        "MAILSEC_AUTHORIZED_MAILBOXES": ",".join(config["authorized_mailboxes"]),
        "MAILSEC_WORKSPACE_NAME": config["workspace_name"],
        "MAILSEC_INITIAL_QUERY": "-in:sent -in:drafts" + (
            f" after:{config['history_cutoff_epoch']}" if config["history_cutoff_epoch"] is not None else ""),
        "MAILSEC_TRUSTED_PROXY_IPS": config["trusted_proxy_ips"],
        # Single-file bind mounts retain their original inode after atomic file
        # replacement. An environment change makes Compose recreate app services.
        "MAILSEC_SETUP_REVISION": revision.hexdigest(),
        "MAILSEC_APP_BUILD_REVISION": config["image"] or build_revision(root, ["Dockerfile.selfhost", "requirements.lock", "requirements-inspection.lock", "pyproject.toml", "README.md", "LICENSE", "NOTICE", "deploy/selfhost", "scripts/container_runtime.py", "scripts/container_health.py", "scripts/container_backup.py", "mailsec"]),
    }
    write_file(state / "compose.env", "".join(f"{key}='{value}'\n" for key, value in values.items()), mode=0o600, replace=True)
    return config


def compose_command(engine: str = "auto") -> list[str]:
    choices = []
    if engine in {"auto", "docker"} and shutil.which("docker"):
        choices.append(["docker", "compose"])
    if engine in {"auto", "podman"}:
        if shutil.which("podman-compose"):
            choices.append(["podman-compose"])
        elif shutil.which("podman"):
            choices.append(["podman", "compose"])
    for choice in choices:
        probe = subprocess.run(choice + ["version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        if probe.returncode == 0:
            return choice
    raise ValueError("Install Docker Compose v2 or rootless Podman with podman-compose; then rerun ./selfhost.sh")


def backup(state: Path, command: list[str], environment: dict, output_dir: Path | None = None) -> Path:
    """Snapshot Postgres and its matching encryption keys; cache data is rebuildable."""
    destination = (output_dir or state / "backups").expanduser().absolute()
    private_directory(destination)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    archive = destination / ("mailsec-" + stamp + "-" + secrets.token_hex(3) + ".tar.gz")
    with tempfile.TemporaryDirectory(prefix=".backup-", dir=destination) as temporary:
        staging = Path(temporary)
        dump = staging / "database.dump"
        with dump.open("xb") as stream:
            completed = subprocess.run(command + ["exec", "-T", "mailsec", "python", "/opt/mailsec/container_backup.py"],
                                       stdout=stream, cwd=ROOT, env=environment, check=False)
        if completed.returncode or not dump.stat().st_size:
            raise ValueError("Database backup failed; no archive was created")
        try:
            with tarfile.open(archive, "x:gz") as output:
                output.add(dump, arcname="database.dump")
                for name in [MARKER, "settings.json", "compose.env", "organization.yaml", "secrets"]:
                    path = state / name
                    members = list(path.rglob("*")) if path.is_dir() else [path]
                    if path.is_symlink() or any(member.is_symlink() for member in members):
                        raise ValueError("Refusing to back up symbolic links in private state")
                    output.add(path, arcname="state/" + name, recursive=True)
        except Exception:
            archive.unlink(missing_ok=True)
            raise
        archive.chmod(0o600)
    return archive


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("command", nargs="?", default="start", choices=["start", "configure", "check", "status", "logs", "stop", "token", "backup"])
    result.add_argument("--engine", choices=["auto", "docker", "podman"], default="auto")
    result.add_argument("--runtime-dir", type=Path, default=ROOT / ".selfhost")
    result.add_argument("--project-name", help="Independent Compose project, default mailsec-selfhost; fixed after initialization")
    result.add_argument("--port", type=int)
    result.add_argument("--public-url")
    result.add_argument("--mailboxes", dest="authorized_mailboxes")
    result.add_argument("--history-days", type=int, help="Initial incoming history: 30 days by default; 0 for all history")
    result.add_argument("--workspace-name")
    result.add_argument("--trusted-proxy-ips")
    result.add_argument("--jev-key-file", type=Path, help="Optional existing key file; its value is never printed")
    result.add_argument("--oauth-client-file", type=Path, help="Downloaded Google Web application OAuth JSON")
    result.add_argument("--database-only", action=argparse.BooleanOptionalAction, default=None, help="Maintenance mode: start only PostgreSQL for an empty-target restore")
    result.add_argument("--non-interactive", action="store_true")
    image_choice = result.add_mutually_exclusive_group()
    image_choice.add_argument("--image", help="Use a prebuilt registry/repository@sha256:<digest> image; saved for subsequent starts")
    image_choice.add_argument("--build-from-source", action="store_true", help="Clear a saved registry image and use this release's source build")
    result.add_argument("--no-pull", action="store_true", help="Use an already loaded pinned registry image without contacting its registry")
    result.add_argument("--no-build", action="store_true", help="Use images previously built for this release")
    result.add_argument("--backup-dir", type=Path, help="Private backup destination; defaults to the installation's backups directory")
    return result


def main(argv=None):
    os.umask(0o077)
    args = parser().parse_args(argv)
    state = args.runtime_dir.expanduser().absolute()
    try:
        if args.command in {"status", "logs", "stop", "token", "check", "backup"} and not (state / MARKER).is_file():
            raise ValueError("No installation found here; run ./selfhost.sh first")
        if args.command == "token":
            if state.is_symlink() or (state / "secrets/console-token").is_symlink():
                raise ValueError("Refusing a symbolic link in the console token path")
            print((state / "secrets/console-token").read_text().strip())
            return 0
        if args.command in {"start", "configure"}:
            interactive = args.command == "configure" and not args.non_interactive and sys.stdin.isatty()
            config = prepare(ROOT, state, args, interactive=interactive)
        else:
            if (state / MARKER).read_text() != MARKER_CONTENT:
                raise ValueError("Legacy six-service installation: use its saved Compose file; migrate into a new state directory")
            config = validate_settings(json.loads((state / "settings.json").read_text()))
        if args.command == "configure":
            print("Configuration saved. Credentials were not printed. Run ./selfhost.sh to apply it.")
            print("Google OAuth callback: " + config["public_url"] + "/oauth/google/callback")
            return 0
        if args.command == 'start' and not config['database_only']:
            check_host_isolation()
        compose = ROOT / "compose.selfhost.yaml"
        if not compose.is_file():
            raise ValueError("Missing compose.selfhost.yaml; use a complete release checkout")
        command = compose_command(args.engine) + ["--env-file", str(state / "compose.env"), "-f", str(compose), "-p", config["project_name"]]
        operation = {"check": ["config", "--quiet"], "status": ["ps"], "logs": ["logs", "--tail", "100", "-f"], "stop": ["stop"]}
        if args.command == "start":
            operation["start"] = ["up", "-d", "--no-build"]
        # Ignore inherited MAILSEC_* values to keep this separate from an operator's
        # pilot shell. Compose takes only the explicit nonsecret installation file.
        environment = {key: value for key, value in os.environ.items() if not key.startswith(("MAILSEC_", "GOOGLE_OAUTH_", "COMPOSE_"))}
        if args.command == "backup":
            archive = backup(state, command, environment, args.backup_dir)
            print("Private backup created: " + str(archive))
            print("Contains email, authorization credentials, and encryption keys. Encrypt it before copying off this host.")
            return 0
        if args.command == "start" and config["image"] and not args.no_pull:
            pulled = subprocess.run(command + ["pull", "mailsec"], cwd=ROOT, env=environment, check=False)
            if pulled.returncode:
                return pulled.returncode
        if args.command == "start" and not config["image"] and not args.no_build:
            built = subprocess.run(command + ["build", "mailsec"], cwd=ROOT, env=environment, check=False)
            if built.returncode:
                return built.returncode
        completed = subprocess.run(command + operation[args.command], cwd=ROOT, env=environment, check=False)
        if completed.returncode:
            return completed.returncode
        if args.command == "start":
            if config["database_only"]:
                print("Database-only maintenance mode started. No web console, worker, or mailbox processing is running.")
                return 0
            print("\nOne Mailsec container started in passive mode (existing saved protection controls are preserved).")
            print("Console: " + config["public_url"])
            print("Get the private console token: ./selfhost.sh token" + (
                " --runtime-dir " + str(state) if state != ROOT / ".selfhost" else ""))
            print("Open the console walkthrough to configure analysis and Gmail. First antivirus signature download can take several minutes.")
            print("Settings and encryption keys: " + str(state) + "; keep a private backup with the database.")
        return 0
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print("Setup error: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
