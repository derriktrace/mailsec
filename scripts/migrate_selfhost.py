#!/usr/bin/env python3
"""Stage and verify an isolated PostgreSQL 18 migration; never perform cutover.

Requires only Python's standard library plus an installed Docker/Podman CLI.
The source database is read through one exported repeatable-read snapshot. No
mail worker is started, stopped, or reconfigured by this helper. Dumps and keys
remain in a private staging directory and must never be committed or published.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import select
import shutil
import stat
import subprocess
import sys
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

FORMAT = "mailsec-migration-v1"
SECRET_NAMES = ("token-encryption-key", "console-token", "google-oauth-client.json", "jev-key")
STATE_NAMES = (".mailsec-selfhost", "settings.json", "compose.env", "organization.yaml", "secrets")

# Runs only inside an explicitly selected bundled source container. Credentials
# never leave that container or enter process arguments. Every database command
# starts as the ordinary owner with read-only transactions, including pg_dump.
SOURCE_BRIDGE = r'''
import os,re,stat,subprocess,sys,tempfile
from pathlib import Path
program=sys.argv[1]
if program not in {'psql','pg_dump'}:
    raise ValueError('Unsupported source database command')
fd=os.open('/data/app/secrets/postgres-password',os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
with os.fdopen(fd,'rb') as stream:
    info=os.fstat(stream.fileno())
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
        raise ValueError('Source requires a private regular database credential')
    value=stream.read(257)
password=value.decode('ascii').strip()
if len(value)>256 or not re.fullmatch(r'[A-Za-z0-9_-]{32,128}',password):
    raise ValueError('Invalid source database credential')
os.setgroups([])
os.setgid(10004)
os.setuid(10004)
with tempfile.TemporaryDirectory(prefix='migration-read-',dir='/tmp/mailsec-postgres') as folder:
    passfile=Path(folder)/'pgpass'
    fd=os.open(passfile,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as stream:
        stream.write('127.0.0.1:5432:mailsec:mailsec:'+password+'\n')
    del password,value
    command=['/usr/lib/postgresql/18/bin/'+program,'-h','127.0.0.1',*sys.argv[2:]]
    result=subprocess.call(command,env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8',
        'PGPASSFILE':str(passfile),'PGOPTIONS':'-c default_transaction_read_only=on'})
raise SystemExit(result)
'''


def checksum(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for part in iter(lambda: stream.read(65536), b""):
            digest.update(part)
    return digest.hexdigest()


def identifier(value):
    if not isinstance(value, str) or not value or "\0" in value:
        raise ValueError("Invalid database identifier")
    return '"' + value.replace('"', '""') + '"'


def private_directory(path):
    if path.exists() or path.is_symlink():
        raise ValueError("Migration staging destination must not already exist")
    path.mkdir(parents=False, mode=0o700)


def state_files(root):
    """Enumerate only expected local state; reject links and unusual file types."""
    result = []
    if root.is_symlink() or not root.is_dir() or not (root / ".mailsec-selfhost").is_file():
        raise ValueError("Source must be a recognized self-host runtime directory")
    for name in STATE_NAMES:
        path = root / name
        if not path.exists() and not path.is_symlink():
            raise ValueError("Source runtime is missing required state")
        candidates = [path, *path.rglob("*")] if path.is_dir() and not path.is_symlink() else [path]
        for candidate in candidates:
            mode = candidate.lstat().st_mode
            if stat.S_ISLNK(mode) or not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
                raise ValueError("Runtime state must contain only regular files and directories")
            if stat.S_ISREG(mode):
                result.append(candidate.relative_to(root))
    return sorted(result)


def copy_state(source, target):
    files = state_files(source)
    hashes = {}
    target.mkdir(mode=0o700)
    for relative in files:
        destination = target / relative
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with (source / relative).open("rb") as incoming, destination.open("xb") as outgoing:
            shutil.copyfileobj(incoming, outgoing)
        destination.chmod(0o600)
        hashes[str(relative)] = checksum(destination)
    return hashes


def assert_state_unchanged(source, hashes):
    if {str(path) for path in state_files(source)} != set(hashes):
        raise ValueError("Source configuration changed while staging; take a new snapshot")
    if any(checksum(source / relative) != digest for relative, digest in hashes.items()):
        raise ValueError("Source configuration changed while staging; take a new snapshot")


class Container:
    def __init__(self, runtime, name, *, target=False, source_layout='postgres-service'):
        if runtime not in {"docker", "podman"} or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", name):
            raise ValueError("Choose Docker/Podman and an explicit container name")
        if source_layout not in {'postgres-service', 'single-container'} or target and source_layout != 'postgres-service':
            raise ValueError('Choose a supported source layout; targets always use the maintenance helper')
        self.runtime, self.name, self.target, self.source_layout = runtime, name, target, source_layout

    def command(self, args, *, interactive=False, database=True):
        command = [self.runtime, "exec"]
        if interactive:
            command.append("-i")
        if self.target and database:
            command += ["--user", "10004"]
        if not self.target and database and self.source_layout == 'single-container':
            if not args or args[0] not in {'psql', 'pg_dump'}:
                raise ValueError('Unsupported bundled source database command')
            args = ['python', '-c', SOURCE_BRIDGE, *args]
        return command + [self.name] + args

    def database_args(self):
        if self.target:
            raise ValueError("Target queries require the ordinary-login maintenance helper")
        return ["-U", "mailsec", "-d", "mailsec"]

    def query(self, sql, snapshot=None):
        if self.target:
            if snapshot:
                raise ValueError("Target verification does not import source transaction snapshots")
            return self.command(["python", "/opt/mailsec/container_backup.py", "verify-query"],
                                interactive=True, database=False)
        if snapshot:
            if not re.fullmatch(r"[0-9A-Fa-f]+-[0-9A-Fa-f]+-[0-9]+", snapshot):
                raise ValueError("Invalid exported database snapshot")
            sql = "BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SET TRANSACTION SNAPSHOT '" + snapshot + "'; " + sql
        return self.command(["psql", "-X", "-w", "-qAt", *self.database_args(), "-c", sql])

    def scalar(self, sql, snapshot=None):
        completed = subprocess.run(self.query(sql, snapshot), stdout=subprocess.PIPE,
                                   input=sql.encode() if self.target else None,
                                   stderr=subprocess.DEVNULL, timeout=60, check=False)
        if completed.returncode:
            raise ValueError("Database metadata check failed; source and target were not changed")
        return completed.stdout.decode().strip()


@contextmanager
def exported_snapshot(container):
    command = container.command(["psql", "-X", "-w", "-qAt", *container.database_args()], interactive=True)
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    try:
        process.stdin.write(b"BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY; SELECT pg_export_snapshot();\n")
        process.stdin.flush()
        if not select.select([process.stdout], [], [], 30)[0]:
            raise ValueError("Could not start a consistent database snapshot")
        snapshot = process.stdout.readline(128).decode().strip()
        if not re.fullmatch(r"[0-9A-Fa-f]+-[0-9A-Fa-f]+-[0-9]+", snapshot):
            raise ValueError("Could not start a consistent database snapshot")
        yield snapshot
    finally:
        if process.poll() is None:
            try:
                process.stdin.write(b"ROLLBACK;\n\\q\n")
                process.stdin.flush()
                process.wait(timeout=10)
            except (OSError, subprocess.TimeoutExpired):
                process.kill()
                process.wait()
        process.stdin.close()
        process.stdout.close()


def stream_digest(command, destination=None, *, input_data=None):
    """Hash rows/dump incrementally without printing or buffering private content."""
    digest, lines = hashlib.sha256(), 0
    process = subprocess.Popen(command, stdin=subprocess.PIPE if input_data is not None else None,
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    deadline = time.monotonic() + 3600
    try:
        if input_data is not None:
            process.stdin.write(input_data)
            process.stdin.close()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([process.stdout], [], [], remaining)[0]:
                raise ValueError("Database transfer exceeded its one-hour deadline")
            part = os.read(process.stdout.fileno(), 65536)
            if not part:
                break
            digest.update(part)
            lines += part.count(b"\n")
            if destination:
                destination.write(part)
        if process.wait(timeout=10):
            raise ValueError("Database transfer failed; do not use this migration stage")
        return {"sha256": digest.hexdigest(), "rows": lines}
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
        if process.stdin is not None and not process.stdin.closed:
            process.stdin.close()
        process.stdout.close()


CATALOG_SQL = """SELECT COALESCE(json_agg(json_build_object('name', t.table_name, 'keys',
  (SELECT json_agg(k.column_name ORDER BY k.ordinal_position)
   FROM information_schema.table_constraints c JOIN information_schema.key_column_usage k
   ON c.constraint_schema=k.constraint_schema AND c.constraint_name=k.constraint_name
   WHERE c.table_schema=t.table_schema AND c.table_name=t.table_name AND c.constraint_type='PRIMARY KEY'))
  ORDER BY t.table_name), '[]') FROM information_schema.tables t
  WHERE t.table_schema='public' AND t.table_type='BASE TABLE';"""
EMPTY_SQL = """SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
  WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%'
  AND c.relkind IN ('r','p','v','m','S','f');"""


def table_fingerprints(container, snapshot=None):
    tables = json.loads(container.scalar(CATALOG_SQL, snapshot))
    result = {}
    for table in tables:
        # Canonical JSON and C sorting make hashes independent of physical row
        # order, collation defaults, and JSON object key order after restore.
        order = ", ".join("(" + identifier(key) + ')::text COLLATE "C"' for key in table["keys"] or [])
        order = order or 'to_jsonb(row_data)::text COLLATE "C"'
        sql = ('COPY (SELECT to_jsonb(row_data)::text FROM "public".' + identifier(table["name"])
               + " AS row_data ORDER BY " + order + ") TO STDOUT;")
        command = container.query(sql, snapshot)
        result[table["name"]] = (stream_digest(command, input_data=sql.encode()) if container.target
                                else stream_digest(command))
    return result


def major_version(container):
    return int(container.scalar("SHOW server_version_num;")) // 10000


def stage(source, source_state, destination):
    if major_version(source) != 18:
        raise ValueError("This migration path requires PostgreSQL 18 on source and target")
    state_files(source_state)
    private_directory(destination)
    try:
        hashes = copy_state(source_state, destination / "source-state")
        with exported_snapshot(source) as snapshot:
            with (destination / "database.dump").open("xb") as output:
                dump = stream_digest(source.command(["pg_dump", *source.database_args(), "--format=custom", "--snapshot=" + snapshot]), output)
            tables = table_fingerprints(source, snapshot)
        assert_state_unchanged(source_state, hashes)
        manifest = {"format": FORMAT, "created_at": datetime.now(timezone.utc).isoformat(),
                    "source_container": source.name, "postgres_major": 18,
                    "source_layout": source.source_layout,
                    "dump_sha256": dump["sha256"], "state_sha256": hashes, "tables": tables}
        (destination / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        return manifest
    except Exception:
        # This directory was newly created by this invocation only.
        shutil.rmtree(destination)
        raise


def load_stage(path):
    if path.is_symlink() or not path.is_dir() or path.stat().st_mode & 0o077:
        raise ValueError("Migration stage must be a private directory, not a link")
    for name in ("manifest.json", "database.dump", "source-state"):
        if (path / name).is_symlink():
            raise ValueError("Migration stage must not contain symbolic links")
    manifest = json.loads((path / "manifest.json").read_text())
    if manifest.get("format") != FORMAT or manifest.get("postgres_major") != 18:
        raise ValueError("Unsupported migration stage")
    if checksum(path / "database.dump") != manifest["dump_sha256"]:
        raise ValueError("Database dump checksum does not match the migration stage")
    assert_state_unchanged(path / "source-state", manifest["state_sha256"])
    return manifest


def target_material(container):
    code = "import hashlib,json,os,pathlib; p=pathlib.Path('/data/app/secrets'); state=json.loads(pathlib.Path('/run/mailsec-supervisor.json').read_text()); print(json.dumps({'database_only':os.environ.get('MAILSEC_DATABASE_ONLY','').lower()=='true' and state.get('database_only') is True and set(state.get('services',{}))=={'postgres'},'secrets':{n:hashlib.sha256((p/n).read_bytes()).hexdigest() for n in " + repr(SECRET_NAMES) + "}}))"
    completed = subprocess.run(container.command(["python", "-c", code], database=False),
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30, check=False)
    if completed.returncode:
        raise ValueError("Cannot verify isolated target mode and original credentials")
    return json.loads(completed.stdout)


def restore(target, directory):
    manifest = load_stage(directory)
    if target.name == manifest["source_container"]:
        raise ValueError("Source and target containers must differ")
    material = target_material(target)
    if not material["database_only"]:
        raise ValueError("Target must run with MAILSEC_DATABASE_ONLY=true; no mailbox worker may run")
    for name in SECRET_NAMES:
        if material["secrets"].get(name) != manifest["state_sha256"].get("secrets/" + name):
            raise ValueError("Target credentials do not match staged source; copy original keys before first startup")
    if major_version(target) != 18:
        raise ValueError("This migration path requires PostgreSQL 18 on source and target")
    if target.scalar(EMPTY_SQL) != "0":
        raise ValueError("Restore target must have no user relations; existing data is never overwritten")
    with (directory / "database.dump").open("rb") as incoming:
        completed = subprocess.run(target.command(["python", "/opt/mailsec/container_backup.py", "restore"],
                                                 interactive=True, database=False),
            stdin=incoming, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3600, check=False)
    if completed.returncode:
        raise ValueError("Restore failed; target must remain database-only and must not be used")
    actual = table_fingerprints(target)
    if actual != manifest["tables"]:
        raise ValueError("Restored table counts or hashes differ; keep target isolated and preserve the source")
    result = {"verified_at": datetime.now(timezone.utc).isoformat(), "target_container": target.name,
              "tables": len(actual), "rows": sum(table["rows"] for table in actual.values()),
              "result": "verified_database_only", "cutover_performed": False}
    (directory / ("verified-" + target.name + ".json")).write_text(json.dumps(result, indent=2) + "\n")
    return result


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", choices=("docker", "podman"), required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    snapshot = commands.add_parser("stage", help="Read source database and copy protected configuration")
    snapshot.add_argument("--source-container", required=True)
    snapshot.add_argument("--source-layout", choices=('postgres-service', 'single-container'),
                          default='postgres-service', help='Use single-container for a bundled alpha1/alpha2 source')
    snapshot.add_argument("--source-state", type=Path, required=True)
    snapshot.add_argument("--output", type=Path, required=True)
    restored = commands.add_parser("restore", help="Restore only into an empty database-only target")
    restored.add_argument("--target-container", required=True)
    restored.add_argument("--stage", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "stage":
            result = stage(Container(args.runtime, args.source_container, source_layout=args.source_layout),
                           args.source_state.absolute(), args.output.absolute())
            print(json.dumps({"staged": True, "tables": len(result["tables"]), "source_changed": False}))
        else:
            print(json.dumps(restore(Container(args.runtime, args.target_container, target=True), args.stage.absolute())))
    except (ValueError, OSError, subprocess.SubprocessError, KeyError, TypeError):
        # Runtime/database diagnostics may contain connection or configuration
        # values. Keep them out of terminal logs and public support reports.
        print("Migration did not complete. Verify the private stage, PostgreSQL version, empty database-only target, and matching original credentials. No cutover was performed.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
