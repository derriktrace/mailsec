"""Private migration guards; synthetic state and subprocesses only."""
import hashlib
import importlib.util
import json
import stat
import sys
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

SPEC = importlib.util.spec_from_file_location("migrate_selfhost", Path(__file__).parents[1] / "scripts/migrate_selfhost.py")
migration = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(migration)


def source_state(path):
    path.mkdir(mode=0o700)
    (path / "secrets").mkdir(mode=0o700)
    for name in migration.STATE_NAMES:
        if name != "secrets":
            (path / name).write_text("synthetic setup\n")
    for name in migration.SECRET_NAMES:
        (path / "secrets" / name).write_text("synthetic-" + name)
    return path


def staged(tmp_path):
    source = source_state(tmp_path / "source")
    destination = tmp_path / "stage"
    destination.mkdir(mode=0o700)
    hashes = migration.copy_state(source, destination / "source-state")
    (destination / "database.dump").write_bytes(b"PGDMPsynthetic")
    manifest = {"format": migration.FORMAT, "postgres_major": 18,
                "source_container": "original-postgres", "dump_sha256": migration.checksum(destination / "database.dump"),
                "state_sha256": hashes, "tables": {"messages": {"rows": 2, "sha256": "synthetic-row-hash"},
                    "mailsec_google_accounts": {"rows": 1, "sha256": "synthetic-encrypted-token-hash"}}}
    (destination / "manifest.json").write_text(json.dumps(manifest))
    return source, destination, manifest


def test_private_stage_copies_all_original_credentials_without_changing_source(tmp_path):
    source, destination, manifest = staged(tmp_path)
    assert migration.load_stage(destination) == manifest
    migration.assert_state_unchanged(source, manifest["state_sha256"])
    assert all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in (destination / "source-state").rglob("*") if path.is_file())
    assert (destination / "source-state/secrets/token-encryption-key").read_bytes() == (source / "secrets/token-encryption-key").read_bytes()


@pytest.mark.parametrize("tamper", ["dump", "key", "link", "public_directory", "path_escape"])
def test_modified_or_unsafe_stages_are_rejected(tmp_path, tamper):
    source, directory, manifest = staged(tmp_path)
    if tamper == "dump":
        (directory / "database.dump").write_bytes(b"modified")
    elif tamper == "key":
        (directory / "source-state/secrets/token-encryption-key").write_text("modified")
    elif tamper == "link":
        (directory / "source-state/secrets/extra").symlink_to(source / "secrets/console-token")
    elif tamper == "public_directory":
        directory.chmod(0o755)
    else:
        manifest["state_sha256"]["../../outside"] = "not-a-hash"
        (directory / "manifest.json").write_text(json.dumps(manifest))
    with pytest.raises(ValueError):
        migration.load_stage(directory)


def test_stream_hash_is_incremental_does_not_print_rows_and_tracks_row_count(tmp_path, capsys):
    payload = b'{"id":"a","body":"synthetic"}\n{"id":"b"}\n'
    command = [sys.executable, "-c", "import sys;sys.stdout.buffer.write(" + repr(payload) + ")"]
    with (tmp_path / "private-output").open("wb") as output:
        result = migration.stream_digest(command, output)
    assert result == {"rows": 2, "sha256": hashlib.sha256(payload).hexdigest()}
    assert (tmp_path / "private-output").read_bytes() == payload
    assert not capsys.readouterr().out


def test_failed_stream_is_not_a_verified_dump():
    command = [sys.executable, "-c", "import sys;sys.stdout.write('incomplete');sys.exit(2)"]
    with pytest.raises(ValueError, match="transfer failed"):
        migration.stream_digest(command)


def test_source_queries_use_the_same_snapshot_and_canonical_row_order(monkeypatch):
    source = migration.Container("podman", "source-postgres")
    calls = []
    def scalar(sql, snapshot=None):
        assert snapshot == "00000003-0000000A-1"
        return json.dumps([{"name": "messages", "keys": ["id"]}, {"name": "cache", "keys": ["tenant", "key"]}])
    monkeypatch.setattr(source, "scalar", scalar)
    monkeypatch.setattr(migration, "stream_digest", lambda command: calls.append(command) or {"rows": 0, "sha256": "empty"})
    assert len(migration.table_fingerprints(source, "00000003-0000000A-1")) == 2
    assert all("SET TRANSACTION SNAPSHOT '00000003-0000000A-1'" in call[-1] for call in calls)
    assert all('COPY (SELECT to_jsonb(row_data)::text FROM "public".' in call[-1] for call in calls)
    assert 'ORDER BY ("tenant")::text COLLATE "C", ("key")::text COLLATE "C"' in calls[1][-1]


def test_stage_uses_one_snapshot_for_dump_and_rows_and_cleans_failed_stage(tmp_path, monkeypatch):
    source = migration.Container("podman", "original-postgres")
    state = source_state(tmp_path / "source")
    output = tmp_path / "stage"
    monkeypatch.setattr(migration, "major_version", lambda _: 18)
    @contextmanager
    def snapshot(_):
        yield "00000003-0000000A-1"
    monkeypatch.setattr(migration, "exported_snapshot", snapshot)
    def dump(command, destination):
        assert "--snapshot=00000003-0000000A-1" in command
        destination.write(b"synthetic")
        return {"sha256": hashlib.sha256(b"synthetic").hexdigest()}
    monkeypatch.setattr(migration, "stream_digest", dump)
    def fingerprint(container, snapshot):
        assert container is source and snapshot == "00000003-0000000A-1"
        (state / "secrets/console-token").write_text("changed during staging")
        return {}
    monkeypatch.setattr(migration, "table_fingerprints", fingerprint)
    with pytest.raises(ValueError, match="configuration changed"):
        migration.stage(source, state, output)
    assert not output.exists()
    assert (state / "secrets/console-token").read_text() == "changed during staging"


@pytest.mark.parametrize("blocker", ["same_container", "running_worker", "different_key", "old_postgres", "existing_tables"])
def test_restore_guard_prevents_any_database_write(tmp_path, monkeypatch, blocker):
    _, directory, manifest = staged(tmp_path)
    target = migration.Container("podman", "original-postgres" if blocker == "same_container" else "new-target", target=True)
    secrets = {name: manifest["state_sha256"]["secrets/" + name] for name in migration.SECRET_NAMES}
    if blocker == "different_key":
        secrets["token-encryption-key"] = "different"
    monkeypatch.setattr(migration, "target_material", lambda _: {"database_only": blocker != "running_worker", "secrets": secrets})
    monkeypatch.setattr(migration, "major_version", lambda _: 15 if blocker == "old_postgres" else 18)
    monkeypatch.setattr(target, "scalar", lambda _: "1" if blocker == "existing_tables" else "0")
    monkeypatch.setattr(migration.subprocess, "run", lambda *args, **kwargs: pytest.fail("Restore ran before safety guards passed"))
    with pytest.raises(ValueError):
        migration.restore(target, directory)


@pytest.mark.parametrize("failure", [None, "restore_error", "row_mismatch", "missing_account"])
def test_restore_is_atomic_and_requires_every_table_hash_including_oauth(tmp_path, monkeypatch, failure):
    _, directory, manifest = staged(tmp_path)
    target = migration.Container("podman", "new-target", target=True)
    secrets = {name: manifest["state_sha256"]["secrets/" + name] for name in migration.SECRET_NAMES}
    monkeypatch.setattr(migration, "target_material", lambda _: {"database_only": True, "secrets": secrets})
    monkeypatch.setattr(migration, "major_version", lambda _: 18)
    monkeypatch.setattr(target, "scalar", lambda _: "0")
    calls = []
    def run(command, **kwargs):
        calls.append(command)
        assert kwargs["stdin"].read() == b"PGDMPsynthetic"
        return SimpleNamespace(returncode=1 if failure == "restore_error" else 0)
    monkeypatch.setattr(migration.subprocess, "run", run)
    restored = dict(manifest["tables"])
    if failure == "row_mismatch":
        restored["messages"] = {"rows": 2, "sha256": "different-hash-same-count"}
    if failure == "missing_account":
        restored.pop("mailsec_google_accounts")
    monkeypatch.setattr(migration, "table_fingerprints", lambda _: restored)
    if failure:
        with pytest.raises(ValueError):
            migration.restore(target, directory)
        assert not (directory / "verified-new-target.json").exists()
    else:
        result = migration.restore(target, directory)
        assert result["tables"] == 2 and result["rows"] == 3 and not result["cutover_performed"]
        assert (directory / "verified-new-target.json").is_file()
    assert calls[0] == ["podman", "exec", "-i", "new-target", "python", "/opt/mailsec/container_backup.py", "restore"]


def test_target_queries_and_row_hashes_use_ordinary_login_helper(monkeypatch):
    target = migration.Container("docker", "new-target", target=True)
    command = ["docker", "exec", "-i", "new-target", "python", "/opt/mailsec/container_backup.py", "verify-query"]
    calls = []
    def query(args, **kwargs):
        assert args == command
        calls.append(kwargs['input'])
        return SimpleNamespace(returncode=0, stdout=b'[{"name":"messages","keys":["id"]}]')
    monkeypatch.setattr(migration.subprocess, 'run', query)
    def digest(args, **kwargs):
        assert args == command and b'COPY (SELECT to_jsonb(row_data)' in kwargs['input_data']
        return {'rows': 1, 'sha256': 'synthetic'}
    monkeypatch.setattr(migration, 'stream_digest', digest)
    assert migration.table_fingerprints(target) == {'messages': {'rows': 1, 'sha256': 'synthetic'}}
    assert calls == [migration.CATALOG_SQL.encode()]
    with pytest.raises(ValueError, match='ordinary-login'):
        target.database_args()


def test_stream_digest_sends_verification_sql_over_stdin_without_printing():
    query = b'SELECT synthetic-only;'
    command = [sys.executable, '-c', 'import sys; query=sys.stdin.buffer.read(); sys.stdout.buffer.write(query)']
    assert migration.stream_digest(command, input_data=query) == {
        'sha256': hashlib.sha256(query).hexdigest(), 'rows': 0}


def test_bundled_source_bridge_uses_ordinary_readonly_login_and_snapshot():
    source = migration.Container('podman', 'old-bundled', source_layout='single-container')
    command = source.query('SELECT current_user;', '00000003-0000000A-1')
    assert command[:6] == ['podman', 'exec', 'old-bundled', 'python', '-c', migration.SOURCE_BRIDGE]
    assert command[6] == 'psql'
    assert command[command.index('-U') + 1] == 'mailsec'
    assert 'SET TRANSACTION SNAPSHOT' in command[-1]
    assert 'default_transaction_read_only=on' in command[5]
    assert 'os.setuid(10004)' in command[5] and 'os.O_NOFOLLOW' in command[5]
    compile(migration.SOURCE_BRIDGE, 'source_bridge', 'exec')
    dump = source.command(['pg_dump', *source.database_args(), '--format=custom', '--snapshot=00000003-0000000A-1'])
    assert dump[6] == 'pg_dump' and dump[-1] == '--snapshot=00000003-0000000A-1'


def test_bundled_bridge_does_not_wrap_nondatabase_operations():
    source = migration.Container('docker', 'old-bundled', source_layout='single-container')
    assert source.command(['python', '-c', 'print(1)'], database=False) == ['docker', 'exec', 'old-bundled', 'python', '-c', 'print(1)']
    with pytest.raises(ValueError, match='Unsupported bundled'):
        source.command(['sh', '-c', 'anything'])


@pytest.mark.parametrize('target,layout', [(False, 'unknown'), (True, 'single-container')])
def test_invalid_source_layout_refused(target, layout):
    with pytest.raises(ValueError, match='source layout'):
        migration.Container('podman', 'instance', target=target, source_layout=layout)
