"""Fast migration checks use synthetic SQLite sources and targets; CLI requires PostgreSQL."""
import importlib.util
from pathlib import Path

import pytest
from sqlalchemy import create_engine, event, func, inspect, select, text

from mailsec.parsing import parse_email
from mailsec.storage import Store, feedback, jobs, messages, now, runs

spec = importlib.util.spec_from_file_location("mailsec_migration", Path(__file__).parents[1] / "scripts/migrate_sqlite.py")
migration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(migration)
RAW = b"From: vendor@example.test\r\nTo: me@example.test\r\nSubject: Private receipt\r\n\r\ncontent"


def source_snapshot(tmp_path, count=2):
    path = tmp_path / "source.sqlite"
    store = Store(f"sqlite:///{path}")
    for number in range(count):
        item = store.ingest(RAW, parse_email(RAW), provider="gmail", mailbox="me@example.test", provider_message_id=str(number))
        job = store.claim()
        rid = store.finish(job, {"nested": [True, None, {"unicode": "café"}]},
            {"answers": {"verdict": {"choice": "suspicious", "confidence": .5}}},
            {"eligible_action": "none"}, {"engine": "test"}, {}, now())
        store.add_feedback(item["id"], "clean", "human decision", "test", rid)
    with store.engine.begin() as db:
        db.exec_driver_sql("PRAGMA wal_checkpoint(TRUNCATE)")
    store.engine.dispose()
    return path


def test_dry_run_is_readonly_and_apply_preserves_ids_hashes_json_and_blobs(tmp_path):
    source = source_snapshot(tmp_path)
    original = source.read_bytes()
    destination = create_engine(f"sqlite:///{tmp_path}/target.sqlite")
    report = migration.migrate(source, destination, _allow_test_sqlite=True)
    assert report["mode"] == "dry_run" and not report["destination_verified"]
    assert report["tables"]["messages"]["rows"] == 2 and report["total_rows"] == 8
    assert inspect(destination).get_table_names() == []
    copied = migration.migrate(source, destination, apply=True, batch_size=1, _allow_test_sqlite=True)
    assert copied["destination_verified"] and copied["source_unchanged"]
    assert copied["tables"] == report["tables"] and source.read_bytes() == original
    source_db = migration.source_engine(source)
    try:
        with source_db.connect() as src, destination.connect() as dst:
            for table in (messages, jobs, runs, feedback):
                columns = list(table.c)
                left = list(src.execute(select(*columns).order_by(table.c.id)).mappings())
                right = list(dst.execute(select(*columns).order_by(table.c.id)).mappings())
                assert left == right
            assert dst.execute(select(messages.c.raw)).first()[0] == RAW
    finally:
        source_db.dispose()
        destination.dispose()


def test_rejects_nonempty_target_without_changing_either_side(tmp_path):
    source = source_snapshot(tmp_path)
    destination = create_engine(f"sqlite:///{tmp_path}/target.sqlite")
    with destination.begin() as db:
        db.execute(text("CREATE TABLE existing (id INTEGER)"))
        db.execute(text("INSERT INTO existing VALUES (7)"))
    for apply in (False, True):
        with pytest.raises(migration.MigrationError, match="not empty"):
            migration.migrate(source, destination, apply=apply, _allow_test_sqlite=True)
    assert inspect(destination).get_table_names() == ["existing"]


def test_batch_failure_rolls_back_all_inserted_data(tmp_path):
    source = source_snapshot(tmp_path)
    destination = create_engine(f"sqlite:///{tmp_path}/target.sqlite")
    migration.application_metadata().create_all(destination)
    inserts = []
    @event.listens_for(destination, "before_cursor_execute")
    def fail_late(conn, cursor, statement, params, context, executemany):
        if statement.startswith("INSERT"):
            inserts.append(statement)
            if len(inserts) == 3:
                raise RuntimeError("synthetic late copy failure")
    with pytest.raises(RuntimeError, match="synthetic"):
        migration.migrate(source, destination, apply=True, batch_size=1, _allow_test_sqlite=True)
    event.remove(destination, "before_cursor_execute", fail_late)
    with destination.connect() as db:
        for table in migration.application_metadata().tables.values():
            assert db.execute(select(func.count()).select_from(table)).scalar_one() == 0


def test_rejects_wal_and_schema_drift_instead_of_discarding_source_data(tmp_path):
    source = source_snapshot(tmp_path)
    wal = Path(str(source) + "-wal")
    wal.write_bytes(b"nonempty WAL requires snapshot")
    with pytest.raises(migration.MigrationError, match="WAL"):
        migration.source_engine(source)
    wal.unlink()  # Only this test's synthetic file.
    engine = create_engine(f"sqlite:///{source}")
    with engine.begin() as db:
        db.execute(text("ALTER TABLE messages ADD COLUMN future_field TEXT"))
    engine.dispose()
    destination = create_engine(f"sqlite:///{tmp_path}/target.sqlite")
    with pytest.raises(migration.MigrationError, match="unrecognized columns"):
        migration.migrate(source, destination, apply=True, _allow_test_sqlite=True)
    assert inspect(destination).get_table_names() == []


def test_cli_requires_secret_file_and_never_echoes_driver_credentials(monkeypatch, capsys, tmp_path):
    monkeypatch.delenv("MAILSEC_DATABASE_URL_FILE", raising=False)
    assert migration.main([str(tmp_path / "not-opened")]) == 2
    assert "MAILSEC_DATABASE_URL_FILE" in capsys.readouterr().err
    secret = tmp_path / "dsn"
    secret.write_text("not-a-dsn-secret-value")
    monkeypatch.setenv("MAILSEC_DATABASE_URL_FILE", str(secret))
    assert migration.main([str(tmp_path / "not-opened")]) == 2
    assert "not-a-dsn-secret-value" not in capsys.readouterr().err
