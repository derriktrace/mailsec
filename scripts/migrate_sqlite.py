#!/usr/bin/env python3
"""Copy a closed, standalone SQLite snapshot to an empty PostgreSQL schema.

Defaults to dry run. DSN comes exclusively from MAILSEC_DATABASE_URL_FILE. The
source is opened mode=ro, immutable=1; a nonempty SQLite WAL is rejected. Stop
writers and create a consistent standalone snapshot before running this script.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sqlite3
import sys
from pathlib import Path
from urllib.parse import quote

from sqlalchemy import MetaData, create_engine, inspect, select, text
from sqlalchemy.engine import Engine, make_url

# Permit direct execution from a repository checkout or readonly script mount.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


class MigrationError(RuntimeError):
    """A safe diagnostic that never contains a DSN, credential, or email row."""


def application_metadata():
    from mailsec.accounts import metadata as accounts_metadata
    from mailsec.mailbox_actions import metadata as actions_metadata
    from mailsec.runtime_controls import metadata as controls_metadata
    from mailsec.security_cache import metadata as cache_metadata
    from mailsec.storage import metadata as storage_metadata
    combined = MetaData()
    for metadata in (storage_metadata, accounts_metadata, actions_metadata, controls_metadata, cache_metadata):
        for table in metadata.sorted_tables:
            if table.name not in combined.tables:
                table.to_metadata(combined)
    return combined


def file_digest(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def source_engine(path):
    path = Path(path).resolve(strict=True)
    if not path.is_file():
        raise MigrationError("SQLite source must be a regular standalone snapshot")
    wal = Path(str(path) + "-wal")
    if wal.exists() and wal.stat().st_size:
        raise MigrationError("SQLite source has a nonempty WAL; use a closed, consistent standalone snapshot")
    uri = "file:" + quote(str(path), safe="/") + "?mode=ro&immutable=1"
    return create_engine("sqlite://", creator=lambda: sqlite3.connect(uri, uri=True))


def _canonical(value):
    if isinstance(value, (bytes, bytearray, memoryview)):
        return {"$bytes": base64.b64encode(bytes(value)).decode("ascii")}
    if isinstance(value, dict):
        return {key: _canonical(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_canonical(item) for item in value]
    return value


def _row_digest(rows):
    # Hash each row, then sort fixed-size hashes. This keeps raw mail out of the
    # working set and avoids SQLite/PostgreSQL collation ordering differences.
    row_hashes = []
    count = 0
    for row in rows:
        encoded = json.dumps(_canonical(dict(row)), sort_keys=True, ensure_ascii=False,
                             separators=(",", ":"), allow_nan=False).encode()
        row_hashes.append(hashlib.sha256(encoded).digest())
        count += 1
    digest = hashlib.sha256(b"".join(sorted(row_hashes)))
    return {"rows": count, "sha256": digest.hexdigest()}


def _source_plan(source, metadata):
    inspector = inspect(source)
    table_names = set(inspector.get_table_names())
    core = {"messages", "analysis_jobs", "analysis_runs", "feedback"}
    if not core <= table_names:
        raise MigrationError("Source does not contain the required Mailsec tables")
    if table_names - set(metadata.tables):
        raise MigrationError("Source contains unrecognized tables; review schema before migration")
    plan = []
    for name in sorted(table_names):
        table = metadata.tables[name]
        present = {column["name"] for column in inspector.get_columns(name)}
        if present - set(table.c.keys()):
            raise MigrationError(f"Source table {name} has unrecognized columns; no fields will be silently discarded")
        for column in table.c:
            if column.name not in present and not column.nullable and column.default is None and column.server_default is None:
                raise MigrationError(f"Source table {name} is missing a required destination column")
        columns = [column for column in table.c if column.name in present]
        keys = [column for column in table.primary_key if column.name in present]
        if not keys:
            raise MigrationError(f"Source table {name} has no compatible primary key")
        statement = select(*columns).order_by(*keys)
        stats = _row_digest(source.execute(statement).mappings())
        plan.append({"name": name, "table": table, "statement": statement, "columns": columns, **stats})
    # All currently supported schemas use scalar IDs, but ordering by known
    # metadata dependencies also supports future explicit foreign keys.
    order = {table.name: index for index, table in enumerate(metadata.sorted_tables)}
    return sorted(plan, key=lambda entry: order[entry["name"]])


def _assert_target_empty(target, *, lock=False):
    inspector = inspect(target)
    schema = inspector.default_schema_name
    for name in sorted(inspector.get_table_names()):
        preparer = target.dialect.identifier_preparer
        qualified = (preparer.quote_schema(schema) + "." if schema else "") + preparer.quote(name)
        if lock and target.dialect.name == "postgresql":
            target.execute(text(f"LOCK TABLE {qualified} IN ACCESS EXCLUSIVE MODE"))
        if target.execute(text(f"SELECT 1 FROM {qualified} LIMIT 1")).first():
            raise MigrationError("Destination schema is not empty; migration never merges or overwrites existing data")


def migrate(source_path, destination: Engine, *, apply=False, batch_size=100, _allow_test_sqlite=False):
    """Return counts and content digests; all applied target changes commit together.

    The private test switch exists only for fast local rollback/oracle tests;
    command-line execution always requires a PostgreSQL destination.
    """
    if not 1 <= batch_size <= 1000:
        raise MigrationError("Batch size must be between 1 and 1000")
    if destination.dialect.name != "postgresql" and not _allow_test_sqlite:
        raise MigrationError("Migration destination must be PostgreSQL")
    source_path = Path(source_path).resolve(strict=True)
    original_hash = file_digest(source_path)
    source_db = source_engine(source_path)
    metadata = application_metadata()
    try:
        with source_db.connect() as source:
            integrity = source.exec_driver_sql("PRAGMA quick_check").scalars().all()
            if integrity != ["ok"]:
                raise MigrationError("SQLite snapshot integrity check failed")
            plan = _source_plan(source, metadata)
            report = {"mode": "apply" if apply else "dry_run", "source_sha256": original_hash,
                "tables": {row["name"]: {"rows": row["rows"], "sha256": row["sha256"]} for row in plan},
                "total_rows": sum(row["rows"] for row in plan), "source_unchanged": False,
                "destination_verified": False}
            with destination.begin() as target:
                if apply and destination.dialect.name == "postgresql":
                    # Serializes two migration attempts; application writers must be stopped.
                    target.execute(text("SELECT pg_advisory_xact_lock(7157413668521341)"))
                _assert_target_empty(target, lock=apply)
                if apply:
                    metadata.create_all(target)
                    for row in plan:
                        result = source.execution_options(stream_results=True).execute(row["statement"]).mappings()
                        while batch := result.fetchmany(batch_size):
                            target.execute(row["table"].insert(), [dict(item) for item in batch])
                        copied = _row_digest(target.execute(row["statement"]).mappings())
                        if copied != {"rows": row["rows"], "sha256": row["sha256"]}:
                            raise MigrationError(f"Destination verification failed for {row['name']}; transaction rolled back")
                    report["destination_verified"] = True
                if file_digest(source_path) != original_hash:
                    raise MigrationError("SQLite snapshot changed during migration; destination transaction rolled back")
                report["source_unchanged"] = True
            return report
    finally:
        source_db.dispose()


def destination_from_secret_file():
    path = os.environ.get("MAILSEC_DATABASE_URL_FILE", "")
    if not path:
        raise MigrationError("Set MAILSEC_DATABASE_URL_FILE to a protected PostgreSQL DSN file")
    try:
        value = Path(path).read_text().strip()
        url = make_url(value)
        if url.get_backend_name() != "postgresql":
            raise ValueError()
        return create_engine(url, pool_pre_ping=True, hide_parameters=True)
    except Exception:
        raise MigrationError("Unable to read a valid PostgreSQL DSN from the configured secret file") from None


def main(argv=None):
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="Standalone SQLite snapshot mounted read-only")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--apply", action="store_true", help="Copy into an empty PostgreSQL schema")
    mode.add_argument("--dry-run", action="store_true", help="Verify schemas and show counts without changing PostgreSQL (default)")
    parser.add_argument("--batch-size", type=int, default=100)
    args = parser.parse_args(argv)
    destination = None
    try:
        destination = destination_from_secret_file()
        report = migrate(args.source, destination, apply=args.apply, batch_size=args.batch_size)
    except MigrationError as exc:
        print(f"Migration refused: {exc}", file=sys.stderr)
        return 2
    except Exception:
        # Driver errors can embed credentials, SQL bind parameters, or mail content.
        print("Migration failed; no target data committed. Check connectivity, schema, and the readonly snapshot.", file=sys.stderr)
        return 1
    finally:
        if destination is not None:
            destination.dispose()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
