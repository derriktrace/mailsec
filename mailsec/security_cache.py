"""Tenant-scoped, expiring component caches; no body-only verdict reuse."""
import hashlib
import json
import time
from datetime import datetime, timezone

from sqlalchemy import JSON, Column, Float, Integer, MetaData, String, Table, delete, func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

metadata = MetaData()
entries = Table('security_cache', metadata,
    Column('tenant', String(160), primary_key=True), Column('namespace', String(64), primary_key=True),
    Column('key', String(64), primary_key=True), Column('value', JSON, nullable=False),
    Column('created_at', Float, nullable=False), Column('expires_at', Float, nullable=False),
    Column('hits', Integer, nullable=False, default=0))
budgets = Table('security_lookup_budgets', metadata,
    Column('tenant', String(160), primary_key=True), Column('period', String(7), primary_key=True),
    Column('count', Integer, nullable=False))


def digest(value):
    # Raw email headers may contain surrogate-escaped non-UTF8 bytes. Preserve
    # valid-text hashes exactly while representing these invalid code points
    # deterministically; they must not abort an otherwise analyzable message.
    data = value if isinstance(value, bytes) else json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(',', ':')).encode('utf-8', 'backslashreplace')
    return hashlib.sha256(data).hexdigest()


class SecurityCache:
    def __init__(self, engine, tenant='local', epoch='1', clock=time.time):
        self.engine, self.tenant, self.epoch, self.clock = engine, tenant, epoch, clock
        metadata.create_all(engine)

    def _insert(self, table):
        return (pg_insert if self.engine.dialect.name == 'postgresql' else sqlite_insert)(table)

    def _where(self, namespace, key):
        return (entries.c.tenant == self.tenant, entries.c.namespace == namespace,
                entries.c.key == digest([self.epoch, key]))

    def get(self, namespace, key):
        with self.engine.begin() as db:
            row = db.execute(select(entries).where(*self._where(namespace, key), entries.c.expires_at > self.clock())).mappings().first()
            if row is None:
                return None
            db.execute(update(entries).where(*self._where(namespace, key)).values(hits=entries.c.hits + 1))
            return {'value': row['value'], 'expires_at': row['expires_at'], 'created_at': row['created_at']}

    def put(self, namespace, key, value, expires_at):
        if expires_at <= self.clock():
            return
        values = dict(tenant=self.tenant, namespace=namespace, key=digest([self.epoch, key]), value=value,
                      created_at=self.clock(), expires_at=expires_at, hits=0)
        stmt = self._insert(entries).values(**values)
        stmt = stmt.on_conflict_do_update(index_elements=['tenant', 'namespace', 'key'], set_={k:values[k] for k in ('value','created_at','expires_at','hits')})
        with self.engine.begin() as db:
            db.execute(stmt)

    def invalidate(self, namespace=None):
        statement = delete(entries).where(entries.c.tenant == self.tenant)
        if namespace:
            statement = statement.where(entries.c.namespace == namespace)
        with self.engine.begin() as db:
            return db.execute(statement).rowcount

    def reserve_lookup(self, limit):
        if limit <= 0:
            return False
        period = datetime.fromtimestamp(self.clock(), timezone.utc).strftime('%Y-%m')
        stmt = self._insert(budgets).values(tenant=self.tenant, period=period, count=1)
        stmt = stmt.on_conflict_do_update(index_elements=['tenant', 'period'], set_={'count':budgets.c.count + 1}, where=budgets.c.count < limit).returning(budgets.c.count)
        with self.engine.begin() as db:
            return db.execute(stmt).scalar_one_or_none() is not None

    def status(self):
        period = datetime.fromtimestamp(self.clock(), timezone.utc).strftime('%Y-%m')
        with self.engine.connect() as db:
            rows = db.execute(select(entries.c.namespace, func.count().label('entries'), func.sum(entries.c.hits).label('hits')).where(entries.c.tenant == self.tenant, entries.c.expires_at > self.clock()).group_by(entries.c.namespace)).mappings()
            count = db.execute(select(budgets.c.count).where(budgets.c.tenant == self.tenant, budgets.c.period == period)).scalar_one_or_none()
            return {'components': [dict(r) for r in rows], 'lookup_month':period, 'lookups_reserved':count or 0}

    def prune(self):
        with self.engine.begin() as db:
            db.execute(delete(entries).where(entries.c.tenant == self.tenant, entries.c.expires_at <= self.clock()))
