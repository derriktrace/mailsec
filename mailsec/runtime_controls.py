"""Persistent single-organization operator controls with an append-only audit."""
from sqlalchemy import JSON, Column, MetaData, String, Table, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from .storage import new_id, now

metadata=MetaData()
controls=Table('protection_controls',metadata,Column('tenant',String(160),primary_key=True),
               Column('values',JSON,nullable=False),Column('updated_at',String(40),nullable=False))
audit=Table('protection_control_audit',metadata,Column('id',String(32),primary_key=True),
            Column('tenant',String(160),nullable=False),Column('created_at',String(40),nullable=False),
            Column('before',JSON,nullable=False),Column('after',JSON,nullable=False),
            Column('actor',String(80),nullable=False))


def refresh_controls(settings,store):
    if getattr(settings, 'evaluation_mode', False):
        settings.enforcement_mode = 'passive'
        settings.notifications_enabled = False
        return {'mode':'passive','notifications_enabled':False}
    metadata.create_all(store.engine)
    with store.engine.connect() as db:
        row=db.execute(select(controls.c['values']).where(controls.c.tenant==settings.tenant_id)).scalar_one_or_none()
    if row:
        settings.enforcement_mode=row['mode']
        settings.notifications_enabled=row['notifications_enabled']
    return {'mode':settings.enforcement_mode,'notifications_enabled':settings.notifications_enabled}


def update_controls(settings, store, changes):
    if getattr(settings, 'evaluation_mode', False):
        raise ValueError('Evaluation workspaces cannot enable mailbox actions')
    metadata.create_all(store.engine)
    insert = pg_insert if store.engine.dialect.name == 'postgresql' else sqlite_insert
    defaults = {'mode': settings.enforcement_mode, 'notifications_enabled': settings.notifications_enabled}
    with store.engine.begin() as db:
        if store.engine.dialect.name == 'sqlite':
            # Reserve the writer before reading, across threads AND processes.
            db.exec_driver_sql('BEGIN IMMEDIATE')
        db.execute(insert(controls).values(tenant=settings.tenant_id, values=defaults, updated_at=now())
                   .on_conflict_do_nothing(index_elements=['tenant']))
        current = db.execute(select(controls.c['values']).where(controls.c.tenant == settings.tenant_id)
                             .with_for_update()).scalar_one()
        future = {**current, **changes}
        if (set(future) != {'mode', 'notifications_enabled'} or
                future['mode'] not in ('passive', 'flag_only', 'auto_quarantine') or
                type(future['notifications_enabled']) is not bool):
            raise ValueError('Invalid protection controls')
        db.execute(controls.update().where(controls.c.tenant == settings.tenant_id)
                   .values(values=future, updated_at=now()))
        db.execute(audit.insert().values(id=new_id(), tenant=settings.tenant_id, created_at=now(),
                   before=current, after=future, actor='authenticated_console'))
    return refresh_controls(settings, store)
