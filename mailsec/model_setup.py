"""Authenticated setup, encrypted provider configuration, and worker refresh."""
from __future__ import annotations

import hashlib
import threading
import weakref
from dataclasses import replace
from typing import Literal

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, StrictBool
from sqlalchemy import Column, MetaData, String, Table, Text, select
from sqlalchemy import text as sql_text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from .accounts import _decrypt, _encrypt, _fernet
from .config import configuration_snapshot
from .decision import configured, decision_client, endpoint
from .jev import JevError
from .provider_consent import (
    PrivacyConsentRequired,
    PrivacyConsents,
    authorization_stamp,
    destination,
    privacy_status,
    require_consent,
)
from .storage import now

metadata = MetaData()
model_settings = Table("decision_provider_settings", metadata,
    Column("tenant", String(160), primary_key=True), Column("encrypted_config", Text, nullable=False),
    Column("updated_at", String(40), nullable=False))
_initialized = weakref.WeakSet()
_lock = threading.Lock()


def initialize(store):
    with _lock:
        if store.engine not in _initialized:
            with store.engine.connect() as db:
                if store.engine.dialect.name == "sqlite":
                    db.exec_driver_sql("BEGIN IMMEDIATE")
                elif store.engine.dialect.name == "postgresql":
                    db.execute(sql_text("SELECT pg_advisory_xact_lock(6217339011422)"))
                metadata.create_all(db)
                db.commit()
            _initialized.add(store.engine)


class ModelConfiguration(BaseModel):
    model_config = ConfigDict(extra="forbid")
    provider: Literal["jev", "ollama", "openai_compatible"]
    model: str = Field(min_length=1, max_length=200)
    base_url: str = Field(default="", max_length=2048)
    api_key: str | None = Field(default=None, max_length=8192, repr=False)
    timeout_seconds: int = Field(default=120, ge=10, le=300)
    recipient_address_masking: StrictBool = False


def refresh_model_settings(settings, store):
    """Return an independent provider snapshot; never mutate shared API settings."""
    return model_snapshot(settings, store)


def model_snapshot(settings, store):
    snapshot = configuration_snapshot(settings)
    if settings.evaluation_mode:
        return snapshot
    initialize(store)
    with store.engine.connect() as db:
        return read_model_settings(snapshot, db)


def lock_model_configuration(db, tenant):
    """Serialize model saves and question activation across API processes."""
    if db.dialect.name == "postgresql":
        key = int.from_bytes(hashlib.sha256(("model-settings:" + tenant).encode()).digest()[:8], "big") & ((1 << 63) - 1)
        db.execute(sql_text("SELECT pg_advisory_xact_lock(:key)"), {"key": key})
    elif db.dialect.name == "sqlite":
        db.exec_driver_sql("BEGIN IMMEDIATE")


def read_model_settings(settings, db):
    """Read one committed encrypted configuration into one detached Settings value."""
    snapshot = configuration_snapshot(settings)
    row = db.execute(select(model_settings).where(
        model_settings.c.tenant == settings.tenant_id)).mappings().first()
    if row:
        value = _decrypt(settings, row["encrypted_config"])
        return replace(snapshot, decision_provider=value["provider"], model=value["model"],
            decision_base_url=value["base_url"], decision_timeout_seconds=value["timeout_seconds"],
            decision_recipient_address_masking=value.get("recipient_address_masking", False),
            decision_privacy_authorization=value.get("privacy_authorization", {}),
            decision_configuration_revision=row["updated_at"],
            api_key=value["api_key"] if value["provider"] == "jev" else "",
            decision_api_key=value["api_key"] if value["provider"] != "jev" else "")
    return snapshot


def model_status(settings, store):
    settings = model_snapshot(settings, store)
    try:
        _fernet(settings)
        writable = bool(settings.app_token) and not settings.evaluation_mode
    except ValueError:
        writable = False
    privacy = privacy_status(settings, store)
    return {"provider": settings.decision_provider, "model": settings.model,
            "base_url": settings.decision_base_url, "configured": configured(settings),
            "key_configured": bool(settings.api_key if settings.decision_provider == "jev" else settings.decision_api_key),
            "timeout_seconds": settings.decision_timeout_seconds, "setup_writable": writable,
            "recipient_address_masking": settings.decision_recipient_address_masking,
            "privacy": privacy, "privacy_accepted": privacy["accepted"],
            "analysis_paused": not privacy.get("analysis_allowed", False),
            "score_semantics": "provider_probabilities" if settings.decision_provider == "jev" else "uncalibrated_model_estimates",
            "model_automatic_quarantine": settings.decision_provider == "jev",
            "data_flow": "Selected email evidence is sent to TypeSafe for analysis." if settings.decision_provider == "jev" else
                         "Selected email evidence is sent only to the model endpoint you configure; this may be local or remote."}


def candidate(settings, body):
    from dataclasses import replace
    value = body.model_dump()
    if 'recipient_address_masking' not in body.model_fields_set:
        # Older clients omitting this optional field must not silently turn off
        # a privacy choice already saved by the owner. Fresh installs default off.
        value['recipient_address_masking'] = settings.decision_recipient_address_masking
    value["model"] = value["model"].strip()
    if not value["model"] or any(ord(c) < 32 for c in value["model"]):
        raise ValueError("Use a valid installed model name")
    value["base_url"] = value["base_url"].strip().rstrip("/")
    if value["provider"] != "jev":
        endpoint(value["base_url"], value["provider"])
    else:
        value["base_url"] = ""
    if value["api_key"] is None:
        same_endpoint = (value["provider"] == "jev" or
                         (value["provider"] == settings.decision_provider and settings.decision_base_url and
                          endpoint(value["base_url"], value["provider"]) ==
                          endpoint(settings.decision_base_url, settings.decision_provider)))
        value["api_key"] = ((settings.api_key if value["provider"] == "jev" else settings.decision_api_key)
                            if value["provider"] == settings.decision_provider and same_endpoint else "")
    probe = replace(settings, decision_provider=value["provider"], model=value["model"],
                    decision_base_url=value["base_url"], decision_timeout_seconds=value["timeout_seconds"],
                    decision_recipient_address_masking=value["recipient_address_masking"])
    if value["provider"] == "jev":
        probe.api_key = value["api_key"]
    else:
        probe.decision_api_key = value["api_key"]
    if not configured(probe):
        raise ValueError("Provide an API key for Jev, or a model and endpoint for local analysis")
    return value, probe


PROBE_QUESTIONS = {
    "kind": {"type": "choice", "instructions": "Classify the supplied synthetic note.",
             "criteria": {"greeting": "A simple greeting", "other": "Anything else"}},
    "requests_password": {"type": "noul", "instructions": "Does the note request a password?",
                          "criteria": {"true": "Requests a password", "false": "Does not request a password"}},
}


def register_model_setup_routes(app, settings, store):
    @app.get("/api/setup/model")
    def status():
        return model_status(settings, store)

    def validate(body):
        if not settings.app_token:
            raise HTTPException(403, "Configure a console token before saving model settings")
        try:
            snapshot = model_snapshot(settings, store)
            value, probe = candidate(snapshot, body)
            require_consent(probe, store, purpose="setup")
            output = decision_client(probe, store=store, purpose="setup").evaluate({"note": "Hello!"},
                                                     questions=PROBE_QUESTIONS)
            if output["answers"]["kind"]["choice"] != "greeting" or output["answers"]["requests_password"]["noul"] >= .5:
                raise ValueError("The server returned structured output but failed the basic synthetic setup check")
            return value, output
        except PrivacyConsentRequired as exc:
            raise HTTPException(403, str(exc)) from None
        except (ValueError, JevError) as exc:
            raise HTTPException(400, str(exc)) from None

    @app.post("/api/setup/model/test")
    def test(body: ModelConfiguration):
        _, output = validate(body)
        return {"ok": True, "model": output["model"], "usage": output["usage"],
                "note": "Connection and structured-output check passed. This is not a detection accuracy test."}

    @app.post("/api/setup/model")
    def save(body: ModelConfiguration):
        try:
            _fernet(settings)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from None
        value, _ = validate(body)
        initialize(store)
        consents = PrivacyConsents(store, settings.tenant_id)
        scope = destination(value["provider"], value["base_url"])
        insert = pg_insert if store.engine.dialect.name == "postgresql" else sqlite_insert
        with store.engine.begin() as db:
            lock_model_configuration(db, settings.tenant_id)
            accepted = consents.status(scope, db)
            if not accepted["accepted"]:
                raise HTTPException(403, "Sharing permission changed during setup. Review and accept the disclosure again")
            value["privacy_authorization"] = authorization_stamp(accepted, value["recipient_address_masking"])
            encrypted = _encrypt(settings, value)
            db.execute(insert(model_settings).values(tenant=settings.tenant_id, encrypted_config=encrypted,
                updated_at=now()).on_conflict_do_update(index_elements=["tenant"],
                    set_={"encrypted_config": encrypted, "updated_at": now()}))
        return {"ok": True, **model_status(settings, store),
                "note": "Saved securely. New analyses use this provider; previous results are retained."}
