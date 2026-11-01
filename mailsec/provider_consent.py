"""Explicit owner authorization for every configured email-evidence destination.

No setting, environment variable, existing API key, prior Google consent or old
installation grants this authorization. The append-only ledger binds acceptance
to the exact destination and current disclosure; provider calls check it again.
"""
from __future__ import annotations

import threading
import weakref
from typing import Literal

import httpx
from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, StrictBool
from sqlalchemy import JSON, Boolean, Column, Integer, MetaData, String, Table, select
from sqlalchemy import text as sql_text

from .security_cache import digest
from .storage import now

DISCLOSURE_VERSION = "email-sharing-v1"
JEV_DESTINATION = "https://api.typesafe.ai/v1/systemone"
metadata = MetaData()
privacy_events = Table("provider_privacy_events", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("tenant", String(160), nullable=False, index=True),
    Column("destination_sha256", String(64), nullable=False, index=True),
    Column("provider", String(30), nullable=False), Column("destination", String(2048), nullable=False),
    Column("disclosure_version", String(80), nullable=False), Column("disclosure_sha256", String(64), nullable=False),
    Column("accepted", Boolean, nullable=False), Column("actor", String(80), nullable=False),
    Column("created_at", String(40), nullable=False), Column("document", JSON, nullable=False))
_initialized = weakref.WeakSet()
_lock = threading.Lock()


class PrivacyConsentRequired(Exception):
    """A normal paused state, never a malicious/error message assessment."""


def initialize(store):
    with _lock:
        if store.engine not in _initialized:
            with store.engine.connect() as db:
                if db.dialect.name == "sqlite":
                    db.exec_driver_sql("BEGIN IMMEDIATE")
                elif db.dialect.name == "postgresql":
                    db.execute(sql_text("SELECT pg_advisory_xact_lock(6217339011423)"))
                metadata.create_all(db)
                db.commit()
            _initialized.add(store.engine)


def destination(provider, base_url=""):
    if provider == "jev":
        url = JEV_DESTINATION
    else:
        from .decision import endpoint
        url = str(httpx.URL(endpoint(base_url, provider)))
    return {"provider": provider, "destination": url,
            "destination_sha256": digest({"provider": provider, "destination": url})}


def disclosure(scope):
    jev = scope["provider"] == "jev"
    title = "Jev sends email data to TypeSafe" if jev else "Authorize this model endpoint"
    summary = ("Jev is a hosted service operated by TypeSafe, a third party. Mailsec sends email content and "
               "identifying information to TypeSafe for analysis. This is not on-device analysis, and the data is not "
               "automatically anonymous or redacted." if jev else
               "Mailsec sends email content and identifying information to the exact model endpoint below. "
               "Ollama and compatible APIs may run locally or on another machine or a remote service. The name of "
               "the adapter does not prove where the server runs or how its operator handles data.")
    acknowledgment = ("I understand and authorize Mailsec to send the email evidence described here, including "
        "message content and recipient identifiers, to " + ("TypeSafe's hosted Jev service" if jev else "this configured model endpoint") +
        " for all mail selected for scanning, including past imports, future messages and manual tests. "
        "I have permission from the mailbox owners and understand the limits of optional address masking.")
    document = {**scope, "disclosure_version": DISCLOSURE_VERSION, "third_party": True if jev else None, "title": title,
        "summary": summary, "acknowledgment": acknowledgment, "sends_identifiers": True,
        "sends_raw_attachments": False, "sections": [
            {"title": "Past and future email", "body": "Acceptance covers all messages you select for analysis, "
             "historical imports, future messages automatically scanned from connected accounts, replays, and "
             "manual question comparisons using pasted text or captured message evidence. It is not limited to a setup probe."},
            {"title": "What is sent", "body": "The configured model receives selected message content and metadata: "
             "subject and visible, quoted and hidden HTML-derived body text; sender names and addresses, reply-to, "
             "mailbox, To, Cc and available Bcc details when present in the evidence; full links including URL query "
             "parameters and fragments; authentication and domain findings; filenames, attachment metadata and "
             "inspection findings; extracted attachment and document text, OCR and QR contents; relevant organization "
             "and communication context; and the "
             "detection questions and criteria. This can include sensitive personal or business information, secrets "
             "and identifiers contained in email text or URLs. Requests may split a message into several evidence views."},
            {"title": "Recipient identifiers", "body": "Yes, recipient identifiers can be sent. To, Cc, available Bcc and other "
             "recipient or mailbox email addresses can appear in structured evidence, message text, quoted history "
             "or URLs. Address masking is optional and off by default. When enabled it replaces recognized recipient "
             "addresses in outbound evidence and questions; it does not anonymize names, domains, sender addresses, "
             "message content or every possible identifier, and it can reduce detection accuracy. Consent is still required."},
            {"title": "Attachments and local storage", "body": "Mailsec does not upload the original .eml file or raw "
             "attachment binary files to the decision provider. It can send text, OCR, decoded QR content and findings "
             "extracted from those files. Original mail and local analysis records remain in your installation. "
             "Sending selected evidence still transfers a copy of that information to the provider."},
            {"title": "Provider handling", "body": ("TypeSafe operates the Jev endpoint independently of Mailsec. "
             "Review TypeSafe's current privacy and service terms for its handling, retention and processing practices. "
             "Mailsec does not promise provider-side deletion, zero retention or that data stays on your network."
             if jev else "The endpoint operator controls where the model runs, logging, retention and any onward "
             "transfers. A local-looking address, adapter name or self-hosted Mailsec container does not guarantee "
             "that the model server keeps data local. Verify the server configuration and operator's policies.")},
            {"title": "Your choice and revocation", "body": "Only the authenticated owner can accept this disclosure. "
             "Existing API keys and Google mailbox permissions do not count as acceptance. Without current acceptance, "
             "analysis and provider tests stay paused and queued mail is preserved. Accepting this disclosure permits "
             "synthetic setup tests only. Save the selected provider and address-masking setting to enable mail "
             "analysis and question comparisons. You can revoke acceptance or choose "
             "another endpoint; each new destination and changed disclosure needs its own acceptance. Revocation stops "
             "subsequent model requests but cannot recall data already sent or a request already in flight."},
        ]}
    return document | {"disclosure_sha256": digest(document)}


class PrivacyConsents:
    def __init__(self, store, tenant):
        self.store, self.tenant = store, tenant
        initialize(store)

    def status(self, scope, db=None):
        document = disclosure(scope)
        def latest(connection):
            return connection.execute(select(privacy_events).where(privacy_events.c.tenant == self.tenant,
                privacy_events.c.destination_sha256 == scope["destination_sha256"])
                .order_by(privacy_events.c.id.desc()).limit(1)).mappings().first()
        if db is None:
            with self.store.engine.connect() as connection:
                row = latest(connection)
        else:
            row = latest(db)
        accepted = bool(row and row["accepted"] and row["disclosure_version"] == DISCLOSURE_VERSION
                        and row["disclosure_sha256"] == document["disclosure_sha256"])
        return document | {"accepted": accepted, "accepted_at": row["created_at"] if accepted else None,
            "acceptance_id": row["id"] if accepted else None,
            "requires_acceptance": True, "blocking": not accepted,
            "last_action": None if not row else "accepted" if row["accepted"] else "revoked"}

    def record(self, scope, accepted, db=None):
        if type(accepted) is not bool:
            raise ValueError("Explicit acceptance or revocation is required")
        document = disclosure(scope)
        def insert(connection):
            connection.execute(privacy_events.insert().values(tenant=self.tenant, **scope,
                disclosure_version=DISCLOSURE_VERSION, disclosure_sha256=document["disclosure_sha256"],
                accepted=accepted, actor="authenticated_console", created_at=now(), document=document))
        if db is not None:
            insert(db)
            return self.status(scope, db)
        with self.store.engine.begin() as connection:
            from .model_setup import lock_model_configuration
            lock_model_configuration(connection, self.tenant)
            insert(connection)
        return self.status(scope)


def authorization_stamp(status, masking):
    return {key: status[key] for key in ("acceptance_id", "destination_sha256", "disclosure_version",
                                         "disclosure_sha256")} | {"recipient_address_masking": masking}


def analysis_authorized(settings, store, scope, status):
    """Production needs a saved provider/masking configuration bound to consent.

    A newly checked disclosure never resumes an old, unmasked configuration.
    Every request also rejects an obsolete client after a provider/masking save.
    """
    if not status["accepted"]:
        return False
    from .accounts import _decrypt
    from .model_setup import initialize as initialize_models
    from .model_setup import model_settings
    initialize_models(store)
    with store.engine.connect() as db:
        row = db.execute(select(model_settings).where(model_settings.c.tenant == settings.tenant_id)).mappings().first()
    if not row or row["updated_at"] != settings.decision_configuration_revision:
        return False
    value = _decrypt(settings, row["encrypted_config"])
    if destination(value["provider"], value["base_url"]) != scope:
        return False
    masking = value.get("recipient_address_masking", False)
    expected = authorization_stamp(status, masking)
    return (value.get("privacy_authorization") == expected
            and settings.decision_privacy_authorization == expected
            and settings.decision_recipient_address_masking is masking
            and settings.decision_provider == value['provider'] and settings.model == value['model']
            and settings.decision_base_url == value['base_url']
            and settings.decision_timeout_seconds == value['timeout_seconds']
            and (settings.api_key if value['provider'] == 'jev' else settings.decision_api_key) == value['api_key'])


def privacy_status(settings, store, scope=None):
    try:
        scope = scope or destination(settings.decision_provider, settings.decision_base_url)
    except ValueError:
        return {"accepted": False, "blocking": True, "requires_acceptance": True,
                "disclosure_version": DISCLOSURE_VERSION, "writable": bool(settings.app_token) and not settings.evaluation_mode,
                "error": "Choose a valid model endpoint before reviewing its disclosure"}
    status = PrivacyConsents(store, settings.tenant_id).status(scope)
    allowed = analysis_authorized(settings, store, scope, status)
    return status | {"analysis_allowed": allowed, "activation_required": status["accepted"] and not allowed,
        "blocking": not allowed, "writable": bool(settings.app_token) and not settings.evaluation_mode}


def require_consent(settings, store, *, purpose="analysis"):
    try:
        status = privacy_status(settings, store) if store is not None else {}
        allowed = status.get("accepted") if purpose == "setup" else status.get("analysis_allowed")
    except Exception:
        raise PrivacyConsentRequired("Email-sharing permission could not be confirmed; analysis remains paused") from None
    if not allowed:
        raise PrivacyConsentRequired("Analysis is paused. Accept the current email-sharing disclosure, then save the selected provider and masking setting in Setup")


class PrivacyDestination(BaseModel):
    model_config = ConfigDict(extra="forbid")
    provider: Literal["jev", "ollama", "openai_compatible"]
    base_url: str = Field(default="", max_length=2048)


class PrivacyAcceptance(PrivacyDestination):
    disclosure_version: str = Field(min_length=1, max_length=80)
    disclosure_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    accepted: StrictBool


class PrivacyRevocation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    destination_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


def register_privacy_routes(app, settings, store):
    def writable():
        if not settings.app_token or settings.evaluation_mode:
            raise HTTPException(403, "Only the authenticated owner of a mail workspace can authorize email sharing")

    def preview(body):
        try:
            scope = destination(body.provider, body.base_url)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from None
        return privacy_status(current(), store, scope)

    def current():
        from .model_setup import model_snapshot
        return model_snapshot(settings, store)

    @app.get("/api/setup/privacy")
    def status():
        return privacy_status(current(), store)

    @app.post("/api/setup/privacy/preview")
    def preview_route(body: PrivacyDestination):
        writable()
        return preview(body)

    @app.post("/api/setup/privacy/accept")
    def accept(body: PrivacyAcceptance):
        writable()
        status = preview(body)
        if (body.accepted is not True or body.disclosure_version != DISCLOSURE_VERSION
                or body.disclosure_sha256 != status["disclosure_sha256"]):
            raise HTTPException(409, "Read the current disclosure and explicitly accept it before enabling email sharing")
        scope = destination(body.provider, body.base_url)
        PrivacyConsents(store, settings.tenant_id).record(scope, True)
        return privacy_status(current(), store, scope)

    @app.post("/api/setup/privacy/revoke")
    def revoke(body: PrivacyRevocation):
        writable()
        from .model_setup import initialize as initialize_models
        from .model_setup import lock_model_configuration, read_model_settings
        consents = PrivacyConsents(store, settings.tenant_id)
        initialize_models(store)
        with store.engine.begin() as db:
            lock_model_configuration(db, settings.tenant_id)
            snapshot = read_model_settings(settings, db)
            scope = destination(snapshot.decision_provider, snapshot.decision_base_url)
            if body.destination_sha256 != scope["destination_sha256"]:
                raise HTTPException(409, "The current model endpoint changed; reload before revoking its authorization")
            consents.record(scope, False, db)
        return privacy_status(current(), store, scope)
