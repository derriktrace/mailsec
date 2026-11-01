"""Explicit synthetic-owner authorization for isolated tests, never runtime code."""
from cryptography.fernet import Fernet
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from mailsec.accounts import _encrypt
from mailsec.model_setup import initialize, model_settings, refresh_model_settings
from mailsec.provider_consent import PrivacyConsents, authorization_stamp, destination
from mailsec.storage import now


def accept_test_disclosure(settings, store, *, provider=None, base_url=None):
    scope = destination(provider or settings.decision_provider,
                        settings.decision_base_url if base_url is None else base_url)
    return PrivacyConsents(store, settings.tenant_id).record(scope, True)


def authorize_test_provider(settings, store):
    """Represent a test owner's explicit acceptance followed by model Save."""
    if not settings.token_encryption_key:
        settings.token_encryption_key = Fernet.generate_key().decode()
    accepted = accept_test_disclosure(settings, store)
    initialize(store)
    value = {"provider": settings.decision_provider, "model": settings.model,
             "base_url": settings.decision_base_url, "timeout_seconds": settings.decision_timeout_seconds,
             "api_key": settings.api_key if settings.decision_provider == "jev" else settings.decision_api_key,
             "recipient_address_masking": settings.decision_recipient_address_masking,
             "privacy_authorization": authorization_stamp(accepted, settings.decision_recipient_address_masking)}
    insert = pg_insert if store.engine.dialect.name == "postgresql" else sqlite_insert
    encrypted, updated = _encrypt(settings, value), now()
    with store.engine.begin() as db:
        db.execute(insert(model_settings).values(tenant=settings.tenant_id, encrypted_config=encrypted,
            updated_at=updated).on_conflict_do_update(index_elements=["tenant"],
            set_={"encrypted_config": encrypted, "updated_at": updated}))
    if settings.evaluation_mode:
        settings.decision_privacy_authorization = value["privacy_authorization"]
        settings.decision_configuration_revision = updated
    else:
        # Fixtures explicitly opt in to mutating their own isolated Settings;
        # application refresh functions return detached immutable snapshots.
        configured = refresh_model_settings(settings, store)
        settings.__dict__.update(configured.__dict__)
    return accepted
