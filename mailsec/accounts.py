"""Explicit Gmail OAuth connections; tokens are encrypted with an external key.

No mailbox is connected by installing this module. The operator supplies a Google
Web OAuth client and Fernet key, then completes consent for each allowed account.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import threading
import weakref
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal
from urllib.parse import urlencode, urlsplit

import httpx
from cryptography.fernet import Fernet, InvalidToken
from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from google.oauth2.credentials import Credentials
from pydantic import BaseModel, Field
from sqlalchemy import Column, MetaData, String, Table, Text, delete, select, update
from sqlalchemy.exc import IntegrityError

from .gmail import MODIFY_SCOPE, READONLY_SCOPE, GmailAuthorizationError, GmailClient, GmailError
from .outbound import bounded_response

AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
COOKIE = "mailsec_oauth_browser"
STATE_SECONDS = 600
ACCESS_SCOPES = {"monitor": READONLY_SCOPE, "manage": MODIFY_SCOPE}
metadata = MetaData()
accounts = Table("mailsec_google_accounts", metadata,
    Column("mailbox", String(320), primary_key=True), Column("encrypted_tokens", Text, nullable=False),
    Column("scopes", Text, nullable=False), Column("connected_at", String(40)),
    Column("updated_at", String(40)), Column("last_verified_at", String(40)),
    Column("last_error", Text))
oauth_states = Table("mailsec_google_oauth_states", metadata,
    Column("state_hash", String(64), primary_key=True), Column("mailbox", String(320), nullable=False),
    Column("browser_hash", String(64), nullable=False), Column("encrypted_verifier", Text, nullable=False),
    Column("expires_at", String(40), nullable=False))
google_setup = Table("mailsec_google_setup", metadata,
    Column("id", String(20), primary_key=True), Column("encrypted_config", Text, nullable=False),
    Column("updated_at", String(40), nullable=False))
_initialized = weakref.WeakSet()
_init_lock = threading.Lock()


def initialize(store):
    with _init_lock:
        if store.engine not in _initialized:
            metadata.create_all(store.engine)
            _initialized.add(store.engine)


def _now():
    return datetime.now(UTC).isoformat(timespec="microseconds")


def _hash(value):
    return hashlib.sha256(value.encode()).hexdigest()


def _mailbox(value):
    value = value.strip().lower()
    if not value or len(value) > 320 or value.count("@") != 1 or any(c.isspace() for c in value):
        raise ValueError("A valid mailbox address is required")
    return value


def _load_google_setup(settings, store):
    """Refresh wizard configuration in API and worker processes without restart."""
    initialize(store)
    settings._google_setup_store = store
    with store.engine.connect() as db:
        row = db.execute(select(google_setup).where(google_setup.c.id == "google")).mappings().first()
    if row and getattr(settings, "_google_setup_revision", None) != row["updated_at"]:
        config = _decrypt(settings, row["encrypted_config"])
        settings._google_oauth_client_config = config["client_config"]
        settings.google_oauth_redirect_uri = config["redirect_uri"]
        settings.authorized_mailboxes = config["mailboxes"]
        if "initial_query" in config:
            settings.initial_query = config["initial_query"]
            settings._google_initial_history = config["initial_history"]
        settings._google_setup_revision = row["updated_at"]


def allowed_mailboxes(settings, store=None):
    store = store or getattr(settings, "_google_setup_store", None)
    if store is not None:
        _load_google_setup(settings, store)
    return sorted({_mailbox(value) for value in getattr(settings, "authorized_mailboxes", [])})


def _require_allowed(settings, mailbox, store=None):
    mailbox = _mailbox(mailbox)
    if mailbox not in allowed_mailboxes(settings, store):
        raise ValueError("Mailbox is not explicitly authorized")
    return mailbox


def _fernet(settings):
    try:
        key = getattr(settings, "token_encryption_key", "")
        if not key:
            raise ValueError()
        return Fernet(key.encode() if isinstance(key, str) else key)
    except (ValueError, TypeError) as exc:
        raise ValueError("A valid external MAILSEC_TOKEN_ENCRYPTION_KEY is required") from exc


def _encrypt(settings, value):
    return _fernet(settings).encrypt(json.dumps(value, separators=(",", ":")).encode()).decode()


def _decrypt(settings, value):
    try:
        return json.loads(_fernet(settings).decrypt(value.encode()))
    except (InvalidToken, ValueError, TypeError) as exc:
        raise ValueError("Stored account credentials cannot be decrypted with the configured key") from exc


def _client_config(settings):
    path = getattr(settings, "google_oauth_client_file", "")
    try:
        supplied = getattr(settings, "_google_oauth_client_config", None)
        config = (supplied if supplied is not None else json.loads(Path(path).read_text()))["web"]
        client_id, client_secret = config["client_id"], config["client_secret"]
        if (not isinstance(client_id, str) or not 1 <= len(client_id) <= 1024
            or not isinstance(client_secret, str) or not 1 <= len(client_secret) <= 4096):
            raise ValueError()
    except (OSError, KeyError, TypeError, ValueError) as exc:
        raise ValueError("A Google Web application OAuth client JSON file is required") from exc
    redirect = getattr(settings, "google_oauth_redirect_uri", "")
    try:
        parsed = urlsplit(redirect)
        parsed.port  # Validate the port rather than deferring failure to Google's redirect.
    except ValueError:
        raise ValueError("OAuth redirect URI is invalid") from None
    if (parsed.path != "/oauth/google/callback" or parsed.query or parsed.fragment
        or parsed.username is not None or parsed.password is not None
        or not parsed.hostname or (parsed.scheme != "https" and not
        (parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"}))):
        raise ValueError("OAuth redirect must use HTTPS (or loopback HTTP) and /oauth/google/callback")
    redirects = config.get("redirect_uris", [])
    if not isinstance(redirects, list) or redirect not in redirects:
        raise ValueError("OAuth redirect URI must exactly match an authorized redirect in the client JSON")
    return {"client_id": client_id, "client_secret": client_secret, "redirect_uri": redirect}


def connected_mailboxes(settings, store):
    """Return only explicitly allowed, configured connections (no domain discovery)."""
    _load_google_setup(settings, store)
    with store.engine.connect() as db:
        oauth = set(db.execute(select(accounts.c.mailbox).where(accounts.c.encrypted_tokens != "")).scalars())
    service = set()
    if getattr(settings, "google_service_account_file", ""):
        service = {_mailbox(value) for value in getattr(settings, "mailboxes", [])}
    return sorted((oauth | service) & set(allowed_mailboxes(settings)))


def oauth_write_restriction(store, mailbox):
    """Keep local disconnect and read-only consent effective in the action worker."""
    initialize(store)
    with store.engine.connect() as db:
        row = db.execute(select(accounts.c.encrypted_tokens, accounts.c.scopes)
                         .where(accounts.c.mailbox == mailbox)).mappings().first()
    if row is not None:
        if not row["encrypted_tokens"]:
            return "Mailbox OAuth connection has been disconnected"
        if MODIFY_SCOPE not in row["scopes"].split():
            return "Mailbox consent permits monitoring only; reconnect with management access to change Gmail"
    return None


def account_health(settings, store):
    _load_google_setup(settings, store)
    with store.engine.connect() as db:
        rows = {row["mailbox"]: dict(row) for row in db.execute(select(accounts.c.mailbox,
            accounts.c.connected_at, accounts.c.last_verified_at, accounts.c.last_error,
            accounts.c.scopes, (accounts.c.encrypted_tokens != "").label("active"))).mappings()}
    service = {_mailbox(value) for value in getattr(settings, "mailboxes", [])}
    configured = bool(getattr(settings, "google_service_account_file", ""))
    result = []
    for mailbox in allowed_mailboxes(settings):
        row = rows.get(mailbox)
        row = row if row and row["active"] else None
        can_modify = MODIFY_SCOPE in row["scopes"].split() if row else bool(configured and mailbox in service)
        result.append({"mailbox": mailbox, "connected": bool(row) or (configured and mailbox in service),
            "connection_type": "oauth" if row else "service_account" if configured and mailbox in service else None,
            "status": "attention" if row and row["last_error"] else "connected" if row else
                      "configured_unverified" if configured and mailbox in service else "not_connected",
            "connected_at": row["connected_at"] if row else None,
            "last_verified_at": row["last_verified_at"] if row else None,
            "last_error": row["last_error"] if row else None,
            "can_modify": can_modify,
            "access_mode": ("manage" if can_modify else "monitor") if row or can_modify else None,
            "can_disconnect": bool(row) and not (configured and mailbox in service)})
    blockers = []
    for check in (_client_config, _fernet):
        try:
            check(settings)
        except ValueError as exc:
            blockers.append(str(exc))
    if not getattr(settings, "app_token", ""):
        blockers.append("Configure MAILSEC_APP_TOKEN before connecting Gmail")
    return {"accounts": result, "oauth_configured": not blockers, "setup_blockers": blockers,
            "enforcement_mode": getattr(settings, "enforcement_mode", "passive"),
            "notifications_enabled": bool(getattr(settings, "notifications_enabled", False)),
            "initial_query": getattr(settings, "initial_query", "-in:sent -in:drafts"),
            "max_initial_messages_per_poll": getattr(settings, "max_initial_messages", 500),
            "quarantine_limitation": "Quarantine removes INBOX and adds a label; messages remain accessible in Gmail All Mail."}


@contextmanager
def gmail_client(settings, store, mailbox, *, for_actions=False):
    mailbox = _require_allowed(settings, mailbox, store)
    initialize(store)
    with store.engine.connect() as db:
        row = db.execute(select(accounts).where(accounts.c.mailbox == mailbox)).mappings().first()
    if row:
        if not row["encrypted_tokens"]:
            raise ValueError("Mailbox OAuth connection has been disconnected")
        scopes = row["scopes"].split()
        if not ({READONLY_SCOPE, MODIFY_SCOPE} & set(scopes)):
            raise ValueError("Mailbox has no supported Gmail permission; reconnect")
        if for_actions and MODIFY_SCOPE not in scopes:
            raise ValueError("Mailbox consent permits monitoring only; reconnect with management access")
        tokens = _decrypt(settings, row["encrypted_tokens"])
        config = _client_config(settings)
        if tokens.get("client_id", config["client_id"]) != config["client_id"]:
            raise ValueError("Stored consent belongs to a different Google OAuth client; reconnect")
        expiry = datetime.fromisoformat(tokens["expiry"]) if tokens.get("expiry") else None
        credentials = Credentials(token=tokens.get("access_token"), refresh_token=tokens.get("refresh_token"),
            token_uri=TOKEN_URL, client_id=config["client_id"], client_secret=config["client_secret"],
            scopes=scopes, expiry=expiry)

        def persist(refreshed):
            updated = {"access_token": refreshed.token, "refresh_token": refreshed.refresh_token,
                       "expiry": refreshed.expiry.isoformat() if refreshed.expiry else None,
                       "client_id": config["client_id"]}
            with store.engine.begin() as db:
                # A refresh already in flight must not overwrite a newly reconnected account.
                db.execute(update(accounts).where(accounts.c.mailbox == mailbox,
                    accounts.c.connected_at == row["connected_at"]).values(
                    encrypted_tokens=_encrypt(settings, updated), updated_at=_now(), last_error=None))
        client = GmailClient("", mailbox, credentials=credentials, scopes=scopes,
                             credentials_updated=persist)

        def check_connection():
            with store.engine.connect() as db:
                current = db.execute(select(accounts.c.connected_at, accounts.c.encrypted_tokens)
                    .where(accounts.c.mailbox == mailbox)).mappings().first()
            if not current or not current["encrypted_tokens"] or current["connected_at"] != row["connected_at"]:
                raise GmailError("Gmail connection was disconnected or replaced; this request was stopped")

        # Separate from the action policy guard, which mailbox_actions replaces.
        client.connection_guard = check_connection
    else:
        if not getattr(settings, "google_service_account_file", "") or mailbox not in {
            _mailbox(value) for value in getattr(settings, "mailboxes", [])
        }:
            raise ValueError("Mailbox has no authorized Gmail connection")
        scopes = [MODIFY_SCOPE] if for_actions else [READONLY_SCOPE]
        client = GmailClient(settings.google_service_account_file, mailbox, scopes=scopes)
    provider_failed = False
    try:
        with client:
            yield client
    except GmailError as exc:
        provider_failed = True
        if row:
            error = (str(exc) if isinstance(exc, GmailAuthorizationError) else
                     "Gmail temporarily rate-limited requests; automatic retries will resume after backoff"
                     if exc.rate_limited else "Gmail access failed; check account consent and provider availability")
            with store.engine.begin() as db:
                db.execute(update(accounts).where(accounts.c.mailbox == mailbox,
                    accounts.c.connected_at == row["connected_at"]).values(last_error=error))
        raise exc
    finally:
        # Local policy cancellation or ingest errors do not invalidate successful
        # provider reads. Keep connection health separate from the caller's work.
        if not provider_failed and row and getattr(client, "successful_requests", 0):
            with store.engine.begin() as db:
                # Do not erase a concurrent reconnect or a newer failure.
                db.execute(update(accounts).where(accounts.c.mailbox == mailbox,
                    accounts.c.connected_at == row["connected_at"],
                    accounts.c.last_error == row["last_error"]).values(
                    last_error=None, last_verified_at=_now()))


class ConnectRequest(BaseModel):
    mailbox: str = Field(min_length=3, max_length=320)
    access_mode: Literal["monitor", "manage"] = "manage"


class DisconnectRequest(BaseModel):
    mailbox: str = Field(min_length=3, max_length=320)


class GoogleSetupRequest(BaseModel):
    client_config: dict
    mailboxes: list[str] = Field(min_length=1, max_length=100)
    redirect_uri: str | None = Field(default=None, max_length=2048)
    initial_history: Literal["new", "30_days", "all"] = "30_days"


def register_account_routes(app, settings, store, *, transport=None):
    """Register account endpoints. OAuth callback is authenticated by state + browser cookie."""
    initialize(store)

    def require_admin(request):
        token = getattr(settings, "app_token", "")
        if not token or not hmac.compare_digest(request.headers.get("authorization", ""), "Bearer " + token):
            raise HTTPException(401, "A configured application token is required to manage Gmail connections")

    @app.get("/api/setup/google")
    def get_google_setup(request: Request):
        require_admin(request)
        health = account_health(settings, store)
        return {"configured": health["oauth_configured"], "setup_blockers": health["setup_blockers"],
                "redirect_uri": getattr(settings, "google_oauth_redirect_uri", ""),
                "authorized_mailboxes": allowed_mailboxes(settings),
                "source": "wizard" if getattr(settings, "_google_setup_revision", None) else "environment",
                "initial_history": getattr(settings, "_google_initial_history", "configured"),
                "initial_query": getattr(settings, "initial_query", "-in:sent -in:drafts"),
                "supports_personal_gmail": True, "supports_google_workspace": True}

    @app.post("/api/setup/google")
    def save_google_setup(body: GoogleSetupRequest, request: Request):
        require_admin(request)
        _load_google_setup(settings, store)
        try:
            _fernet(settings)
            mailboxes = sorted({_mailbox(value) for value in body.mailboxes})
            redirect = body.redirect_uri or getattr(settings, "google_oauth_redirect_uri", "")
            # Validate a disposable object before modifying process configuration.
            from types import SimpleNamespace
            candidate = SimpleNamespace(_google_oauth_client_config=body.client_config,
                                        google_oauth_redirect_uri=redirect)
            config = _client_config(candidate)
            with store.engine.connect() as db:
                active = set(db.execute(select(accounts.c.mailbox)
                    .where(accounts.c.encrypted_tokens != "")).scalars())
            if active - set(mailboxes):
                raise ValueError("Disconnect connected mailboxes before removing them from authorization")
            if active:
                try:
                    existing = _client_config(settings)
                except ValueError:
                    raise ValueError("Disconnect existing mailboxes before replacing an unavailable OAuth client") from None
                if config["client_id"] != existing["client_id"]:
                    raise ValueError("Disconnect existing mailboxes before changing the Google OAuth client ID")
            # Retain only fields needed by this application; uploaded JSON can
            # contain unrelated project metadata that should not enter backups.
            # A fixed epoch cutoff is stable across pagination and restarts.
            # Relative newer_than queries would silently move the backfill window.
            initial_query = "-in:sent -in:drafts"
            if body.initial_history != "all":
                cutoff = datetime.now(UTC) - timedelta(days=30 if body.initial_history == "30_days" else 0)
                initial_query += " after:" + str(int(cutoff.timestamp()))
            value = {"client_config": {"web": {"client_id": config["client_id"],
                     "client_secret": config["client_secret"], "redirect_uris": [redirect]}},
                     "mailboxes": mailboxes, "redirect_uri": redirect,
                     "initial_history": body.initial_history, "initial_query": initial_query}
            record = {"encrypted_config": _encrypt(settings, value), "updated_at": _now()}
            with store.engine.begin() as db:
                if not db.execute(update(google_setup).where(google_setup.c.id == "google").values(**record)).rowcount:
                    db.execute(google_setup.insert().values(id="google", **record))
                db.execute(delete(oauth_states))
        except (ValueError, TypeError) as exc:
            # Validation messages are controlled locally and never contain the uploaded JSON.
            raise HTTPException(400, str(exc)) from None
        except IntegrityError:
            raise HTTPException(409, "Google setup changed concurrently; reload and save again") from None
        return get_google_setup(request)

    @app.get("/api/accounts")
    def get_accounts():
        return account_health(settings, store)

    @app.post("/api/accounts/connect")
    def connect(body: ConnectRequest, request: Request):
        require_admin(request)
        try:
            mailbox = _require_allowed(settings, body.mailbox, store)
            config = _client_config(settings)
            _fernet(settings)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from None
        redirect_origin = urlsplit(config["redirect_uri"])
        if (request.url.scheme, request.url.netloc) != (redirect_origin.scheme, redirect_origin.netloc):
            raise HTTPException(400, "Open the console at the configured OAuth redirect origin before connecting")
        state, browser, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(32), secrets.token_urlsafe(64)
        scope = ACCESS_SCOPES[body.access_mode]
        with store.engine.begin() as db:
            revision = db.execute(select(accounts.c.connected_at).where(accounts.c.mailbox == mailbox)).scalar_one_or_none()
            db.execute(delete(oauth_states).where(oauth_states.c.expires_at < _now()))
            db.execute(oauth_states.insert().values(state_hash=_hash(state), mailbox=mailbox,
                browser_hash=_hash(browser), encrypted_verifier=_encrypt(settings,
                    {"verifier": verifier, "scope": scope, "account_revision": revision,
                     "setup_revision": getattr(settings, "_google_setup_revision", None)}),
                expires_at=(datetime.now(UTC) + timedelta(seconds=STATE_SECONDS)).isoformat(timespec="microseconds")))
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        url = AUTH_URL + "?" + urlencode({"client_id": config["client_id"], "redirect_uri": config["redirect_uri"],
            "response_type": "code", "scope": scope, "access_type": "offline", "prompt": "consent",
            "state": state, "login_hint": mailbox, "code_challenge": challenge, "code_challenge_method": "S256"})
        response = JSONResponse({"authorization_url": url, "mailbox": mailbox, "access_mode": body.access_mode,
                                 "expires_in": STATE_SECONDS})
        response.set_cookie(COOKIE, browser, max_age=STATE_SECONDS, httponly=True, secure=redirect_origin.scheme == "https",
                            samesite="lax", path="/oauth/google")
        return response

    @app.post("/api/accounts/disconnect")
    def disconnect(body: DisconnectRequest, request: Request):
        require_admin(request)
        try:
            mailbox = _require_allowed(settings, body.mailbox, store)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from None
        if getattr(settings, "google_service_account_file", "") and mailbox in {
            _mailbox(value) for value in getattr(settings, "mailboxes", [])
        }:
            raise HTTPException(409, "Remove this mailbox from the service-account configuration before disconnecting")
        # Keep a token-free revision marker so a callback or refresh already in
        # flight cannot resurrect a disconnected connection. Mail stays intact.
        stamp = _now()
        values = {"encrypted_tokens": "", "scopes": "", "connected_at": stamp,
                  "updated_at": stamp, "last_verified_at": None, "last_error": None}
        try:
            with store.engine.begin() as db:
                if not db.execute(update(accounts).where(accounts.c.mailbox == mailbox).values(**values)).rowcount:
                    db.execute(accounts.insert().values(mailbox=mailbox, **values))
                db.execute(delete(oauth_states).where(oauth_states.c.mailbox == mailbox))
        except IntegrityError:
            with store.engine.begin() as db:
                db.execute(update(accounts).where(accounts.c.mailbox == mailbox).values(**values))
                db.execute(delete(oauth_states).where(oauth_states.c.mailbox == mailbox))
        return {"mailbox": mailbox, "connected": False, "retained_messages": True,
                "provider_grant_revoked": False, "revoke_access_url": "https://myaccount.google.com/connections",
                "notice": "Local credentials were removed. Requests already sent may finish. Saved messages and labels are retained; revoke the Google grant in your Google Account to remove provider authorization."}

    @app.get("/oauth/google/callback")
    def callback(request: Request, state: str = "", code: str = "", error: str = ""):
        if not state or len(state) > 512 or len(code) > 8192:
            raise HTTPException(400, "Invalid OAuth callback")
        with store.engine.begin() as db:
            row = db.execute(select(oauth_states).where(oauth_states.c.state_hash == _hash(state))).mappings().first()
            browser = request.cookies.get(COOKIE, "")
            if not row or row["expires_at"] < _now() or not browser or not hmac.compare_digest(row["browser_hash"], _hash(browser)):
                raise HTTPException(400, "OAuth state expired, invalid, or belongs to another browser")
            # Atomic delete makes the callback single use even across workers.
            removed = db.execute(delete(oauth_states).where(oauth_states.c.state_hash == row["state_hash"]))
            if removed.rowcount != 1:
                raise HTTPException(400, "OAuth state has already been used")
        if error or not code:
            raise HTTPException(400, "Google authorization was declined or incomplete")
        try:
            mailbox = _require_allowed(settings, row["mailbox"], store)
            config = _client_config(settings)
            authorization = _decrypt(settings, row["encrypted_verifier"])
            # Legacy, pending consent flows requested management access.
            verifier = authorization if isinstance(authorization, str) else authorization["verifier"]
            scope = MODIFY_SCOPE if isinstance(authorization, str) else authorization["scope"]
            revision = None if isinstance(authorization, str) else authorization["account_revision"]
            with httpx.Client(timeout=httpx.Timeout(30, connect=10), follow_redirects=False,
                              trust_env=False, transport=transport) as http:
                response = bounded_response(http, "POST", TOKEN_URL, max_bytes=65536, total_seconds=30,
                    data={**config, "grant_type": "authorization_code", "code": code, "code_verifier": verifier})
                if not response.is_success:
                    raise ValueError("Google could not exchange the authorization code; start a new connection")
                tokens = response.json()
                if (not isinstance(tokens, dict) or not isinstance(tokens.get("scope"), str)
                    or scope not in tokens["scope"].split()):
                    raise ValueError("Google did not grant the required Gmail permission")
                if not isinstance(tokens.get("access_token"), str) or not tokens["access_token"]:
                    raise ValueError("Google returned an invalid access token")
                if not isinstance(tokens.get("refresh_token"), str) or not tokens["refresh_token"]:
                    raise ValueError("Google did not grant offline access; reconnect with consent")
                profile_response = bounded_response(http, "GET", "https://gmail.googleapis.com/gmail/v1/users/me/profile",
                    max_bytes=16384, total_seconds=30,
                    headers={"Authorization": "Bearer " + tokens["access_token"]})
                if not profile_response.is_success:
                    raise ValueError("Unable to verify the authorized Gmail account")
                profile = profile_response.json()
                if not isinstance(profile, dict) or str(profile.get("emailAddress", "")).lower() != mailbox:
                    raise ValueError("Google account does not match the mailbox selected in the console")
            expires = int(tokens.get("expires_in", 3600))
            if not 0 < expires <= 86400:
                raise ValueError("Google returned an invalid token expiry")
            # google-auth uses naive UTC expiry internally.
            payload = {"access_token": tokens["access_token"], "refresh_token": tokens["refresh_token"],
                       "expiry": (datetime.now(UTC) + timedelta(seconds=expires)).replace(tzinfo=None).isoformat(),
                       "client_id": config["client_id"]}
            stamp = _now()
            values = {"encrypted_tokens": _encrypt(settings, payload), "scopes": scope,
                      "connected_at": stamp, "updated_at": stamp, "last_verified_at": stamp, "last_error": None}
            try:
                with store.engine.begin() as db:
                    setup_revision = db.execute(select(google_setup.c.updated_at)
                        .where(google_setup.c.id == "google")).scalar_one_or_none()
                    if isinstance(authorization, dict) and setup_revision != authorization.get("setup_revision"):
                        raise ValueError("Google setup changed during authorization; start a new connection")
                    present = db.execute(update(accounts).where(accounts.c.mailbox == mailbox,
                        accounts.c.connected_at == revision).values(**values)).rowcount
                    if not present:
                        if revision is not None or db.execute(select(accounts.c.mailbox)
                            .where(accounts.c.mailbox == mailbox)).first():
                            raise ValueError("Connection changed during authorization; start a new connection")
                        db.execute(accounts.insert().values(mailbox=mailbox, **values))
            except IntegrityError:
                raise ValueError("Connection changed during authorization; start a new connection") from None
        except (ValueError, TypeError, KeyError, RecursionError, httpx.HTTPError):
            # Token endpoint errors and exception strings can include sensitive OAuth material.
            raise HTTPException(400, "Gmail connection failed: verify the selected account, granted permission, and OAuth configuration; then reconnect") from None
        response = RedirectResponse("/?gmail=connected", status_code=303)
        response.delete_cookie(COOKIE, path="/oauth/google")
        return response
