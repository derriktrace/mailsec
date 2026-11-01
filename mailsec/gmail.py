"""Gmail ingestion and explicit, narrowly scoped mailbox operations.

Callbacks must commit each message (or confirm an existing durable duplicate)
before returning. Retrying a failed pass deliberately replays earlier messages.
"""

from __future__ import annotations

import base64
import binascii
import logging
import math
import re
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, Self
from urllib.parse import quote

import httpx
from google.auth.exceptions import RefreshError

from .outbound import bounded_response

READONLY_SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
MODIFY_SCOPE = "https://www.googleapis.com/auth/gmail.modify"
BASE_URL = "https://gmail.googleapis.com/gmail/v1/users/me"
TOKEN_URLS = {"https://oauth2.googleapis.com/token", "https://accounts.google.com/o/oauth2/token"}
MAX_MESSAGE_BYTES = 25 * 1024 * 1024
log = logging.getLogger("mailsec.gmail")
RATE_LIMIT_REASONS = frozenset({"rateLimitExceeded", "userRateLimitExceeded"})
SAFE_ERROR_REASONS = RATE_LIMIT_REASONS | {"dailyLimitExceeded", "domainPolicy", "forbidden",
    "insufficientPermissions", "authError", "notFound", "backendError"}


class _QuotaPacer:
    """Share a conservative per-mailbox budget across clients in this process.

    New Google projects allow 6,000 units/user/minute and messages.get costs 20
    units. Use half that budget to leave room for other processes and clients.
    Provider backoff remains authoritative when another consumer uses the quota.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._next: dict[str, float] = {}

    def wait(self, mailbox: str, units: int) -> None:
        with self._lock:
            now = time.monotonic()
            start = max(now, self._next.get(mailbox, now))
            self._next[mailbox] = start + units / 50
        if start > now:
            time.sleep(start - now)


_quota_pacer = _QuotaPacer()


def _quota_units(method: str, path: str) -> int:
    if method == "GET":
        if path in {"profile", "labels"}:
            return 1
        if path == "history":
            return 2
        return 5 if path == "messages" else 20
    return 100 if path == "messages/send" else 5


def _error_reason(response: httpx.Response) -> str | None:
    # Never retain provider messages, URLs, mailbox data, or arbitrary strings.
    try:
        error = response.json().get("error", {})
        errors = error.get("errors", []) if isinstance(error, dict) else []
        for item in errors if isinstance(errors, list) else []:
            reason = item.get("reason") if isinstance(item, dict) else None
            if isinstance(reason, str) and reason in SAFE_ERROR_REASONS:
                return reason
    except (ValueError, AttributeError, RecursionError):
        pass
    return None


class GmailError(RuntimeError):
    """Sanitized provider error: never includes messages, credentials, or bodies."""

    def __init__(self, message: str, status_code: int | None = None, *, reason: str | None = None):
        super().__init__(message)
        self.status_code = status_code
        self.reason = reason if isinstance(reason, str) and reason in SAFE_ERROR_REASONS else None
        self.rate_limited = status_code == 429 or (status_code == 403 and self.reason in RATE_LIMIT_REASONS)


class GmailAuthorizationError(GmailError):
    """A structured invalid_grant response requires the owner's new consent."""

    def __init__(self):
        super().__init__("Reconnect Gmail: authorization expired or revoked.", reason="authError")


class GmailMessageMissing(GmailError):
    """The exact provider message ID no longer exists in this mailbox."""


class _AuthResponse:
    def __init__(self, response: httpx.Response):
        self.status = response.status_code
        self.data = response.content
        self.headers = response.headers


class GmailClient:
    """One explicitly authorized personal Gmail or Workspace mailbox.

    OAuth credentials work for either account type. Service-account delegation
    is a separate Workspace-only option.

    The HTTP transport is injectable; Google credential handling is never bypassed
    when a transport is supplied. Use this client as a context manager or close it.
    """

    def __init__(
        self,
        service_account_file: str,
        mailbox: str,
        *,
        transport: httpx.BaseTransport | None = None,
        credentials: Any = None,
        scopes: list[str] | None = None,
        credentials_updated: Callable[[Any], None] | None = None,
    ):
        from google.oauth2 import service_account

        if not mailbox or "@" not in mailbox:
            raise ValueError("A Gmail mailbox email address is required")
        self.mailbox = mailbox.strip().lower()
        self._scopes = scopes or [READONLY_SCOPE]
        self._credentials = credentials or service_account.Credentials.from_service_account_file(
            service_account_file, scopes=self._scopes
        ).with_subject(self.mailbox)
        self._credentials_updated = credentials_updated
        self.successful_requests = 0
        self.connection_guard: Callable[[], None] | None = None
        self.write_guard: Callable[[], None] | None = None
        self._http = httpx.Client(
            timeout=httpx.Timeout(30.0, connect=10.0),
            transport=transport,
            follow_redirects=False,
            trust_env=False,
        )

    def _auth_request(
        self,
        url: str,
        method: str = "GET",
        body: bytes | None = None,
        headers: dict | None = None,
        timeout: float | None = None,
        **kwargs: Any,
    ) -> _AuthResponse:
        # google-auth accepts this Request-compatible callable for token refresh.
        if url not in TOKEN_URLS or method.upper() != "POST":
            raise GmailError("Unexpected Google credential endpoint")
        response = bounded_response(self._http,
            method,
            url,
            max_bytes=65536,
            total_seconds=30,
            content=body,
            headers=headers,
            timeout=min(timeout or 30.0, 30.0),
        )
        return _AuthResponse(response)

    def _request(self, method: str, path: str, *, params: dict | None = None,
                 json: dict | None = None, retry: bool = True) -> dict:
        url = f"{BASE_URL}/{path}"
        attempts = 4 if retry else 1
        for attempt in range(attempts):
            if self.connection_guard:
                self.connection_guard()
            headers: dict[str, str] = {}
            try:
                old_token = getattr(self._credentials, "token", None)
                self._credentials.before_request(self._auth_request, method, url, headers)
                if self._credentials_updated and old_token != getattr(self._credentials, "token", None):
                    self._credentials_updated(self._credentials)
            except Exception as exc:
                # google-auth puts the decoded OAuth response in args[1]. Never
                # infer a permanent grant failure from its free-text description,
                # which can contain provider data or merely mention invalid_grant.
                if (isinstance(exc, RefreshError) and len(exc.args) > 1
                        and isinstance(exc.args[1], dict) and exc.args[1].get("error") == "invalid_grant"):
                    raise GmailAuthorizationError() from None
                raise GmailError("Gmail credential refresh failed; reconnect OAuth or verify Workspace delegation") from None
            _quota_pacer.wait(self.mailbox, _quota_units(method, path))
            if self.connection_guard:
                self.connection_guard()
            # Enforcers can recheck a persisted kill switch immediately before
            # every external write, including each idempotent retry.
            if method != "GET" and self.write_guard:
                self.write_guard()
            try:
                # A 25 MiB raw email expands by 4/3 in Gmail's JSON response.
                limit = 36 * 1024 * 1024 if params and params.get("format") == "raw" else 2 * 1024 * 1024
                response = bounded_response(self._http, method, url, params=params, json=json,
                                            headers=headers, max_bytes=limit, total_seconds=30)
            except ValueError:
                raise GmailError("Gmail returned an oversized or unsupported response") from None
            except httpx.TransportError as exc:
                if attempt == attempts - 1:
                    raise GmailError("Gmail transport failed after bounded retries") from exc
                time.sleep(2**attempt)
                continue
            reason = _error_reason(response) if not response.is_success else None
            rate_limited = response.status_code == 429 or (response.status_code == 403 and reason in RATE_LIMIT_REASONS)
            if rate_limited:
                log.warning("Gmail temporary quota limit (HTTP %s; reason=%s)", response.status_code,
                            reason or "rate_limit")
            if (rate_limited or 500 <= response.status_code < 600) and attempt < attempts - 1:
                try:
                    retry_after = float(response.headers.get("retry-after", "0"))
                except ValueError:
                    retry_after = 0
                if not math.isfinite(retry_after):
                    retry_after = 0
                time.sleep(min(30, max((5 if rate_limited else 1) * 2**attempt, retry_after)))
                continue
            if not response.is_success:
                suffix = f" ({reason})" if reason else ""
                raise GmailError(f"Gmail returned HTTP {response.status_code}{suffix}", response.status_code, reason=reason)
            try:
                payload = response.json()
            except (ValueError, RecursionError):
                raise GmailError("Gmail returned invalid JSON") from None
            if not isinstance(payload, dict):
                raise GmailError("Gmail returned an invalid response object")
            self.successful_requests += 1
            return payload
        raise GmailError("Gmail request exhausted retries")  # defensive

    def _get(self, path: str, params: dict | None = None) -> dict:
        return self._request("GET", path, params=params)

    def _require_modify(self) -> None:
        if MODIFY_SCOPE not in self._scopes:
            raise GmailError("Mailbox changes require the explicitly configured gmail.modify scope")

    def message_labels(self, message_id: str) -> list[str]:
        try:
            payload = self._get(f"messages/{quote(message_id, safe='')}", {"format": "minimal"})
        except GmailError as exc:
            if exc.status_code == 404:
                raise GmailMessageMissing("Message no longer exists in Gmail", 404) from None
            raise
        if _message_id(payload) != message_id:
            raise GmailError("Gmail returned a different message ID")
        labels = payload.get("labelIds", [])
        if not isinstance(labels, list) or any(not isinstance(label, str) for label in labels):
            raise GmailError("Gmail message has invalid label IDs")
        return labels

    def list_labels(self) -> list[dict]:
        labels = _array(self._get("labels"), "labels")
        if any(not isinstance(label, dict) or not isinstance(label.get("id"), str)
               or not isinstance(label.get("name"), str) for label in labels):
            raise GmailError("Gmail returned invalid labels")
        return labels

    def ensure_label(self, name: str) -> str:
        self._require_modify()
        if name not in {"Mailsec/Quarantine", "Mailsec/Review", "Mailsec/Clean", "Mailsec/Spam",
                        "Mailsec/Suspicious", "Mailsec/Phishing"}:
            raise ValueError("Only Mailsec labels may be created")
        for label in self.list_labels():
            if label["name"] == name:
                return label["id"]
        # Label creation is not blindly retried: another process or a lost
        # response may already have created it. Reconcile by exact label name.
        try:
            payload = self._request("POST", "labels", json={"name": name,
                "labelListVisibility": "labelShow", "messageListVisibility": "show"}, retry=False)
            return _message_id(payload)
        except GmailError:
            for label in self.list_labels():
                if label["name"] == name:
                    return label["id"]
            raise

    def modify_labels(self, message_id: str, *, add: list[str], remove: list[str]) -> dict:
        self._require_modify()
        # Adding/removing an existing label is idempotent and safely retryable.
        payload = self._request("POST", f"messages/{quote(message_id, safe='')}/modify",
                                json={"addLabelIds": add, "removeLabelIds": remove})
        if _message_id(payload) != message_id:
            raise GmailError("Gmail returned a different message ID")
        return payload

    def send_message(self, raw: bytes) -> dict:
        self._require_modify()
        # Gmail send has no idempotency key. The durable action ledger must
        # record 'sending' before entering here and never blindly retry it.
        payload = self._request("POST", "messages/send", retry=False,
                                json={"raw": base64.urlsafe_b64encode(raw).decode()})
        _message_id(payload)
        return payload

    def get_profile(self) -> dict:
        payload = self._get("profile")
        _history_id(payload.get("historyId"))
        return payload

    def list_messages(self, query: str = "", page_token: str | None = None, max_results: int = 100) -> dict:
        if not 1 <= max_results <= 500:
            raise ValueError("max_results must be between 1 and 500")
        params: dict[str, Any] = {"maxResults": max_results, "includeSpamTrash": "true"}
        if query:
            params["q"] = query
        if page_token:
            params["pageToken"] = page_token
        payload = self._get("messages", params)
        for message in _array(payload, "messages"):
            _message_id(message)
        _next_token(payload)
        return payload

    def get_message(self, message_id: str) -> dict:
        if not isinstance(message_id, str) or not message_id:
            raise ValueError("message_id must be nonempty")
        payload = self._get(f"messages/{quote(message_id, safe='')}", {"format": "raw"})
        identifier = _message_id(payload)
        if identifier != message_id:
            raise GmailError("Gmail returned a different message ID")
        raw = payload.get("raw")
        thread = payload.get("threadId")
        labels = payload.get("labelIds", [])
        if not isinstance(raw, str) or not raw or not isinstance(thread, str) or not thread:
            raise GmailError("Gmail message is missing raw content or thread ID")
        if len(raw) > ((MAX_MESSAGE_BYTES + 2) // 3) * 4:
            raise GmailError("Gmail message exceeds the 25 MiB import limit")
        # CPython's altchars parameter also accepts the ordinary '+/' alphabet
        # (CVE-2025-12781). Gmail raw data must use exactly base64url; check that
        # alphabet before decoding so mixed representations are never accepted.
        if not re.fullmatch(r"[A-Za-z0-9_-]+={0,2}", raw):
            raise GmailError("Gmail message has invalid base64url content")
        if not isinstance(labels, list) or any(not isinstance(label, str) for label in labels):
            raise GmailError("Gmail message has invalid label IDs")
        try:
            decoded = base64.b64decode(raw + "=" * (-len(raw) % 4), altchars=b"-_", validate=True)
            if len(decoded) > MAX_MESSAGE_BYTES:
                raise GmailError("Gmail message exceeds the 25 MiB import limit")
            milliseconds = int(payload["internalDate"])
            if milliseconds < 0:
                raise ValueError("negative timestamp")
            received_at = datetime.fromtimestamp(milliseconds / 1000, UTC)
        except (KeyError, TypeError, ValueError, OverflowError, OSError, binascii.Error) as exc:
            raise GmailError("Gmail message has invalid raw content or internal date") from exc
        return {
            "id": identifier,
            "thread_id": thread,
            "raw": decoded,
            "internal_date": milliseconds,
            "received_at": received_at,
            "labels": labels,
        }

    def history(self, start_history_id: str, page_token: str | None = None) -> dict:
        params = {
            "startHistoryId": _history_id(start_history_id),
            "historyTypes": "messageAdded",
            "maxResults": 500,
        }
        if page_token:
            params["pageToken"] = page_token
        payload = self._get("history", params)
        _history_id(payload.get("historyId"))
        for record in _array(payload, "history"):
            if not isinstance(record, dict):
                raise GmailError("Gmail returned an invalid history record")
            for item in _array(record, "messagesAdded"):
                if not isinstance(item, dict):
                    raise GmailError("Gmail returned an invalid messageAdded record")
                _message_id(item.get("message"))
        _next_token(payload)
        return payload

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


def _array(payload: dict, key: str) -> list:
    value = payload.get(key, [])
    if not isinstance(value, list):
        raise GmailError(f"Gmail returned an invalid {key} list")
    return value


def _message_id(message: Any) -> str:
    if not isinstance(message, dict) or not isinstance(message.get("id"), str) or not message["id"]:
        raise GmailError("Gmail returned an invalid message ID")
    return message["id"]


def _history_id(value: Any) -> str:
    if not isinstance(value, str) or not value.isascii() or not value.isdigit():
        raise GmailError("Gmail returned an invalid history ID")
    return value


def _next_token(payload: dict) -> str | None:
    token = payload.get("nextPageToken")
    if token is not None and (not isinstance(token, str) or not token):
        raise GmailError("Gmail returned an invalid page token")
    return token


def sync_mailbox(
    client: GmailClient,
    cursor: str | None,
    ingest: Callable[..., Any],
    save_cursor: Callable[[str], Any],
    initial_query: str = "-in:sent -in:drafts",
    max_initial_messages: int = 500,
    resume: dict | None = None,
) -> dict:
    """Synchronize inbound mail, returning explicit coverage and progress.

    Initial/recovery queries are historical selection only. Once checkpointed,
    *all* newly added inbound mail is processed, including archived/spam/trash.
    The limit never permits a partial enumeration to advance the history cursor.
    A failed pass leaves its previous cursor intact. Successfully committed rows
    may be replayed, so the caller must enforce durable provider-ID uniqueness.
    """
    if max_initial_messages < 1:
        raise ValueError("max_initial_messages must be positive")
    summary: dict[str, Any] = {
        "mailbox": client.mailbox,
        "mode": "incremental" if cursor else "initial",
        "cursor_before": cursor,
        "cursor_after": cursor,
        "checkpoint_saved": False,
        "fetched": 0,
        "ingested": 0,
        "duplicates": 0,
        "skipped_non_inbound": 0,
        "vanished": 0,
        "listed": 0,
        "pages": 0,
        "complete": False,
        "truncated": False,
        "query": None,
        "next_page_token": None,
        "backfill_resume": None,
    }
    seen: set[str] = set()

    def import_message(identifier: str) -> None:
        if identifier in seen:
            return
        seen.add(identifier)
        try:
            message = client.get_message(identifier)
        except GmailError as exc:
            if exc.status_code != 404:
                raise
            summary["vanished"] += 1
            return  # Permanently deleted between enumeration and retrieval.
        summary["fetched"] += 1
        if {"SENT", "DRAFT"}.intersection(message["labels"]):
            summary["skipped_non_inbound"] += 1
            return
        result = ingest(
            message["raw"],
            mailbox=client.mailbox,
            provider="gmail",
            provider_message_id=message["id"],
            provider_thread_id=message["thread_id"],
            received_at=message["received_at"],
        )
        # False or {"duplicate": True} denotes an already-committed duplicate.
        # An exception prevents checkpointing; every normal return means durable.
        duplicate = result is False or (isinstance(result, dict) and result.get("duplicate") is True)
        summary["duplicates" if duplicate else "ingested"] += 1

    def checkpoint(value: str) -> dict:
        save_cursor(value)
        summary.update(cursor_after=value, checkpoint_saved=True, complete=True)
        return summary

    valid_resume = (isinstance(resume, dict) and resume.get("version") == 1
        and resume.get("query") == initial_query and resume.get("cursor_before") == cursor
        and isinstance(resume.get("page_token"), str) and bool(resume["page_token"])
        and isinstance(resume.get("boundary"), str) and resume["boundary"].isascii()
        and resume["boundary"].isdigit() and resume.get("mode") in {"initial", "recovery"})
    if not valid_resume:
        resume = None
    else:
        summary["mode"] = resume["mode"]
    if cursor is not None and resume is None:
        token = None
        tokens: set[str] = set()
        while True:
            try:
                page = client.history(cursor, page_token=token)
            except GmailError as exc:
                if exc.status_code != 404:
                    raise
                summary["mode"] = "recovery"
                summary["notice"] = (
                    "Expired history cursor: recovery covers only the configured historical query. Older or permanently deleted mail may be outside coverage."
                )
                break
            summary["pages"] += 1
            for record in _array(page, "history"):
                for item in _array(record, "messagesAdded"):
                    summary["listed"] += 1
                    import_message(_message_id(item.get("message")))
            next_cursor = _history_id(page.get("historyId"))
            token = _next_token(page)
            if token is None:
                return checkpoint(next_cursor)
            if token in tokens:
                raise GmailError("Gmail repeated a history page token")
            tokens.add(token)

    # Capture the boundary before listing. Messages arriving during enumeration
    # are picked up by the next history pass; retrieving profile afterward loses them.
    boundary = resume["boundary"] if resume else _history_id(client.get_profile().get("historyId"))
    summary["query"] = initial_query
    token = resume["page_token"] if resume else None
    tokens = {token} if token else set()
    enumerated = 0
    prior_enumerated = max(0, int(resume.get("enumerated_total", 0))) if resume else 0
    restart_allowed = bool(resume)
    while True:
        try:
            page = client.list_messages(
                query=initial_query,
                page_token=token,
                max_results=min(500, max_initial_messages - enumerated),
            )
        except GmailError as exc:
            if not restart_allowed or exc.status_code not in {400, 404}:
                raise
            # A provider page token may expire. Restart once, bounded to this
            # pass's remaining budget; previously committed rows deduplicate.
            restart_allowed = False
            token, tokens, prior_enumerated = None, set(), 0
            boundary = _history_id(client.get_profile().get("historyId"))
            summary["notice"] = "Saved backfill page expired; enumeration restarted with durable duplicate protection."
            continue
        summary["pages"] += 1
        messages = _array(page, "messages")
        if len(messages) > max_initial_messages - enumerated:
            raise GmailError("Gmail exceeded the requested page size")
        for message in messages:
            enumerated += 1
            summary["listed"] += 1
            import_message(_message_id(message))
        token = _next_token(page)
        if token is None:
            return checkpoint(boundary)
        if token in tokens:
            raise GmailError("Gmail repeated a message page token")
        tokens.add(token)
        if enumerated >= max_initial_messages:
            summary.update(
                truncated=True,
                next_page_token=token,
                backfill_resume={"version": 1, "query": initial_query, "cursor_before": cursor,
                    "boundary": boundary, "page_token": token, "mode": summary["mode"],
                    "enumerated_total": prior_enumerated + enumerated},
                notice="Historical backfill reached this pass's limit. Continue from the saved page on the next poll; the history cursor was not advanced.",
            )
            return summary
