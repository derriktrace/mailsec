"""Console boundary: authenticate before parsing and bound streamed request bodies."""

import asyncio
import hmac
from urllib.parse import urlsplit

from starlette.datastructures import Headers, MutableHeaders
from starlette.responses import JSONResponse


def _origin(value):
    """Compare browser origins, including the scheme and effective port."""
    try:
        parsed = urlsplit(value)
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or parsed.path or parsed.query or parsed.fragment):
            return None
        return parsed.scheme, parsed.hostname.lower(), parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        return None


class ConsoleSecurityMiddleware:
    # Bound aggregate uploads as well as each request. These are local service
    # limits, not a substitute for a reverse proxy's connection/rate limits.
    upload_timeout_seconds = 30
    upload_slots = 4

    def __init__(self, app, settings):
        self.app = app
        self.settings = settings
        self.slots = asyncio.Semaphore(self.upload_slots)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)

        async def secured_send(message):
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers["Content-Security-Policy"] = (
                    "default-src 'self'; script-src 'self'; style-src 'self'; "
                    "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
                    "base-uri 'none'; form-action 'self'; object-src 'none'"
                )
                headers["X-Content-Type-Options"] = "nosniff"
                headers["Referrer-Policy"] = "no-referrer"
                headers["Cache-Control"] = "no-store"
                headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
                if scope["scheme"] == "https":
                    headers["Strict-Transport-Security"] = "max-age=31536000"
            await send(message)

        async def reject(status, detail, headers=None):
            await JSONResponse({"detail": detail}, status_code=status, headers=headers)(scope, receive, secured_send)

        path = scope["path"]
        method = scope["method"]
        headers = Headers(scope=scope)
        is_api = path.startswith(("/api/", "/evaluation/api/"))
        # A proxy and an application must not choose different interpretations
        # of the authority or bearer credential in an ambiguous request.
        if len(headers.getlist("host")) != 1 or len(headers.getlist("authorization")) > 1:
            return await reject(400, "Ambiguous request headers")
        if is_api:
            if self.settings.app_token and not hmac.compare_digest(
                    headers.get("authorization", "").encode("utf-8"),
                    ("Bearer " + self.settings.app_token).encode("utf-8")):
                return await reject(401, "Application token required")
            origin = headers.get("origin")
            expected = _origin(scope["scheme"] + "://" + headers.get("host", ""))
            if origin is not None and (_origin(origin) is None or _origin(origin) != expected):
                return await reject(403, "Cross-origin requests are disabled")
            if headers.get("sec-fetch-site") == "cross-site":
                return await reject(403, "Cross-site requests are disabled")

        if self.settings.evaluation_mode and (
                path.startswith("/oauth/") or
                (method not in ("GET", "HEAD") and (
                    path.startswith(("/api/accounts", "/api/protection", "/api/notifications", "/api/demo", "/api/setup"))
                    or path.endswith("/release")))):
            return await reject(403, "Evaluation workspace: mailbox connections and actions are disabled.")

        if not is_api:
            return await self.app(scope, receive, secured_send)

        is_import = path in {"/api/import", "/evaluation/api/import"}
        limit = self.settings.max_message_bytes + 65536 if is_import else 65536
        declared = headers.get("content-length")
        if declared is not None and headers.get("transfer-encoding") is not None:
            return await reject(400, "Ambiguous request framing")
        if declared is not None:
            # No signed, negative, duplicate, or otherwise ambiguous lengths.
            if not declared.isascii() or not declared.isdecimal() or len(headers.getlist("content-length")) != 1:
                return await reject(400, "Invalid content length")
            if len(declared) > 20 or int(declared) > limit:
                return await reject(413, "Request exceeds upload size limit")
        if headers.get("content-encoding", "identity").lower() != "identity":
            return await reject(415, "Compressed request bodies are not supported")

        # Read before FastAPI/Starlette parses multipart fields or files. Checking
        # UploadFile.read alone happens after the potentially unbounded parser.
        has_body = method not in {"GET", "HEAD", "OPTIONS"} or bool(
            headers.get("transfer-encoding") or (declared and int(declared)))
        if has_body:
            try:
                await asyncio.wait_for(self.slots.acquire(), timeout=0.1)
            except TimeoutError:
                return await reject(429, "Console is busy; retry shortly", {"Retry-After": "1"})
        try:
            body = bytearray()
            try:
                async with asyncio.timeout(self.upload_timeout_seconds):
                    while True:
                        message = await receive()
                        if message["type"] == "http.disconnect":
                            return
                        chunk = message.get("body", b"")
                        if len(body) + len(chunk) > limit:
                            return await reject(413, "Request exceeds upload size limit")
                        body.extend(chunk)
                        if not message.get("more_body", False):
                            break
            except TimeoutError:
                return await reject(408, "Request upload timed out")
            if declared is not None and len(body) != int(declared):
                return await reject(400, "Content length does not match request body")
            consumed = False

            async def buffered_receive():
                nonlocal consumed
                if not consumed:
                    consumed = True
                    return {"type": "http.request", "body": bytes(body), "more_body": False}
                return await receive()

            await self.app(scope, buffered_receive, secured_send)
        finally:
            if has_body:
                self.slots.release()
