"""Private isolated inspector HTTP surface. Bind only on its internal network."""

import asyncio
import hmac

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from .service import Inspector
from .settings import InspectionSettings


def create_app(settings=None, inspector=None):
    settings = settings or InspectionSettings.load()
    inspector = inspector or Inspector(settings)
    app = FastAPI(title="Local mail inspector", docs_url=None, redoc_url=None, openapi_url=None)
    slots = asyncio.Semaphore(settings.concurrency)

    @app.get("/health")
    async def health():
        report = await asyncio.to_thread(inspector.health)
        return JSONResponse(report, status_code=200 if report["ready"] else 503)

    @app.post("/inspect")
    async def inspect(request: Request):
        authorizations = request.headers.getlist('authorization')
        if settings.api_token and (len(authorizations) != 1 or not hmac.compare_digest(
                authorizations[0].encode('utf-8'), ('Bearer ' + settings.api_token).encode('utf-8'))):
            raise HTTPException(401, "Inspection token required")
        if len(authorizations) > 1:
            raise HTTPException(400, 'Ambiguous authorization header')
        lengths = request.headers.getlist('content-length')
        if (len(lengths) > 1 or (lengths and request.headers.getlist('transfer-encoding'))
                or len(request.headers.getlist('content-type')) > 1):
            raise HTTPException(400, 'Ambiguous upload headers')
        encodings = request.headers.getlist('content-encoding')
        if len(encodings) > 1 or (encodings and encodings[0].strip().lower() != 'identity'):
            raise HTTPException(415, 'Send uncompressed RFC email bytes')
        if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() not in {"application/octet-stream", "message/rfc822"}:
            raise HTTPException(415, "Send raw RFC email as application/octet-stream or message/rfc822")
        try:
            declared = int(request.headers.get("content-length", "0"))
            if declared < 0:
                raise ValueError
        except ValueError:
            raise HTTPException(400, "Invalid content length") from None
        if declared > settings.max_raw_bytes:
            raise HTTPException(413, "Email exceeds inspection size limit")
        try:
            await asyncio.wait_for(slots.acquire(), timeout=0.05)
        except TimeoutError:
            raise HTTPException(429, "Inspector is busy", headers={"Retry-After": "1"}) from None
        try:
            raw = bytearray()
            try:
                async with asyncio.timeout(settings.upload_timeout_seconds):
                    async for chunk in request.stream():
                        if len(raw) + len(chunk) > settings.max_raw_bytes:
                            raise HTTPException(413, "Email exceeds inspection size limit")
                        raw.extend(chunk)
            except TimeoutError:
                raise HTTPException(408, "Email upload timed out") from None
            if not raw:
                raise HTTPException(400, "Email is empty")
            if lengths and len(raw) != declared:
                raise HTTPException(400, 'Upload length does not match Content-Length')
            task = asyncio.create_task(asyncio.to_thread(inspector.inspect, bytes(raw)))
            try:
                return await asyncio.shield(task)
            except asyncio.CancelledError:
                # Keep the concurrency lease until bounded work actually terminates.
                await task
                raise
        finally:
            slots.release()

    return app
