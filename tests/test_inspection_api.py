import asyncio
from dataclasses import replace

import httpx
import pytest

from mailsec.inspection.api import create_app
from mailsec.inspection.settings import InspectionSettings


class FakeInspector:
    def __init__(self):
        self.calls = []
    def inspect(self, raw):
        self.calls.append(raw)
        return {"status": "partial", "antivirus": {"status": "unavailable"}, "findings": [],
                "coverage": {}, "attachments": [], "urls": [], "stats": {}}
    def health(self):
        return {"ready": False, "status": "stale", "antivirus": {"signatures_current": False}, "scan_performed": False}


def test_health_does_not_report_stale_av_as_ready(tmp_path, monkeypatch):
    fake = FakeInspector()
    settings = replace(InspectionSettings(), cache_path=str(tmp_path / "cache.db"))
    async def direct_thread(function, *args):
        return function(*args)
    monkeypatch.setattr("mailsec.inspection.api.asyncio.to_thread", direct_thread)
    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(create_app(settings, fake)), base_url="http://inspector") as client:
            response = await client.get("/health")
            assert response.status_code == 503
            assert response.json()["ready"] is False
            assert response.json()["scan_performed"] is False
    asyncio.run(run())
    assert fake.calls == []


def test_api_upload_limits_auth_and_raw_contract(tmp_path, monkeypatch):
    fake = FakeInspector()
    settings = replace(InspectionSettings(), cache_path=str(tmp_path / "cache.db"), max_raw_bytes=32, api_token="local-test-token")
    app = create_app(settings, fake)
    async def direct_thread(function, *args):
        return function(*args)
    monkeypatch.setattr("mailsec.inspection.api.asyncio.to_thread", direct_thread)
    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://inspector") as client:
            headers = {"content-type": "application/octet-stream", "authorization": "Bearer local-test-token"}
            assert (await client.post("/inspect", content=b"test", headers={"content-type": "application/octet-stream"})).status_code == 401
            assert (await client.post("/inspect", content=b"test", headers={**headers, "content-type": "text/html"})).status_code == 415
            assert (await client.post("/inspect", content=b"x" * 33, headers=headers)).status_code == 413
            assert (await client.post("/inspect", content=b"", headers=headers)).status_code == 400
            response = await client.post("/inspect", content=b"From: a@example.com\n\nHi", headers=headers)
            assert response.status_code == 200
            assert response.json()["antivirus"]["status"] == "unavailable"
    asyncio.run(run())
    assert len(fake.calls) == 1


def test_api_rejects_streaming_upload_without_trusting_content_length(tmp_path):
    fake = FakeInspector()
    settings = replace(InspectionSettings(), cache_path=str(tmp_path / "cache.db"), max_raw_bytes=10)
    async def chunks():
        yield b"123456"
        yield b"789012"
    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(create_app(settings, fake)), base_url="http://inspector") as client:
            response = await client.post("/inspect", content=chunks(), headers={"content-type": "application/octet-stream"})
            assert response.status_code == 413
    asyncio.run(run())
    assert fake.calls == []


def test_api_concurrency_rejects_excess_work(tmp_path, monkeypatch):
    fake = FakeInspector()
    settings = replace(InspectionSettings(), cache_path=str(tmp_path / "cache.db"), concurrency=1)
    async def run():
        entered, release = asyncio.Event(), asyncio.Event()
        async def blocked_thread(function, *args):
            entered.set()
            await release.wait()
            return function(*args)
        monkeypatch.setattr("mailsec.inspection.api.asyncio.to_thread", blocked_thread)
        async with httpx.AsyncClient(transport=httpx.ASGITransport(create_app(settings, fake)), base_url="http://inspector") as client:
            headers = {"content-type": "application/octet-stream"}
            first = asyncio.create_task(client.post("/inspect", content=b"one", headers=headers))
            await entered.wait()
            excess = await client.post("/inspect", content=b"two", headers=headers)
            assert excess.status_code == 429
            release.set()
            assert (await first).status_code == 200
    asyncio.run(run())
    assert len(fake.calls) == 1


@pytest.mark.parametrize(('extra', 'status'), [
    ([(b'authorization', b'Bearer \xff-invalid')], 401),
    ([(b'authorization', b'Bearer local-test-token'), (b'authorization', b'Bearer other')], 401),
    ([(b'content-length', b'4'), (b'content-length', b'4')], 400),
    ([(b'content-length', b'4'), (b'transfer-encoding', b'chunked')], 400),
    ([(b'content-type', b'text/html')], 400),
    ([(b'content-encoding', b'gzip')], 415),
    ([(b'content-encoding', b'identity'), (b'content-encoding', b'gzip')], 415),
    ([(b'content-length', b'3')], 400),
])
def test_inspection_rejects_malformed_security_headers_before_parsing(tmp_path, extra, status):
    fake = FakeInspector()
    settings = replace(InspectionSettings(), cache_path=str(tmp_path / 'cache.db'), api_token='local-test-token')
    headers = [(b'content-type', b'application/octet-stream')]
    if not any(name == b'authorization' for name, _ in extra):
        headers.append((b'authorization', b'Bearer local-test-token'))

    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(create_app(settings, fake)),
                                     base_url='http://inspector') as client:
            response = await client.post('/inspect', content=b'test', headers=headers + extra)
            assert response.status_code == status

    asyncio.run(run())
    assert fake.calls == []
