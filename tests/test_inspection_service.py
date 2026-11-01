import base64
import copy
import hashlib
import json
from dataclasses import replace
from email.message import EmailMessage

from mailsec.inspection.cache import Cache, cache_key
from mailsec.inspection.service import RESPONSE_BYTES, Inspector, bound_response, parser_failure
from mailsec.inspection.settings import InspectionSettings


class FakeAV:
    def __init__(self, status="clean", current=True):
        self.status = status
        self.current = current
        self.signature = "100"
        self.engine = "1.4"
        self.scanned = []
    def version(self):
        return {"engine_version": self.engine, "signature_version": self.signature,
                "signatures_current": self.current}
    def scan(self, data, metadata):
        self.scanned.append(data)
        status = self.status if self.current or self.status == "malicious" else "stale"
        return {**metadata, "status": status, "scan_completed": status in {"clean", "malicious", "stale"},
                "malware_signature": "Eicar-Signature" if status == "malicious" else None}


def parsed(attachment=None):
    result = {"status": "complete", "findings": [], "attachments": [], "urls": [],
              "coverage": {"mime": "complete", "archives": "complete", "documents": "complete"}, "stats": {}}
    if attachment is not None:
        result["attachments"].append({"evidence_ref": "mime/1", "filename": "file.bin", "size": len(attachment),
            "sha256": hashlib.sha256(attachment).hexdigest(), "_payload_b64": base64.b64encode(attachment).decode()})
    return result


def inspector(tmp_path, av=None, parser=None, **kwargs):
    settings = replace(InspectionSettings(), cache_path=str(tmp_path / "cache.db"), **kwargs)
    return Inspector(settings, av or FakeAV(), parser or (lambda *args: parsed()))


def test_hard_malware_hit_survives_document_parser_failure(tmp_path):
    service = inspector(tmp_path, FakeAV("malicious"), lambda *args: parser_failure("Timeout"))
    result = service.inspect(b"test bytes")
    assert result["status"] == "partial"
    assert result["antivirus"]["status"] == "malicious"
    assert any(item["kind"] == "antivirus_signature" and item["severity"] == "critical" for item in result["findings"])


def test_unavailable_antivirus_and_parser_never_become_clean(tmp_path):
    result = inspector(tmp_path, FakeAV("unavailable"), lambda *args: parser_failure("Unavailable")).inspect(b"raw")
    assert result["status"] == "unavailable"
    assert result["antivirus"]["status"] == "unavailable"
    assert result["coverage"]["antivirus"] == "partial"


def test_same_message_cache_is_signature_engine_and_tenant_scoped(tmp_path):
    av = FakeAV()
    service = inspector(tmp_path, av)
    assert service.inspect(b"raw")["stats"]["message_cache_hit"] is False
    assert service.inspect(b"raw")["stats"]["message_cache_hit"] is True
    assert len(av.scanned) == 1
    av.signature = "101"
    assert service.inspect(b"raw")["stats"]["message_cache_hit"] is False
    av.engine = "1.5"
    assert service.inspect(b"raw")["stats"]["message_cache_hit"] is False
    other = inspector(tmp_path, av, tenant_id="other-tenant")
    assert other.inspect(b"raw")["stats"]["message_cache_hit"] is False
    assert len(av.scanned) == 4


def test_attachment_cache_reuses_bytes_but_not_old_signatures(tmp_path):
    av = FakeAV()
    service = inspector(tmp_path, av, lambda *args: parsed(b"same attachment"))
    one = service.inspect(b"message-one")
    two = service.inspect(b"message-two")
    assert one["stats"]["attachment_cache_hits"] == 0
    assert two["stats"]["attachment_cache_hits"] == 1
    assert av.scanned.count(b"same attachment") == 1
    assert "_payload_b64" not in two["attachments"][0]
    av.signature = "new-signatures"
    three = service.inspect(b"message-three")
    assert three["stats"]["attachment_cache_hits"] == 0
    assert av.scanned.count(b"same attachment") == 2


def test_stale_version_bypasses_cached_clean_result(tmp_path):
    av = FakeAV()
    service = inspector(tmp_path, av)
    assert service.inspect(b"raw")["antivirus"]["status"] == "clean"
    av.current = False
    result = service.inspect(b"raw")
    assert result["antivirus"]["status"] == "stale"
    assert result["stats"]["message_cache_hit"] is False


def test_database_change_mid_scan_prevents_clean_promotion(tmp_path):
    av = FakeAV()
    def parser(*args):
        av.signature = "new-database"
        return parsed()
    result = inspector(tmp_path, av, parser).inspect(b"raw")
    assert result["antivirus"]["status"] == "stale"
    assert result["antivirus"]["signature_stable_during_inspection"] is False
    assert result["status"] == "partial"


def test_invalid_extracted_bytes_cannot_count_as_scanned(tmp_path):
    value = parsed(b"bytes")
    value["attachments"][0]["sha256"] = "incorrect"
    result = inspector(tmp_path, parser=lambda *args: copy.deepcopy(value)).inspect(b"raw")
    assert result["attachments"][0]["antivirus"]["status"] == "error"
    assert result["status"] == "partial"


def test_cache_ttl_and_namespace_keys(tmp_path, monkeypatch):
    monkeypatch.setattr("mailsec.inspection.cache.time.time", lambda: 100)
    cache = Cache(tmp_path / "metadata.db", ttl=5)
    key = cache_key("tenant", "attachment", "sha", "engine", "db1")
    cache.put(key, {"status": "clean"})
    assert cache.get(key)["status"] == "clean"
    assert cache.get(cache_key("tenant", "attachment", "sha", "engine", "db2")) is None
    assert cache.get(cache_key("other", "attachment", "sha", "engine", "db1")) is None
    monkeypatch.setattr("mailsec.inspection.cache.time.time", lambda: 106)
    assert cache.get(key) is None


def test_large_valid_html_response_preserves_hard_hit_and_whole_urls(tmp_path):
    urls = ["https://example.test/" + str(i) + "/" + "x" * 3000 for i in range(200)]
    message = EmailMessage()
    message["From"] = "sender@example.test"
    message["To"] = "recipient@example.test"
    message.set_content("".join('<a href="' + url + '">Open</a>' for url in urls), subtype="html")
    service = Inspector(replace(InspectionSettings(), cache_path=str(tmp_path / "cache.db")), FakeAV("malicious"))
    result = service.inspect(message.as_bytes())
    assert len(json.dumps(result, ensure_ascii=True, separators=(",", ":")).encode()) <= RESPONSE_BYTES
    assert result["status"] == "partial"
    assert result["antivirus"]["status"] == "malicious"
    assert any(item["kind"] == "antivirus_signature" for item in result["findings"])
    assert result["stats"]["response_urls_omitted"] > 0
    assert all(url in urls for url in result["urls"])


def test_response_fallback_bounds_unicode_and_aggregates_repetitive_findings():
    result = parsed()
    result["antivirus"] = {"status": "malicious", "malware_signature": "Eicar-Signature"}
    result["findings"] = [{"kind": "antivirus_signature", "severity": "critical", "signature": "Eicar-Signature",
                           "evidence_ref": "mime/" + str(i), "summary": "\U0001f9ea" * 5000} for i in range(200)]
    result["attachments"] = [{"filename": "\U0001f9ea" * 200000, "text": "x" * 100000}]
    limited = bound_response(result)
    assert len(json.dumps(limited, ensure_ascii=True, separators=(",", ":")).encode()) <= RESPONSE_BYTES
    assert limited["antivirus"]["status"] == "malicious"
    hit = next(item for item in limited["findings"] if item["kind"] == "antivirus_signature")
    assert hit["count"] == 200 and hit["signature"] == "Eicar-Signature"
    assert limited["stats"]["response_attachments_omitted"] == 1


def test_health_checks_version_without_scanning(tmp_path):
    av = FakeAV()
    service = inspector(tmp_path, av)
    report = service.health()
    assert report["ready"] and report["status"] == "ready" and not report["scan_performed"]
    assert av.scanned == []
    av.current = False
    assert service.health()["ready"] is False
    assert av.scanned == []


def test_health_stops_processing_when_kernel_cannot_confine_parser(tmp_path, monkeypatch):
    av = FakeAV()
    service = inspector(tmp_path, av)
    monkeypatch.setattr('mailsec.inspection.service.isolation_status', lambda: {
        'status': 'unavailable', 'landlock_abi': 5, 'minimum_landlock_abi': 6,
        'peer_signals_isolated': False})
    report = service.health()
    assert not report['ready']
    assert report['status'] == 'parser_isolation_unavailable'
    assert report['parser_isolation']['minimum_landlock_abi'] == 6
    assert av.scanned == []
