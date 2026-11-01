import os
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from mailsec.inspection.clamav import ClamAV
from mailsec.inspection.settings import InspectionSettings

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def current_metadata():
    return {"status": "ready", "engine_version": "1.4.3", "signature_version": "12345",
            "signatures_current": True}


def test_instream_uses_bounded_chunks_and_no_path_commands(monkeypatch):
    class Socket:
        def __init__(self):
            self.sent = []
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def settimeout(self, value):
            assert value > 0
        def sendall(self, value):
            self.sent.append(value)
        def recv(self, size):
            return b"stream: Eicar-Signature FOUND\0"
    connection = Socket()
    scanner = ClamAV(InspectionSettings())
    monkeypatch.setattr(scanner, "_connect", lambda: connection)
    result = scanner.scan(EICAR, current_metadata())
    assert connection.sent[0] == b"zINSTREAM\0"
    assert connection.sent[1][4:] == EICAR
    assert int.from_bytes(connection.sent[1][:4], "big") == len(EICAR)
    assert connection.sent[-1] == b"\0\0\0\0"
    assert result["status"] == "malicious"


@pytest.mark.parametrize("signature", ["Heuristics.Encrypted.Zip", "Heuristics.Limits.Exceeded.MaxScanSize", "Heuristics.OLE2.ContainsMacros", "PUA.Win.Tool"])
def test_heuristics_are_review_not_affirmative_malware(monkeypatch, signature):
    scanner = ClamAV(InspectionSettings())
    monkeypatch.setattr(scanner, "_exchange", lambda *args: f"stream: {signature} FOUND")
    result = scanner.scan(b"untrusted bytes", current_metadata())
    assert result["status"] == "error"
    assert result["review_signature"] == signature
    assert result["malware_signature"] is None


def test_unknown_or_stale_signatures_cannot_make_a_clean_result(monkeypatch):
    scanner = ClamAV(InspectionSettings())
    monkeypatch.setattr(scanner, "_exchange", lambda *args: "stream: OK")
    assert scanner.scan(b"test", {"signatures_current": False})["status"] == "stale"
    assert scanner.scan(b"test", current_metadata())["status"] == "clean"


def test_signature_hit_survives_stale_metadata(monkeypatch):
    scanner = ClamAV(InspectionSettings())
    monkeypatch.setattr(scanner, "_exchange", lambda *args: "stream: Eicar-Signature FOUND")
    assert scanner.scan(EICAR, {"signatures_current": False})["status"] == "malicious"


def test_version_freshness_and_invalid_version(monkeypatch):
    scanner = ClamAV(InspectionSettings(signature_max_age_hours=72))
    recent = datetime.now(timezone.utc).strftime("%a %b %d %H:%M:%S %Y")
    old = (datetime.now(timezone.utc) - timedelta(days=10)).strftime("%a %b %d %H:%M:%S %Y")
    monkeypatch.setattr(scanner, "_exchange", lambda *args: f"ClamAV 1.4.3/12345/{recent}")
    assert scanner.version()["signatures_current"] is True
    monkeypatch.setattr(scanner, "_exchange", lambda *args: f"ClamAV 1.4.3/12345/{old}")
    assert scanner.version()["status"] == "stale"
    monkeypatch.setattr(scanner, "_exchange", lambda *args: "COMMAND UNAVAILABLE")
    assert scanner.version()["status"] == "unavailable"


def test_scan_protocol_error_is_not_clean(monkeypatch):
    scanner = ClamAV(InspectionSettings())
    monkeypatch.setattr(scanner, "_exchange", lambda *args: "INSTREAM size limit exceeded. ERROR")
    assert scanner.scan(b"test", current_metadata())["status"] == "error"


@pytest.mark.skipif(os.getenv("MAILSEC_TEST_LIVE_CLAMD") != "1", reason="Requires explicitly configured local clamd")
def test_optional_live_local_clamd_eicar():
    scanner = ClamAV(replace(InspectionSettings.load(), clamd_timeout_seconds=30))
    result = scanner.scan(EICAR, scanner.version())
    assert result["status"] == "malicious"
    assert result["malware_signature"]
