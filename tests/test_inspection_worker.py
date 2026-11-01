import io
import struct
import zipfile
from dataclasses import replace
from email.message import EmailMessage

import pytest

from mailsec.inspection.service import run_parser
from mailsec.inspection.settings import InspectionSettings
from mailsec.inspection.worker import inspect_message


def mail_attachment(data, name="document.zip"):
    msg = EmailMessage()
    msg["From"] = "sender@example.com"
    msg["To"] = "recipient@example.org"
    msg.set_content("See the attached file.")
    msg.add_attachment(data, maintype="application", subtype="octet-stream", filename=name)
    return msg.as_bytes()


def archive(entries, compression=zipfile.ZIP_DEFLATED):
    result = io.BytesIO()
    with zipfile.ZipFile(result, "w", compression=compression) as zipped:
        for name, data in entries:
            zipped.writestr(name, data)
    return result.getvalue()


def inspect(raw, **overrides):
    return inspect_message(raw, replace(InspectionSettings(), **overrides).parser_limits())


def test_zip_bomb_size_ratio_is_blocked_before_member_expansion():
    data = archive([("huge.txt", b"A" * 100000)])
    result = inspect(mail_attachment(data), max_compression_ratio=20)
    assert result["status"] == "partial"
    assert result["stats"]["expanded_bytes"] == 0
    assert any(item["kind"] == "inspection_limit" for item in result["findings"])


def test_archive_traversal_and_links_are_never_written(tmp_path):
    data = archive([("../../outside.txt", b"evil"), ("/absolute.txt", b"evil"), ("C:\\escape.txt", b"evil")])
    result = inspect(mail_attachment(data))
    assert result["stats"]["expanded_bytes"] == 0
    assert len([item for item in result["findings"] if item["kind"] == "archive_unsafe_path"]) == 3
    assert not (tmp_path / "outside.txt").exists()


def test_encrypted_zip_flag_is_explicitly_uninspected():
    data = bytearray(archive([("secret.txt", b"secret")], zipfile.ZIP_STORED))
    local = data.index(b"PK\x03\x04")
    central = data.index(b"PK\x01\x02")
    struct.pack_into("<H", data, local + 6, struct.unpack_from("<H", data, local + 6)[0] | 1)
    struct.pack_into("<H", data, central + 8, struct.unpack_from("<H", data, central + 8)[0] | 1)
    result = inspect(mail_attachment(bytes(data)))
    assert result["status"] == "partial"
    assert any(item["kind"] == "encrypted_content" for item in result["findings"])
    assert not any(item["severity"] == "critical" for item in result["findings"])


def test_nested_archive_depth_and_entry_count_are_bounded():
    inside = archive([("text.txt", b"visit https://example.com/document")])
    result = inspect(mail_attachment(archive([("inside.zip", inside)])), max_archive_depth=1)
    assert result["status"] == "partial"
    assert any("nesting" in item["summary"].lower() for item in result["findings"])
    crowded = inspect(mail_attachment(archive([(f"{i}.txt", b"test") for i in range(4)])), max_archive_entries=3)
    assert crowded["stats"]["archive_entries"] == 0
    assert crowded["status"] == "partial"


def test_archive_text_url_is_extracted_without_fetch():
    result = inspect(mail_attachment(archive([("note.txt", b"Read https://example.com/document")])))
    assert "https://example.com/document" in result["urls"]
    assert result["coverage"]["network_fetch"] == "disabled"
    assert result["stats"]["expanded_bytes"] > 0


def test_invalid_archive_and_document_remain_explicit():
    invalid = inspect(mail_attachment(b"not a ZIP", "broken.zip"))
    assert invalid["status"] == "partial"
    assert any(item["kind"] == "archive_invalid" for item in invalid["findings"])
    pdf = inspect(mail_attachment(b"%PDF-1.7 invalid", "broken.pdf"))
    assert pdf["status"] == "partial"


def test_real_subprocess_applies_wall_clock_timeout(tmp_path):
    settings = replace(InspectionSettings(), cache_path=str(tmp_path / "cache.db"), parser_timeout_seconds=.001)
    result = run_parser(mail_attachment(b"plain", "note.txt"), settings)
    assert result["status"] == "partial"
    assert result["coverage"]["mime"] == "unavailable"
    assert any("limit" in item["summary"] for item in result["findings"])


def test_real_subprocess_handles_valid_and_malformed_mail(tmp_path):
    settings = replace(InspectionSettings(), cache_path=str(tmp_path / "cache.db"))
    result = run_parser(mail_attachment(b"read https://example.org/guide", "note.txt"), settings)
    assert "https://example.org/guide" in result["urls"]
    assert result["attachments"][0]["sha256"]
    malformed = run_parser(b"not an RFC message", settings)
    assert malformed["status"] == "partial"


@pytest.mark.parametrize("attachment", [False, True])
@pytest.mark.parametrize("payload", [b"YQ==Yg==", b"YQ==!!", b"YQ"])
def test_lazy_transfer_decoding_defects_are_material_coverage_gaps(attachment, payload):
    disposition = b'Content-Disposition: attachment; filename="note.txt"\r\n' if attachment else b''
    raw = (b"From: sender@example.test\r\nTo: recipient@example.test\r\n"
           b"Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n"
           + disposition + b"\r\n" + payload)
    result = inspect(raw)
    assert result["status"] == "partial"
    assert result["coverage"]["mime"] == "partial"
    assert result["coverage"]["material_content_gap"] is True
    assert any(item["kind"] == "mime_invalid" and "transfer encoding" in item["summary"]
               for item in result["findings"])


def test_valid_wrapped_base64_preserves_complete_mime_coverage():
    raw = (b"From: sender@example.test\r\nContent-Type: text/plain\r\n"
           b"Content-Transfer-Encoding: base64\r\n\r\naGVsbG8g\r\nd29ybGQ=\r\n")
    result = inspect(raw)
    assert result["coverage"]["mime"] == "complete"
    assert not result["coverage"].get("material_content_gap")
