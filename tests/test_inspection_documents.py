"""Static extraction must preserve evidence without activating document features."""

import io
import struct
import sys
import types
import zipfile

import pytest

from mailsec.inspection.documents import inspect_document


def inspect(data, filename="note.txt", mime="text/plain", **limits):
    return inspect_document(data, filename, mime, limits=limits)


def office_zip(parts=None, compression=zipfile.ZIP_STORED):
    content = {
        "[Content_Types].xml": '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Override PartName="/word/document.xml" '
        'ContentType="application/vnd.ms-word.document.macroEnabled.main+xml"/></Types>',
        "word/document.xml": '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        '<w:body><w:p><w:r><w:t>Review your invoice.</w:t></w:r></w:p></w:body></w:document>',
    }
    content.update(parts or {})
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=compression) as archive:
        for name, payload in content.items():
            archive.writestr(name, payload)
    return output.getvalue()


def pdf_bytes(*, encrypted=False, pages=1, active=True):
    pypdf = pytest.importorskip("pypdf")
    from pypdf.generic import (
        ArrayObject,
        DecodedStreamObject,
        DictionaryObject,
        FloatObject,
        NameObject,
        NumberObject,
        TextStringObject,
    )

    writer = pypdf.PdfWriter()
    for _ in range(pages):
        page = writer.add_blank_page(width=300, height=300)
        font = DictionaryObject({NameObject("/Type"): NameObject("/Font"),
                                 NameObject("/Subtype"): NameObject("/Type1"),
                                 NameObject("/BaseFont"): NameObject("/Helvetica")})
        page[NameObject("/Resources")] = DictionaryObject({
            NameObject("/Font"): DictionaryObject({NameObject("/F1"): writer._add_object(font)})})
        stream = DecodedStreamObject()
        stream.set_data(b"BT /F1 12 Tf 30 200 Td (Review invoice at https://billing.example.test/view) Tj ET")
        page[NameObject("/Contents")] = writer._add_object(stream)
        link = DictionaryObject({
            NameObject("/Type"): NameObject("/Annot"), NameObject("/Subtype"): NameObject("/Link"),
            NameObject("/Rect"): ArrayObject([FloatObject(n) for n in (0, 0, 100, 30)]),
            NameObject("/A"): DictionaryObject({NameObject("/S"): NameObject("/URI"),
                                                 NameObject("/URI"): TextStringObject(
                                                     "https://login.example.test/account")}),
        })
        page[NameObject("/Annots")] = ArrayObject([writer._add_object(link)])
    if active:
        writer.add_js("throw new Error('MUST NOT EXECUTE');")
        writer._root_object[NameObject("/OpenAction")] = DictionaryObject({
            NameObject("/S"): NameObject("/Launch"),
            NameObject("/F"): TextStringObject("must-not-execute.exe"),
            NameObject("/NewWindow"): NumberObject(1),
        })
    if encrypted:
        writer.encrypt("unavailable-password")
    output = io.BytesIO()
    writer.write(output)
    return output.getvalue()


def test_plain_text_extracts_urls_with_a_real_output_bound():
    result = inspect(b"Hello https://billing.example.test/pay\n" + b"x" * 200, max_text_chars=80)
    assert result["urls"] == ["https://billing.example.test/pay"]
    assert len(result["text"]) == 80
    assert result["coverage"]["status"] == "partial"
    assert "text_character_limit" in result["coverage"]["limitations"]
    assert result["findings"] == []


def test_plain_text_complete_does_not_mean_clean_or_malicious():
    result = inspect(b"A routine message.")
    assert result["coverage"]["status"] == "complete"
    assert result["coverage"]["scope"] == "static_extraction_only"
    assert "verdict" not in result
    assert "malicious" not in result


def test_html_extracts_visible_text_links_and_active_metadata_without_execution(monkeypatch):
    def prohibited(*args, **kwargs):
        pytest.fail("Static document inspection must not invoke network or subprocesses")

    monkeypatch.setattr("socket.create_connection", prohibited)
    monkeypatch.setattr("subprocess.Popen", prohibited)
    data = b'''<html><head><title>Not visible</title></head><body>
      <p>Sign in to review</p><a href="https://example.test/login">your invoice</a>
      <p hidden>HIDDEN SECRET</p><span style="display:none">ALSO HIDDEN</span>
      <script>throw Error('MUST NOT EXECUTE'); fetch('https://hidden.test/')</script>
      <form action="https://example.test/submit"><input name="password"></form>
      <meta http-equiv="refresh" content="0;url=https://example.test/next">
    </body></html>'''
    result = inspect(data, "invoice.html", "text/html")
    assert "Sign in to review" in result["text"]
    assert "HIDDEN" not in result["text"]
    assert "Not visible" not in result["text"]
    assert "MUST NOT EXECUTE" not in result["text"]
    assert set(result["urls"]) == {"https://example.test/login", "https://example.test/submit",
                                  "https://example.test/next"}
    assert {item["id"] for item in result["findings"]} == {"html_active_content", "html_refresh"}
    assert all(item["severity"] in {"review", "info"} for item in result["findings"])
    assert result["coverage"]["status"] == "complete"
    assert result["coverage"]["rendering"] == "not_performed"


def test_office_extracts_relationship_and_macro_metadata_without_running_it(monkeypatch):
    pytest.importorskip("defusedxml")
    data = office_zip({
        "word/vbaProject.bin": b"Not executed and not asserted to be malicious",
        "word/_rels/document.xml.rels": '<Relationships '
        'xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/hyperlink" '
        'Target="https://login.example.test/reset" TargetMode="External"/></Relationships>',
    })
    result = inspect(data, "invoice.docm", "application/octet-stream")
    assert result["kind"] == "office_ooxml"
    assert result["text"] == "Review your invoice."
    assert result["urls"] == ["https://login.example.test/reset"]
    findings = {item["id"]: item for item in result["findings"]}
    assert findings["office_macro_part"]["severity"] == "review"
    assert findings["office_external_relationship"]["severity"] == "info"
    assert result["coverage"]["macros"] == "package_metadata_only"
    assert result["coverage"]["status"] == "complete"


def test_office_entity_expansion_is_rejected_without_reading_external_files(tmp_path):
    pytest.importorskip("defusedxml")
    secret = tmp_path / "local-secret.txt"
    secret.write_text("MUST NOT BE READ")
    data = office_zip({"word/document.xml": f'''<!DOCTYPE doc [<!ENTITY xxe SYSTEM "{secret.as_uri()}">]>
      <doc><t>&xxe;</t></doc>'''})
    result = inspect(data, "invoice.docx", "application/octet-stream")
    assert "MUST NOT BE READ" not in result["text"]
    assert "office_xml_invalid_or_unsafe" in result["coverage"]["limitations"]
    assert result["coverage"]["status"] == "partial"


@pytest.mark.parametrize("limits,reason", [
    ({"max_archive_entries": 1}, "office_archive_entry_limit"),
    ({"max_compression_ratio": 2}, "office_compression_ratio_limit"),
])
def test_office_zip_limits_are_checked_before_member_decompression(monkeypatch, limits, reason):
    pytest.importorskip("defusedxml")
    data = office_zip({"word/document.xml": "<doc>" + "A" * 10_000 + "</doc>"}, zipfile.ZIP_DEFLATED)
    def prohibited(*args, **kwargs):
        pytest.fail("Oversized package must be rejected before opening a ZIP member")
    monkeypatch.setattr(zipfile.ZipFile, "open", prohibited)
    result = inspect(data, "invoice.docx", "application/octet-stream", **limits)
    assert reason in result["coverage"]["limitations"]
    assert result["coverage"]["status"] == "partial"


def test_office_encrypted_zip_member_remains_unknown():
    pytest.importorskip("defusedxml")
    data = bytearray(office_zip())
    # Mark each local and central record encrypted; extraction must stop before
    # attempting to read data, so no actual password/cipher is required here.
    for signature, offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        start = 0
        while (position := data.find(signature, start)) != -1:
            flag = struct.unpack_from("<H", data, position + offset)[0]
            struct.pack_into("<H", data, position + offset, flag | 1)
            start = position + 4
    result = inspect(bytes(data), "invoice.docx", "application/octet-stream")
    assert result["coverage"]["status"] == "encrypted"
    assert result["text"] == ""
    assert result["findings"] == []


def test_office_unsupported_binary_part_is_an_explicit_coverage_gap():
    pytest.importorskip("defusedxml")
    result = inspect(office_zip({"xl/workbook.bin": b"opaque"}), "invoice.xlsb", "application/octet-stream")
    assert "office_binary_parts_not_decoded" in result["coverage"]["limitations"]
    assert result["coverage"]["status"] == "partial"


def test_pdf_extracts_text_uri_and_active_metadata_without_execution(monkeypatch):
    data = pdf_bytes()
    def prohibited(*args, **kwargs):
        pytest.fail("PDF actions must never be executed or fetched")
    monkeypatch.setattr("socket.create_connection", prohibited)
    monkeypatch.setattr("subprocess.Popen", prohibited)
    result = inspect(data, "invoice.pdf", "application/pdf")
    assert result["coverage"]["status"] == "complete"
    assert "Review invoice" in result["text"]
    assert set(result["urls"]) == {"https://login.example.test/account", "https://billing.example.test/view"}
    assert any(item["id"] == "pdf_active_action" for item in result["findings"])
    assert all(item["severity"] in {"review", "info"} for item in result["findings"])
    assert "MUST NOT EXECUTE" not in result["text"]


def test_pdf_page_and_text_limits_report_incomplete_coverage():
    result = inspect(pdf_bytes(pages=3), "invoice.pdf", "application/pdf",
                     max_document_pages=1, max_text_chars=20)
    assert result["coverage"]["pages_seen"] == 1
    assert result["coverage"]["pages_total"] == 3
    assert len(result["text"]) == 20
    assert "pdf_page_limit" in result["coverage"]["limitations"]
    assert "text_character_limit" in result["coverage"]["limitations"]
    assert result["coverage"]["status"] == "partial"


def test_pdf_encryption_is_not_treated_as_no_indicators():
    result = inspect(pdf_bytes(encrypted=True), "invoice.pdf", "application/pdf")
    assert result["coverage"]["status"] == "encrypted"
    assert result["coverage"]["text"] == "not_inspected"
    assert result["text"] == ""
    assert result["urls"] == []


@pytest.mark.parametrize("filename,mime", [("broken.pdf", "application/pdf"),
                                           ("broken.docx", "application/octet-stream"),
                                           ("broken.png", "image/png")])
def test_malformed_document_is_never_reported_as_complete(filename, mime):
    result = inspect(b"not a valid file", filename, mime)
    assert result["coverage"]["status"] in {"invalid", "unavailable"}
    assert result["findings"] == []


def test_missing_pdf_decoder_is_explicitly_unavailable(monkeypatch):
    monkeypatch.setitem(sys.modules, "pypdf", None)
    result = inspect(b"%PDF-1.4\n", "invoice.pdf", "application/pdf")
    assert result["coverage"]["status"] == "unavailable"
    assert result["coverage"]["text"] == "unavailable"


def test_image_qr_contents_are_retained_but_not_visited(monkeypatch):
    image = pytest.importorskip("PIL.Image")
    buffer = io.BytesIO()
    image.new("RGB", (16, 16), "white").save(buffer, "PNG")
    calls = []
    def decode(pixels, **kwargs):
        calls.append(pixels.size)
        return [types.SimpleNamespace(valid=True, text="https://qr.example.test/auth")]
    fake = types.SimpleNamespace(read_barcodes=decode, BarcodeFormat=types.SimpleNamespace(QRCode="QR"))
    monkeypatch.setitem(sys.modules, "zxingcpp", fake)
    result = inspect(buffer.getvalue(), "photo.png", "image/png")
    assert calls == [(16, 16)]
    assert result["urls"] == ["https://qr.example.test/auth"]
    assert result["coverage"]["qr"] == "scanned"
    assert result["coverage"]["status"] == "complete"
    assert result["coverage"]["ocr"] == "not_applicable"
    assert result["coverage"]["ocr_small_images_skipped"] == 1
    assert result["findings"][0]["severity"] == "info"


def test_image_pixel_limit_is_checked_before_qr_decode(monkeypatch):
    image = pytest.importorskip("PIL.Image")
    buffer = io.BytesIO()
    image.new("RGB", (16, 16), "white").save(buffer, "PNG")
    def prohibited(*args, **kwargs):
        pytest.fail("Image over pixel budget must not be decoded")
    monkeypatch.setattr(image.Image, "convert", prohibited)
    result = inspect(buffer.getvalue(), "photo.png", "image/png", max_image_pixels=100)
    assert result["coverage"]["qr"] == "limited"
    assert result["coverage"]["status"] == "partial"


def test_missing_qr_decoder_is_unknown_not_no_qr(monkeypatch):
    image = pytest.importorskip("PIL.Image")
    buffer = io.BytesIO()
    image.new("RGB", (16, 16), "white").save(buffer, "PNG")
    monkeypatch.setitem(sys.modules, "zxingcpp", None)
    result = inspect(buffer.getvalue(), "photo.png", "image/png")
    assert result["coverage"]["qr"] == "unavailable"
    assert result["coverage"]["status"] == "partial"


@pytest.mark.parametrize("as_pdf", [False, True])
def test_actual_qr_decoder_reads_image_and_embedded_pdf_image(as_pdf):
    zxing = pytest.importorskip("zxingcpp")
    image_module = pytest.importorskip("PIL.Image")
    code = zxing.create_barcode("https://qr.example.test/secure", zxing.BarcodeFormat.QRCode)
    pixels = memoryview(code.to_image(scale=4))
    image = image_module.frombytes("L", (pixels.shape[1], pixels.shape[0]), pixels.tobytes())
    output = io.BytesIO()
    if as_pdf:
        pypdf = pytest.importorskip("pypdf")
        from pypdf.generic import DecodedStreamObject, DictionaryObject, NameObject, NumberObject
        writer = pypdf.PdfWriter()
        page = writer.add_blank_page(width=300, height=300)
        obj = DecodedStreamObject()
        obj.set_data(image.tobytes())
        obj.update({NameObject("/Type"): NameObject("/XObject"), NameObject("/Subtype"): NameObject("/Image"),
                    NameObject("/Width"): NumberObject(image.width), NameObject("/Height"): NumberObject(image.height),
                    NameObject("/ColorSpace"): NameObject("/DeviceGray"),
                    NameObject("/BitsPerComponent"): NumberObject(8)})
        page[NameObject("/Resources")] = DictionaryObject({
            NameObject("/XObject"): DictionaryObject({NameObject("/QR"): writer._add_object(obj)})})
        writer.write(output)
        result = inspect(output.getvalue(), "qr.pdf", "application/pdf")
    else:
        image.save(output, "PNG")
        result = inspect(output.getvalue(), "qr.png", "image/png")
    assert result["urls"] == ["https://qr.example.test/secure"]
    assert result["coverage"]["qr"] == "scanned"
    assert result["coverage"]["qr_images_scanned"] == (2 if as_pdf else 1)
    assert result["coverage"]["status"] == "complete"


@pytest.mark.parametrize("encrypted", [False, True])
def test_legacy_office_encryption_and_vba_detection_never_run_emulation(monkeypatch, encrypted):
    olefile = pytest.importorskip("olefile")
    crypto = pytest.importorskip("oletools.crypto")
    olevba = pytest.importorskip("oletools.olevba")
    calls = []
    class Container:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def listdir(self, **kwargs):
            return [["EncryptedPackage" if encrypted else "WordDocument"]]
        def get_size(self, parts):
            return 100
    class Parser:
        def __init__(self, name, **kwargs):
            assert kwargs["disable_pcode"] is True
            calls.append("opened")
        def detect_vba_macros(self):
            assert self.no_xlm is True
            calls.append("detect_vba_only")
            return True
        def close(self):
            calls.append("closed")
    monkeypatch.setattr(olefile, "OleFileIO", lambda *args, **kwargs: Container())
    monkeypatch.setattr(crypto, "is_encrypted", lambda *args: False)
    monkeypatch.setattr(olevba, "VBA_Parser", Parser)
    result = inspect(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"Review invoice at https://example.test/review",
                     "invoice.doc", "application/msword")
    if encrypted:
        assert calls == []
        assert result["coverage"]["status"] == "encrypted"
        assert result["text"] == ""
    else:
        assert calls == ["opened", "detect_vba_only", "closed"]
        assert result["findings"][0]["id"] == "office_vba_present"
        assert result["findings"][0]["severity"] == "review"
        assert result["urls"] == ["https://example.test/review"]
        assert result["coverage"]["text_scope"] == "printable_container_strings_only"


def test_pdf_magic_wins_over_misleading_attachment_filename():
    result = inspect(pdf_bytes(active=False), "picture.png", "image/png")
    assert result["kind"] == "pdf"
    assert "Review invoice" in result["text"]


def test_unrecognized_binary_is_explicitly_unsupported():
    result = inspect(b"\x01\x00\x02", "sample.unknown", "application/octet-stream")
    assert result["coverage"]["status"] == "unsupported"
    assert result["coverage"]["material_content_gap"] is True
    assert result["findings"] == []
