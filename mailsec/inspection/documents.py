"""Passive document extraction, intended to run in the isolated inspection worker.

This module never opens URLs, renders active content, decrypts files, or executes
macros. ``complete`` describes the advertised static extraction scope, not a
security verdict. The caller must also impose process memory and time limits:
third-party decoders cannot all guarantee an allocation bound before decoding.
"""

from __future__ import annotations

import io
import re
import warnings
import zipfile
from html.parser import HTMLParser
from pathlib import PurePosixPath
from urllib.parse import urlsplit

from mailsec.html_visibility import extract_html, material_image_gap

from .ocr import OCRBudget, OCRFailure, read_image, render_pdf_page
from .static_scripts import inspect_html_scripts

DEFAULT_LIMITS = {
    "max_document_pages": 20,
    "max_text_chars": 20_000,
    "max_image_pixels": 16_000_000,
    "max_archive_entries": 200,
    "max_uncompressed_bytes": 25 * 1024 * 1024,
    "max_compression_ratio": 100,
    "max_qr_images": 20,
    "max_ocr_images": 8,
    "max_ocr_seconds": 10,
    "max_static_decoded_bytes": 2 * 1024 * 1024,
    "max_static_payloads": 8,
}
_URL = re.compile(r"https?://[^\s<>\"\x00-\x1f]+", re.IGNORECASE)
_OOXML_EXT = {".docx", ".docm", ".dotx", ".dotm", ".xlsx", ".xlsm", ".xltx", ".xltm",
              ".xlsb", ".pptx", ".pptm", ".potx", ".potm", ".ppsx", ".ppsm"}
_OLE_EXT = {".doc", ".dot", ".xls", ".xlt", ".ppt", ".pps", ".pot"}
_IMAGE_EXT = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tif", ".tiff", ".webp", ".ico"}
_OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


class _Extraction:
    def __init__(self, kind: str, limits: dict, ocr_budget=None):
        self.limits = {name: max(0, int(limits.get(name, value))) for name, value in DEFAULT_LIMITS.items()}
        self.result = {
            "kind": kind, "text": "", "urls": [], "findings": [],
            "coverage": {"status": "complete", "scope": "static_extraction_only", "text": "not_present",
                         "links": "absolute_http_urls_only", "qr": "not_applicable", "macros": "not_applicable",
                         "limitations": []},
        }
        self.qr_images = 0
        self.ocr_budget = ocr_budget or OCRBudget(self.limits)
        self.ocr_images = 0

    @property
    def coverage(self):
        return self.result["coverage"]

    def gap(self, reason: str, status: str = "partial"):
        if reason not in self.coverage["limitations"]:
            self.coverage["limitations"].append(reason)
        # Preserve a stronger, terminal status if a subsequent extraction step fails.
        if self.coverage["status"] in {"complete", "partial"}:
            self.coverage["status"] = status

    def finding(self, key: str, kind: str, summary: str, severity: str = "review"):
        if not any(item["id"] == key for item in self.result["findings"]):
            self.result["findings"].append({"id": key, "kind": kind, "severity": severity, "summary": summary})

    def text(self, value: str):
        if not value:
            return
        value = value.replace("\x00", "")
        remaining = self.limits["max_text_chars"] - len(self.result["text"])
        separator = "\n" if self.result["text"] else ""
        fragment = separator + value
        if len(fragment) > remaining:
            self.gap("text_character_limit")
            self.coverage["text"] = "limited"
            self.coverage["material_content_gap"] = True
        elif self.coverage["text"] != "limited":
            self.coverage["text"] = "extracted"
        self.result["text"] += fragment[:max(0, remaining)]

    def url(self, value: str):
        value = value.strip()
        if len(value) > 4096:
            self.gap("url_length_limit")
            return
        try:
            parsed = urlsplit(value)
            if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
                return
        except ValueError:
            self.gap("invalid_url")
            return
        if any(ord(char) < 32 for char in value):
            self.gap("invalid_url")
            return
        if value in self.result["urls"]:
            return
        if len(self.result["urls"]) >= self.limits["max_archive_entries"]:
            self.gap("url_count_limit")
            return
        self.result["urls"].append(value)

    def text_urls(self, value: str):
        for match in _URL.finditer(value):
            self.url(match.group().rstrip(".,;!?)']"))


def inspect_document(data: bytes, filename: str, content_type: str, *, limits: dict, ocr_budget=None) -> dict:
    """Extract bounded text, HTTP(S) URLs, and static review indicators.

    Import failures are coverage gaps, not clean results. File signatures take
    precedence over extensions. ZIP containers without Office parts are left to
    the archive inspector, and unknown binary types are explicitly unsupported.
    """
    extension = PurePosixPath(filename.replace("\\", "/")).suffix.lower()
    mime = content_type.lower().split(";", 1)[0].strip()
    prefix = data[:1024].lstrip()
    image_signature = data.startswith((b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff", b"GIF87a", b"GIF89a"))
    if prefix.startswith(b"%PDF-"):
        kind, inspector = "pdf", _inspect_pdf
    elif data.startswith(_OLE_MAGIC):
        kind, inspector = "office_legacy", _inspect_ole
    elif data.startswith(b"PK\x03\x04"):
        kind, inspector = "office_ooxml", _inspect_ooxml
    elif image_signature:
        kind, inspector = "image", _inspect_image
    elif extension == ".pdf" or mime == "application/pdf":
        kind, inspector = "pdf", _inspect_pdf
    elif extension in _OLE_EXT:
        kind, inspector = "office_legacy", _inspect_ole
    elif extension in _OOXML_EXT or "officedocument" in mime:
        kind, inspector = "office_ooxml", _inspect_ooxml
    elif (mime == "text/html" or extension in {".html", ".htm"}
          or prefix.lower().startswith((b"<!doctype html", b"<html"))):
        kind, inspector = "html", _inspect_html
    elif mime.startswith("image/") or extension in _IMAGE_EXT:
        kind, inspector = "image", _inspect_image
    elif mime.startswith("text/") or extension == ".txt":
        kind, inspector = "text", _inspect_text
    else:
        result = _Extraction("unsupported", limits)
        result.gap("unsupported_document_type", "unsupported")
        result.coverage["material_content_gap"] = True
        return result.result

    result = _Extraction(kind, limits, ocr_budget)
    if len(data) > result.limits["max_uncompressed_bytes"]:
        result.gap("document_input_byte_limit")
        result.coverage["text"] = "not_inspected"
        result.coverage["material_content_gap"] = True
        return result.result
    try:
        inspector(data, result)
    except ImportError:
        result.gap("document_decoder_unavailable", "unavailable")
        result.coverage["text"] = "unavailable"
        if kind == "image":
            result.coverage["ocr_material_gap"] = True
        else:
            result.coverage["material_content_gap"] = True
    except Exception:
        # Parser errors must not expose document content or become a security verdict.
        result.gap("document_parse_failed", "invalid")
        result.coverage["text"] = "error"
        if kind in {"pdf", "office_ooxml", "office_legacy", "html"}:
            result.coverage["material_content_gap"] = True
        elif kind == "image":
            result.coverage["ocr_material_gap"] = True
    result.text_urls(result.result["text"])
    return result.result


def _decode_text(data: bytes, result: _Extraction) -> str:
    encoding = "utf-16" if data.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig"
    try:
        return data.decode(encoding)
    except UnicodeError:
        result.gap("text_encoding_replacement")
        return data.decode(encoding, errors="replace")


def _inspect_text(data: bytes, result: _Extraction):
    result.text(_decode_text(data, result))


class _StaticHTML(HTMLParser):
    _hidden_tags = {"script", "style", "head", "template", "noscript"}
    _void_tags = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param",
                  "source", "track", "wbr"}

    def __init__(self, result: _Extraction):
        super().__init__(convert_charrefs=True)
        self.result = result
        self.stack = []

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        style = re.sub(r"\s+", "", (values.get("style") or "").lower())
        hidden = (tag in self._hidden_tags or "hidden" in values or values.get("aria-hidden") == "true"
                  or "display:none" in style or "visibility:hidden" in style)
        if tag not in self._void_tags:
            if len(self.stack) >= 256:
                self.result.gap("html_nesting_limit")
                raise ValueError("HTML nesting limit")
            self.stack.append((tag, hidden or bool(self.stack and self.stack[-1][1])))
        for key, value in attrs:
            if not value:
                continue
            if key in {"href", "src", "action", "formaction", "poster", "data"}:
                self.result.url(value)
                if value.lstrip().lower().startswith("javascript:"):
                    self._active()
            if key.startswith("on"):
                self._active()
        if tag in {"script", "object", "embed", "iframe", "form"}:
            self._active()
        if tag == "meta" and (values.get("http-equiv") or "").lower() == "refresh":
            match = re.search(r"url\s*=\s*['\"]?([^'\"]+)", values.get("content") or "", re.I)
            if match:
                self.result.url(match.group(1).strip())
                self.result.finding("html_refresh", "automatic_navigation",
                                    "HTML declares automatic navigation; the destination was not visited.")

    def _active(self):
        self.result.finding("html_active_content", "active_content",
                            "HTML contains a form or active-content feature; it was not executed.")

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag not in self._void_tags:
            self.handle_endtag(tag)

    def handle_endtag(self, tag):
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index][0] == tag:
                del self.stack[index:]
                break

    def handle_data(self, value):
        # Visible text is supplied by the shared CSS-aware projection below.
        pass


def _inspect_html(data: bytes, result: _Extraction):
    source = _decode_text(data, result)
    parser = _StaticHTML(result)
    parser.feed(source)
    parser.close()
    visible = extract_html(source)
    # Replace the legacy inline-only text projection; keep its passive action
    # metadata and URLs. Hidden/quoted text is context, never visible body copy.
    result.result["text"] = ""
    result.coverage["text"] = "not_present"
    result.text(visible["visible_text"])
    result.result["hidden_text"] = visible["hidden_text"][:4000]
    result.result["quoted_text"] = visible["quoted_text"][:4000]
    result.coverage["visibility_limits"] = visible["limits"]
    result.coverage["visibility_uncertainties"] = visible["visibility_uncertainties"]
    if material_image_gap(visible, schemes=("data:",)):
        result.gap("embedded_image_content_unread")
        result.coverage["material_content_gap"] = True
        result.finding("embedded_image_content_unread", "unread_embedded_image",
                       "Important embedded image content was not decoded or inspected.")
    if visible["coverage"] == "partial":
        result.gap("html_visibility_incomplete")
        # Responsive/dark-mode CSS often has conditional hiding, but the text
        # remains available. Keep the uncertainty without inventing lost content.
        # Match the MIME projection: actual limits/source loss are material;
        # unresolved unconditional hiding can also matter for substantive copy.
        unresolved = set(visible["visibility_uncertainties"]) - {"conditional_visibility"}
        if visible["limits"] or (unresolved and len(visible["visible_text"]) > 1000):
            result.coverage["material_content_gap"] = True
    inspect_html_scripts(source, result)
    result.coverage["rendering"] = "not_performed"
    result.coverage["visibility"] = visible["coverage"]
    result.coverage["scope_exclusions"] = ["html_css_and_script_rendering"]
    if any(image.get("src", "").lower().startswith("data:") for image in visible["images"]):
        result.coverage["scope_exclusions"].append("embedded_data_images_not_decoded")


def _ocr_image(image, result: _Extraction):
    result.coverage.setdefault("ocr", "not_applicable")
    result.coverage["ocr_languages"] = ["eng", "por", "spa"]
    # Tracking pixels and small icons cannot contain substantive readable copy.
    # This exception must not turn a large unread attachment into a clean signal.
    if (image.width <= 64 and image.height <= 64) or min(image.width, image.height) <= 16:
        result.coverage["ocr_small_images_skipped"] = result.coverage.get("ocr_small_images_skipped", 0) + 1
        return
    if image.width * image.height > result.limits["max_image_pixels"]:
        _ocr_gap(result, "image_pixel_limit", "limited")
        return
    try:
        text, confidence = read_image(image, result.ocr_budget)
    except OCRFailure as exc:
        reason = str(exc)
        status = "limited" if "limit" in reason or "timeout" in reason else (
            "unavailable" if "unavailable" in reason else "error")
        _ocr_gap(result, reason, status)
        return
    result.ocr_images += 1
    result.coverage["ocr_images_scanned"] = result.ocr_images
    result.coverage["ocr_mean_confidence"] = confidence
    if not result.coverage.get("ocr_material_gap"):
        result.coverage["ocr"] = "extracted" if text else "no_text_detected"
    if text:
        result.text("[OCR image text; recognition may contain errors]\n" + text)
        result.finding("ocr_text", "image_text",
                       "Image text was read using local OCR; recognition errors are possible.", "info")
        # A few noisy glyphs on a logo/QR are not proof substantive copy was
        # missed. A longer low-confidence transcription does require review.
        if confidence is not None and confidence < 35 and len(text) >= 20:
            _ocr_gap(result, "ocr_low_recognition_confidence", "limited")


def _ocr_gap(result, reason, status):
    result.coverage["ocr"] = status
    result.coverage["ocr_material_gap"] = True
    result.gap(reason)


def _scan_qr(image, result: _Extraction):
    if result.qr_images >= result.limits["max_qr_images"]:
        result.coverage["qr"] = "limited"
        result.gap("qr_image_count_limit")
        return
    if image.width * image.height > result.limits["max_image_pixels"]:
        result.coverage["qr"] = "limited"
        result.gap("image_pixel_limit")
        return
    result.qr_images += 1
    try:
        import zxingcpp
    except ImportError:
        result.coverage["qr"] = "unavailable"
        result.gap("qr_decoder_unavailable")
        return
    try:
        codes = zxingcpp.read_barcodes(image.convert("RGB"), formats=zxingcpp.BarcodeFormat.QRCode)
        if result.coverage["qr"] not in {"limited", "error", "unavailable"}:
            result.coverage["qr"] = "scanned"
        for code in codes[:result.limits["max_archive_entries"]]:
            if not getattr(code, "valid", True):
                continue
            text = str(code.text)
            result.text(text)
            result.text_urls(text)
            result.finding("qr_content", "qr_code",
                           "A QR code was decoded; its contents and any URLs were extracted without visiting them.",
                           "info")
    except Exception:
        result.coverage["qr"] = "error"
        result.gap("qr_decode_failed")


def _inspect_image(data: bytes, result: _Extraction):
    from PIL import Image

    with warnings.catch_warnings():
        warnings.simplefilter("error", Image.DecompressionBombWarning)
        with Image.open(io.BytesIO(data)) as image:
            if image.width * image.height > result.limits["max_image_pixels"]:
                result.coverage["qr"] = "limited"
                result.gap("image_pixel_limit")
                _ocr_gap(result, "image_pixel_limit", "limited")
                return
            # Animated images can conceal a destination in a later frame.
            frames = min(getattr(image, "n_frames", 1), result.limits["max_qr_images"])
            if getattr(image, "n_frames", 1) > frames:
                result.gap("qr_image_count_limit")
                result.coverage["qr"] = "limited"
                _ocr_gap(result, "image_frame_count_limit", "limited")
            for index in range(frames):
                image.seek(index)
                _scan_qr(image, result)
                _ocr_image(image, result)
    result.coverage["qr_images_scanned"] = result.qr_images


def _inspect_ooxml(data: bytes, result: _Extraction):
    from defusedxml import ElementTree

    result.coverage["macros"] = "package_metadata_only"
    result.coverage["qr"] = "not_present"
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        if len(entries) > result.limits["max_archive_entries"]:
            result.gap("office_archive_entry_limit")
            return
        names = [entry.filename.lower() for entry in entries]
        if not ("[content_types].xml" in names and any(
                name.startswith(("word/", "xl/", "ppt/")) for name in names)):
            result.gap("zip_is_not_supported_office_document", "unsupported")
            return
        if len(set(names)) != len(names):
            result.gap("office_duplicate_part_names", "invalid")
            return
        total = 0
        for entry in entries:
            if entry.flag_bits & 1:
                result.gap("office_encrypted_zip_member", "encrypted")
                result.coverage["material_content_gap"] = True
                return
            total += entry.file_size
            if total > result.limits["max_uncompressed_bytes"]:
                result.gap("office_uncompressed_byte_limit")
                return
            if entry.file_size > max(1, entry.compress_size) * result.limits["max_compression_ratio"]:
                result.gap("office_compression_ratio_limit")
                return
            if ".." in PurePosixPath(entry.filename.replace("\\", "/")).parts:
                result.gap("office_noncanonical_part_name", "invalid")
                return

        consumed = 0
        for entry in entries:
            name = entry.filename.lower()
            if name.endswith("vbaproject.bin") or "/macrosheets/" in name:
                result.finding("office_macro_part", "macro_presence",
                               "The Office package contains a VBA project or macro-sheet part; macro presence alone "
                               "does not establish maliciousness.")
            if "/activex/" in name or "/embeddings/" in name:
                result.finding("office_embedded_content", "embedded_content",
                               "The Office package contains an embedded object or ActiveX part; it was not executed.")
                result.gap("office_embedded_objects_not_recursively_inspected")
            is_image = "/media/" in name and PurePosixPath(name).suffix in _IMAGE_EXT
            if entry.is_dir() or not (name.endswith((".xml", ".rels")) or is_image):
                if name.endswith(".bin") and not name.endswith("vbaproject.bin"):
                    result.gap("office_binary_parts_not_decoded")
                continue
            # Bound reads independently of central-directory claims; never extract to disk.
            remaining = result.limits["max_uncompressed_bytes"] - consumed
            with archive.open(entry) as stream:
                payload = stream.read(min(entry.file_size, remaining) + 1)
            consumed += len(payload)
            if len(payload) > entry.file_size or consumed > result.limits["max_uncompressed_bytes"]:
                result.gap("office_uncompressed_byte_limit")
                return
            if is_image:
                _office_image(payload, result)
                continue
            try:
                document = ElementTree.fromstring(payload, forbid_dtd=True)
            except Exception:
                result.gap("office_xml_invalid_or_unsafe")
                continue
            for element in document.iter():
                tag = element.tag.rsplit("}", 1)[-1]
                if tag == "Relationship" and element.attrib.get("TargetMode", "").lower() == "external":
                    result.url(element.attrib.get("Target", ""))
                    result.finding("office_external_relationship", "external_relationship",
                                   "The Office package references an external resource; it was not fetched.", "info")
                if tag in {"Override", "Default"} and "macroenabled" in element.attrib.get(
                        "ContentType", "").lower():
                    result.finding("office_macro_format", "macro_capable_format",
                                   "Office content types declare a macro-capable format; this is not a malware verdict.",
                                   "info")
                # Text runs, spreadsheet values and formulas are extracted as inert text.
                if name.startswith(("word/", "xl/", "ppt/")) and tag in {"t", "v", "f", "instrText"}:
                    result.text(element.text or "")
                    result.text_urls(element.text or "")
        result.coverage["qr_images_scanned"] = result.qr_images


def _office_image(data: bytes, result: _Extraction):
    try:
        from PIL import Image

        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(data)) as image:
                _scan_qr(image, result)
                _ocr_image(image, result)
                if getattr(image, "n_frames", 1) > 1:
                    result.gap("office_image_later_frames_not_scanned")
                    _ocr_gap(result, "office_image_later_frames_not_scanned", "limited")
    except ImportError:
        result.coverage["qr"] = "unavailable"
        result.gap("office_image_decoder_unavailable")
        _ocr_gap(result, "office_image_decoder_unavailable", "unavailable")
    except Exception:
        result.coverage["qr"] = "error"
        result.gap("office_image_decode_failed")
        _ocr_gap(result, "office_image_decode_failed", "error")


def _pdf_walk(root, result: _Extraction):
    """Inspect action/name dictionaries with bounded traversal and no stream decoding."""
    from pypdf.generic import ArrayObject, DictionaryObject, IndirectObject

    pending = [(root, 0)]
    seen = set()
    budget = result.limits["max_archive_entries"] * 10
    while pending and len(seen) < budget:
        item, depth = pending.pop()
        if isinstance(item, IndirectObject):
            identity = (item.idnum, item.generation)
            if identity in seen:
                continue
            seen.add(identity)
            item = item.get_object()
        else:
            identity = id(item)
            if identity in seen:
                continue
            seen.add(identity)
        if depth > 20:
            result.gap("pdf_object_depth_limit")
            continue
        if isinstance(item, DictionaryObject):
            if item.get("/URI"):
                result.url(str(item["/URI"]))
            action = str(item.get("/S", ""))
            if action in {"/JavaScript", "/Launch", "/SubmitForm", "/ImportData", "/GoToR", "/GoToE",
                          "/Rendition"} or "/JS" in item or "/JavaScript" in item:
                result.finding("pdf_active_action", "active_content",
                               "The PDF declares an active or external action; it was not executed. "
                               "Action presence alone does not establish maliciousness.")
            if "/EmbeddedFiles" in item or str(item.get("/Subtype", "")) == "/FileAttachment":
                result.finding("pdf_embedded_file", "embedded_content",
                               "The PDF contains an embedded-file reference; that file was not executed.")
                result.gap("pdf_embedded_files_not_recursively_inspected")
            if action in {"/SubmitForm", "/GoToR", "/ImportData"}:
                target = item.get("/F")
                if isinstance(target, DictionaryObject):
                    target = target.get("/UF") or target.get("/F")
                if target:
                    result.url(str(target))
            for index, (key, value) in enumerate(item.items()):
                if index >= budget:
                    result.gap("pdf_object_count_limit")
                    break
                if key not in {"/Parent", "/Pages", "/Resources", "/Contents", "/EF"}:
                    if isinstance(value, (DictionaryObject, ArrayObject, IndirectObject)):
                        pending.append((value, depth + 1))
        elif isinstance(item, ArrayObject):
            pending.extend((value, depth + 1) for value in item[:budget])
        if len(pending) > budget:
            result.gap("pdf_object_count_limit")
            pending = pending[:budget]
    if pending:
        result.gap("pdf_object_count_limit")


def _pdf_images(page, result: _Extraction, *, ocr=True):
    """Check declared dimensions before decoding page and nested-form XObjects."""
    pending = [(page.get("/Resources"), 0)]
    seen = set()
    while pending:
        reference, depth = pending.pop()
        if reference is None:
            continue
        resources = reference.get_object()
        identity = id(resources)
        if identity in seen:
            continue
        seen.add(identity)
        if depth > 10 or len(seen) > result.limits["max_archive_entries"]:
            result.gap("pdf_image_resource_limit")
            return
        objects = resources.get("/XObject")
        if objects is None:
            continue
        for index, reference in enumerate(objects.get_object().values()):
            if index >= result.limits["max_archive_entries"]:
                result.gap("pdf_image_resource_limit")
                return
            obj = reference.get_object()
            if obj.get("/Subtype") == "/Form":
                pending.append((obj.get("/Resources"), depth + 1))
            elif obj.get("/Subtype") == "/Image":
                if result.qr_images >= result.limits["max_qr_images"]:
                    result.coverage["qr"] = "limited"
                    result.gap("qr_image_count_limit")
                    if ocr:
                        _ocr_gap(result, "pdf_image_count_limit", "limited")
                    return
                if int(obj.get("/Width", 0)) * int(obj.get("/Height", 0)) > result.limits["max_image_pixels"]:
                    result.coverage["qr"] = "limited"
                    result.gap("image_pixel_limit")
                    if ocr:
                        _ocr_gap(result, "image_pixel_limit", "limited")
                    continue
                try:
                    image = obj.decode_as_image()
                    if image is None:
                        raise ValueError("No image")
                    with image:
                        _scan_qr(image, result)
                        if ocr:
                            _ocr_image(image, result)
                except ImportError:
                    result.coverage["qr"] = "unavailable"
                    result.gap("pdf_image_decoder_unavailable")
                    if ocr:
                        _ocr_gap(result, "pdf_image_decoder_unavailable", "unavailable")
                except Exception:
                    result.coverage["qr"] = "error"
                    result.gap("pdf_image_decode_failed")
                    if ocr:
                        _ocr_gap(result, "pdf_image_decode_failed", "error")


def _inspect_pdf(data: bytes, result: _Extraction):
    from pypdf import PdfReader

    result.coverage["actions"] = "static_metadata_only"
    result.coverage["qr"] = "not_present"
    reader = PdfReader(io.BytesIO(data), strict=True)
    if reader.is_encrypted:
        result.coverage["text"] = "not_inspected"
        result.coverage["material_content_gap"] = True
        result.gap("pdf_encrypted", "encrypted")
        return
    _pdf_walk(reader.trailer["/Root"], result)
    count = len(reader.pages)
    result.coverage["pages_total"] = count
    result.coverage["pages_seen"] = min(count, result.limits["max_document_pages"])
    if count > result.limits["max_document_pages"]:
        result.gap("pdf_page_limit")
        result.coverage["material_content_gap"] = True
    decoded = 0
    for index in range(result.coverage["pages_seen"]):
        page = reader.pages[index]
        _pdf_walk(page, result)
        page_text = ""
        try:
            content = page.get_contents()
            if content is not None:
                decoded += len(content.get_data())
            if decoded > result.limits["max_uncompressed_bytes"]:
                result.gap("pdf_decoded_content_byte_limit")
                result.coverage["material_content_gap"] = True
            else:
                page_text = page.extract_text() or ""
                result.text(page_text)
        except Exception:
            result.gap("pdf_page_text_failed")
        try:
            # For image-only pages, rendering also covers inline images and
            # composition; avoid OCRing every embedded tile a second time.
            _pdf_images(page, result, ocr=bool(page_text.strip()))
        except Exception:
            result.gap("pdf_page_image_failed")
        if not page_text.strip():
            try:
                with render_pdf_page(data, index + 1, result.ocr_budget) as image:
                    _scan_qr(image, result)
                    _ocr_image(image, result)
                result.coverage["ocr_pages_rendered"] = result.coverage.get("ocr_pages_rendered", 0) + 1
            except OCRFailure as exc:
                _ocr_gap(result, str(exc), "unavailable" if "unavailable" in str(exc) else "limited")
    result.coverage["qr_images_scanned"] = result.qr_images
    result.coverage["qr_scope"] = "embedded_xobjects_and_image_only_page_rasterization"
    result.coverage["rendering"] = "image_only_pages_local_rasterization"
    result.coverage["scope_exclusions"] = ["pdf_rendered_or_inline_image_qr_on_text_pages"]


def _inspect_ole(data: bytes, result: _Extraction):
    import olefile
    from oletools.crypto import is_encrypted
    from oletools.olevba import VBA_Parser

    result.coverage["macros"] = "vba_presence_only"
    # Encrypted OOXML is itself an OLE container. Do not mistake its opaque bytes
    # for a legacy document with no macros.
    with olefile.OleFileIO(io.BytesIO(data)) as container:
        streams = container.listdir(streams=True, storages=False)
        if any(parts[-1].lower() in {"encryptedpackage", "encryptioninfo"} for parts in streams):
            result.gap("office_encrypted_container", "encrypted")
            result.coverage["text"] = "not_inspected"
            result.coverage["material_content_gap"] = True
            return
        if len(streams) > result.limits["max_archive_entries"]:
            result.gap("office_stream_count_limit")
            return
        if sum(container.get_size(parts) for parts in streams) > result.limits["max_uncompressed_bytes"]:
            result.gap("office_stream_byte_limit")
            return
        if is_encrypted(container):
            result.gap("office_encryption_metadata", "encrypted")
            result.coverage["text"] = "not_inspected"
            result.coverage["material_content_gap"] = True
            return
        result.coverage["encryption"] = "metadata_checked"
    parser = VBA_Parser("attachment.ole", data=data, relaxed=False, disable_pcode=True)
    try:
        # Never call analyze_macros(), XLM deobfuscation/emulation, or extract p-code.
        parser.no_xlm = True
        if parser.detect_vba_macros():
            result.finding("office_vba_present", "macro_presence",
                           "Static inspection found a possible VBA project; its code was not executed and "
                           "macro presence alone does not establish maliciousness.")
    finally:
        parser.close()
    # These are explicitly container strings, not rendered/visible Office text.
    result.coverage["text_scope"] = "printable_container_strings_only"
    result.coverage["scope_exclusions"] = ["legacy_office_rendered_text", "xlm_macro_inspection"]
    for match in re.finditer(rb"[\x20-\x7e]{6,}", data):
        result.text(match.group().decode("ascii"))
        if len(result.result["text"]) >= result.limits["max_text_chars"]:
            result.gap("text_character_limit")
            result.coverage["text"] = "limited"
            break
