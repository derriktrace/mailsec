"""Bounded, offline RFC 5322/MIME decomposition. Nothing here executes content."""

from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import re
from email import policy
from email.errors import HeaderParseError
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses, parsedate_to_datetime
from urllib.parse import urlsplit, urlunsplit

import tldextract

from mailsec.html_visibility import extract_html, material_image_gap

PARSER_VERSION = "mime-v3.4"
MAX_RAW_BYTES = 25 * 1024 * 1024
MAX_BODY_CHARS = 40_000
MAX_TEXT_SOURCE_CHARS = 2_000_000
MAX_PARTS = 256
# Stop construction itself, before the later evidence traversal limit applies.
# Otherwise a small email with thousands of empty MIME parts allocates all of
# them inside the standard-library parser before MAX_PARTS can protect us.
MAX_PARSED_PARTS = 1024
MAX_HEADERS_PER_PART = 500
MAX_PARSED_HEADERS = 4000
MAX_LINKS = 200
MAX_ATTACHMENTS = 100
MAX_HEADER_CHARS = 8_192
_PSL = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True)
_URL = re.compile(r"\b(?:https?://|www\.)[^\s<>\"']+", re.I)
_EXECUTABLES = {"exe", "com", "scr", "dll", "msi", "bat", "cmd", "ps1", "sh", "vbs", "js", "jse", "wsf", "hta", "lnk", "app", "dmg", "iso"}
_SCRIPTS = {"bat", "cmd", "ps1", "sh", "vbs", "js", "jse", "wsf", "hta", "py", "pl"}
_OFFICE = {"doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt", "pptx", "pptm", "rtf"}
_ARCHIVES = {"zip", "rar", "7z", "gz", "tar", "bz2", "xz", "iso"}
_SHORTENERS = {"bit.ly", "t.co", "tinyurl.com", "is.gd", "ow.ly", "buff.ly", "goo.gl", "lnkd.in"}
_TRANSFER_DECODING_DEFECTS = {
    "InvalidBase64CharactersDefect", "InvalidBase64PaddingDefect", "InvalidBase64LengthDefect",
}
_BASE64_ENCODED_WORD = re.compile(r"=\?[^?\r\n]*\?[bB]\?")
_ENCODED_WORD_MATERIAL_HEADERS = {
    "subject", "from", "sender", "reply-to", "return-path", "to", "cc", "bcc",
    "message-id", "content-type", "content-disposition", "content-id", "date",
}


def _encoded_word_defects(value: str) -> set[str]:
    """Validate bounded RFC 2047 words before the permissive header decoder.

    HeaderRegistry can silently discard defects on unstructured fields such as
    Subject. Inspect the original encoded words, including attachment parameter
    values, instead of trusting the decoded string or header.defects.
    """
    defects = set()
    value = value[:MAX_HEADER_CHARS]
    position = 0
    while match := _BASE64_ENCODED_WORD.search(value, position):
        end = value.find("?=", match.end())
        if end < 0:
            # An incomplete word is already malformed; no content beyond the
            # bounded header prefix may be decoded to validate it.
            defects.add("InvalidBase64CharactersDefect")
            break
        encoded = value[match.end():end]
        position = end + 2
        try:
            base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error):
            if len(encoded.rstrip("=")) % 4 == 1:
                defects.add("InvalidBase64LengthDefect")
            elif len(encoded) % 4:
                defects.add("InvalidBase64PaddingDefect")
            else:
                defects.add("InvalidBase64CharactersDefect")
    return defects


def normalize_domain(domain: str) -> str:
    """ASCII IDNA hostname; never equate a suffix with its parent label."""
    value = domain.strip().strip("[]").rstrip(".").lower()
    if not value:
        return ""
    try:
        return ipaddress.ip_address(value).compressed
    except ValueError:
        pass
    try:
        return value.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return value


def root_domain(domain: str) -> str:
    host = normalize_domain(domain)
    if not host:
        return ""
    try:
        return ipaddress.ip_address(host).compressed
    except ValueError:
        pass
    parsed = _PSL(host)
    # Unknown suffixes stay exact: do not infer an organizational boundary.
    return parsed.top_domain_under_public_suffix or host


def _addresses(values: list[str]) -> list[tuple[str, str]]:
    try:
        addresses = getaddresses(values, strict=False)
    except (TypeError, ValueError):
        addresses = []
    return [(name.strip(), address.strip().lower()) for name, address in addresses if address]


def _address_domain(address: str) -> str:
    return normalize_domain(address.rsplit("@", 1)[-1]) if "@" in address else ""


def _clean_text(value: str) -> str:
    # Collapse formatting whitespace without changing words, URLs or Unicode controls.
    value = value.replace("\r\n", "\n").replace("\x00", "")
    value = "\n".join(re.sub(r"[^\S\n]+", " ", line).strip() for line in value.split("\n"))
    return re.sub(r"\n{3,}", "\n\n", value).strip()


def _safe_evidence_unicode(value, quality):
    """Raw email bytes remain preserved; derived JSON must be valid Unicode.

    email.raw_items() can expose malformed header bytes using surrogateescape.
    PostgreSQL JSON and UTF-8 reports cannot retain lone surrogate codepoints.
    """
    if isinstance(value, str):
        if re.search(r"[\ud800-\udfff]", value):
            quality["decoding_replacement"] = True
            return re.sub(r"[\ud800-\udfff]", "\ufffd", value)
    elif isinstance(value, dict):
        for key in value:
            value[key] = _safe_evidence_unicode(value[key], quality)
    elif isinstance(value, list):
        for index in range(len(value)):
            value[index] = _safe_evidence_unicode(value[index], quality)
    return value


def _decode(part, quality: dict) -> str:
    payload = part.get_payload(decode=True)
    if payload is None:
        value = part.get_payload()
        return value if isinstance(value, str) else ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="strict")
    except (LookupError, UnicodeError):
        quality["decoding_replacement"] = True
        try:
            return payload.decode(charset, errors="replace")
        except LookupError:
            return payload.decode("utf-8", errors="replace")


def _link(raw: str, display: str, source: str) -> dict:
    raw = raw.strip()[:MAX_HEADER_CHARS]
    parse_value = "https://" + raw if raw.lower().startswith("www.") else raw
    try:
        parsed = urlsplit(parse_value)
        host = normalize_domain(parsed.hostname or "")
        scheme = parsed.scheme.lower()
        port = parsed.port
        host_netloc = f"[{host}]" if ":" in host else host
        netloc = host_netloc + (f":{port}" if port else "")
        if parsed.username is not None:
            netloc = parsed.netloc  # Retain deceptive userinfo in the evidence.
        normalized = urlunsplit((scheme, netloc, parsed.path or ("/" if host else ""), parsed.query, parsed.fragment))
        malformed = not bool(scheme) or (scheme in {"http", "https"} and not host)
        userinfo = parsed.username is not None
    except ValueError:
        host, scheme, normalized, malformed, userinfo = "", "", raw, True, False
    try:
        ipaddress.ip_address(host)
        ip_literal = True
    except ValueError:
        ip_literal = False
    display_matches = list(_URL.finditer(display))
    displayed_domain = ""
    if display_matches:
        try:
            shown = display_matches[0].group().rstrip(".,;!?)")
            displayed_domain = root_domain(urlsplit("https://" + shown if shown.startswith("www.") else shown).hostname or "")
        except ValueError:
            pass
    return {
        "display_text": display[:1000], "raw_url": raw, "normalized_url": normalized,
        "source": source, "scheme": scheme, "domain": host, "root_domain": root_domain(host),
        "displayed_domain": displayed_domain or None,
        "display_domain_mismatch": bool(displayed_domain and host and displayed_domain != root_domain(host)),
        "has_userinfo": userinfo, "is_shortener": root_domain(host) in _SHORTENERS,
        "is_ip_literal": ip_literal, "contains_punycode": "xn--" in host,
        "malformed": malformed, "redirect_chain": [], "final_domain": None,
        "reputation": "unknown", "scan_status": "not_scanned", "affirmatively_malicious": False,
    }


def _attachment(part) -> dict:
    filename = str(part.get_filename() or "")[:1000]
    payload = part.get_payload(decode=True)
    if payload is None:
        payload = part.as_bytes(policy=policy.default)
    extension = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    declared = part.get_content_type()
    magic = None
    for signature, mime in (
        (b"%PDF-", "application/pdf"), (b"PK\x03\x04", "application/zip"),
        (b"\x1f\x8b", "application/gzip"), (b"Rar!", "application/vnd.rar"),
        (b"7z\xbc\xaf\x27\x1c", "application/x-7z-compressed"),
        (b"MZ", "application/x-dosexec"), (b"\x7fELF", "application/x-elf"),
        (b"\xd0\xcf\x11\xe0", "application/x-ole-storage"),
        (b"\x89PNG\r\n\x1a\n", "image/png"), (b"\xff\xd8\xff", "image/jpeg"),
        (b"GIF8", "image/gif"),
    ):
        if payload.startswith(signature):
            magic = mime
            break
    return {
        "filename": filename or None, "declared_mime_type": declared, "detected_mime_type": magic,
        "extension": extension or None, "size": len(payload), "sha256": hashlib.sha256(payload).hexdigest(),
        "filename_contains_bidi_controls": any(character in filename for character in "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"),
        "multiple_filename_extensions": filename.count(".") > 1,
        "inline": part.get_content_disposition() == "inline", "content_id": str(part.get("Content-ID", ""))[:1000] or None,
        "archive": extension in _ARCHIVES or magic in {"application/zip", "application/gzip", "application/vnd.rar", "application/x-7z-compressed"},
        "password_protected": None, "executable": extension in _EXECUTABLES or magic in {"application/x-dosexec", "application/x-elf"},
        "script": extension in _SCRIPTS, "office": extension in _OFFICE,
        "macro_capable_extension": extension in {"docm", "xlsm", "pptm", "doc", "xls", "ppt"},
        "pdf": extension == "pdf" or magic == "application/pdf", "html": extension in {"html", "htm", "shtml"} or declared == "text/html",
        "scan_status": "static_metadata_only", "affirmatively_malicious": False,
        "limitations": ["No antivirus scan, archive extraction, macro inspection, or execution was performed."],
    }


def parse_email(raw: bytes, *, mailbox: str = "", provider: str = "eml", provider_message_id: str | None = None,
                provider_thread_id: str | None = None, received_at: str | None = None) -> dict:
    provided_received_at = received_at is not None
    if not isinstance(raw, bytes) or not raw:
        raise ValueError("A nonempty RFC email byte string is required")
    if len(raw) > MAX_RAW_BYTES:
        raise ValueError("Email exceeds the 25 MiB parsing limit")
    budget = {"parts": 0, "headers": 0, "headers_truncated": False, "header_transfer_defects": set()}

    class BoundedMessage(EmailMessage):
        def __init__(self, *args, **kwargs):
            budget["parts"] += 1
            if budget["parts"] > MAX_PARSED_PARTS:
                raise ValueError("Email MIME structure exceeds parsing limits")
            super().__init__(*args, **kwargs)

        def set_raw(self, name, value):
            budget["headers"] += 1
            if len(self._headers) >= MAX_HEADERS_PER_PART or budget["headers"] > MAX_PARSED_HEADERS:
                raise ValueError("Email header count exceeds parsing limits")
            if len(value) > MAX_HEADER_CHARS:
                budget["headers_truncated"] = True
            # Arbitrary metadata and raw transport/auth fields are not decoded
            # as identity/content evidence; their syntax must not invent a
            # consequential content gap for an otherwise readable message.
            if name.lower() in _ENCODED_WORD_MATERIAL_HEADERS:
                budget["header_transfer_defects"].update(_encoded_word_defects(value))
            super().set_raw(name, value)

    def bounded_header(name, value):
        # Structured address/header decoding can be expensive. Keep the original
        # bytes in local storage, but never decode an unbounded header as evidence.
        return policy.default.header_factory(name, value[:MAX_HEADER_CHARS])

    msg = BytesParser(policy=policy.default.clone(
        message_factory=BoundedMessage, header_factory=bounded_header)).parsebytes(raw)
    raw_sha256 = hashlib.sha256(raw).hexdigest()
    quality = {
        "body_truncated": False, "links_truncated": False, "attachments_truncated": False,
        "parts_truncated": False, "headers_truncated": budget["headers_truncated"], "decoding_replacement": False,
        "mime_defects": sorted(budget["header_transfer_defects"]),
        "missing_body": False, "transfer_decoding_ambiguous": False,
    }
    def headers(name):
        try:
            return [str(value) for value in msg.get_all(name, [])]
        except (AttributeError, IndexError, ValueError, TypeError, HeaderParseError):
            # Python's structured header parser can reject malformed address
            # groups. Do not invent an address or discard the rest of the mail.
            quality['header_parse_failed'] = True
            quality.setdefault('unparsed_headers', []).append(name)
            return []
    subjects, from_headers = headers('Subject'), headers('From')
    quality.update(missing_subject=not any(subjects),missing_sender=not any(from_headers),
                   multiple_from_headers=len(from_headers)>1)
    raw_headers = []
    for index, (key, value) in enumerate(msg.raw_items()):
        if index >= 500:
            quality["headers_truncated"] = True
            break
        if len(value) > MAX_HEADER_CHARS:
            quality["headers_truncated"] = True
        # Only transport/auth fields are needed later; arbitrary headers aren't adjudication evidence.
        if key.lower() in {"received", "authentication-results", "received-spf", "dkim-signature", "arc-authentication-results", "sender"}:
            raw_headers.append({"index": index, "name": key.lower(), "value": value[:MAX_HEADER_CHARS]})
    senders = _addresses(from_headers)
    name, address = senders[0] if senders else ("", "")
    quality["multiple_from_addresses"] = len(senders) > 1
    domain = _address_domain(address)
    quality["invalid_sender_address"] = not bool(address and "@" in address and domain)
    reply = _addresses(headers('Reply-To'))
    returns = _addresses(headers('Return-Path'))
    recipients = _addresses([value for header in ('To','Cc','Bcc') for value in headers(header)])
    dates = headers('Date')
    if not received_at and dates:
        try:
            received_at = parsedate_to_datetime(dates[0]).isoformat()
        except (TypeError, ValueError, OverflowError):
            pass
    plain_parts: list[str] = []
    html_parts: list[str] = []
    html_evidence: list[dict] = []
    links: list[dict] = []
    attachments: list[dict] = []
    parts = [msg]
    count = 0
    source_remaining = MAX_TEXT_SOURCE_CHARS
    while parts:
        part = parts.pop(0)
        count += 1
        if count > MAX_PARTS:
            quality["parts_truncated"] = True
            break
        quality["mime_defects"].extend(type(defect).__name__ for defect in part.defects)
        mime = part.get_content_type()
        is_attachment = part.get_content_disposition() == "attachment" or bool(part.get_filename()) or mime == "message/rfc822"
        if part.is_multipart() and not is_attachment:
            parts[0:0] = list(part.iter_parts())
            continue
        if is_attachment or mime not in {"text/plain", "text/html"}:
            if len(attachments) >= MAX_ATTACHMENTS:
                quality["attachments_truncated"] = True
            else:
                attachments.append(_attachment(part))
                # Transfer decoding adds defects lazily. Record them after
                # decoding attachments as well as text, including hidden tails
                # after a padded base64 block.
                quality["mime_defects"].extend(type(defect).__name__ for defect in part.defects)
            continue
        text = _decode(part, quality)
        quality["mime_defects"].extend(type(defect).__name__ for defect in part.defects)
        # Bound source work separately from visible text: HTML templates can
        # contain >40k of CSS before the first meaningful word or action link.
        if len(text) > source_remaining:
            quality["body_truncated"] = True
            quality["text_source_truncated"] = True
        text = text[:source_remaining]
        source_remaining -= len(text)
        if mime == "text/html":
            extracted = extract_html(text)
            html_evidence.append(extracted)
            html_parts.append(extracted["visible_text"])
            links.extend(extracted["links"])
            for field, visibility, quoted in (("visible_text", "visible", False), ("hidden_text", "hidden", False), ("quoted_text", "visible", True)):
                links.extend({"raw_url": match.group().rstrip(".,;!?)"), "display_text": match.group().rstrip(".,;!?)"),
                              "source": "html_text", "visibility": visibility, "quoted_context": quoted}
                             for match in _URL.finditer(extracted[field]))
        else:
            plain_parts.append(_clean_text(text))
            links.extend({"raw_url": match.group().rstrip(".,;!?)"), "display_text": match.group().rstrip(".,;!?)"),
                          "source": "plain_text", "visibility": "plain_alternative", "quoted_context": False}
                         for match in _URL.finditer(text))
    plain = "\n\n".join(plain_parts)
    html_visible = "\n\n".join(html_parts)
    hidden = "\n\n".join(part["hidden_text"] for part in html_evidence)
    quoted = "\n\n".join(part["quoted_text"] for part in html_evidence)
    alternatives_differ = bool(plain and html_evidence and re.sub(r"\s+", " ", plain) != re.sub(r"\s+", " ", html_visible))
    # HTML is the usual rendered MIME alternative. Keep different plain text as
    # separately identified evidence, never let hidden HTML filler replace CTAs.
    body = html_visible if html_evidence else plain
    if alternatives_differ:
        body += "\n\n[Plain-text MIME alternative; rendering may differ]\n" + plain
    if quoted:
        body += "\n\n[Quoted history, not necessarily the current sender's request]\n" + quoted
    if len(body) > MAX_BODY_CHARS:
        quality["body_truncated"] = True
    body = body[:MAX_BODY_CHARS]
    quality["missing_body"] = not bool(body.strip())
    visibility_limits = sorted({limit for part in html_evidence for limit in part["limits"]})
    # Responsive email CSS is routinely conditional. Report uncertainty, but
    # materiality requires substantial content that could be hidden or a bound.
    uncertain_hiding = any(part["unsupported_hiding"] for part in html_evidence)
    visibility_uncertainties = sorted({reason for part in html_evidence for reason in part["visibility_uncertainties"]})
    material_visibility_gap = bool(visibility_limits or (set(visibility_uncertainties) - {"conditional_visibility"} and len(html_visible) > 1000))
    quality["content_visibility_incomplete"] = material_visibility_gap
    quality["mime_defects"] = sorted(set(quality["mime_defects"]))
    quality["transfer_decoding_ambiguous"] = bool(
        _TRANSFER_DECODING_DEFECTS.intersection(quality["mime_defects"]))
    unique_links: list[dict] = []
    seen = set()
    action_sources = {"html_anchor", "plain_text", "html_text", "html_form_action", "html_button_formaction", "html_input_formaction"}
    # Current visible actions precede quoted/hidden filler and passive resources.
    links.sort(key=lambda item: (item.get("visibility") in {"hidden", "noncontent"}, item.get("quoted_context", False), item["source"] not in action_sources))
    for item in links:
        url, display, source = item["raw_url"], item["display_text"], item["source"]
        key = (url, display, item.get("visibility"), item.get("quoted_context", False))
        if key in seen:
            continue
        seen.add(key)
        if len(unique_links) >= MAX_LINKS:
            quality["links_truncated"] = True
            break
        if len(url) > MAX_HEADER_CHARS:
            quality["links_truncated"] = True
        link = _link(url, display, source)
        link.update({key: item[key] for key in ("visibility", "quoted_context", "image_context") if key in item})
        unique_links.append(link)
    images = [image for part in html_evidence for image in part["images"]][:200]
    image_content = {"visible_text": html_visible, "images": images, "links": links}
    remote_image_gap = material_image_gap(image_content, schemes=("https://", "http://"))
    inline_image_gap = material_image_gap(image_content, schemes=("data:",))
    visibility_findings = sorted({finding for part in html_evidence for finding in part["findings"]})
    if alternatives_differ:
        visibility_findings.append("html_plain_alternatives_differ")
    evidence = {
        "schema_version": "evidence-v1", "parser_version": PARSER_VERSION,
        "message": {
            "id": raw_sha256, "raw_sha256": raw_sha256, "provider": provider,
            "provider_message_id": provider_message_id, "provider_thread_id": provider_thread_id,
            "mailbox": mailbox.lower(), "direction": "inbound", "subject": (subjects or [''])[0][:2000],
            "internet_message_id": (headers('Message-ID') or [''])[0][:MAX_HEADER_CHARS] or None,
            "received_at": received_at, "received_at_source": "provider" if provided_received_at and provider == "gmail" else "message_header_or_import",
            "sender": {"display_name": name[:1000], "address": address, "domain": domain, "root_domain": root_domain(domain)},
            "reply_to": reply[0][1] if reply else None, "reply_to_addresses": [a for _, a in reply],
            "return_path": returns[0][1] if returns else None, "recipients": list(dict.fromkeys(a for _, a in recipients)),
        },
        "authentication": {"status": "not_evaluated", "spf": "unknown", "dkim": "unknown", "dmarc": "unknown", "transport_headers": raw_headers},
        "identity": {}, "organization_context": {},
        "content": {
            "extraction_method": "bounded_static_html_visibility", "has_plain_body": bool(plain),
            "has_html_body": bool(html_evidence), "semantic_extraction": "not_run",
            "visible_text": (html_visible if html_evidence else plain)[:200_000],
            "plain_alternative": plain[:200_000] if alternatives_differ else "",
            "hidden_text": hidden[:40_000], "quoted_text": quoted[:200_000],
            "text_counts": {"visible": len(html_visible if html_evidence else plain), "plain_alternative": len(plain) if alternatives_differ else 0,
                            "hidden": len(hidden), "quoted": len(quoted)},
            "visibility": {"method": "offline_supported_css_subset", "findings": visibility_findings,
                           "limits": visibility_limits, "unsupported_hiding": uncertain_hiding,
                           "uncertainties": visibility_uncertainties,
                           "material_remote_image_gap": remote_image_gap,
                           "material_inline_image_gap": inline_image_gap,
                           "hidden_text_truncated": len(hidden) > 40_000,
                           "source_text_truncated": any(len(value) > 200_000 for value in (html_visible, plain, quoted)),
                           "images": images},
        },
        "body": body, "links": unique_links, "attachments": attachments, "quality": quality,
        "threat_intelligence": {"status": "not_configured", "affirmative_malicious_url": False, "affirmative_malicious_attachment": False},
    }
    return _safe_evidence_unicode(evidence, quality)
