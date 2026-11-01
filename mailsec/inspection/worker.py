"""Subprocess entry point: untrusted MIME/documents never parse in the HTTP process."""

import base64
import gzip
import hashlib
import io
import json
import os
import re
import resource
import stat
import sys
import tarfile
import zipfile
from email import policy
from email.parser import BytesParser
from pathlib import PurePosixPath

from . import PARSER_VERSION
from .ocr import OCRBudget


def unsafe_archive_path(name):
    value = name.replace("\\", "/")
    path = PurePosixPath(value)
    return (not value or "\x00" in value or path.is_absolute() or ".." in path.parts
            or bool(re.match(r"^[a-zA-Z]:", value)))


def inspect_message(raw, limits, cache_context=None):
    from .documents import inspect_document

    ocr_budget = OCRBudget(limits)
    result = {"status": "complete", "findings": [], "attachments": [], "urls": [],
              "coverage": {"mime": "complete", "archives": "complete", "documents": "complete",
                           "network_fetch": "disabled", "payload_execution": "disabled", "limitations": []},
              "stats": {"mime_parts": 0, "archive_entries": 0, "expanded_bytes": 0,
                        "document_cache_hits": 0, "extracted_text_chars": 0, "attachment_payload_bytes": 0}, "parser_version": PARSER_VERSION}

    def finding(kind, ref, summary, severity="review"):
        result["status"] = "partial" if severity == "review" else result["status"]
        result["findings"].append({"id": f"{kind}:{ref}", "kind": kind, "severity": severity,
                                   "evidence_ref": ref, "summary": summary})

    def partial(section, ref, summary, kind="inspection_limit"):
        result["coverage"][section] = "partial"
        finding(kind, ref, summary)

    def urls(values):
        for value in values:
            if isinstance(value, str) and value not in result["urls"]:
                if len(result["urls"]) >= limits["max_urls"]:
                    partial("documents", "message", "URL extraction limit reached")
                    break
                result["urls"].append(value[:8192])

    def extract(data, filename, mime, ref):
        try:
            document = inspect_document(data, filename, mime, limits=limits, ocr_budget=ocr_budget)
        except Exception:
            document = {"kind": "unknown", "text": "", "urls": [], "findings": [],
                        "coverage": {"status": "invalid", "limitations": ["Document parsing failed"]}}
        if document.get("coverage", {}).get("status") != "complete":
            partial("documents", ref, "Document extraction incomplete; see per-document coverage", "document_incomplete")
        for gap in ("ocr_material_gap", "material_content_gap"):
            if document.get("coverage", {}).get(gap):
                result["coverage"][gap] = True
        for item in document.get("findings", []):
            finding(item.get("kind", "document_indicator"), ref, item.get("summary", "Document indicator"),
                    item.get("severity", "review"))
        urls(document.get("urls", []))
        text = document.get("text", "")
        remaining = max(0, limits["max_total_text_chars"] - result["stats"]["extracted_text_chars"])
        if len(text) > remaining:
            document = {**document, "text": text[:remaining]}
            document["coverage"] = {**document.get("coverage", {}), "material_content_gap": True}
            result["coverage"]["material_content_gap"] = True
            partial("documents", ref, "Aggregate extracted-text budget reached")
        result["stats"]["extracted_text_chars"] += len(document.get("text", ""))
        return document

    def archive(data, filename, depth, ref):
        if depth >= limits["max_archive_depth"]:
            partial("archives", ref, "Archive nesting limit reached")
            return
        extension = filename.rsplit(".", 1)[-1].lower()
        try:
            if data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")) or extension == "zip":
                with zipfile.ZipFile(io.BytesIO(data)) as container:
                    entries = container.infolist()
                    if len(entries) + result["stats"]["archive_entries"] > limits["max_archive_entries"]:
                        partial("archives", ref, "Archive entry-count budget exceeded")
                        return
                    for entry in entries:
                        if entry.is_dir():
                            continue
                        result["stats"]["archive_entries"] += 1
                        child = ref + "/entry-" + str(result["stats"]["archive_entries"])
                        if unsafe_archive_path(entry.filename) or stat.S_ISLNK(entry.external_attr >> 16):
                            partial("archives", child, "Unsafe archive path or symbolic link was not extracted", "archive_unsafe_path")
                            continue
                        if entry.flag_bits & 1:
                            partial("archives", child, "Encrypted archive member cannot be inspected", "encrypted_content")
                            continue
                        if entry.file_size > limits["max_file_bytes"] or entry.file_size / max(1, entry.compress_size) > limits["max_compression_ratio"]:
                            partial("archives", child, "Archive member exceeds size or compression-ratio limit")
                            continue
                        if entry.file_size + result["stats"]["expanded_bytes"] > limits["max_uncompressed_bytes"]:
                            partial("archives", child, "Aggregate archive expansion budget exceeded")
                            break
                        with container.open(entry) as stream:
                            content = stream.read(min(entry.file_size, limits["max_file_bytes"]) + 1)
                        if len(content) != entry.file_size:
                            partial("archives", child, "Archive member length does not match metadata", "archive_invalid")
                            continue
                        result["stats"]["expanded_bytes"] += len(content)
                        attachment(content, entry.filename, "application/octet-stream", depth + 1, child)
                return
            if data.startswith(b"\x1f\x8b") or extension in {"tar", "tgz", "gz"}:
                try:
                    container = tarfile.open(fileobj=io.BytesIO(data), mode="r:*")
                except tarfile.ReadError:
                    container = None
                if container is not None:
                    with container:
                        for entry in container:
                            result["stats"]["archive_entries"] += 1
                            child = ref + "/entry-" + str(result["stats"]["archive_entries"])
                            if result["stats"]["archive_entries"] > limits["max_archive_entries"]:
                                partial("archives", ref, "Archive entry-count budget exceeded")
                                break
                            if entry.isdir():
                                continue
                            if unsafe_archive_path(entry.name) or not entry.isfile():
                                partial("archives", child, "Unsafe path, link, or special archive entry was not extracted", "archive_unsafe_path")
                                continue
                            remaining = limits["max_uncompressed_bytes"] - result["stats"]["expanded_bytes"]
                            if entry.size > min(limits["max_file_bytes"], remaining):
                                partial("archives", child, "Archive expansion size budget exceeded")
                                break
                            if (result["stats"]["expanded_bytes"] + entry.size) / max(1, len(data)) > limits["max_compression_ratio"]:
                                partial("archives", child, "Archive compression-ratio limit exceeded")
                                break
                            stream = container.extractfile(entry)
                            if stream is None:
                                partial("archives", child, "Archive member unavailable", "archive_invalid")
                                continue
                            with stream:
                                content = stream.read(entry.size + 1)
                            if len(content) != entry.size:
                                partial("archives", child, "Archive member size mismatch", "archive_invalid")
                                continue
                            result["stats"]["expanded_bytes"] += len(content)
                            attachment(content, entry.name, "application/octet-stream", depth + 1, child)
                    return
                if data.startswith(b"\x1f\x8b"):
                    allowance = min(limits["max_file_bytes"], limits["max_uncompressed_bytes"] - result["stats"]["expanded_bytes"],
                                    len(data) * limits["max_compression_ratio"])
                    with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
                        content = stream.read(allowance + 1)
                    if len(content) > allowance:
                        partial("archives", ref, "Gzip expansion size or compression-ratio budget exceeded")
                        return
                    result["stats"]["archive_entries"] += 1
                    result["stats"]["expanded_bytes"] += len(content)
                    attachment(content, filename.removesuffix(".gz") or "expanded", "application/octet-stream", depth + 1, ref + "/gzip")
                    return
            partial("archives", ref, "Archive format is unsupported; content was not extracted", "archive_unsupported")
        except (ValueError, OSError, RuntimeError, EOFError, zipfile.BadZipFile, tarfile.TarError, NotImplementedError):
            partial("archives", ref, "Archive could not be safely parsed", "archive_invalid")

    def attachment(data, filename, mime, archive_depth, ref):
        if len(result["attachments"]) >= limits["max_attachments"]:
            partial("mime", ref, "Attachment count budget exceeded")
            return
        if len(data) + result["stats"]["attachment_payload_bytes"] > limits["max_uncompressed_bytes"]:
            partial("archives", ref, "Aggregate attachment-payload budget exceeded")
            return
        result["stats"]["attachment_payload_bytes"] += len(data)
        entry = {"evidence_ref": ref, "filename": filename[:1000], "content_type": mime,
                 "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                 "_payload_b64": base64.b64encode(data).decode("ascii")}
        result["attachments"].append(entry)
        extension = filename.rsplit(".", 1)[-1].lower()
        is_office = extension in {"docx", "docm", "xlsx", "xlsm", "pptx", "pptm", "odt", "ods", "odp"}
        is_archive = not is_office and (extension in {"zip", "tar", "tgz", "gz", "rar", "7z", "bz2", "xz", "iso"}
                                        or data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"\x1f\x8b", b"Rar!", b"7z\xbc\xaf")))
        if is_archive:
            entry.update(kind="archive", text="", urls=[], coverage={"status": "complete", "recursive_extraction": "bounded"})
            old = len(result["findings"])
            archive(data, filename, archive_depth, ref)
            if len(result["findings"]) > old:
                entry["coverage"]["status"] = "partial"
        elif len(data) > limits["max_file_bytes"]:
            entry.update(kind="unknown", text="", urls=[], coverage={"status": "partial", "reason": "Document size budget exceeded"})
            partial("documents", ref, "Document exceeds extraction size budget")
        else:
            entry.update(extract(data, filename, mime, ref))
            entry.pop("findings", None)

    message = BytesParser(policy=policy.default).parsebytes(raw)
    if not list(message.keys()):
        partial("mime", "message", "No RFC message headers were found", "mime_invalid")
    queue = [(message, 0, "mime/0")]
    decoded_bytes = 0
    while queue:
        part, depth, ref = queue.pop(0)
        if depth > limits["max_mime_depth"]:
            partial("mime", ref, "MIME nesting depth budget exceeded")
            continue
        result["stats"]["mime_parts"] += 1
        if result["stats"]["mime_parts"] > limits["max_parts"]:
            partial("mime", ref, "MIME part count budget exceeded")
            break
        if part.defects:
            partial("mime", ref, "Malformed MIME structure was encountered", "mime_invalid")
        defects_before_decode = len(part.defects)
        mime = part.get_content_type()
        is_attachment = bool(part.get_filename()) or part.get_content_disposition() == "attachment" or mime == "message/rfc822"
        if part.is_multipart() and mime != "message/rfc822":
            queue[0:0] = [(child, depth + 1, ref + "/" + str(index)) for index, child in enumerate(part.iter_parts())]
            continue
        if mime == "message/rfc822":
            children = part.get_payload()
            if isinstance(children, list):
                data = b"\n".join(child.as_bytes(policy=policy.default) for child in children)
                queue[0:0] = [(child, depth + 1, ref + "/message-" + str(index)) for index, child in enumerate(children)]
            else:
                data = part.get_payload(decode=True) or b""
        else:
            data = part.get_payload(decode=True) or b""
        # email's transfer decoders attach defects lazily. For example,
        # YQ==Yg== becomes only b'a' and gains a base64-character defect here.
        # Scanning that decoded prefix must never imply complete MIME coverage.
        if len(part.defects) > defects_before_decode:
            result["coverage"]["material_content_gap"] = True
            partial("mime", ref, "Ambiguous MIME transfer encoding may hide content after decoding", "mime_invalid")
        decoded_bytes += len(data)
        if decoded_bytes > limits["max_uncompressed_bytes"]:
            partial("mime", ref, "Aggregate decoded MIME budget exceeded")
            break
        if is_attachment or mime not in {"text/plain", "text/html"}:
            attachment(data, str(part.get_filename() or "unnamed"), mime, 0, ref)
        else:
            extract(data, "body.html" if mime == "text/html" else "body.txt", mime, ref)
    result["stats"]["decoded_mime_bytes"] = decoded_bytes
    return result


def main():
    from .process_policy import restrict_filesystem, restrict_parser

    restrict_parser()
    restrict_filesystem(os.environ["INSPECTION_WORKER_SCRATCH"])
    limits = json.loads(os.environ["INSPECTION_WORKER_LIMITS"])
    resource.setrlimit(resource.RLIMIT_AS, (limits["parser_memory_bytes"], limits["parser_memory_bytes"]))
    resource.setrlimit(resource.RLIMIT_CPU, (limits["parser_cpu_seconds"], limits["parser_cpu_seconds"] + 1))
    resource.setrlimit(resource.RLIMIT_FSIZE, (limits["parser_output_bytes"], limits["parser_output_bytes"]))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    os.umask(0o077)
    raw = sys.stdin.buffer.read(limits["max_raw_bytes"] + 1)
    if not raw or len(raw) > limits["max_raw_bytes"]:
        raise ValueError("Invalid raw input size")
    output = inspect_message(raw, limits)
    sys.stdout.write(json.dumps(output, ensure_ascii=True))


if __name__ == "__main__":
    main()
