"""Independent antivirus and subprocess extraction; positive detections survive gaps."""

import base64
import hashlib
import json
import os
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
from dataclasses import replace
from pathlib import Path

from . import PARSER_VERSION
from .cache import Cache, cache_key
from .clamav import ClamAV
from .process_policy import isolation_status

RESPONSE_BYTES = 480 * 1024


def bound_response(result):
    """Keep a hard detection deliverable even when optional extraction is large.

    ASCII-escaped JSON is an upper bound on the HTTP serializer's UTF-8 bytes.
    Omitted URLs remain a coverage gap; individual URLs are never shortened into
    different destinations. The last fallback aggregates repetitive findings.
    """
    def size():
        return len(json.dumps(result, ensure_ascii=True, separators=(",", ":")).encode())
    if size() <= RESPONSE_BYTES:
        return result
    reason = "Response budget exceeded; extracted detail was omitted, antivirus findings retained"
    result["status"] = "partial"
    result.setdefault("coverage", {}).update(response="partial")
    result["coverage"].setdefault("limitations", []).append(reason)
    if any(entry.get("text") for entry in result.get("attachments", [])):
        result["coverage"]["material_content_gap"] = True
    result.setdefault("stats", {})["response_truncated"] = True
    result.setdefault("findings", []).append({"id": "response_limit:message", "kind": "inspection_limit",
        "severity": "review", "evidence_ref": "message", "summary": reason})
    for entry in result.get("attachments", []):
        if entry.get("text") or entry.get("urls") or entry.get("findings"):
            entry.update(text="", urls=[], findings=[])
            entry.setdefault("coverage", {}).update(response_detail_omitted=True)
    urls = result.get("urls", [])
    if size() > RESPONSE_BYTES and urls:
        low, high = 0, len(urls)
        while low < high:
            middle = (low + high + 1) // 2
            result["urls"] = urls[:middle]
            # Reserve bytes for the omitted count added after this search.
            if size() <= RESPONSE_BYTES - 128:
                low = middle
            else:
                high = middle - 1
        result["urls"] = urls[:low]
        result["stats"]["response_urls_omitted"] = len(urls) - low
    if size() <= RESPONSE_BYTES:
        return result

    # Large attachment names or repetitive document indicators must not crowd out
    # the independent AV conclusion. Keep each finding category and its count,
    # preserving all normal bounded scan signatures before optional indicators.
    def clip(value, budget):
        value = str(value)
        low, high = 0, min(len(value), budget)
        while low < high:
            middle = (low + high + 1) // 2
            if len(json.dumps(value[:middle], ensure_ascii=True)) <= budget:
                low = middle
            else:
                high = middle - 1
        return value[:low]

    def compact_av(value):
        keys = ("status", "engine_version", "signature_version", "signature_timestamp", "signature_age_hours",
                "signatures_current", "signature_stable_during_inspection", "scan_completed", "scan_method",
                "malware_signature", "review_signature", "objects_scanned", "objects_total")
        return {key: (clip(value[key], 512) if isinstance(value[key], str) else value[key])
                for key in keys if key in value and isinstance(value[key], (str, bool, int, float, type(None)))}
    groups = {}
    for item in result["findings"]:
        key = (clip(item.get("kind", "indicator"), 128), clip(item.get("severity", "review"), 32),
               clip(item.get("signature", ""), 512))
        if key not in groups:
            groups[key] = {"id": "aggregate:" + str(len(groups)), "kind": key[0], "severity": key[1],
                "evidence_ref": "message", "summary": clip(item.get("summary", "Inspection finding"), 512),
                "count": 0, "sample_evidence_refs": []}
            if key[2]:
                groups[key]["signature"] = key[2]
        group = groups[key]
        group["count"] += 1
        ref = clip(item.get("evidence_ref", "message"), 128)
        if len(group["sample_evidence_refs"]) < 3 and ref not in group["sample_evidence_refs"]:
            group["sample_evidence_refs"].append(ref)
    grouped = sorted(groups.values(), key=lambda item: item["severity"] != "critical")
    # Parser limits permit at most 101 distinct AV object hits. The generous cap
    # also bounds a malformed internal response; aggregate AV status is retained.
    core = {"status": "partial", "parser_version": PARSER_VERSION, "raw_sha256": clip(result.get("raw_sha256", ""), 128),
        "antivirus": compact_av(result.get("antivirus", {})), "findings": grouped[:128],
        "attachments": [], "urls": [], "coverage": {"response": "partial", "network_fetch": "disabled",
            "payload_execution": "disabled", "material_content_gap": True, "limitations": [reason]},
        "stats": {"response_truncated": True, "response_findings_aggregated": len(result["findings"]),
            "response_finding_groups_omitted": max(0, len(grouped) - 128),
            "response_attachments_omitted": len(result.get("attachments", [])),
            "response_urls_omitted": len(urls)}}
    return core


def parser_failure(reason):
    return {"status": "partial", "findings": [{"id": "parser_incomplete:message", "kind": "parser_incomplete",
            "severity": "review", "evidence_ref": "message", "summary": reason}], "attachments": [], "urls": [],
            "coverage": {"mime": "unavailable", "archives": "unavailable", "documents": "unavailable",
                         "network_fetch": "disabled", "payload_execution": "disabled", "limitations": [reason]}, "stats": {}}


def run_parser(raw, settings, cache_context=None):
    # Persistent cache access belongs only to the HTTP parent. A compromised
    # native decoder must not read other messages or poison future AV cache hits.
    environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
                   "PYTHONDONTWRITEBYTECODE": "1", "PYTHONNOUSERSITE": "1",
                   "INSPECTION_WORKER_LIMITS": json.dumps(settings.parser_limits())}
    package_root = str(Path(__file__).resolve().parents[2])
    with tempfile.TemporaryDirectory(prefix="mailsec-parser-") as scratch, tempfile.TemporaryFile() as output:
        environment.update(TMPDIR=scratch, HOME=scratch, INSPECTION_WORKER_SCRATCH=scratch)
        process = None
        try:
            process = subprocess.Popen([sys.executable, "-B", "-m", "mailsec.inspection.worker"],
                stdin=subprocess.PIPE, stdout=output, stderr=subprocess.DEVNULL,
                env=environment, cwd=package_root, start_new_session=True)
            try:
                process.communicate(input=raw, timeout=settings.parser_timeout_seconds)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate()
                return parser_failure("Document parser exceeded its wall-clock limit")
            if process.returncode != 0:
                return parser_failure("Document parser failed or exceeded a resource limit")
            output.seek(0)
            encoded = output.read(settings.parser_output_bytes + 1)
            if len(encoded) > settings.parser_output_bytes:
                return parser_failure("Document parser exceeded its response budget")
            result = json.loads(encoded)
            if not isinstance(result, dict) or not isinstance(result.get("attachments"), list):
                return parser_failure("Document parser returned an invalid response")
            return result
        except (OSError, ValueError):
            return parser_failure("Document parser is unavailable or returned invalid output")
        finally:
            # A native decoder can fork. Reap the whole process group even after
            # the direct parser exits normally so background descendants cannot
            # outlive their job or keep its scratch files open indefinitely.
            if process is not None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass


class Inspector:
    def __init__(self, settings, antivirus=None, parser=None):
        self.settings = settings
        self.antivirus = antivirus or ClamAV(settings)
        self.parser = parser or run_parser
        try:
            self.cache = Cache(settings.cache_path, settings.cache_ttl_seconds, settings.cache_max_entries, settings.cache_max_bytes)
        except (OSError, ValueError, sqlite3.Error):
            self.cache = None

    def health(self):
        """Read clamd VERSION only; readiness never claims a successful scan."""
        antivirus = self.antivirus
        if isinstance(antivirus, ClamAV):
            antivirus = ClamAV(replace(self.settings, clamd_timeout_seconds=min(1.5, self.settings.clamd_timeout_seconds)))
        try:
            metadata = antivirus.version()
        except Exception:
            metadata = {"status": "unavailable", "signatures_current": False}
        isolation = isolation_status()
        antivirus_ready = bool(metadata.get("signatures_current") and metadata.get("engine_version")
                               and metadata.get("signature_version"))
        ready = antivirus_ready and isolation['status'] == 'ready'
        unavailable = 'parser_isolation_unavailable' if antivirus_ready else metadata.get('status', 'unavailable')
        return {"status": "ready" if ready else unavailable, "ready": ready, 'parser_isolation': isolation,
                "parser_version": PARSER_VERSION, "antivirus": metadata, "scan_performed": False,
                "scope": "local_static_inspection", "max_raw_bytes": self.settings.max_raw_bytes}

    def inspect(self, raw):
        started = time.monotonic()
        deadline = started + self.settings.request_timeout_seconds
        def bounded_antivirus():
            if isinstance(self.antivirus, ClamAV):
                return ClamAV(replace(self.settings, clamd_timeout_seconds=min(self.settings.clamd_timeout_seconds,
                            max(.01, deadline - time.monotonic()))))
            return self.antivirus
        metadata = bounded_antivirus().version()
        identity = [metadata.get("engine_version"), metadata.get("signature_version")]
        content_hash = hashlib.sha256(raw).hexdigest()
        full_key = cache_key(self.settings.tenant_id, "message", content_hash, *identity,
                             self.settings.parser_limits())
        if self.cache and metadata.get("signatures_current"):
            cached = self.cache.get(full_key)
            if cached is not None:
                cached["stats"]["message_cache_hit"] = True
                cached["stats"]["elapsed_seconds"] = round(time.monotonic() - started, 3)
                cached["antivirus"].update({key: metadata[key] for key in ("signature_age_hours", "signatures_current") if key in metadata})
                return bound_response(cached)
        raw_av = bounded_antivirus().scan(raw, metadata)
        context = None
        if self.cache:
            context = {"path": self.settings.cache_path, "ttl": self.settings.cache_ttl_seconds,
                       "max_entries": self.settings.cache_max_entries, "max_bytes": self.settings.cache_max_bytes,
                       "tenant": self.settings.tenant_id,
                       "engine": identity[0], "signature": identity[1]}
        try:
            parser_settings = replace(self.settings, parser_timeout_seconds=min(self.settings.parser_timeout_seconds,
                                      max(.01, deadline - time.monotonic())))
            result = self.parser(raw, parser_settings, context)
        except Exception:
            result = parser_failure("Document extraction failed")
        result["parser_version"] = PARSER_VERSION
        result["raw_sha256"] = content_hash
        result.setdefault("findings", [])
        result.setdefault("coverage", {})
        result.setdefault("stats", {})
        result["stats"].update(raw_bytes=len(raw), attachment_cache_hits=0,
                                message_cache_hit=False, cache_available=self.cache is not None)
        all_av = [("message", raw_av)]
        for entry in result.get("attachments", []):
            payload = entry.pop("_payload_b64", None)
            if payload is None:
                entry["antivirus"] = {"status": "unavailable", "scan_completed": False,
                                       "reason": "Attachment bytes unavailable"}
                all_av.append((entry["evidence_ref"], entry["antivirus"]))
                continue
            if time.monotonic() >= deadline:
                entry["antivirus"] = {"status": "unavailable", "scan_completed": False,
                                       "reason": "Total inspection deadline reached"}
                all_av.append((entry["evidence_ref"], entry["antivirus"]))
                continue
            try:
                data = base64.b64decode(payload, validate=True)
                if len(data) > self.settings.max_raw_bytes or hashlib.sha256(data).hexdigest() != entry["sha256"]:
                    raise ValueError("Attachment integrity mismatch")
            except (ValueError, KeyError):
                entry["antivirus"] = {"status": "error", "scan_completed": False,
                                       "reason": "Attachment extraction integrity check failed"}
                all_av.append((entry["evidence_ref"], entry["antivirus"]))
                continue
            key = cache_key(self.settings.tenant_id, "attachment_av", entry["sha256"], *identity,
                            self.settings.parser_limits())
            scanned = self.cache.get(key) if self.cache and metadata.get("signatures_current") else None
            if scanned is None:
                scanned = bounded_antivirus().scan(data, metadata)
                if self.cache and metadata.get("signatures_current") and scanned["status"] in {"clean", "malicious"}:
                    self.cache.put(key, scanned)
            else:
                result["stats"]["attachment_cache_hits"] += 1
                scanned["cache_hit"] = True
            entry["antivirus"] = scanned
            all_av.append((entry["evidence_ref"], scanned))
        after = bounded_antivirus().version()
        signature_stable = identity == [after.get("engine_version"), after.get("signature_version")]
        if not signature_stable or not after.get("signatures_current"):
            for _, scanned in all_av:
                if scanned.get("status") == "clean":
                    scanned.update(status="stale", signatures_current=False,
                                   reason="Antivirus database changed or freshness became unavailable during inspection")
        for ref, scanned in all_av:
            if scanned.get("status") == "malicious":
                result["findings"].append({"id": "antivirus_signature:" + ref, "kind": "antivirus_signature",
                    "severity": "critical", "evidence_ref": ref,
                    "summary": "ClamAV detected a malware signature", "signature": scanned.get("malware_signature")})
            elif scanned.get("review_signature"):
                result["findings"].append({"id": "antivirus_heuristic:" + ref, "kind": "antivirus_heuristic",
                    "severity": "review", "evidence_ref": ref,
                    "summary": "Antivirus heuristic or inspection-limit alert requires review", "signature": scanned["review_signature"]})
        priorities = {"malicious": 5, "error": 4, "unavailable": 3, "stale": 2, "clean": 1}
        worst = max((scan for _, scan in all_av), key=lambda value: priorities.get(value.get("status"), 3))
        result["antivirus"] = {**worst, "raw_message": raw_av,
            "objects_scanned": sum(scan.get("scan_completed", False) for _, scan in all_av),
            "objects_total": len(all_av), "signature_stable_during_inspection": signature_stable,
            "limitations": ["Signature scanning is not proof that a message is safe.",
                            "clamd must be configured to alert on encrypted content and scan limits."]}
        result["coverage"]["antivirus"] = "complete" if all(scan.get("status") in {"clean", "malicious"} for _, scan in all_av) else "partial"
        if result["coverage"]["antivirus"] != "complete" or result.get("status") != "complete":
            result["status"] = "partial"
        if result["coverage"].get("mime") == "unavailable" and raw_av["status"] == "unavailable":
            result["status"] = "unavailable"
        result["stats"]["elapsed_seconds"] = round(time.monotonic() - started, 3)
        result["coverage"]["scope"] = "Bounded local signature scanning and static extraction; no remote fetch or payload execution"
        result = bound_response(result)
        if self.cache and signature_stable and after.get("signatures_current") and result["status"] == "complete":
            self.cache.put(full_key, result)
        return result
