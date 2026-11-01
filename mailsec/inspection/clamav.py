"""Minimal bounded clamd VERSION/INSTREAM client for a private local service."""

import re
import socket
import struct
import time
from datetime import datetime, timezone


class ClamAV:
    def __init__(self, settings):
        self.settings = settings

    def _connect(self):
        if self.settings.clamd_socket:
            connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            connection.settimeout(self.settings.clamd_timeout_seconds)
            try:
                connection.connect(self.settings.clamd_socket)
            except OSError:
                connection.close()
                raise
            return connection
        return socket.create_connection((self.settings.clamd_host, self.settings.clamd_port),
                                        timeout=self.settings.clamd_timeout_seconds)

    def _exchange(self, command, data=None):
        deadline = time.monotonic() + self.settings.clamd_timeout_seconds
        with self._connect() as connection:
            def timeout():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("clamd deadline")
                connection.settimeout(remaining)
            timeout()
            connection.sendall(command)
            if data is not None:
                for offset in range(0, len(data), 65536):
                    chunk = data[offset:offset + 65536]
                    timeout()
                    connection.sendall(struct.pack("!I", len(chunk)) + chunk)
                timeout()
                connection.sendall(b"\0\0\0\0")
            reply = bytearray()
            while len(reply) < 8192:
                timeout()
                chunk = connection.recv(min(4096, 8192 - len(reply)))
                if not chunk:
                    break
                reply.extend(chunk)
                if b"\0" in chunk:
                    break
            if b"\0" not in reply:
                raise ValueError("Unterminated or oversized clamd reply")
            return bytes(reply).split(b"\0", 1)[0].decode("utf-8", errors="replace")

    def version(self):
        result = {"status": "unavailable", "engine_version": None, "signature_version": None,
                  "signature_timestamp": None, "signature_age_hours": None, "signatures_current": False}
        try:
            text = self._exchange(b"zVERSION\0")
            match = re.fullmatch(r"ClamAV ([^/\s]+)/([0-9]+)/(.+)", text.strip())
            if not match:
                return {**result, "reason": "Unrecognized or unavailable clamd version metadata"}
            engine, signature, timestamp = match.groups()
            result.update(engine_version=engine, signature_version=signature)
            try:
                parsed = datetime.strptime(timestamp.strip(), "%a %b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
                age = (datetime.now(timezone.utc) - parsed).total_seconds() / 3600
                current = -1 <= age <= self.settings.signature_max_age_hours
                result.update(signature_timestamp=parsed.isoformat(), signature_age_hours=round(age, 3),
                              signatures_current=current, status="ready" if current else "stale",
                              signature_timestamp_timezone_assumption="UTC; run clamd with TZ=UTC")
            except ValueError:
                result.update(status="stale", reason="Signature build time could not be established")
            return result
        except (OSError, ValueError):
            return {**result, "reason": "Local clamd is unavailable or returned invalid version metadata"}

    def scan(self, data, metadata):
        result = {**metadata, "status": "unavailable", "scan_completed": False,
                  "malware_signature": None, "scan_method": "clamd_instream"}
        try:
            reply = self._exchange(b"zINSTREAM\0", data)
        except (OSError, ValueError):
            return {**result, "reason": "Local antivirus scan unavailable or interrupted"}
        if reply == "stream: OK":
            current = metadata.get("signatures_current", False)
            return {**result, "status": "clean" if current else "stale", "scan_completed": True,
                    "reason": "No signature detection" if current else "No detection, but current signatures could not be established"}
        match = re.fullmatch(r"stream: (.{1,500}) FOUND", reply)
        if match:
            signature = match.group(1)
            if signature.startswith(("Heuristics.", "PUA.")):
                return {**result, "status": "error", "review_signature": signature,
                        "detection_type": "heuristic_review", "reason": "Heuristic, encrypted-content, limit, or unwanted-application alert requires review"}
            return {**result, "status": "malicious", "scan_completed": True,
                    "malware_signature": signature, "detection_type": "signature"}
        return {**result, "status": "error", "reason": "Antivirus returned a scan error or unsupported response"}
