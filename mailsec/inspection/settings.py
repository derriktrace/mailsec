import os
from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class InspectionSettings:
    max_raw_bytes: int = 25 * 1024 * 1024
    concurrency: int = 1
    upload_timeout_seconds: float = 30
    parser_timeout_seconds: float = 25
    parser_cpu_seconds: int = 20
    parser_memory_bytes: int = 384 * 1024 * 1024
    parser_output_bytes: int = 64 * 1024 * 1024
    request_timeout_seconds: float = 90
    clamd_host: str = "clamd"
    clamd_port: int = 3310
    clamd_socket: str = ""
    clamd_timeout_seconds: float = 15
    signature_max_age_hours: float = 72
    tenant_id: str = "local"
    cache_path: str = "/var/cache/mailsec-inspection/cache.sqlite3"
    cache_ttl_seconds: int = 86400
    cache_max_entries: int = 10000
    cache_max_bytes: int = 128 * 1024 * 1024
    api_token: str = ""
    max_mime_depth: int = 12
    max_parts: int = 128
    max_attachments: int = 100
    max_archive_depth: int = 3
    max_archive_entries: int = 200
    max_uncompressed_bytes: int = 25 * 1024 * 1024
    max_file_bytes: int = 10 * 1024 * 1024
    max_compression_ratio: int = 100
    max_document_pages: int = 20
    max_text_chars: int = 20000
    max_total_text_chars: int = 100000
    max_urls: int = 500
    max_image_pixels: int = 16_000_000
    max_qr_images: int = 20
    max_ocr_images: int = 8
    max_ocr_seconds: int = 10
    max_static_decoded_bytes: int = 2 * 1024 * 1024
    max_static_payloads: int = 8

    @classmethod
    def load(cls):
        defaults = cls()
        values = {}
        for key, default in asdict(defaults).items():
            raw = os.getenv("INSPECTION_" + key.upper())
            if raw is not None:
                values[key] = type(default)(raw)
        result = cls(**values)
        if not result.tenant_id or result.concurrency < 1 or result.concurrency > 8:
            raise ValueError("Inspection requires a tenant and concurrency between 1 and 8")
        for key, value in asdict(result).items():
            if isinstance(value, (float, int)) and value <= 0:
                raise ValueError(f"Inspection setting {key} must be positive")
        if result.max_raw_bytes > 25 * 1024 * 1024:
            raise ValueError("Maximum accepted RFC message size is 25 MiB")
        return result

    def parser_limits(self):
        return {key: value for key, value in asdict(self).items()
                if key.startswith("max_") or key.startswith("parser_")}
