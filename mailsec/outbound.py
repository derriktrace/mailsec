"""Bound fixed-provider responses before parsing or decompressing their bodies."""
from __future__ import annotations

import time

import httpx


def bounded_response(client, method, url, *, max_bytes, total_seconds, **kwargs):
    """Read raw chunks with a byte cap and an elapsed-time budget.

    Socket timeouts still bound the currently outstanding read. Checking every
    raw chunk also stops a peer that keeps the socket alive with small writes.
    Never decode compressed data before applying a memory bound.
    """
    headers = dict(kwargs.pop("headers", {}) or {})
    headers["Accept-Encoding"] = "identity"
    deadline = time.monotonic() + total_seconds
    with client.stream(method, url, headers=headers, **kwargs) as response:
        if response.headers.get("content-encoding", "identity").strip().lower() != "identity":
            raise ValueError("Provider returned unsupported compressed content")
        try:
            length = int(response.headers.get("content-length", "0"))
        except ValueError:
            raise ValueError("Provider returned an invalid content length") from None
        if length < 0 or length > max_bytes:
            raise ValueError("Provider response exceeds the permitted byte limit")
        body = bytearray()
        chunks = (response.content,) if response.is_stream_consumed else response.iter_raw()
        for chunk in chunks:
            if time.monotonic() > deadline:
                raise httpx.ReadTimeout("Provider exceeded the response time budget")
            if len(body) + len(chunk) > max_bytes:
                raise ValueError("Provider response exceeds the permitted byte limit")
            body.extend(chunk)
        if time.monotonic() > deadline:
            raise httpx.ReadTimeout("Provider exceeded the response time budget")
        return httpx.Response(response.status_code, headers=response.headers, content=bytes(body))
