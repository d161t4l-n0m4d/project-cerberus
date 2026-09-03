"""Lightweight nmap wrapper (top ports + version)."""

from __future__ import annotations

import asyncio
import re
from typing import Any

from cerberus.core.phase import Phase
from cerberus.core.plugin_api import OpsecLevel, Plugin, PluginMeta, register_plugin


@register_plugin
class NmapBasicPlugin(Plugin):
    meta = PluginMeta(
        name="nmap_basic",
        description="Fast nmap: top 1000 ports + service version detection",
        phase=[Phase.RECON, Phase.ENUM],
        opsec=OpsecLevel.MEDIUM,
        requires=["rhost"],
        produces=["port", "service"],
    )

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        target = kwargs.get("target") or self.config.rhost
        if not target:
            return {"success": False, "message": "no target"}

        # Respect stealth profile
        timing = "-T3"
        if self.config.stealth == "ninja":
            timing = "-T2"
        elif self.config.stealth == "noisy":
            timing = "-T4"

        cmd = [
            "nmap", "-sV", "--top-ports", "1000", timing,
            "-oX", str(self.config.sessions_dir / f"scan_{target}.xml"),
            target,
        ]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        output = stdout.decode(errors="ignore")

        evidence_ids = []
        # Very naive port parsing from text output (real version would parse XML)
        for match in re.finditer(r"(\d+)/(tcp|udp)\s+open\s+(\S+)", output):
            port, proto, service = match.groups()
            item = self.evidence.add(
                kind="port",
                target=target,
                data={"port": int(port), "proto": proto, "state": "open", "service": service},
                source="nmap_basic",
                plugin="nmap_basic",
                confidence=0.9,
            )
            evidence_ids.append(item.id)

            self.evidence.add(
                kind="service",
                target=target,
                data={"port": int(port), "service": service},
                source="nmap_basic",
                plugin="nmap_basic",
                confidence=0.85,
            )

        return {
            "success": proc.returncode == 0,
            "message": f"nmap finished on {target}",
            "evidence_ids": evidence_ids,
            "ports_found": len(evidence_ids),
        }
