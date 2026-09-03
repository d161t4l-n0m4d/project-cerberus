"""Basic host reachability check."""

from __future__ import annotations

import asyncio
from typing import Any

from cerberus.core.phase import Phase
from cerberus.core.plugin_api import OpsecLevel, Plugin, PluginMeta, register_plugin


@register_plugin
class PingPlugin(Plugin):
    meta = PluginMeta(
        name="ping",
        description="ICMP reachability check against rhost",
        phase=[Phase.RECON],
        opsec=OpsecLevel.SAFE,
        requires=["rhost"],
        produces=["host"],
    )

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        target = kwargs.get("target") or self.config.rhost
        if not target:
            return {"success": False, "message": "no target (set rhost or pass target=)"}

        # Use system ping for simplicity and low dependency
        proc = await asyncio.create_subprocess_exec(
            "ping", "-c", "2", "-W", "2", target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        alive = proc.returncode == 0

        evidence_ids = []
        if alive:
            item = self.evidence.add(
                kind="host",
                target=target,
                data={"alive": True, "method": "icmp"},
                source="ping",
                plugin="ping",
                confidence=0.95,
                tags=["reachable"],
            )
            evidence_ids.append(item.id)

        return {
            "success": alive,
            "message": f"{target} is {'alive' if alive else 'unreachable'}",
            "evidence_ids": evidence_ids,
            "raw": stdout.decode(errors="ignore")[:500],
        }
