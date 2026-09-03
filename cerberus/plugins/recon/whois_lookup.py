"""WHOIS lookup for IP or domain."""

from __future__ import annotations

import asyncio
from typing import Any

from cerberus.core.phase import Phase
from cerberus.core.plugin_api import OpsecLevel, Plugin, PluginMeta, register_plugin


@register_plugin
class WhoisPlugin(Plugin):
    meta = PluginMeta(
        name="whois",
        description="WHOIS lookup for rhost/domain",
        phase=[Phase.RECON],
        opsec=OpsecLevel.SAFE,
        requires=[],
        produces=["host"],
    )

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        target = kwargs.get("target") or self.config.domain or self.config.rhost
        if not target:
            return {"success": False, "message": "need target"}

        proc = await asyncio.create_subprocess_exec(
            "whois", target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        text = stdout.decode(errors="ignore")[:4000]

        item = self.evidence.add(
            kind="host",
            target=target,
            data={"whois": text[:2000]},
            source="whois",
            plugin="whois",
            confidence=0.8,
            tags=["osint"],
            notes="whois raw",
        )

        return {
            "success": proc.returncode == 0 or bool(text),
            "message": f"whois {target} ({len(text)} bytes)",
            "preview": text[:500],
            "evidence_ids": [item.id],
        }
