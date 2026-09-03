"""DNS reconnaissance (A, MX, NS, TXT)."""

from __future__ import annotations

import asyncio
from typing import Any

from cerberus.core.phase import Phase
from cerberus.core.plugin_api import OpsecLevel, Plugin, PluginMeta, register_plugin


@register_plugin
class DnsEnumPlugin(Plugin):
    meta = PluginMeta(
        name="dns_enum",
        description="Basic DNS lookup (A/AAAA/MX/NS/TXT) for domain or rhost hostname",
        phase=[Phase.RECON],
        opsec=OpsecLevel.SAFE,
        requires=[],
        produces=["host"],
    )

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        domain = kwargs.get("domain") or kwargs.get("target") or self.config.domain or self.config.rhost
        if not domain:
            return {"success": False, "message": "need domain= or config.domain/rhost"}

        records: dict[str, list[str]] = {}
        for rtype in ("A", "AAAA", "MX", "NS", "TXT"):
            proc = await asyncio.create_subprocess_exec(
                "dig", "+short", rtype, domain,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            out, _ = await proc.communicate()
            lines = [l.strip() for l in out.decode(errors="ignore").splitlines() if l.strip()]
            if lines:
                records[rtype] = lines

        evidence_ids = []
        for ip in records.get("A", []) + records.get("AAAA", []):
            item = self.evidence.add(
                kind="host",
                target=ip,
                data={"domain": domain, "records": records},
                source="dns_enum",
                plugin="dns_enum",
                confidence=0.95,
                tags=["dns"],
            )
            evidence_ids.append(item.id)

        if not evidence_ids:
            item = self.evidence.add(
                kind="host",
                target=domain,
                data={"domain": domain, "records": records},
                source="dns_enum",
                plugin="dns_enum",
                confidence=0.6,
                tags=["dns"],
            )
            evidence_ids.append(item.id)

        return {
            "success": bool(records),
            "message": f"dns {domain}: { {k: len(v) for k, v in records.items()} }",
            "records": records,
            "evidence_ids": evidence_ids,
        }
