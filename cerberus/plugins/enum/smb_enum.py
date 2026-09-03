"""SMB null-session / share listing (smbclient)."""

from __future__ import annotations

import asyncio
from typing import Any

from cerberus.core.phase import Phase
from cerberus.core.plugin_api import OpsecLevel, Plugin, PluginMeta, register_plugin


@register_plugin
class SmbEnumPlugin(Plugin):
    meta = PluginMeta(
        name="smb_enum",
        description="List SMB shares (null session) via smbclient",
        phase=[Phase.ENUM],
        opsec=OpsecLevel.MEDIUM,
        requires=[],
        produces=["service"],
    )

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        target = kwargs.get("target") or self.config.rhost
        if not target:
            return {"success": False, "message": "need target/rhost"}

        proc = await asyncio.create_subprocess_exec(
            "smbclient", "-L", f"//{target}", "-N", "-g",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        output = stdout.decode(errors="ignore") + stderr.decode(errors="ignore")

        shares = []
        for line in output.splitlines():
            # Disk|IPC$|...
            if "|" in line and not line.startswith("WARNING"):
                parts = line.split("|")
                if len(parts) >= 2:
                    shares.append({"type": parts[0], "name": parts[1]})

        item = self.evidence.add(
            kind="service",
            target=target,
            data={"service": "smb", "port": 445, "shares": shares, "raw": output[:1000]},
            source="smb_enum",
            plugin="smb_enum",
            confidence=0.85 if shares else 0.4,
            tags=["smb"],
        )

        return {
            "success": proc.returncode == 0 or bool(shares),
            "message": f"smb {target}: {len(shares)} share(s)",
            "shares": shares,
            "evidence_ids": [item.id],
        }
