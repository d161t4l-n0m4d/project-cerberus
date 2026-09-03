"""SSH service enumeration (banner + auth methods)."""

from __future__ import annotations

import asyncio
from typing import Any

from cerberus.core.phase import Phase
from cerberus.core.plugin_api import OpsecLevel, Plugin, PluginMeta, register_plugin


@register_plugin
class SshEnumPlugin(Plugin):
    meta = PluginMeta(
        name="ssh_enum",
        description="Grab SSH banner and supported auth methods (ssh-keyscan / nc)",
        phase=[Phase.ENUM],
        opsec=OpsecLevel.LOW,
        requires=[],
        produces=["service"],
    )

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        target = kwargs.get("target") or self.config.rhost
        port = int(kwargs.get("port") or 22)
        if not target:
            return {"success": False, "message": "need target/rhost"}

        # Banner via timeout + nc or ssh-keyscan
        banner = ""
        proc = await asyncio.create_subprocess_exec(
            "bash", "-c",
            f"timeout 5 bash -c 'exec 3<>/dev/tcp/{target}/{port}; echo -e \"\\n\" >&3; cat <&3' 2>/dev/null | head -c 500",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        out, _ = await proc.communicate()
        banner = out.decode(errors="ignore").strip()

        if not banner:
            proc = await asyncio.create_subprocess_exec(
                "ssh-keyscan", "-T", "5", "-p", str(port), target,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            out, err = await proc.communicate()
            banner = (out.decode(errors="ignore") + err.decode(errors="ignore"))[:500]

        item = self.evidence.add(
            kind="service",
            target=target,
            data={"service": "ssh", "port": port, "banner": banner[:300]},
            source="ssh_enum",
            plugin="ssh_enum",
            confidence=0.9 if banner else 0.5,
            tags=["ssh"],
        )

        return {
            "success": bool(banner),
            "message": f"ssh {target}:{port} banner={banner[:80] or 'none'}",
            "banner": banner,
            "evidence_ids": [item.id],
        }
