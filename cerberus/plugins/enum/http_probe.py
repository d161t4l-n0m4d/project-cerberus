"""HTTP/HTTPS service fingerprinting."""

from __future__ import annotations

import asyncio
import re
from typing import Any

from cerberus.core.phase import Phase
from cerberus.core.opsec import random_ua
from cerberus.core.plugin_api import OpsecLevel, Plugin, PluginMeta, register_plugin


@register_plugin
class HttpProbePlugin(Plugin):
    meta = PluginMeta(
        name="http_probe",
        description="Probe HTTP(S) headers, title, server banner for a host/url",
        phase=[Phase.RECON, Phase.ENUM],
        opsec=OpsecLevel.LOW,
        requires=[],
        produces=["service"],
    )

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        target = kwargs.get("target") or self.config.rhost
        url = kwargs.get("url")
        port = int(kwargs.get("port") or 80)
        if not url:
            if not target:
                return {"success": False, "message": "need url= or rhost"}
            scheme = "https" if port in (443, 8443) else "http"
            url = f"{scheme}://{target}" if port in (80, 443) else f"{scheme}://{target}:{port}"

        proc = await asyncio.create_subprocess_exec(
            "curl", "-sI", "-L", "--connect-timeout", "5", "-m", "10",
            "-A", random_ua(),
            url,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        headers = stdout.decode(errors="ignore")

        # Also grab title from body (small)
        proc2 = await asyncio.create_subprocess_exec(
            "curl", "-s", "-L", "--connect-timeout", "5", "-m", "10",
            "-A", random_ua(),
            url,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        body, _ = await proc2.communicate()
        body_text = body.decode(errors="ignore")[:50000]
        title_m = re.search(r"<title[^>]*>(.*?)</title>", body_text, re.I | re.S)
        title = title_m.group(1).strip() if title_m else ""

        server = ""
        for line in headers.splitlines():
            if line.lower().startswith("server:"):
                server = line.split(":", 1)[1].strip()
                break

        data = {
            "url": url,
            "server": server,
            "title": title[:200],
            "headers_sample": headers[:1500],
        }
        item = self.evidence.add(
            kind="service",
            target=target or url,
            data={**data, "service": "http", "port": port},
            source="http_probe",
            plugin="http_probe",
            confidence=0.9,
            tags=["web", "http"],
        )

        return {
            "success": proc.returncode == 0 or bool(headers),
            "message": f"probed {url} server={server or '?'} title={title[:40] or '?'}",
            "data": data,
            "evidence_ids": [item.id],
        }
