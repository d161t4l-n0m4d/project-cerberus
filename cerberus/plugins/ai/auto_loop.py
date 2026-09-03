"""Basic autonomous loop (v0.1).

Runs a simple sequence of plugins based on current phase and evidence.
Later versions will use Ollama + policy + detection oracle.
"""

from __future__ import annotations

from typing import Any

from cerberus.core.phase import Phase
from cerberus.core.plugin_api import OpsecLevel, Plugin, PluginMeta, get_plugin, register_plugin


@register_plugin
class AutoLoopPlugin(Plugin):
    meta = PluginMeta(
        name="auto_loop",
        description="Basic autonomous loop: ping → nmap_basic when evidence is missing",
        phase=[Phase.RECON, Phase.ENUM],
        opsec=OpsecLevel.MEDIUM,
        requires=["rhost"],
        produces=["host", "port", "service"],
    )

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        target = kwargs.get("target") or self.config.rhost
        if not target:
            return {"success": False, "message": "no target"}

        results = []
        max_steps = kwargs.get("max_steps", 3)

        # Step 1: ensure host is alive
        hosts = self.evidence.find(kind="host", target=target)
        if not hosts:
            ping_cls = get_plugin("ping")
            if ping_cls:
                ping = ping_cls(self.config, self.evidence, self.phase)
                r = await ping.run(target=target)
                results.append(("ping", r))
                if not r.get("success"):
                    return {
                        "success": False,
                        "message": f"target {target} unreachable — aborting auto_loop",
                        "steps": results,
                    }

        # Step 2: basic port scan if no ports known
        ports = self.evidence.find(kind="port", target=target)
        if not ports and max_steps >= 2:
            nmap_cls = get_plugin("nmap_basic")
            if nmap_cls:
                nmap = nmap_cls(self.config, self.evidence, self.phase)
                r = await nmap.run(target=target)
                results.append(("nmap_basic", r))

        return {
            "success": True,
            "message": f"auto_loop completed {len(results)} step(s) on {target}",
            "steps": [(name, r.get("message")) for name, r in results],
        }
