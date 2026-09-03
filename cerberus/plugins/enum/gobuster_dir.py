"""Directory enumeration via gobuster (or fallback ffuf/curl wordlist)."""

from __future__ import annotations

import asyncio
import shutil
from pathlib import Path
from typing import Any

from cerberus.core.phase import Phase
from cerberus.core.plugin_api import OpsecLevel, Plugin, PluginMeta, register_plugin


@register_plugin
class GobusterDirPlugin(Plugin):
    meta = PluginMeta(
        name="gobuster_dir",
        description="Directory/file brute-force against a web root (gobuster preferred)",
        phase=[Phase.ENUM],
        opsec=OpsecLevel.MEDIUM,
        requires=[],
        produces=["dir"],
    )

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        target = kwargs.get("target") or self.config.rhost
        url = kwargs.get("url")
        if not url:
            if not target:
                return {"success": False, "message": "need url= or rhost"}
            # Prefer https if stealth is ninja? default http
            port = kwargs.get("port") or 80
            scheme = "https" if int(port) in (443, 8443) else "http"
            if int(port) in (80, 443):
                url = f"{scheme}://{target}/"
            else:
                url = f"{scheme}://{target}:{port}/"

        wordlist = kwargs.get("wordlist") or self.config.dirwordlist
        if not Path(wordlist).exists():
            # fallback common paths
            for candidate in (
                "/usr/share/wordlists/dirb/common.txt",
                "/usr/share/seclists/Discovery/Web-Content/common.txt",
                "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
            ):
                if Path(candidate).exists():
                    wordlist = candidate
                    break

        threads = 20 if self.config.stealth != "ninja" else 5
        evidence_ids: list[str] = []

        gobuster = shutil.which("gobuster")
        if gobuster:
            cmd = [
                gobuster, "dir",
                "-u", url,
                "-w", wordlist,
                "-t", str(threads),
                "-q",
                "--no-error",
            ]
            if self.config.stealth == "ninja":
                cmd += ["--delay", "200ms"]

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            output = stdout.decode(errors="ignore")
            found = []
            for line in output.splitlines():
                line = line.strip()
                if not line or line.startswith("="):
                    continue
                # gobuster: /admin (Status: 200) [Size: 1234]
                if "(Status:" in line or line.startswith("/"):
                    path = line.split()[0]
                    found.append(line)
                    item = self.evidence.add(
                        kind="dir",
                        target=target or url,
                        data={"url": url.rstrip("/") + path if path.startswith("/") else path, "raw": line},
                        source="gobuster_dir",
                        plugin="gobuster_dir",
                        confidence=0.85,
                        tags=["web"],
                    )
                    evidence_ids.append(item.id)

            return {
                "success": proc.returncode == 0 or bool(found),
                "message": f"gobuster found {len(found)} path(s) on {url}",
                "found": found[:50],
                "evidence_ids": evidence_ids,
            }

        # Fallback: tiny built-in wordlist probe with httpx-style curl
        small = ["admin", "login", "api", "robots.txt", "sitemap.xml", ".git/HEAD", "backup", "wp-admin"]
        found = []
        for path in small:
            test_url = url.rstrip("/") + "/" + path
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                "--connect-timeout", "3", "-m", "5", test_url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            out, _ = await proc.communicate()
            code = out.decode().strip()
            if code and code not in ("000", "404"):
                found.append(f"{path} -> {code}")
                item = self.evidence.add(
                    kind="dir",
                    target=target or url,
                    data={"url": test_url, "status": code},
                    source="gobuster_dir",
                    plugin="gobuster_dir",
                    confidence=0.7,
                    tags=["web"],
                )
                evidence_ids.append(item.id)

        return {
            "success": True,
            "message": f"fallback probe found {len(found)} path(s) (install gobuster for full enum)",
            "found": found,
            "evidence_ids": evidence_ids,
        }
