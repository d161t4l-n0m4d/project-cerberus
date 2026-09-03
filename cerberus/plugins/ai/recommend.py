"""Next-action recommender — evidence + service triggers + phase hints."""

from __future__ import annotations

from typing import Any

# service name / port → suggested plugins
SERVICE_TRIGGERS: list[tuple[callable, str, str]] = []  # filled below


def _port_set(ports: list) -> set[int]:
    out = set()
    for p in ports:
        try:
            out.add(int(p.data.get("port")))
        except Exception:
            pass
    return out


def _svc_blob(services: list) -> str:
    parts = []
    for s in services:
        parts.append(str(s.data.get("service", "")).lower())
        parts.append(str(s.data.get("banner", "")).lower())
        parts.append(str(s.data.get("server", "")).lower())
    return " ".join(parts)


async def recommend_next(cfg: Any, store: Any, engine: Any, use_ollama: bool = False) -> dict:
    phase = engine.current.value if hasattr(engine.current, "value") else str(engine.current)
    rhost = cfg.rhost
    hosts = store.find(kind="host", target=rhost) if rhost else store.find(kind="host")
    ports = store.find(kind="port", target=rhost) if rhost else store.find(kind="port")
    services = store.find(kind="service", target=rhost) if rhost else store.find(kind="service")
    dirs = store.find(kind="dir", target=rhost) if rhost else []
    creds = store.find(kind="credential")
    persist = store.find(kind="persistence")

    suggestions: list[dict] = []
    port_nums = _port_set(ports)
    svc = _svc_blob(services)

    def add(action: str, plugin: str | None, reason: str, priority: int = 50) -> None:
        suggestions.append({
            "action": action,
            "plugin": plugin,
            "reason": reason,
            "priority": priority,
        })

    # --- foundation ---
    if not rhost:
        add("set rhost <target>", None, "no target configured", 100)
    elif not hosts:
        add("run ping", "ping", "no host reachability evidence", 95)
    elif not ports and phase in ("recon", "enum"):
        add("run nmap_basic", "nmap_basic", "no open ports known", 90)

    # --- service triggers (recon/enum) ---
    if ports or services:
        web_ports = port_nums & {80, 443, 8080, 8443, 8000, 8888, 3000}
        if web_ports and not any("http" in (d.data.get("url") or "") for d in dirs):
            add(
                "run http_probe",
                "http_probe",
                f"web port(s) {sorted(web_ports)} without fingerprint",
                80,
            )
            add(
                "run gobuster_dir",
                "gobuster_dir",
                f"directory enum on web port(s) {sorted(web_ports)}",
                75,
            )
        if 22 in port_nums or "ssh" in svc:
            if not any("ssh" in str(s.data.get("service", "")).lower() for s in services if s.data.get("banner")):
                add("run ssh_enum", "ssh_enum", "SSH port/service seen", 70)
        if port_nums & {139, 445} or "smb" in svc or "microsoft-ds" in svc:
            add("run smb_enum", "smb_enum", "SMB-related port/service", 70)
        if 53 in port_nums:
            add("run dns_enum", "dns_enum", "DNS port open", 55)

    # --- phase advancement ---
    if phase == "recon" and ports:
        add("phase enum", None, "ports known — advance kill-chain", 60)
    if phase == "enum" and (dirs or services) and not creds:
        add("phase exploit", None, "enum data present — consider exploit phase", 50)
    if phase in ("exploit", "privesc") and not persist:
        add("run persist_check", "persist_check", "no persistence evidence yet", 40)

    # --- post-ex if C2 likely ---
    from cerberus.core.c2 import get_c2
    from cerberus.core.c2_control import control_request

    c2 = get_c2()
    beacon_count = len(c2.beacons) if c2 else 0
    if not c2:
        # try daemon control plane
        try:
            st = await control_request("127.0.0.1", 8444, {"op": "status"}, timeout=0.5)
            if st.get("ok"):
                beacon_count = st.get("data", {}).get("beacons", 0)
                add("c2 attach (daemon live)", None, "C2 daemon reachable on :8444", 45)
        except Exception:
            pass
    if beacon_count:
        add("run c2_beacons", "c2_beacons", f"{beacon_count} beacon session(s)", 65)
        add("run cred_harvest_linux", "cred_harvest_linux", "harvest creds from active beacon", 55)
    elif phase in ("exploit", "privesc", "lateral") and rhost:
        add("run c2_start / c2-daemon", "c2_start", "no beacons — start listener", 50)
        add("run cerb_payload implant", "cerb_payload", "generate implant one-liner", 48)

    if creds and phase in ("enum", "exploit", "lateral"):
        add("run lateral_ssh / lateral_psexec", "lateral_ssh", f"{len(creds)} cred(s) available for lateral", 58)

    if not suggestions:
        add("run auto_loop", "auto_loop", f"phase={phase} hosts={len(hosts)} ports={len(ports)}", 30)

    suggestions.sort(key=lambda x: -x.get("priority", 0))
    # dedupe by plugin
    seen = set()
    uniq = []
    for s in suggestions:
        key = s.get("plugin") or s.get("action")
        if key in seen:
            continue
        seen.add(key)
        uniq.append(s)

    result: dict[str, Any] = {
        "phase": phase,
        "rhost": rhost,
        "counts": {
            "hosts": len(hosts),
            "ports": len(ports),
            "services": len(services),
            "dirs": len(dirs),
            "creds": len(creds),
            "beacons": beacon_count,
        },
        "suggestions": uniq[:8],
        "triggers": {
            "ports": sorted(port_nums),
            "svc_blob": svc[:200],
        },
    }

    if use_ollama:
        try:
            from cerberus.plugins.ai.ollama_client import ask_ollama
            ctx = (
                f"Phase={phase} target={rhost} counts={result['counts']}\n"
                f"Suggestions: {uniq[:5]}"
            )
            reply = await ask_ollama(
                cfg,
                "Recommend the single best next command and why. Be brief.",
                context=ctx,
            )
            result["ollama"] = reply
        except Exception as e:
            result["ollama_error"] = str(e)

    return result
