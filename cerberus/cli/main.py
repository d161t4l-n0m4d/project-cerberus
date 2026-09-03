"""Cerberus CLI entry point (Typer + Rich)."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from cerberus.core.config import Config, load_config, save_config
from cerberus.core.evidence import EvidenceStore
from cerberus.core.phase import Phase, PhaseEngine
from cerberus.core.plugin_api import discover_plugins, get_plugin, list_plugins

app = typer.Typer(
    name="cerberus",
    help="Cerberus — Elite Red Team Framework",
    no_args_is_help=True,
)
console = Console()


def get_runtime() -> tuple[Config, EvidenceStore, PhaseEngine]:
    cfg = load_config()
    cfg.ensure_dirs()
    store = EvidenceStore(cfg.sessions_dir)
    phase = PhaseEngine(Phase(cfg.phase) if cfg.phase else Phase.RECON)
    return cfg, store, phase


@app.command()
def version() -> None:
    """Show version."""
    console.print("[bold cyan]Cerberus[/] v0.1.0 — Elite Red Team Framework")


@app.command()
def wizard() -> None:
    """Guided first-run configuration."""
    cfg = load_config()
    console.print(Panel.fit("[bold]Cerberus Setup Wizard[/]", border_style="cyan"))

    rhost = typer.prompt("Target (rhost)", default=cfg.rhost or "")
    lhost = typer.prompt("Attacker IP (lhost)", default=cfg.lhost)
    stealth = typer.prompt("Stealth profile (noisy/balanced/ninja)", default=cfg.stealth)

    cfg.rhost = rhost
    cfg.lhost = lhost
    cfg.stealth = stealth
    cfg.ensure_dirs()
    save_config(cfg)

    console.print("[green]✓ Configuration saved to cerberus.json[/]")
    console.print(f"  rhost  = {cfg.rhost}")
    console.print(f"  lhost  = {cfg.lhost}")
    console.print(f"  stealth = {cfg.stealth}")


@app.command("set")
def set_config(
    key: str = typer.Argument(..., help="Config key"),
    value: str = typer.Argument(..., help="Value"),
) -> None:
    """Set a configuration value."""
    cfg = load_config()
    if not hasattr(cfg, key):
        console.print(f"[red]Unknown key: {key}[/]")
        raise typer.Exit(1)
    # simple type coercion
    current = getattr(cfg, key)
    if isinstance(current, int):
        value = int(value)  # type: ignore
    elif isinstance(current, bool):
        value = value.lower() in ("1", "true", "yes")  # type: ignore
    setattr(cfg, key, value)
    save_config(cfg)
    console.print(f"[green]✓ {key} = {value}[/]")


@app.command()
def show() -> None:
    """Show current configuration."""
    cfg = load_config()
    table = Table(title="Cerberus Config")
    table.add_column("Key", style="cyan")
    table.add_column("Value")
    for k, v in cfg.model_dump().items():
        table.add_row(k, str(v))
    console.print(table)


@app.command()
def phase(
    new_phase: Optional[str] = typer.Argument(None, help="Phase to enter"),
    force: bool = typer.Option(False, "--force", "-f"),
) -> None:
    """Show or change current kill-chain phase."""
    cfg, _, engine = get_runtime()
    if new_phase is None:
        prog = engine.progress()
        console.print(f"Current phase: [bold]{prog['current']}[/]")
        console.print(f"Completed: {', '.join(prog['completed']) or '—'}")
        return

    try:
        target = Phase(new_phase)
        engine.advance(target, force=force)
        cfg.phase = target.value
        save_config(cfg)
        console.print(f"[green]✓ Phase → {target.value}[/]")
    except ValueError as e:
        console.print(f"[red]{e}[/]")
        raise typer.Exit(1)


@app.command("plugins")
def list_plugins_cmd() -> None:
    """List registered plugins."""
    discover_plugins()
    metas = list_plugins()
    if not metas:
        console.print("[yellow]No plugins discovered yet.[/]")
        return
    table = Table(title="Plugins")
    table.add_column("Name", style="cyan")
    table.add_column("Phase")
    table.add_column("OPSEC")
    table.add_column("Description")
    for m in sorted(metas, key=lambda x: x.name):
        table.add_row(
            m.name,
            ", ".join(p.value for p in m.phase),
            m.opsec.value,
            m.description[:60],
        )
    console.print(table)


@app.command()
def run(
    plugin_name: str = typer.Argument(..., help="Plugin to run"),
    target: Optional[str] = typer.Option(None, "--target", "-t"),
    beacon: Optional[str] = typer.Option(None, "--beacon", "-b", help="Beacon ID (C2)"),
    cmd: Optional[str] = typer.Option(None, "--cmd", "-c", help="Shell command / prompt"),
    port: Optional[int] = typer.Option(None, "--port", "-p", help="Port"),
    url: Optional[str] = typer.Option(None, "--url", "-u", help="URL for web plugins"),
    wordlist: Optional[str] = typer.Option(None, "--wordlist", "-w"),
    prompt: Optional[str] = typer.Option(None, "--prompt", help="Prompt for ollama_ask"),
    path: Optional[str] = typer.Option(None, "--path", help="Remote path (ls/cat/download)"),
    local: Optional[str] = typer.Option(None, "--local", help="Local file path (upload)"),
    remote: Optional[str] = typer.Option(None, "--remote", help="Remote dest path (upload)"),
    label: Optional[str] = typer.Option(None, "--label", help="Session label"),
    user: Optional[str] = typer.Option(None, "--user", help="Username for lateral/creds"),
    password: Optional[str] = typer.Option(None, "--password", help="Password"),
    hash: Optional[str] = typer.Option(None, "--hash", help="NT hash"),
    domain: Optional[str] = typer.Option(None, "--domain", help="AD domain"),
    pubkey: Optional[str] = typer.Option(None, "--pubkey", help="SSH public key"),
    payload: Optional[str] = typer.Option(None, "--payload", help="Persistence payload"),
    force: bool = typer.Option(False, "--force", "-f", help="Bypass phase/OPSEC gates"),
) -> None:
    """Run a plugin (phase + OPSEC gates enforced unless --force)."""
    from cerberus.core.gates import evaluate_gates

    discover_plugins()
    cls = get_plugin(plugin_name)
    if not cls:
        console.print(f"[red]Unknown plugin: {plugin_name}[/]")
        console.print("Use [cyan]cerberus plugins[/] to list available plugins.")
        raise typer.Exit(1)

    cfg, store, engine = get_runtime()
    ok, gate_msgs = evaluate_gates(cls.meta, engine, cfg, force=force)
    if not ok:
        for m in gate_msgs:
            console.print(f"[red]✗ {m}[/]")
        raise typer.Exit(2)
    for m in gate_msgs:
        console.print(f"[yellow]! {m}[/]")

    plugin = cls(cfg, store, engine)

    missing = plugin.check_requirements()
    if missing:
        console.print(f"[red]Missing config: {', '.join(missing)}[/]")
        raise typer.Exit(1)


    kwargs: dict = {}
    if target:
        kwargs["target"] = target
    if beacon:
        kwargs["beacon"] = beacon
    if cmd:
        kwargs["cmd"] = cmd
        kwargs["prompt"] = cmd  # alias for ollama_ask
    if prompt:
        kwargs["prompt"] = prompt
    if port is not None:
        kwargs["port"] = port
    if url:
        kwargs["url"] = url
    if wordlist:
        kwargs["wordlist"] = wordlist
    if path:
        kwargs["path"] = path
    if local:
        kwargs["local"] = local
    if remote:
        kwargs["remote"] = remote
    if label:
        kwargs["label"] = label
    if user:
        kwargs["user"] = user
    if password:
        kwargs["password"] = password
    if hash:
        kwargs["hash"] = hash
    if domain:
        kwargs["domain"] = domain
    if pubkey:
        kwargs["pubkey"] = pubkey
    if payload:
        kwargs["payload"] = payload
        kwargs["cmd"] = payload



    console.print(f"[cyan]→ Running {plugin_name}...[/]")
    result = asyncio.run(plugin.run(**kwargs))

    if result.get("success"):
        console.print(f"[green]✓ {result.get('message', 'done')}[/]")
    else:
        console.print(f"[red]✗ {result.get('message', 'failed')}[/]")

    if result.get("evidence_ids"):
        console.print(f"  Evidence: {len(result['evidence_ids'])} item(s) stored")

    if result.get("reply"):
        console.print(Panel(str(result["reply"])[:3000], title="Ollama", border_style="magenta"))

    if result.get("suggestions"):
        for s in result["suggestions"]:
            console.print(f"  → {s.get('action')}  ({s.get('reason')})")

    if result.get("found"):
        for f in result["found"][:20]:
            console.print(f"  {f}")

    if result.get("records"):
        console.print(result["records"])


    # Pretty-print beacons / results when present
    if "beacons" in result:
        table = Table(title="Beacons")
        table.add_column("ID")
        table.add_column("Remote")
        table.add_column("Host")
        table.add_column("User")
        table.add_column("OS")
        table.add_column("Age")
        table.add_column("Conn")
        for b in result["beacons"]:
            table.add_row(
                b["id"][:12],
                b["remote"],
                b.get("hostname", ""),
                b.get("user", ""),
                (b.get("os") or "")[:20],
                str(b.get("age", "")),
                "●" if b.get("connected") else "○",
            )
        console.print(table)

    if "results" in result and result["results"]:
        for r in result["results"][-5:]:
            console.print(Panel(
                str(r.get("output") or r)[:2000],
                title=r.get("cmd", "result"),
                border_style="blue",
            ))



@app.command()
def sitrep() -> None:
    """Situation report from evidence store."""
    cfg, store, engine = get_runtime()
    s = store.sitrep()
    prog = engine.progress()

    console.print(Panel.fit(
        f"[bold]Phase[/]  {prog['current']}\n"
        f"[bold]Hosts[/]  {s['host_count']}\n"
        f"[bold]Evidence files[/]  {s['evidence_files']}\n"
        f"[bold]Updated[/]  {s.get('updated_at', '—')}",
        title="Cerberus SITREP",
        border_style="green",
    ))


@app.command()
def evidence(
    kind: Optional[str] = typer.Option(None, "--kind", "-k"),
    target: Optional[str] = typer.Option(None, "--target", "-t"),
) -> None:
    """Query evidence store."""
    _, store, _ = get_runtime()
    items = store.find(kind=kind, target=target)
    if not items:
        console.print("[yellow]No matching evidence.[/]")
        return
    table = Table(title="Evidence")
    table.add_column("ID", style="dim")
    table.add_column("Kind")
    table.add_column("Target")
    table.add_column("Confidence")
    table.add_column("Source")
    for item in items[:50]:
        table.add_row(
            item.id[:8],
            item.kind,
            item.target,
            f"{item.provenance.confidence:.2f}",
            item.provenance.source,
        )
    console.print(table)


# ─── Cerberus-named  operator commands ───────────────────────────────


def _run_named(plugin_name: str, **kwargs: object) -> None:
    discover_plugins()
    cls = get_plugin(plugin_name)
    if not cls:
        console.print(f"[red]Plugin missing: {plugin_name}[/]")
        raise typer.Exit(1)
    cfg, store, engine = get_runtime()
    result = asyncio.run(cls(cfg, store, engine).run(**kwargs))
    if result.get("success"):
        console.print(f"[green]✓ {result.get('message', 'done')}[/]")
    else:
        console.print(f"[red]✗ {result.get('message', 'failed')}[/]")
    # pretty extras
    for key in ("notes", "pivots", "tasks", "loot", "scans", "hits", "log", "payloads"):
        if key in result and result[key]:
            data = result[key]
            if isinstance(data, list):
                for row in data[:30]:
                    console.print(f"  {row}")
            elif isinstance(data, dict):
                for k, v in data.items():
                    console.print(f"  [cyan]{k}[/]: {v}")
    if result.get("payload"):
        console.print(Panel(str(result["payload"]), title="payload", border_style="yellow"))
    if result.get("listener"):
        console.print(f"[cyan]listener:[/] {result['listener']}")
    if result.get("ctx"):
        console.print(result["ctx"])
    if result.get("surface"):
        for host, info in list(result["surface"].items())[:30]:
            console.print(f"  [bold]{host}[/] ports={info.get('ports')} svc={info.get('services')}")


@app.command()
def ctx() -> None:
    """One-line operator context ( ctx → cerb_ctx)."""
    _run_named("cerb_ctx")


@app.command()
def note(
    text: Optional[str] = typer.Argument(None, help="Note text; omit to list"),
    all_targets: bool = typer.Option(False, "--all", "-a"),
) -> None:
    """Capture or list operator notes ( note → cerb_note)."""
    kwargs: dict = {}
    if text:
        kwargs["text"] = text
        kwargs["cmd"] = text
    if all_targets:
        kwargs["all"] = True
    _run_named("cerb_note", **kwargs)


@app.command()
def loot() -> None:
    """Unified credentials table ( l00t → cerb_loot)."""
    _run_named("cerb_loot")


@app.command()
def pivot(
    ip: Optional[str] = typer.Argument(None, help="New pivot IP; omit to list chain"),
    note_text: Optional[str] = typer.Argument(None, help="Optional note"),
) -> None:
    """Record pivot target or show chain ( pivot → cerb_pivot)."""
    kwargs: dict = {}
    if ip:
        kwargs["target"] = ip
    if note_text:
        kwargs["prompt"] = note_text
    _run_named("cerb_pivot", **kwargs)


@app.command()
def tasks(
    action: Optional[str] = typer.Argument(None, help="list | add <text> | start <id> | done <id> | all"),
) -> None:
    """Task queue ( tasks → cerb_tasks)."""
    _run_named("cerb_tasks", cmd=action or "list")


@app.command()
def scans(
    host: Optional[str] = typer.Argument(None, help="Filter by host or 'rhost'"),
) -> None:
    """List scan artefacts ( scans → cerb_scans)."""
    _run_named("cerb_scans", target=host)


@app.command()
def tgrep(
    pattern: str = typer.Argument(..., help="Regex/string to search session artefacts"),
) -> None:
    """Search notes/creds/logs ( tgrep → cerb_tgrep)."""
    _run_named("cerb_tgrep", cmd=pattern)


@app.command()
def engage(
    target: Optional[str] = typer.Argument(None, help="Target IP (defaults to rhost)"),
) -> None:
    """Auto recon→enum kill-chain on target ( engage → cerb_engage)."""
    _run_named("cerb_engage", target=target)


@app.command()
def surface() -> None:
    """Network surface from evidence ( surface → cerb_surface)."""
    _run_named("cerb_surface")


@app.command()
def payload(
    kind: str = typer.Argument("bash", help="bash|python|nc|nce|powershell|implant|all"),
    port: Optional[int] = typer.Option(None, "--port", "-p"),
) -> None:
    """Generate reverse-shell / implant one-liners ( reverse_shell/msfvenom)."""
    _run_named("cerb_payload", cmd=kind, port=port)


@app.command()
def revshell(
    kind: str = typer.Argument("bash", help="bash|python"),
    port: Optional[int] = typer.Option(None, "--port", "-p"),
) -> None:
    """Listener + reverse shell pair ( reverse_shell → cerb_revshell)."""
    _run_named("cerb_revshell", cmd=kind, port=port)


@app.command("c2-daemon")
def c2_daemon(
    host: str = typer.Option("0.0.0.0", "--host"),
    port: Optional[int] = typer.Option(None, "--port", "-p"),
    ctrl_port: int = typer.Option(8444, "--ctrl-port"),
) -> None:
    """Start long-lived C2 daemon (data plane + localhost control plane)."""
    from cerberus.core.c2_daemon import run_daemon

    cfg, _, _ = get_runtime()
    console.print(
        f"[cyan]Starting C2 daemon data=:{port or cfg.c2_port} control=127.0.0.1:{ctrl_port}[/]"
    )
    asyncio.run(
        run_daemon(
            c2_host=host,
            c2_port=port or cfg.c2_port,
            ctrl_port=ctrl_port,
            secret=getattr(cfg, "c2_key", None),
        )
    )


@app.command("c2-status")
def c2_status(
    ctrl_port: int = typer.Option(8444, "--ctrl-port"),
) -> None:
    """Query C2 daemon control plane status."""
    from cerberus.core.c2_control import control_request

    resp = asyncio.run(control_request("127.0.0.1", ctrl_port, {"op": "status"}))
    if not resp.get("ok"):
        console.print(f"[red]✗ {resp.get('error', resp)}[/]")
        raise typer.Exit(1)
    console.print(resp.get("data"))


@app.command("c2-attach")
def c2_attach(
    op: str = typer.Argument("beacons", help="beacons|task|results|interact"),
    beacon: Optional[str] = typer.Option(None, "--beacon", "-b"),
    cmd: Optional[str] = typer.Option(None, "--cmd", "-c"),
    ctrl_port: int = typer.Option(8444, "--ctrl-port"),
) -> None:
    """Attach to C2 daemon and run a control-plane op."""
    from cerberus.core.c2_control import control_request

    msg: dict = {"op": op}
    if beacon:
        msg["beacon"] = beacon
    if op == "task":
        msg["type"] = "shell"
        msg["data"] = {"cmd": cmd or "id"}
    if op == "interact" and beacon:
        msg["beacon"] = beacon
    resp = asyncio.run(control_request("127.0.0.1", ctrl_port, msg))
    if not resp.get("ok"):
        console.print(f"[red]✗ {resp.get('error', resp)}[/]")
        raise typer.Exit(1)
    data = resp.get("data") or {}
    if "beacons" in data:
        for b in data["beacons"]:
            console.print(
                f"  {b.get('id','')[:12]} {b.get('hostname')} "
                f"user={b.get('user')} conn={'●' if b.get('connected') else '○'}"
            )
    elif "results" in data:
        for r in data["results"][-10:]:
            console.print(Panel(str(r.get("output") or r)[:2000], title=str(r.get("cmd"))))
    else:
        console.print(data)


if __name__ == "__main__":
    app()
