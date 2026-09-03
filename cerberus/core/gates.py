"""Phase + OPSEC policy gates for plugin execution."""

from __future__ import annotations

from typing import Any

from cerberus.core.opsec import allow_opsec, profile
from cerberus.core.phase import PHASE_ORDER, Phase


def check_phase_gate(
    plugin_phases: list[Phase],
    current: Phase,
    force: bool = False,
) -> tuple[bool, str]:
    """Allow if plugin is tagged for current phase, or force=True.

    Plugins tagged with REPORT or multiple phases including current pass.
    Empty phase list → allow (utility plugins).
    """
    if force:
        return True, "forced"
    if not plugin_phases:
        return True, "no phase restriction"
    if current in plugin_phases:
        return True, "phase ok"
    # allow if plugin is purely informational across all phases
    if set(plugin_phases) >= set(PHASE_ORDER):
        return True, "all-phase plugin"
    allowed = ", ".join(p.value for p in plugin_phases)
    return (
        False,
        f"phase gate: current={current.value}, plugin allows [{allowed}] (use --force)",
    )


def check_opsec_gate(
    opsec_level: str,
    stealth: str,
    force: bool = False,
) -> tuple[bool, str]:
    if force:
        return True, "forced"
    level = opsec_level.lower() if isinstance(opsec_level, str) else str(opsec_level)
    if hasattr(opsec_level, "value"):
        level = opsec_level.value  # type: ignore
    if allow_opsec(stealth, level):
        return True, "opsec ok"
    p = profile(stealth)
    return (
        False,
        f"opsec gate: stealth={stealth} blocks level={level} "
        f"(block_dangerous={p.get('block_dangerous')}; use --force)",
    )


def evaluate_gates(
    meta: Any,
    engine: Any,
    config: Any,
    force: bool = False,
) -> tuple[bool, list[str]]:
    """Return (allowed, reasons). reasons non-empty on deny or on forced bypass notes."""
    reasons: list[str] = []
    current = engine.current if hasattr(engine, "current") else Phase.RECON
    phases = list(getattr(meta, "phase", []) or [])
    ok_p, msg_p = check_phase_gate(phases, current, force=force)
    if not ok_p:
        return False, [msg_p]
    if force and current not in phases and phases:
        reasons.append(f"phase bypass: {msg_p}")

    ok_o, msg_o = check_opsec_gate(meta.opsec, getattr(config, "stealth", "balanced"), force=force)
    if not ok_o:
        return False, [msg_o]
    if force and not allow_opsec(getattr(config, "stealth", "balanced"), getattr(meta.opsec, "value", str(meta.opsec))):
        reasons.append(f"opsec bypass: {msg_o}")

    return True, reasons
