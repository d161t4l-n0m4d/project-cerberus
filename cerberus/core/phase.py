"""Kill-chain phase state machine.

Phases are ordered. By default, jumping forward more than one step
or going backwards without explicit force is blocked.
"""

from __future__ import annotations

from enum import Enum
from typing import Iterable


class Phase(str, Enum):
    RECON = "recon"
    ENUM = "enum"
    EXPLOIT = "exploit"
    PRIVESC = "privesc"
    LATERAL = "lateral"
    EXFIL = "exfil"
    REPORT = "report"


# Canonical order
PHASE_ORDER: list[Phase] = [
    Phase.RECON,
    Phase.ENUM,
    Phase.EXPLOIT,
    Phase.PRIVESC,
    Phase.LATERAL,
    Phase.EXFIL,
    Phase.REPORT,
]


class PhaseEngine:
    """Enforces phase discipline."""

    def __init__(self, current: Phase = Phase.RECON) -> None:
        self.current = current
        self.completed: set[Phase] = set()

    def can_enter(self, target: Phase, force: bool = False) -> tuple[bool, str]:
        if force:
            return True, "forced"
        try:
            cur_idx = PHASE_ORDER.index(self.current)
            tgt_idx = PHASE_ORDER.index(target)
        except ValueError:
            return False, f"unknown phase: {target}"

        if tgt_idx == cur_idx:
            return True, "already there"
        if tgt_idx == cur_idx + 1:
            return True, "next phase"
        if tgt_idx < cur_idx:
            return False, f"cannot go backwards from {self.current} to {target} (use force=True)"
        if tgt_idx > cur_idx + 1:
            return False, f"cannot skip from {self.current} to {target} (use force=True)"
        return False, "invalid transition"

    def advance(self, target: Phase, force: bool = False) -> None:
        ok, reason = self.can_enter(target, force=force)
        if not ok:
            raise ValueError(reason)
        if self.current != target:
            self.completed.add(self.current)
        self.current = target

    def mark_completed(self, phase: Phase) -> None:
        self.completed.add(phase)

    def progress(self) -> dict:
        return {
            "current": self.current.value,
            "completed": sorted(p.value for p in self.completed),
            "remaining": [p.value for p in PHASE_ORDER if p not in self.completed and p != self.current],
        }
