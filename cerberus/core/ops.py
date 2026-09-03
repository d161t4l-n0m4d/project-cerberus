"""Operator session artefacts — notes, pivots, tasks, transcript search.

Cerberus equivalents of  note / pivot / tasks / tgrep / l00t / scans.
"""

from __future__ import annotations

import json
import re
import time
import uuid
from pathlib import Path
from typing import Any


def _sessions(base: Path) -> Path:
    base.mkdir(parents=True, exist_ok=True)
    return base


def add_note(sessions_dir: Path, text: str, rhost: str = "", phase: str = "") -> dict:
    path = _sessions(sessions_dir) / "notes.jsonl"
    entry = {
        "id": str(uuid.uuid4())[:8],
        "ts": time.time(),
        "rhost": rhost,
        "phase": phase,
        "text": text,
    }
    with path.open("a") as f:
        f.write(json.dumps(entry) + "\n")
    return entry


def list_notes(sessions_dir: Path, rhost: str | None = None, limit: int = 50) -> list[dict]:
    path = sessions_dir / "notes.jsonl"
    if not path.exists():
        return []
    items = []
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        try:
            items.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    if rhost:
        items = [i for i in items if i.get("rhost") == rhost]
    return items[-limit:]


def add_pivot(sessions_dir: Path, new_ip: str, via: str = "", note: str = "") -> dict:
    path = _sessions(sessions_dir) / "pivots.jsonl"
    entry = {
        "id": str(uuid.uuid4())[:8],
        "ts": time.time(),
        "ip": new_ip,
        "via": via,
        "note": note,
    }
    with path.open("a") as f:
        f.write(json.dumps(entry) + "\n")
    return entry


def list_pivots(sessions_dir: Path) -> list[dict]:
    path = sessions_dir / "pivots.jsonl"
    if not path.exists():
        return []
    out = []
    for line in path.read_text().splitlines():
        if line.strip():
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return out


def load_tasks(sessions_dir: Path) -> list[dict]:
    path = sessions_dir / "tasks.json"
    if not path.exists():
        return []
    try:
        return json.loads(path.read_text())
    except Exception:
        return []


def save_tasks(sessions_dir: Path, tasks: list[dict]) -> None:
    path = _sessions(sessions_dir) / "tasks.json"
    path.write_text(json.dumps(tasks, indent=2))


def add_task(sessions_dir: Path, title: str, operator: str = "operator") -> dict:
    tasks = load_tasks(sessions_dir)
    task = {
        "id": str(uuid.uuid4())[:8],
        "title": title,
        "status": "New",
        "operator": operator,
        "ts": time.time(),
    }
    tasks.append(task)
    save_tasks(sessions_dir, tasks)
    return task


def set_task_status(sessions_dir: Path, task_id: str, status: str) -> bool:
    tasks = load_tasks(sessions_dir)
    for t in tasks:
        if t["id"] == task_id or t["id"].startswith(task_id):
            t["status"] = status
            save_tasks(sessions_dir, tasks)
            return True
    return False


def list_scan_files(sessions_dir: Path, host_filter: str | None = None) -> list[dict]:
    """Find nmap / scan artefacts under sessions/."""
    results = []
    if not sessions_dir.exists():
        return results
    patterns = ("scan_*.xml", "scan_*.nmap", "*nmap*", "*.xml")
    seen = set()
    for pat in patterns:
        for p in sessions_dir.glob(pat):
            if p in seen:
                continue
            seen.add(p)
            if host_filter and host_filter not in p.name:
                continue
            st = p.stat()
            results.append({
                "path": str(p),
                "name": p.name,
                "size": st.st_size,
                "mtime": st.st_mtime,
            })
    # also evidence-based "virtual" scans
    return sorted(results, key=lambda x: x["mtime"], reverse=True)


def tgrep(sessions_dir: Path, pattern: str, limit: int = 40) -> list[dict]:
    """Search notes, credentials, pivots, evidence JSON for a pattern."""
    rx = re.compile(pattern, re.I)
    hits: list[dict] = []

    def _scan_file(path: Path, kind: str) -> None:
        if not path.exists() or not path.is_file():
            return
        try:
            text = path.read_text(errors="ignore")
        except Exception:
            return
        for i, line in enumerate(text.splitlines(), 1):
            if rx.search(line):
                hits.append({"source": str(path), "kind": kind, "line": i, "text": line[:300]})
                if len(hits) >= limit:
                    return

    for name, kind in (
        ("notes.jsonl", "note"),
        ("credentials.txt", "cred"),
        ("pivots.jsonl", "pivot"),
        ("tasks.json", "task"),
    ):
        _scan_file(sessions_dir / name, kind)
        if len(hits) >= limit:
            return hits

    # evidence store
    for p in sessions_dir.glob("**/*"):
        if p.suffix in (".json", ".jsonl", ".txt", ".log", ".csv") and p.is_file():
            if p.name in ("notes.jsonl", "credentials.txt", "pivots.jsonl", "tasks.json"):
                continue
            _scan_file(p, "session")
            if len(hits) >= limit:
                break
    return hits[:limit]


def loot_table(sessions_dir: Path, evidence_items: list[Any] | None = None) -> list[dict]:
    """Unified credentials + hashes view."""
    rows: list[dict] = []
    seen = set()

    cred_file = sessions_dir / "credentials.txt"
    if cred_file.exists():
        for line in cred_file.read_text().splitlines():
            line = line.strip()
            if not line or line in seen:
                continue
            seen.add(line)
            if ":" in line:
                user, secret = line.split(":", 1)
            else:
                user, secret = "?", line
            rows.append({"user": user, "secret": secret, "source": "credentials.txt", "type": "file"})

    if evidence_items:
        for item in evidence_items:
            u = item.data.get("username", "?")
            s = item.data.get("secret") or item.data.get("nthash") or item.data.get("password") or ""
            key = f"{u}:{s}"
            if key in seen:
                continue
            seen.add(key)
            rows.append({
                "user": u,
                "secret": s,
                "source": item.provenance.source,
                "type": item.data.get("type", "credential"),
                "target": item.target,
            })
    return rows
