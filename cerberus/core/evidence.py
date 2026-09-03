"""Evidence store with provenance and freshness.

Every fact carries:
- source (plugin / command that produced it)
- timestamp
- confidence (0.0 – 1.0)
- raw reference (file path or hash)
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

import orjson
from pydantic import BaseModel, Field


class Provenance(BaseModel):
    source: str
    plugin: str | None = None
    timestamp: float = Field(default_factory=lambda: time.time())
    confidence: float = 1.0
    notes: str = ""


class EvidenceItem(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid4()))
    kind: str  # host, port, service, credential, vulnerability, note, ...
    target: str  # usually IP or hostname
    data: dict[str, Any]
    provenance: Provenance
    tags: list[str] = Field(default_factory=list)

    @property
    def age_seconds(self) -> float:
        return time.time() - self.provenance.timestamp

    @property
    def is_stale(self, threshold: float = 7 * 24 * 3600) -> bool:
        return self.age_seconds > threshold


class EvidenceStore:
    """Simple, file-backed evidence store.

    Layout:
        sessions/
          evidence/
            <id>.json
          index.json          # fast lookup
          world_model.json    # aggregated view
    """

    def __init__(self, root: Path) -> None:
        self.root = root
        self.evidence_dir = root / "evidence"
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.index_path = root / "index.json"
        self.world_path = root / "world_model.json"
        self._index: dict[str, list[str]] = self._load_index()

    def _load_index(self) -> dict[str, list[str]]:
        if self.index_path.exists():
            return orjson.loads(self.index_path.read_bytes())
        return {}

    def _save_index(self) -> None:
        self.index_path.write_bytes(orjson.dumps(self._index, option=orjson.OPT_INDENT_2))

    def add(
        self,
        kind: str,
        target: str,
        data: dict[str, Any],
        source: str,
        plugin: str | None = None,
        confidence: float = 1.0,
        tags: list[str] | None = None,
        notes: str = "",
    ) -> EvidenceItem:
        item = EvidenceItem(
            kind=kind,
            target=target,
            data=data,
            provenance=Provenance(
                source=source,
                plugin=plugin,
                confidence=confidence,
                notes=notes,
            ),
            tags=tags or [],
        )
        path = self.evidence_dir / f"{item.id}.json"
        path.write_bytes(orjson.dumps(item.model_dump(), option=orjson.OPT_INDENT_2))

        key = f"{kind}:{target}"
        self._index.setdefault(key, []).append(item.id)
        self._save_index()
        self._update_world_model(item)
        return item

    def get(self, item_id: str) -> EvidenceItem | None:
        path = self.evidence_dir / f"{item_id}.json"
        if not path.exists():
            return None
        return EvidenceItem.model_validate(orjson.loads(path.read_bytes()))

    def find(self, kind: str | None = None, target: str | None = None) -> list[EvidenceItem]:
        results: list[EvidenceItem] = []
        for key, ids in self._index.items():
            k, t = key.split(":", 1)
            if kind and k != kind:
                continue
            if target and t != target:
                continue
            for iid in ids:
                item = self.get(iid)
                if item:
                    results.append(item)
        return results

    def hosts(self) -> list[str]:
        return sorted({t for k, ids in self._index.items() if k.startswith("host:") for t in [k.split(":", 1)[1]]})

    def _update_world_model(self, item: EvidenceItem) -> None:
        """Lightweight aggregated view for quick situational awareness."""
        world: dict[str, Any] = {}
        if self.world_path.exists():
            world = orjson.loads(self.world_path.read_bytes())

        hosts = world.setdefault("hosts", {})
        host = hosts.setdefault(item.target, {"ports": {}, "services": [], "creds": [], "vulns": []})

        if item.kind == "port":
            port = str(item.data.get("port", ""))
            if port:
                host["ports"][port] = item.data
        elif item.kind == "service":
            host["services"].append(item.data)
        elif item.kind == "credential":
            host["creds"].append(item.data)
        elif item.kind == "vulnerability":
            host["vulns"].append(item.data)

        world["updated_at"] = datetime.now(timezone.utc).isoformat()
        self.world_path.write_bytes(orjson.dumps(world, option=orjson.OPT_INDENT_2))

    def sitrep(self) -> dict[str, Any]:
        """Quick situation report."""
        world = {}
        if self.world_path.exists():
            world = orjson.loads(self.world_path.read_bytes())
        return {
            "hosts": list(world.get("hosts", {}).keys()),
            "host_count": len(world.get("hosts", {})),
            "updated_at": world.get("updated_at"),
            "evidence_files": len(list(self.evidence_dir.glob("*.json"))),
        }
