"""Strict plugin contract for Cerberus.

Every plugin must declare:
- name, description, phase tags
- input schema (what it needs from config / evidence)
- output schema (what evidence kinds it produces)
- OPSEC level
- run() method
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, Callable

from pydantic import BaseModel, Field

from .phase import Phase


class OpsecLevel(str, Enum):
    SAFE = "safe"          # passive / very low noise
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"          # active, noisy
    DANGEROUS = "dangerous"


class PluginMeta(BaseModel):
    name: str
    description: str
    phase: list[Phase]
    opsec: OpsecLevel = OpsecLevel.MEDIUM
    requires: list[str] = Field(default_factory=list)  # config keys needed
    produces: list[str] = Field(default_factory=list)  # evidence kinds
    author: str = "cerberus"
    version: str = "0.1.0"


class Plugin(ABC):
    """Base class every plugin must inherit."""

    meta: PluginMeta

    def __init__(self, config: Any, evidence: Any, phase_engine: Any) -> None:
        self.config = config
        self.evidence = evidence
        self.phase = phase_engine

    @abstractmethod
    async def run(self, **kwargs: Any) -> dict[str, Any]:
        """Execute the plugin. Must return a result dict.

        Expected keys (convention):
            success: bool
            message: str
            evidence_ids: list[str]   # ids of items added
        """
        ...

    def check_requirements(self) -> list[str]:
        """Return list of missing config keys."""
        missing = []
        for key in self.meta.requires:
            if not getattr(self.config, key, None):
                missing.append(key)
        return missing


# Simple global registry
_REGISTRY: dict[str, type[Plugin]] = {}


def register_plugin(cls: type[Plugin]) -> type[Plugin]:
    """Decorator to register a plugin class."""
    if not hasattr(cls, "meta"):
        raise TypeError(f"{cls.__name__} must define class attribute 'meta'")
    _REGISTRY[cls.meta.name] = cls
    return cls


def get_plugin(name: str) -> type[Plugin] | None:
    return _REGISTRY.get(name)


def list_plugins() -> list[PluginMeta]:
    return [cls.meta for cls in _REGISTRY.values()]


def discover_plugins() -> None:
    """Import all plugin modules so @register_plugin runs."""
    import importlib
    import pkgutil
    from pathlib import Path

    plugins_root = Path(__file__).parent.parent / "plugins"
    for finder, name, ispkg in pkgutil.walk_packages(
        path=[str(plugins_root)],
        prefix="cerberus.plugins.",
    ):
        try:
            importlib.import_module(name)
        except Exception:
            # Plugin load errors are non-fatal at discovery time
            pass
