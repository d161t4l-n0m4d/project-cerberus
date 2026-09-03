"""Single source of truth for Cerberus configuration."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class StealthProfile(str):
    NOISY = "noisy"
    BALANCED = "balanced"
    NINJA = "ninja"


class Config(BaseModel):
    """Runtime configuration. Everything lives here."""

    # Network
    rhost: str = ""
    lhost: str = "127.0.0.1"
    rport: int = 80
    lport: int = 4444
    domain: str = ""

    # Paths
    sessions_dir: Path = Path("sessions")
    wordlist: str = "/usr/share/wordlists/dirb/common.txt"
    dirwordlist: str = "/usr/share/seclists/Discovery/Web-Content/common.txt"

    # Behaviour
    stealth: str = "balanced"  # noisy | balanced | ninja
    auto_approve: bool = False
    enable_inline_hints: bool = True

    # C2
    c2_port: int = 8443
    c2_user: str = "cerberus"
    c2_pass: str = "change-me"
    c2_key: str = "cerberus-default-key-change-me"  # shared secret → AES-GCM

    # AI
    ollama_host: str = "http://127.0.0.1:11434"
    ollama_model: str = "llama3.2"

    # Meta
    phase: str = "recon"
    operator: str = "operator"

    def ensure_dirs(self) -> None:
        self.sessions_dir.mkdir(parents=True, exist_ok=True)


def default_config_path() -> Path:
    return Path("cerberus.json")


def load_config(path: Path | None = None) -> Config:
    path = path or default_config_path()
    if path.exists():
        data = json.loads(path.read_text())
        return Config.model_validate(data)
    cfg = Config()
    cfg.ensure_dirs()
    return cfg


def save_config(cfg: Config, path: Path | None = None) -> None:
    path = path or default_config_path()
    path.write_text(cfg.model_dump_json(indent=2))
