"""Local Ollama client for Cerberus."""

from __future__ import annotations

from typing import Any

import httpx


async def ask_ollama(cfg: Any, prompt: str, context: str = "", system: str | None = None) -> str:
    """Send a chat completion request to local Ollama.

    Uses cfg.ollama_host and cfg.ollama_model.
    Falls back to a clear error if Ollama is unreachable.
    """
    host = getattr(cfg, "ollama_host", "http://127.0.0.1:11434").rstrip("/")
    model = getattr(cfg, "ollama_model", "llama3.2")

    system_msg = system or (
        "You are Cerberus, an elite red-team assistant. "
        "Be concise, actionable, and phase-aware. Prefer evidence over speculation. "
        "Never suggest illegal activity outside authorized engagements."
    )

    messages = [{"role": "system", "content": system_msg}]
    if context:
        messages.append({"role": "user", "content": f"Context:\n{context}"})
    messages.append({"role": "user", "content": prompt})

    payload = {
        "model": model,
        "messages": messages,
        "stream": False,
        "options": {"temperature": 0.3},
    }

    async with httpx.AsyncClient(timeout=120.0) as client:
        r = await client.post(f"{host}/api/chat", json=payload)
        r.raise_for_status()
        data = r.json()
        return data.get("message", {}).get("content") or data.get("response") or str(data)


async def list_models(cfg: Any) -> list[str]:
    host = getattr(cfg, "ollama_host", "http://127.0.0.1:11434").rstrip("/")
    async with httpx.AsyncClient(timeout=10.0) as client:
        r = await client.get(f"{host}/api/tags")
        r.raise_for_status()
        data = r.json()
        return [m.get("name", "") for m in data.get("models", [])]
