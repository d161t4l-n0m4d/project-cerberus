"""CLI-facing Ollama plugins."""

from __future__ import annotations

from typing import Any

from cerberus.core.phase import Phase
from cerberus.core.plugin_api import OpsecLevel, Plugin, PluginMeta, register_plugin
from cerberus.plugins.ai.ollama_client import ask_ollama, list_models
from cerberus.plugins.ai.recommend import recommend_next


@register_plugin
class OllamaAskPlugin(Plugin):
    meta = PluginMeta(
        name="ollama_ask",
        description="Ask local Ollama (uses ollama_host / ollama_model from config)",
        phase=list(Phase),
        opsec=OpsecLevel.SAFE,
        requires=[],
        produces=[],
    )

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        prompt = kwargs.get("prompt") or kwargs.get("cmd") or ""
        if not prompt:
            return {"success": False, "message": "need prompt=..."}
        context = kwargs.get("context") or ""
        try:
            reply = await ask_ollama(self.config, prompt, context=context)
            return {"success": True, "message": "ollama replied", "reply": reply}
        except Exception as e:
            return {"success": False, "message": f"ollama error: {e}"}


@register_plugin
class RecommendNextPlugin(Plugin):
    meta = PluginMeta(
        name="recommend_next",
        description="Suggest next actions from evidence + phase (optional Ollama)",
        phase=list(Phase),
        opsec=OpsecLevel.SAFE,
        requires=[],
        produces=[],
    )

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        use_ollama = bool(kwargs.get("use_ollama") or kwargs.get("ollama"))
        recs = await recommend_next(self.config, self.evidence, self.phase, use_ollama=use_ollama)
        return {"success": True, "message": "recommendations ready", **recs}


@register_plugin
class OllamaModelsPlugin(Plugin):
    meta = PluginMeta(
        name="ollama_models",
        description="List models available on local Ollama",
        phase=list(Phase),
        opsec=OpsecLevel.SAFE,
        requires=[],
        produces=[],
    )

    async def run(self, **kwargs: Any) -> dict[str, Any]:
        try:
            models = await list_models(self.config)
            return {"success": True, "message": f"{len(models)} model(s)", "models": models}
        except Exception as e:
            return {"success": False, "message": f"ollama error: {e}"}
