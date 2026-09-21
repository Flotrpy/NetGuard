"""LLM access for the explainer and fix generator, with pluggable providers.

Providers: Anthropic (official SDK), Groq (OpenAI-compatible REST) and Google Gemini (REST).
AI is optional: without any key, every feature falls back to deterministic rule-derived output
and says so. Callers must treat model output as untrusted text; validation (fabricated-identifier
checks, exact-match patches, syntax checks) lives in the callers and is provider-independent.

Privacy: finding data and code excerpts are sent to the configured third-party provider.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

import httpx

from netguard.config import Settings, get_settings
from netguard.logging import get_logger

log = get_logger("ai")

PROVIDERS = ("anthropic", "groq", "gemini")


class LlmUnavailable(Exception):
    """No provider configured, the request failed, or the model declined to answer."""


@dataclass
class LlmResult:
    text: str
    model: str
    provider: str = "anthropic"


def _key(settings: Settings, provider: str) -> str:
    return {
        "anthropic": settings.anthropic_api_key,
        "groq": settings.groq_api_key,
        "gemini": settings.gemini_api_key,
    }[provider]


def active_provider(settings: Settings | None = None) -> str | None:
    """The provider that will be used, or ``None`` if AI is not configured."""
    s = settings or get_settings()
    if s.ai_provider in PROVIDERS:
        return s.ai_provider if _key(s, s.ai_provider) else None
    return next((p for p in PROVIDERS if _key(s, p)), None)


def is_configured() -> bool:
    return active_provider() is not None


def _http() -> httpx.Client:  # separate function so tests can inject a mock transport
    return httpx.Client(timeout=get_settings().ai_timeout_seconds)


def complete(
    system: str,
    user: str,
    *,
    max_tokens: int = 4000,
    effort: str = "medium",
    json_mode: bool = False,
) -> LlmResult:
    """Single-turn completion. Raises :class:`LlmUnavailable` on any failure.

    ``effort`` applies to Anthropic only; ``json_mode`` asks providers that support it to
    constrain output to a JSON object.
    """
    settings = get_settings()
    provider = active_provider(settings)
    if provider is None:
        raise LlmUnavailable(
            "AI is not configured (set ANTHROPIC_API_KEY, GROQ_API_KEY or GEMINI_API_KEY)"
        )
    if provider == "groq":
        return _groq(settings, system, user, max_tokens, json_mode)
    if provider == "gemini":
        return _gemini(settings, system, user, max_tokens, json_mode)
    return _anthropic(settings, system, user, max_tokens, effort)


# ---- Anthropic ----------------------------------------------------------------------------------
def _anthropic(s: Settings, system: str, user: str, max_tokens: int, effort: str) -> LlmResult:
    import anthropic

    try:
        client = anthropic.Anthropic(api_key=s.anthropic_api_key, timeout=s.ai_timeout_seconds)
        response = client.messages.create(
            model=s.anthropic_model,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
            output_config={"effort": effort},
        )
    except anthropic.RateLimitError as exc:
        raise LlmUnavailable("The AI service is rate limited; try again shortly") from exc
    except anthropic.AuthenticationError as exc:
        raise LlmUnavailable("The configured Anthropic API key was rejected") from exc
    except anthropic.APIConnectionError as exc:
        raise LlmUnavailable("Could not reach the AI service") from exc
    except anthropic.APIStatusError as exc:
        log.warning("anthropic api error", extra={"status": exc.status_code})
        raise LlmUnavailable(f"The AI service returned an error ({exc.status_code})") from exc
    if response.stop_reason == "refusal":
        raise LlmUnavailable("The AI service declined this request")
    if response.stop_reason == "max_tokens":
        raise LlmUnavailable("The AI response was cut off; try again")
    text = "".join(b.text for b in response.content if b.type == "text").strip()
    return _result(text, response.model, "anthropic")


# ---- Groq (OpenAI-compatible chat completions) --------------------------------------------------
def _post(url: str, headers: dict, payload: dict, provider: str) -> dict:
    try:
        with _http() as client:
            resp = client.post(url, headers=headers, json=payload)
    except httpx.HTTPError as exc:
        raise LlmUnavailable(f"Could not reach the {provider} service") from exc
    if resp.status_code in (401, 403):
        raise LlmUnavailable(f"The configured {provider} API key was rejected")
    if resp.status_code == 429:
        raise LlmUnavailable(f"The {provider} service is rate limited; try again shortly")
    if resp.status_code >= 400:
        log.warning("ai provider error", extra={"provider": provider, "status": resp.status_code})
        raise LlmUnavailable(f"The {provider} service returned an error ({resp.status_code})")
    try:
        return resp.json()
    except ValueError as exc:
        raise LlmUnavailable(f"The {provider} service returned an invalid response") from exc


def _groq(s: Settings, system: str, user: str, max_tokens: int, json_mode: bool) -> LlmResult:
    payload: dict = {
        "model": s.groq_model,
        "max_tokens": max_tokens,
        "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
    }
    if json_mode:
        payload["response_format"] = {"type": "json_object"}
    data = _post(
        f"{s.groq_base_url.rstrip('/')}/chat/completions",
        {"Authorization": f"Bearer {s.groq_api_key}"},
        payload,
        "Groq",
    )
    choice = (data.get("choices") or [{}])[0]
    if choice.get("finish_reason") == "length":
        raise LlmUnavailable("The AI response was cut off; try again")
    text = ((choice.get("message") or {}).get("content") or "").strip()
    return _result(text, data.get("model", s.groq_model), "groq")


# ---- Google Gemini ------------------------------------------------------------------------------
def _gemini(s: Settings, system: str, user: str, max_tokens: int, json_mode: bool) -> LlmResult:
    config: dict = {"maxOutputTokens": max_tokens}
    if json_mode:
        config["responseMimeType"] = "application/json"
    data = _post(
        f"{s.gemini_base_url.rstrip('/')}/models/{s.gemini_model}:generateContent",
        {"x-goog-api-key": s.gemini_api_key},  # header, never the URL (URLs get logged)
        {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": user}]}],
            "generationConfig": config,
        },
        "Gemini",
    )
    block = (data.get("promptFeedback") or {}).get("blockReason")
    if block:
        raise LlmUnavailable("The AI service declined this request")
    candidate = (data.get("candidates") or [{}])[0]
    reason = candidate.get("finishReason", "")
    if reason == "MAX_TOKENS":
        raise LlmUnavailable("The AI response was cut off; try again")
    if reason in ("SAFETY", "RECITATION", "PROHIBITED_CONTENT", "BLOCKLIST"):
        raise LlmUnavailable("The AI service declined this request")
    parts = (candidate.get("content") or {}).get("parts") or []
    text = "".join(p.get("text", "") for p in parts).strip()
    return _result(text, data.get("modelVersion", s.gemini_model), "gemini")


def _result(text: str, model: str, provider: str) -> LlmResult:
    if not text:
        raise LlmUnavailable("The AI service returned an empty response")
    return LlmResult(text=text, model=model, provider=provider)


def extract_json(text: str) -> dict:
    """Parse a JSON object from model output (tolerates a ```json fence)."""
    fenced = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.DOTALL)
    candidate = fenced.group(1) if fenced else text[text.find("{") : text.rfind("}") + 1]
    try:
        data = json.loads(candidate)
    except (json.JSONDecodeError, ValueError) as exc:
        raise LlmUnavailable("The AI response was not valid JSON") from exc
    if not isinstance(data, dict):
        raise LlmUnavailable("The AI response had an unexpected shape")
    return data
