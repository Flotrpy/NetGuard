"""Thin wrapper around the Anthropic SDK used by the explainer and fix generator.

AI is optional: without ``ANTHROPIC_API_KEY`` every feature falls back to deterministic,
rule-derived output and says so. Callers must treat model output as untrusted text.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from netguard.config import get_settings
from netguard.logging import get_logger

log = get_logger("ai")


class LlmUnavailable(Exception):
    """No API key configured, the request failed, or the model declined to answer."""


@dataclass
class LlmResult:
    text: str
    model: str


def is_configured() -> bool:
    return bool(get_settings().anthropic_api_key)


def _client():
    import anthropic

    s = get_settings()
    return anthropic.Anthropic(api_key=s.anthropic_api_key, timeout=s.ai_timeout_seconds)


def complete(
    system: str, user: str, *, max_tokens: int = 4000, effort: str = "medium"
) -> LlmResult:
    """Single-turn completion. Raises :class:`LlmUnavailable` on any failure."""
    settings = get_settings()
    if not settings.anthropic_api_key:
        raise LlmUnavailable("AI is not configured (set ANTHROPIC_API_KEY)")
    import anthropic

    try:
        response = _client().messages.create(
            model=settings.anthropic_model,
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
    if not text:
        raise LlmUnavailable("The AI service returned an empty response")
    return LlmResult(text=text, model=response.model)


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
