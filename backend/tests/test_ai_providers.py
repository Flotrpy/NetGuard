import json

import httpx
import pytest

from netguard import config
from netguard.services.ai import llm


def use_env(monkeypatch, **env):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    config.get_settings.cache_clear()


def mock_http(monkeypatch, handler):
    monkeypatch.setattr(llm, "_http", lambda: httpx.Client(transport=httpx.MockTransport(handler)))


def test_provider_selection_auto_and_explicit(monkeypatch):
    assert llm.active_provider() is None and not llm.is_configured()
    use_env(monkeypatch, GEMINI_API_KEY="g")
    assert llm.active_provider() == "gemini"
    use_env(monkeypatch, GROQ_API_KEY="q")
    assert llm.active_provider() == "groq"  # order: anthropic, groq, gemini
    use_env(monkeypatch, ANTHROPIC_API_KEY="a")
    assert llm.active_provider() == "anthropic"
    use_env(monkeypatch, NETGUARD_AI_PROVIDER="gemini")
    assert llm.active_provider() == "gemini"
    use_env(monkeypatch, NETGUARD_AI_PROVIDER="groq")
    monkeypatch.delenv("GROQ_API_KEY")
    config.get_settings.cache_clear()
    assert llm.active_provider() is None  # explicit choice without its key: not configured


def test_no_provider_raises_helpful_error():
    with pytest.raises(llm.LlmUnavailable, match="GROQ_API_KEY"):
        llm.complete("s", "u")


def test_groq_request_shape_and_response(monkeypatch):
    seen = {}

    def handler(request):
        seen["url"], seen["auth"] = str(request.url), request.headers["authorization"]
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={
            "model": "llama-3.3-70b-versatile",
            "choices": [{"finish_reason": "stop", "message": {"content": ' {"a": 1} '}}]})

    use_env(monkeypatch, GROQ_API_KEY="gsk-test")
    mock_http(monkeypatch, handler)
    r = llm.complete("SYS", "USER", max_tokens=123, json_mode=True)
    assert (r.provider, r.text) == ("groq", '{"a": 1}')
    assert seen["url"] == "https://api.groq.com/openai/v1/chat/completions"
    assert seen["auth"] == "Bearer gsk-test" and "gsk-test" not in seen["url"]
    body = seen["body"]
    assert body["max_tokens"] == 123 and body["response_format"] == {"type": "json_object"}
    assert [m["role"] for m in body["messages"]] == ["system", "user"]


def test_gemini_request_shape_puts_key_in_header_not_url(monkeypatch):
    seen = {}

    def handler(request):
        seen["url"], seen["key"] = str(request.url), request.headers["x-goog-api-key"]
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={
            "modelVersion": "gemini-3.6-flash",
            "candidates": [{"finishReason": "STOP",
                            "content": {"parts": [{"text": '{"a":'}, {"text": " 2}"}]}}]})

    use_env(monkeypatch, GEMINI_API_KEY="AIza-test")
    mock_http(monkeypatch, handler)
    r = llm.complete("SYS", "USER", json_mode=True)
    assert (r.provider, r.text) == ("gemini", '{"a": 2}')
    assert seen["url"].endswith("/models/gemini-3.6-flash:generateContent")
    assert seen["key"] == "AIza-test" and "AIza-test" not in seen["url"]
    body = seen["body"]
    assert body["systemInstruction"]["parts"][0]["text"] == "SYS"
    assert body["generationConfig"]["responseMimeType"] == "application/json"


@pytest.mark.parametrize("status,fragment", [(401, "rejected"), (403, "rejected"),
                                             (429, "rate limited"), (500, r"error \(500\)")])
def test_http_errors_map_to_unavailable(monkeypatch, status, fragment):
    use_env(monkeypatch, GROQ_API_KEY="k")
    mock_http(monkeypatch, lambda r: httpx.Response(status, json={"error": "x"}))
    with pytest.raises(llm.LlmUnavailable, match=fragment):
        llm.complete("s", "u")


def test_network_failure_and_bad_json_body(monkeypatch):
    use_env(monkeypatch, GROQ_API_KEY="k")

    def down(request):
        raise httpx.ConnectError("boom")

    mock_http(monkeypatch, down)
    with pytest.raises(llm.LlmUnavailable, match="Could not reach"):
        llm.complete("s", "u")
    mock_http(monkeypatch, lambda r: httpx.Response(200, content=b"<html>"))
    with pytest.raises(llm.LlmUnavailable, match="invalid response"):
        llm.complete("s", "u")


def test_truncated_blocked_and_empty_outputs_are_rejected(monkeypatch):
    use_env(monkeypatch, GROQ_API_KEY="k")
    mock_http(monkeypatch, lambda r: httpx.Response(200, json={
        "choices": [{"finish_reason": "length", "message": {"content": "{"}}]}))
    with pytest.raises(llm.LlmUnavailable, match="cut off"):
        llm.complete("s", "u")
    mock_http(monkeypatch, lambda r: httpx.Response(200, json={"choices": [{"message": {"content": ""}}]}))
    with pytest.raises(llm.LlmUnavailable, match="empty"):
        llm.complete("s", "u")

    use_env(monkeypatch, NETGUARD_AI_PROVIDER="gemini", GEMINI_API_KEY="g")
    mock_http(monkeypatch, lambda r: httpx.Response(200, json={"promptFeedback": {"blockReason": "SAFETY"}}))
    with pytest.raises(llm.LlmUnavailable, match="declined"):
        llm.complete("s", "u")
    mock_http(monkeypatch, lambda r: httpx.Response(200, json={
        "candidates": [{"finishReason": "MAX_TOKENS", "content": {"parts": [{"text": "x"}]}}]}))
    with pytest.raises(llm.LlmUnavailable, match="cut off"):
        llm.complete("s", "u")


def test_explainer_works_through_groq_and_still_rejects_fabricated_ids(client, monkeypatch):
    from tests.test_ai_explain import GOOD, _seed_finding

    fid = _seed_finding(client)
    use_env(monkeypatch, GROQ_API_KEY="k")
    mock_http(monkeypatch, lambda r: httpx.Response(200, json={
        "model": "llama-3.3-70b-versatile",
        "choices": [{"finish_reason": "stop", "message": {"content": json.dumps(GOOD)}}]}))
    ok = client.post(f"/api/findings/{fid}/explain", json={}).json()
    assert ok["source"] == "ai" and ok["provider"] == "groq" and ok["model"] == "llama-3.3-70b-versatile"

    bad = {**GOOD, "why_it_matters": "See CVE-2099-99999."}
    mock_http(monkeypatch, lambda r: httpx.Response(200, json={
        "choices": [{"finish_reason": "stop", "message": {"content": json.dumps(bad)}}]}))
    rejected = client.post(f"/api/findings/{fid}/explain", json={"refresh": True}).json()
    assert rejected["source"] == "rule" and "CVE-2099-99999" in rejected["notice"]
