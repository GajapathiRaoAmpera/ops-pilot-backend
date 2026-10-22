"""Groq chat-completions client (OpenAI-compatible). Fixed host, bounded time, JSON output only."""
import json
import logging

import httpx

log = logging.getLogger("opspilot.ai")

URL = "https://api.groq.com/openai/v1/chat/completions"
TIMEOUT = 60.0


class AiError(Exception):
    """Coarse reason only: ai_not_configured | ai_unauthorized | ai_rate_limited | ai_model_unavailable
    | ai_unavailable | ai_bad_output."""


class GroqClient:
    def __init__(self, api_key: str, model: str, transport: httpx.BaseTransport | None = None):
        self._key, self.model = api_key, model
        self._http = httpx.Client(timeout=TIMEOUT, transport=transport)

    def json_completion(self, system: str, user: str, max_tokens: int = 1500) -> dict:
        if not self._key:
            raise AiError("ai_not_configured")
        body = {"model": self.model, "temperature": 0.1, "max_tokens": max_tokens,
                "response_format": {"type": "json_object"},
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}]}
        try:
            r = self._http.post(URL, json=body, headers={"Authorization": f"Bearer {self._key}"})
        except httpx.HTTPError as exc:
            log.warning("groq request failed: %s", type(exc).__name__)
            raise AiError("ai_unavailable") from exc
        if r.status_code != 200:  # the provider's message for operators; it never contains the key
            log.warning("groq returned %s for model %s: %s", r.status_code, self.model, r.text[:300])
        if r.status_code == 404:
            raise AiError("ai_model_unavailable")
        if r.status_code in (401, 403):
            raise AiError("ai_unauthorized")
        if r.status_code == 429:
            raise AiError("ai_rate_limited")
        if r.status_code != 200:
            raise AiError("ai_unavailable")
        try:
            return json.loads(r.json()["choices"][0]["message"]["content"])
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise AiError("ai_bad_output") from exc
