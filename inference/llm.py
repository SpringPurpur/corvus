# llm.py — Anthropic SDK wrappers for alert explanation, feedback parsing, and chat.
#
# API key is read from the ANTHROPIC_API_KEY environment variable — never hardcoded.
# All three functions are async; they are called from the WebSocket handler.
#
# Optimisations applied:
#   • Prompt caching (cache_control="ephemeral") on all static system prompts.
#     Anthropic caches the prompt for 5 minutes; repeated calls cost ~10% of
#     full input tokens after the first cache fill.
#   • Hard character cap on ask() context to prevent accidental token overflow.
#   • Exponential-backoff retry (2 attempts) on transient connection/rate errors.
#   • Assistant turn pre-fill ("{") on parse_feedback forces JSON output.
#   • explain() system prompt prohibits markdown so the dashboard <p> renders cleanly.

import asyncio
import json
import logging
import os

import anthropic
from anthropic import APIConnectionError, RateLimitError

log = logging.getLogger(__name__)

MODEL = "claude-sonnet-4-6"

_client: anthropic.AsyncAnthropic | None = None


def get_client() -> anthropic.AsyncAnthropic:
    global _client
    if _client is None:
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise RuntimeError("ANTHROPIC_API_KEY environment variable not set")
        _client = anthropic.AsyncAnthropic(api_key=api_key)
    return _client


async def _retry(coro_fn, retries: int = 2):
    """Call coro_fn(), retrying on transient API errors with exponential back-off."""
    for attempt in range(retries + 1):
        try:
            return await coro_fn()
        except (APIConnectionError, RateLimitError) as exc:
            if attempt == retries:
                raise
            wait = 1.5 ** attempt
            log.warning("LLM transient error (%s) — retry %d/%d in %.1fs",
                        exc.__class__.__name__, attempt + 1, retries, wait)
            await asyncio.sleep(wait)


async def explain(alert: dict) -> str:
    """2-3 sentence plain-text explanation of an alert.

    When the alert dict contains a 'features' key (full-context mode), all OIF
    feature values are available and the explanation can reference any of them.
    Without 'features', only the top-3 path-attribution features are referenced.
    """
    client = get_client()
    has_full_features = bool(alert.get("alert", {}).get("features"))
    feature_note = (
        "The alert includes a 'features' dict with all OIF feature values — "
        "you may reference any of them, not only the top attribution features. "
        if has_full_features else
        "Only the top-3 path-attribution features are provided; reference those. "
    )

    async def _call():
        response = await client.messages.create(
            model=MODEL,
            max_tokens=400 if has_full_features else 256,
            system=[{
                "type": "text",
                "text": (
                    "You are a concise network security analyst assistant. "
                    "The detection system uses an Online Isolation Forest — flows are scored "
                    "by how quickly they are isolated from the baseline of normal traffic. "
                    "Explain the alert in 2-3 sentences, comparing feature values to the "
                    "provided baseline median where available. "
                    + feature_note +
                    "Be specific about what the deviations indicate. "
                    "If the feature pattern matches a known network attack type "
                    "(e.g. slowloris, SSH brute-force, SYN flood, HTTP flood, port scan, "
                    "UDP flood, slow POST, slow read), name it explicitly. "
                    "Output plain text only — no markdown, no bullet points."
                ),
                "cache_control": {"type": "ephemeral"},
            }],
            messages=[{"role": "user", "content": json.dumps(alert)}],
        )
        return response.content[0].text

    return await _retry(_call)


async def parse_feedback(alert: dict, analyst_text: str) -> dict:
    """Parse analyst free-text feedback into a structured correction dict.

    Returns {"corrected_label": str|None, "dismiss": bool, "reason": str}.
    corrected_label is one of INFO / HIGH / CRITICAL, or null if no correction.
    The assistant turn is pre-filled with "{" to force valid JSON output.
    """
    client = get_client()

    async def _call():
        response = await client.messages.create(
            model=MODEL,
            max_tokens=128,
            system=[{
                "type": "text",
                "text": (
                    "You are a structured data extractor. "
                    "The IDS uses anomaly-based detection with three severity levels: INFO, HIGH, CRITICAL. "
                    "Return ONLY a JSON object with keys: "
                    "corrected_label (one of INFO/HIGH/CRITICAL, or null if no correction needed), "
                    "dismiss (bool — true if analyst says this is benign/noise), "
                    "reason (string — brief reason). "
                    "No explanation, no markdown, just the JSON object."
                ),
                "cache_control": {"type": "ephemeral"},
            }],
            messages=[
                {
                    "role": "user",
                    "content": f"Alert: {json.dumps(alert)}\nAnalyst feedback: {analyst_text}",
                },
                # Pre-fill forces the model to start inside a JSON object.
                {"role": "assistant", "content": "{"},
            ],
        )
        # Prepend the pre-filled "{" back before parsing.
        raw = "{" + response.content[0].text
        return json.loads(raw)

    try:
        return await _retry(_call)
    except (json.JSONDecodeError, Exception) as exc:
        log.warning("LLM parse_feedback failed: %s", exc)
        return {"corrected_label": None, "dismiss": False, "reason": "Feedback noted (auto-parse failed)"}


async def ask(alerts_context: list[dict], question: str) -> str:
    """Answer an analyst question about the current alert set."""
    client = get_client()

    # Cap context to ~2 k tokens to prevent accidental overflow.
    context_str = json.dumps(alerts_context[:20])[:8_000]

    async def _call():
        response = await client.messages.create(
            model=MODEL,
            max_tokens=512,
            system=[{
                "type": "text",
                "text": (
                    "You are a network security analyst assistant for an intrusion detection system "
                    "using an Online Isolation Forest. Flows are scored 0–1 by how quickly they "
                    "isolate from the normal traffic baseline; scores above 0.80 are CRITICAL, "
                    "above 0.60 are HIGH. Answer questions about the provided alerts concisely "
                    "and accurately, referencing specific flows (by src_ip, dst_port, or flow_id) "
                    "when relevant. Output plain text only — no markdown, no bullet points."
                ),
                "cache_control": {"type": "ephemeral"},
            }],
            messages=[{
                "role": "user",
                "content": f"Recent alerts: {context_str}\n\nQuestion: {question}",
            }],
        )
        return response.content[0].text

    return await _retry(_call)