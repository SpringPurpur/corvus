# llm.py — Anthropic SDK wrappers for alert explanation, feedback parsing, and chat.
#
# API key is read from the ANTHROPIC_API_KEY environment variable — never hardcoded.
# All three functions are async; they are called from the WebSocket handler.

import json
import logging
import os

import anthropic

log = logging.getLogger(__name__)

MODEL = "claude-sonnet-4-20250514"

_client: anthropic.AsyncAnthropic | None = None


def get_client() -> anthropic.AsyncAnthropic:
    global _client
    if _client is None:
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise RuntimeError("ANTHROPIC_API_KEY environment variable not set")
        _client = anthropic.AsyncAnthropic(api_key=api_key)
    return _client


async def explain(alert: dict) -> str:
    """2-3 sentence explanation of an alert, referencing top path-attribution features."""
    client = get_client()
    response = await client.messages.create(
        model=MODEL,
        max_tokens=256,
        system=(
            "You are a concise network security analyst assistant. "
            "The detection system uses an Online Isolation Forest — flows are scored "
            "by how quickly they are isolated from the baseline of normal traffic. "
            "Explain the alert in 2-3 sentences, referencing the top path-attribution "
            "features (the features that isolated this flow at the shallowest tree depth) "
            "and comparing their values to the provided baseline median. "
            "Be specific about what the deviations indicate."
        ),
        messages=[{"role": "user", "content": json.dumps(alert)}],
    )
    return response.content[0].text


async def parse_feedback(alert: dict, analyst_text: str) -> dict:
    """Parse analyst free-text feedback into a structured correction dict.

    Returns {"corrected_label": str|None, "dismiss": bool, "reason": str}.
    corrected_label is one of INFO / HIGH / CRITICAL, or null if no correction.
    Response must be valid JSON only — any other output is a failure.
    """
    client = get_client()
    response = await client.messages.create(
        model=MODEL,
        max_tokens=128,
        system=(
            "You are a structured data extractor. "
            "The IDS uses anomaly-based detection with three severity levels: INFO, HIGH, CRITICAL. "
            "Return ONLY a JSON object with keys: "
            "corrected_label (one of INFO/HIGH/CRITICAL, or null if no correction needed), "
            "dismiss (bool — true if analyst says this is benign/noise), "
            "reason (string — brief reason). "
            "No explanation, no markdown, just the JSON object."
        ),
        messages=[{
            "role": "user",
            "content": f"Alert: {json.dumps(alert)}\nAnalyst feedback: {analyst_text}",
        }],
    )
    try:
        return json.loads(response.content[0].text)
    except json.JSONDecodeError:
        log.warning("LLM returned non-JSON for parse_feedback")
        return {"corrected_label": None, "dismiss": False, "reason": analyst_text}


async def ask(alerts_context: list[dict], question: str) -> str:
    """Answer an analyst question about the current alert set."""
    client = get_client()
    context_str = json.dumps(alerts_context[:20])   # cap to avoid token overflow
    response = await client.messages.create(
        model=MODEL,
        max_tokens=512,
        system=(
            "You are a network security analyst assistant. "
            "Answer questions about the provided alert data concisely and accurately."
        ),
        messages=[{
            "role": "user",
            "content": f"Recent alerts: {context_str}\n\nQuestion: {question}",
        }],
    )
    return response.content[0].text
