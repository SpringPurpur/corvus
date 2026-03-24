# ws_handler.py — WebSocket connection manager, MessagePack framing, message routing.
#
# All messages are MessagePack binary — never JSON. Downstream frames carry
# alerts and status; upstream frames carry feedback and LLM requests.
# The connection manager keeps a set of active WebSocket connections and
# broadcasts to all of them when a new alert arrives.

import asyncio
import json
import logging
import time
from typing import Any

import msgpack
from fastapi import WebSocket, WebSocketDisconnect

log = logging.getLogger(__name__)


class ConnectionManager:
    def __init__(self) -> None:
        self._connections: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self._connections.add(ws)
        log.debug("WS client connected — %d total", len(self._connections))

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            self._connections.discard(ws)
        log.debug("WS client disconnected — %d remaining", len(self._connections))

    async def broadcast(self, message: dict[str, Any]) -> None:
        """Encode message as MessagePack and send to all connected clients."""
        data = msgpack.packb(message, use_bin_type=True)
        dead: list[WebSocket] = []

        async with self._lock:
            connections = set(self._connections)

        for ws in connections:
            try:
                await ws.send_bytes(data)
            except Exception:
                # Client disconnected mid-send — mark for removal
                dead.append(ws)

        if dead:
            async with self._lock:
                for ws in dead:
                    self._connections.discard(ws)

    async def send(self, ws: WebSocket, message: dict[str, Any]) -> None:
        """Send a MessagePack message to a single client."""
        data = msgpack.packb(message, use_bin_type=True)
        await ws.send_bytes(data)


# Module-level singleton — imported by server.py and main.py
manager = ConnectionManager()


async def handle_websocket(
    ws: WebSocket,
    alert_broadcaster: asyncio.Queue,
    llm_handler: Any,         # llm.py functions, passed in to avoid circular import
) -> None:
    """Handle a single WebSocket connection lifecycle.

    Runs two concurrent tasks:
      - pump_alerts: drains alert_broadcaster and sends to this client
      - receive_loop: reads upstream frames (feedback, llm_request)
    """
    await manager.connect(ws)
    try:
        await asyncio.gather(
            _receive_loop(ws, llm_handler),
            return_exceptions=True,
        )
    except WebSocketDisconnect:
        pass
    finally:
        await manager.disconnect(ws)


async def _receive_loop(ws: WebSocket, llm_handler: Any) -> None:
    """Read upstream frames from the browser and dispatch them."""
    while True:
        try:
            data = await ws.receive_bytes()
        except WebSocketDisconnect:
            break

        try:
            msg = msgpack.unpackb(data, raw=False)
        except Exception as exc:
            log.warning("Failed to decode MessagePack frame: %s", exc)
            continue

        msg_type = msg.get("type")

        if msg_type == "feedback":
            import storage
            storage.upsert_feedback(
                flow_id=msg.get("flow_id", ""),
                ts=time.time(),
                corrected_label=msg.get("corrected_label"),
                dismiss=bool(msg.get("dismiss", False)),
                reason=msg.get("reason", ""),
            )
            log.info("Feedback stored for flow_id=%s", msg.get("flow_id"))

        elif msg_type == "llm_request":
            # Browser asks for an LLM explanation — call async and reply
            asyncio.create_task(_handle_llm_request(ws, msg, llm_handler))

        else:
            log.warning("Unknown upstream message type: %s", msg_type)


async def _handle_llm_request(
    ws: WebSocket,
    msg: dict,
    llm_handler: Any,
) -> None:
    """Call the appropriate LLM function and send the response back."""
    request_id = msg.get("request_id", "")
    fn_name = msg.get("fn")
    payload = msg.get("payload", {})

    try:
        if fn_name == "explain":
            text = await llm_handler.explain(payload)
        elif fn_name == "ask":
            text = await llm_handler.ask(
                payload.get("alerts_context", []),
                payload.get("question", ""),
            )
        elif fn_name == "parse_feedback":
            alert = payload.get("alert", {})
            analyst_text = payload.get("analyst_text", "")
            result = await llm_handler.parse_feedback(alert, analyst_text)
            import storage
            storage.upsert_feedback(
                flow_id=alert.get("flow_id", ""),
                ts=time.time(),
                corrected_label=result.get("corrected_label"),
                dismiss=bool(result.get("dismiss", False)),
                reason=result.get("reason", ""),
                analyst_text=analyst_text,
            )
            text = json.dumps(result)
        else:
            text = f"Unknown function: {fn_name}"
    except Exception as exc:
        log.error("LLM request failed: %s", exc)
        text = "Explanation unavailable."

    await manager.send(ws, {
        "type":       "llm_response",
        "request_id": request_id,
        "text":       text,
    })
