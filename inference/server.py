# server.py — FastAPI app: WebSocket /ws, GET /health, StaticFiles /.
#
# The app is mounted with StaticFiles last so /ws and /health take priority.
# CORSMiddleware allows the Vite dev server (localhost:5173) during development.
# In production the browser is served from the same origin — no CORS needed.

import asyncio
import logging
from pathlib import Path

from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from ws_handler import handle_websocket, manager

log = logging.getLogger(__name__)

STATIC_DIR = Path("/app/static")

app = FastAPI(title="Corvus IDS")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],   # Vite dev server
    allow_methods=["*"],
    allow_headers=["*"],
)

# Injected by main.py after startup so WebSocket handler can call LLM functions
_llm_handler = None
_alert_queue: asyncio.Queue | None = None


def configure(alert_queue: asyncio.Queue, llm_handler) -> None:
    """Called once from main.py before uvicorn starts."""
    global _alert_queue, _llm_handler
    _alert_queue = alert_queue
    _llm_handler = llm_handler


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket) -> None:
    await handle_websocket(ws, _alert_queue, _llm_handler)


# Serve built React bundle — mounted last so API routes take priority.
# Only mounted if the static directory exists; during development the Vite
# dev server serves the frontend instead.
if STATIC_DIR.exists():
    app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")
else:
    log.warning("Static dir %s not found — dashboard will not be served. "
                "Use the Vite dev server at http://localhost:5173 instead.", STATIC_DIR)
