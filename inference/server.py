# server.py — FastAPI app: WebSocket /ws, GET /health, StaticFiles /.
#
# The app is mounted with StaticFiles last so /ws and /health take priority.
# CORSMiddleware allows the Vite dev server (localhost:5173) during development.
# In production the browser is served from the same origin — no CORS needed.

import asyncio
import logging
from dataclasses import asdict
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Query, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, field_validator

import config as cfg_module
import storage
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


class ConfigBody(BaseModel):
    threshold_high:     float
    threshold_critical: float
    baseline_tcp:       int
    baseline_udp:       int

    @field_validator("threshold_high", "threshold_critical")
    @classmethod
    def _check_threshold(cls, v: float) -> float:
        if not (0.0 < v < 1.0):
            raise ValueError("threshold must be between 0 and 1")
        return v

    @field_validator("baseline_tcp", "baseline_udp")
    @classmethod
    def _check_baseline(cls, v: int) -> int:
        if v < 64:
            raise ValueError("baseline must be at least 64 flows")
        return v


@app.get("/config")
async def get_config() -> dict:
    return asdict(cfg_module.cfg)


@app.post("/config")
async def post_config(body: ConfigBody) -> dict:
    if body.threshold_high >= body.threshold_critical:
        raise HTTPException(400, "threshold_high must be less than threshold_critical")
    cfg_module.update(cfg_module.AppConfig(**body.model_dump()))
    return {"ok": True}


@app.post("/baseline/reset")
async def reset_baseline(protocol: str = Query(default="all")) -> dict:
    if protocol not in ("TCP", "UDP", "all"):
        raise HTTPException(400, "protocol must be TCP, UDP, or all")
    # Import here to avoid circular import — online_detector imports config
    from online_detector import reset_detector
    reset_detector(protocol)
    return {"ok": True, "protocol": protocol}


@app.get("/flows")
async def get_flows(
    limit: int = Query(default=200, ge=1, le=2000),
    proto: Optional[str] = Query(default=None),
    label: Optional[str] = Query(default=None),
    src_ip: Optional[str] = Query(default=None),
) -> list:
    return storage.query_flows(limit=limit, proto=proto, label=label, src_ip=src_ip)


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
