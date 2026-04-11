# server.py — FastAPI app: WebSocket /ws, GET /health, StaticFiles /.
#
# The app is mounted with StaticFiles last so /ws and /health take priority.
# CORSMiddleware allows the Vite dev server (localhost:5173) during development.
# In production the browser is served from the same origin — no CORS needed.

import asyncio
import logging
import time
from dataclasses import asdict
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Query, WebSocket
from fastapi.concurrency import run_in_threadpool
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
# Thread queues exposed for /stats queue_depth — set by configure()
_tcp_queue = None
_udp_queue = None
_flow_queue = None


def configure(alert_queue: asyncio.Queue, llm_handler,
              tcp_queue=None, udp_queue=None, flow_queue=None) -> None:
    """Called once from main.py before uvicorn starts."""
    global _alert_queue, _llm_handler, _tcp_queue, _udp_queue, _flow_queue
    _alert_queue = alert_queue
    _llm_handler = llm_handler
    _tcp_queue   = tcp_queue
    _udp_queue   = udp_queue
    _flow_queue  = flow_queue


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


@app.get("/stats")
async def get_stats() -> dict:
    from online_detector import tcp_detector, udp_detector
    tcp_q = _tcp_queue.qsize()  if _tcp_queue  is not None else None
    udp_q = _udp_queue.qsize()  if _udp_queue  is not None else None
    flow_q = _flow_queue.qsize() if _flow_queue is not None else None
    return {
        "tcp":  tcp_detector.metrics()  | {"ready": tcp_detector.is_ready},
        "udp":  udp_detector.metrics()  | {"ready": udp_detector.is_ready},
        "queue_depth": {
            "tcp":  tcp_q,
            "udp":  udp_q,
            "flow": flow_q,
            "total": (tcp_q or 0) + (udp_q or 0) + (flow_q or 0),
        },
    }


class PhaseOpenBody(BaseModel):
    run_id:      str
    scenario:    str
    phase:       str   # baseline | attack | benign | recovery
    t_start:     float
    attacker_ip: Optional[str] = None

class PhaseCloseBody(BaseModel):
    t_end: float

@app.post("/phases")
async def open_phase(body: PhaseOpenBody) -> dict:
    """Record the start of an eval phase. Returns the phase row id."""
    phase_id = await run_in_threadpool(
        storage.write_phase,
        body.run_id, body.scenario, body.phase, body.t_start, body.attacker_ip,
    )
    return {"phase_id": phase_id}

@app.patch("/phases/{phase_id}")
async def close_phase(phase_id: int, body: PhaseCloseBody) -> dict:
    """Set t_end on an open phase row."""
    await run_in_threadpool(storage.close_phase, phase_id, body.t_end)
    return {"ok": True}

@app.get("/phases")
async def get_phases(run_id: Optional[str] = None) -> list:
    """Return phase records, optionally filtered by run_id."""
    return await run_in_threadpool(storage.query_phases, run_id)


@app.get("/baseline/stats")
async def get_baseline_stats() -> dict:
    """Return the fitted scaler's median and IQR per feature for each detector.

    Useful for diagnosing false positives: a feature with a very small IQR
    (after floor application) will produce large OOR deviations for flows
    that differ from the baseline distribution.
    """
    from online_detector import tcp_detector, udp_detector
    return {
        "tcp": {
            "ready":    tcp_detector.is_ready,
            "features": tcp_detector.baseline_stats(),
        },
        "udp": {
            "ready":    udp_detector.is_ready,
            "features": udp_detector.baseline_stats(),
        },
    }


@app.get("/time")
async def get_server_time() -> dict:
    """Return the server's current Unix timestamp.

    Used by the scenario runner to compute the host-to-container clock offset.
    Flow timestamps (ts) come from the C engine's CLOCK_REALTIME; this endpoint
    lets the runner align its own time.time() values with those timestamps.
    """
    return {"ts": time.time()}


@app.get("/flows")
async def get_flows(
    limit: int = Query(default=200, ge=1, le=50000),
    proto: Optional[str] = Query(default=None),
    label: Optional[str] = Query(default=None),
    src_ip: Optional[str] = Query(default=None),
    ts_from: Optional[float] = Query(default=None),
    ts_to: Optional[float] = Query(default=None),
) -> list:
    # Run the SQLite query in a thread pool to avoid blocking the asyncio event
    # loop. Under flood load (thousands of flows) the query can take several
    # seconds; blocking here starves uvicorn and causes clients to time out.
    return await run_in_threadpool(
        storage.query_flows,
        limit=limit, proto=proto, label=label,
        src_ip=src_ip, ts_from=ts_from, ts_to=ts_to,
    )


@app.get("/feedback")
async def get_feedback(flow_id: Optional[str] = Query(default=None)) -> list:
    return await run_in_threadpool(storage.query_feedback, flow_id=flow_id)


@app.delete("/flows")
async def delete_flows() -> dict:
    n = storage.clear_flows()
    return {"deleted": n}


_BASELINE_NODES = [
    "ids_node_1", "ids_node_2", "ids_node_3",
    "ids_node_4", "ids_node_5",
]

@app.post("/dev/fast-baseline")
async def dev_fast_baseline() -> dict:
    """Trigger fast_baseline.sh on all victim node containers in parallel.

    Requires /var/run/docker.sock to be mounted into this container.
    Each node runs the script in the background (detach=True) so this
    endpoint returns immediately without waiting for traffic to complete.
    """
    try:
        import docker as docker_sdk
    except ImportError:
        raise HTTPException(500, "docker SDK not installed — rebuild the inference image")

    def _exec_all() -> dict:
        triggered = []
        skipped = []
        try:
            client = docker_sdk.DockerClient(base_url="unix://var/run/docker.sock")
        except Exception as exc:
            raise RuntimeError(f"Cannot connect to Docker socket: {exc}") from exc

        try:
            for node in _BASELINE_NODES:
                try:
                    container = client.containers.get(node)
                    container.exec_run(
                        ["bash", "/scripts/fast_baseline.sh"],
                        detach=True,
                    )
                    triggered.append(node)
                    log.info("[dev] fast_baseline.sh started on %s", node)
                except docker_sdk.errors.NotFound:
                    log.warning("[dev] Container %s not found — skipping", node)
                    skipped.append(node)
        finally:
            client.close()

        return {"triggered": triggered, "skipped": skipped}

    try:
        result = await run_in_threadpool(_exec_all)
        return {"ok": True, **result}
    except Exception as exc:
        log.error("[dev] fast-baseline failed: %s", exc)
        raise HTTPException(500, str(exc))


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
