# server.py — FastAPI app: WebSocket /ws, GET /health, StaticFiles /.
#
# The app is mounted with StaticFiles last so /ws and /health take priority.
# CORSMiddleware allows the Vite dev server (localhost:5173) during development.
# In production the browser is served from the same origin — no CORS needed.
#
# Authentication:
#   Set CORVUS_API_KEY in the environment to require authentication.
#   API endpoints: X-API-Key: <key> request header.
#   WebSocket /ws: ?key=<key> query parameter (browsers can't set WS headers).
#   Leave CORVUS_API_KEY unset (or empty) to disable — suitable for trusted
#   networks or local development.

import asyncio
import logging
import os
import time
from dataclasses import asdict
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Query, WebSocket
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.responses import Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, field_validator
from starlette.requests import Request as StarletteRequest

import config as cfg_module
import storage
from ws_handler import handle_websocket, manager

log = logging.getLogger(__name__)

STATIC_DIR = Path("/app/static")

# ── API key authentication ─────────────────────────────────────────────────────
# Read once at startup; requires container restart to change.
_API_KEY = os.environ.get("CORVUS_API_KEY", "").strip()

# Paths that bypass authentication — health probes and the dashboard bundle.
_OPEN_PATHS = {"/health", "/llm/status"}


class _ApiKeyMiddleware(BaseHTTPMiddleware):
    """Enforce X-API-Key header (or ?key= for WebSocket) when CORVUS_API_KEY is set."""

    async def dispatch(self, request: StarletteRequest, call_next):
        if not _API_KEY:
            return await call_next(request)          # auth disabled

        path = request.url.path

        # Always open: health probes and the static dashboard bundle
        if path in _OPEN_PATHS:
            return await call_next(request)
        if path == "/" or (path.count("/") == 1 and "." in path):
            # Static asset (e.g. /index.html, /assets/main.js)
            return await call_next(request)

        # WebSocket — check query param (browser JS cannot set custom WS headers)
        if path == "/ws":
            if request.query_params.get("key") == _API_KEY:
                return await call_next(request)
            log.warning("WS connection rejected — missing or wrong key from %s",
                        request.client)
            return Response("Unauthorized", status_code=401)

        # All other API routes — check header
        if request.headers.get("X-API-Key") == _API_KEY:
            return await call_next(request)

        log.warning("API request rejected — missing or wrong key: %s %s",
                    request.method, path)
        return Response(
            '{"detail":"Unauthorized — X-API-Key header required"}',
            status_code=401,
            media_type="application/json",
        )


app = FastAPI(title="Corvus IDS")

# Auth middleware must be added before CORS so it runs outermost
app.add_middleware(_ApiKeyMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],   # Vite dev server
    allow_methods=["*"],
    allow_headers=["*", "X-API-Key"],
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


@app.get("/llm/status")
async def llm_status() -> dict:
    """Return whether the LLM integration is available.

    Checks that ANTHROPIC_API_KEY is set and non-empty — no API call is made,
    so this endpoint is free and instant.
    """
    import os
    available = bool(os.environ.get("ANTHROPIC_API_KEY", "").strip())
    return {"available": available}


class ConfigBody(BaseModel):
    threshold_high:     float
    threshold_critical: float
    baseline_tcp:       int
    baseline_udp:       int
    min_tcp_pkts:       int  = 4
    filter_gateway:     bool = False

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

    @field_validator("min_tcp_pkts")
    @classmethod
    def _check_min_pkts(cls, v: int) -> int:
        if not (2 <= v <= 20):
            raise ValueError("min_tcp_pkts must be between 2 and 20")
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


@app.get("/window_history")
async def get_window_history(
    proto:  str            = Query(default="TCP"),
    since:  Optional[float] = Query(default=None),
    bucket: int            = Query(default=300, ge=10, le=3600),
) -> list:
    """Time-bucketed average per-window OIF scores for the heatmap ribbon.

    Defaults to the last 24 h at 5-minute bucket resolution.
    """
    if since is None:
        since = time.time() - 86_400
    return await run_in_threadpool(
        storage.query_window_history,
        proto=proto, since=since, bucket_sec=bucket,
    )


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


class BulkFeedbackBody(BaseModel):
    flow_ids:        list[str]
    dismiss:         bool = True
    corrected_label: Optional[str] = None
    reason:          str = "Bulk dismissed as false positive"


@app.post("/feedback/bulk")
async def post_feedback_bulk(body: BulkFeedbackBody) -> dict:
    """Write dismiss/correction feedback for multiple flows in a single transaction."""
    n = await run_in_threadpool(
        storage.upsert_feedback_bulk,
        body.flow_ids, body.dismiss, body.corrected_label, body.reason,
    )
    return {"ok": True, "written": n}


@app.delete("/flows")
async def delete_flows() -> dict:
    n = await run_in_threadpool(storage.clear_flows)
    return {"deleted": n}


@app.delete("/queue")
async def drain_queue() -> dict:
    """Discard all flows currently waiting in the inference queues.

    Used by the dashboard when the queue depth spikes (e.g. after a port scan
    with min_tcp_pkts=2) and the operator wants to resume normal operation
    without waiting for the backlog to drain naturally.
    """
    import queue as _queue

    def _drain(q) -> int:
        n = 0
        if q is None:
            return 0
        while True:
            try:
                q.get_nowait()
                n += 1
            except _queue.Empty:
                break
        return n

    n = await run_in_threadpool(
        lambda: _drain(_flow_queue) + _drain(_tcp_queue) + _drain(_udp_queue)
    )
    log.info("Queue drained: %d flows discarded", n)
    return {"drained": n}


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


@app.get("/export/flows.ndjson")
async def export_flows_ndjson() -> StreamingResponse:
    """Stream all flow records as NDJSON (one JSON object per line).

    Includes per-window scores and attribution — suitable for re-running
    through other ML models or comparative analysis in the thesis.
    """
    return StreamingResponse(
        storage.iter_flows_ndjson(),
        media_type="application/x-ndjson",
        headers={"Content-Disposition": 'attachment; filename="corvus_flows.ndjson"'},
    )


@app.get("/export/summary.csv")
async def export_summary_csv() -> Response:
    """Export hourly aggregate statistics as CSV.

    Columns: hour, proto, total_flows, critical, high, info,
             mean_score, max_score, mean_oif_ms.
    Useful for the paper's stability and latency graphs.
    """
    rows = await run_in_threadpool(storage.query_hourly_summary)
    lines = ["hour,proto,total_flows,critical,high,info,mean_score,max_score,mean_oif_ms"]
    for r in rows:
        oif = f"{r['mean_oif_ms']:.4f}" if r["mean_oif_ms"] is not None else ""
        lines.append(
            f"{r['hour']},{r['proto']},{r['total']},"
            f"{r['critical']},{r['high']},{r['info']},"
            f"{r['mean_score']:.6f},{r['max_score']:.6f},{oif}"
        )
    return Response(
        content="\n".join(lines),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="corvus_summary.csv"'},
    )


@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket) -> None:
    await handle_websocket(ws, _alert_queue, _llm_handler)


# ── Capture configuration ──────────────────────────────────────────────────────
# capture.json is bind-mounted into both the inference and monitor containers.
# Inference writes it; monitor reads it on each restart of capture_engine.

import json as _json

_CAPTURE_CONFIG = Path("/app/capture.json")
_MONITOR_CONTAINER = "ids_monitor"


def _read_capture_cfg() -> dict:
    try:
        return _json.loads(_CAPTURE_CONFIG.read_text()) if _CAPTURE_CONFIG.exists() else {}
    except Exception:
        return {}


def _write_capture_cfg(data: dict) -> None:
    _CAPTURE_CONFIG.write_text(_json.dumps(data, indent=2))


@app.get("/capture/interfaces")
async def get_capture_interfaces() -> dict:
    """List network interfaces visible to the monitor container via Docker exec.

    Returns three things so the dashboard can show a complete picture:
      config  — what the analyst configured in capture.json (requested)
      status  — what the monitor is actually running right now (_status key)
      interfaces — live interface list from the monitor container
    Requires /var/run/docker.sock to be mounted.
    """
    try:
        import docker as docker_sdk
    except ImportError:
        raise HTTPException(500, "docker SDK not installed")

    def _list() -> list:
        client = docker_sdk.DockerClient(base_url="unix://var/run/docker.sock")
        try:
            container = client.containers.get(_MONITOR_CONTAINER)
            result = container.exec_run(["ip", "-o", "link", "show"], stdout=True, stderr=False)
            interfaces = []
            for line in result.output.decode().strip().splitlines():
                # Format: "2: eth0: <FLAGS> ..."  or  "3: eth0@if4: ..."
                parts = line.split(":", 2)
                if len(parts) < 3:
                    continue
                name = parts[1].strip().split("@")[0]
                flags = parts[2]
                if name == "lo":
                    continue
                interfaces.append({
                    "name": name,
                    "up": "UP" in flags,
                    "promisc": "PROMISC" in flags,
                })
            return interfaces
        finally:
            client.close()

    try:
        ifaces = await run_in_threadpool(_list)
        raw = _read_capture_cfg()
        # Separate out the _status key written by monitor/start.sh
        status = raw.pop("_status", {})
        return {"interfaces": ifaces, "config": raw, "status": status}
    except Exception as exc:
        raise HTTPException(500, str(exc))


class CaptureConfigBody(BaseModel):
    interface: Optional[str] = None
    filter:    Optional[str] = None
    promisc:   bool = False   # set the interface promiscuous before (re)starting
    restart:   bool = True    # kill capture_engine so the restart loop picks up changes


@app.post("/capture/config")
async def post_capture_config(body: CaptureConfigBody) -> dict:
    """Write capture.json and optionally set promisc + restart the capture engine.

    The monitor container's start.sh restart loop reads capture.json on every
    iteration, so killing capture_engine is enough to apply the new config.
    """
    cfg: dict = {}
    if body.interface:
        cfg["interface"] = body.interface
    if body.filter:
        cfg["filter"] = body.filter
    _write_capture_cfg(cfg)

    if not body.restart and not body.promisc:
        return {"ok": True, "config": cfg}

    try:
        import docker as docker_sdk
    except ImportError:
        # Config written; caller must restart the container manually.
        return {"ok": True, "config": cfg, "warning": "docker SDK not installed — restart monitor manually"}

    def _apply() -> None:
        client = docker_sdk.DockerClient(base_url="unix://var/run/docker.sock")
        try:
            container = client.containers.get(_MONITOR_CONTAINER)
            if body.interface and body.promisc:
                container.exec_run(
                    ["ip", "link", "set", body.interface, "promisc", "on"],
                    detach=False,
                )
                log.info("[capture] set %s promisc on", body.interface)
            if body.restart:
                container.exec_run(["pkill", "-f", "capture_engine"], detach=True)
                log.info("[capture] capture_engine restarted via pkill")
        finally:
            client.close()

    try:
        await run_in_threadpool(_apply)
        return {"ok": True, "config": cfg}
    except Exception as exc:
        log.error("[capture] config apply failed: %s", exc)
        raise HTTPException(500, str(exc))


@app.get("/capture/config")
async def get_capture_config() -> dict:
    """Return the current capture.json contents."""
    return _read_capture_cfg()


# Serve built React bundle — mounted last so API routes take priority.
# Only mounted if the static directory exists; during development the Vite
# dev server serves the frontend instead.
if STATIC_DIR.exists():
    app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")
else:
    log.warning("Static dir %s not found — dashboard will not be served. "
                "Use the Vite dev server at http://localhost:5173 instead.", STATIC_DIR)
