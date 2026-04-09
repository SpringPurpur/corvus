# main.py — starts all threads and runs uvicorn.
#
# Thread layout:
#   Thread 1 (daemon): Unix socket server — socket_reader.run_socket_server()
#   Thread 2 (daemon): inference worker   — reads flow_queue, runs classifier
#   Thread 3 (main):   uvicorn asyncio event loop — FastAPI + WebSocket
#
# The inference worker puts completed alert dicts onto alert_queue. A background
# asyncio task drains alert_queue and broadcasts via the WebSocket manager.

import argparse
import asyncio
import logging
import queue
import threading
import time

import uvicorn

import llm
import online_detector as _od
import storage
from classifier import Classifier
from server import app, configure
from socket_reader import run_socket_server
from ws_handler import manager, notify_capture_up

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
)
log = logging.getLogger(__name__)


def _inference_worker(
    flow_queue: queue.Queue,
    alert_queue: asyncio.Queue,
    loop: asyncio.AbstractEventLoop,
    classifier: Classifier,
) -> None:
    """Drain flow_queue, run inference, push alerts onto the asyncio alert_queue.

    Accesses tcp_detector / udp_detector through the _od module reference so
    that post-reset reassignments in online_detector are always visible — a
    local 'from online_detector import tcp_detector' would capture the old
    object and produce stale stats after a baseline reset.
    """
    _stats_counter = 0
    _capture_signalled = False   # True once the first flow is dequeued
    _detector_was_ready = False  # tracks tcp_detector.is_ready transitions

    while True:
        try:
            flow = flow_queue.get(timeout=1.0)
        except queue.Empty:
            continue

        # ── Signal capture-engine liveness on the first flow ──────────────────
        if not _capture_signalled:
            _capture_signalled = True
            notify_capture_up()
            loop.call_soon_threadsafe(
                alert_queue.put_nowait,
                {"type": "status", "capture": True,
                 "models": _od.tcp_detector.is_ready},
            )

        try:
            alert = classifier.predict(flow)
        except Exception as exc:
            log.error("Classifier error: %s", exc)
            continue

        if alert is None:
            continue

        # During baselining process_flow() returns {"status": "baselining", ...}
        # — forward progress to the dashboard and skip alert logging.
        if alert.get("type") == "baselining":
            loop.call_soon_threadsafe(
                alert_queue.put_nowait,
                {"type": "status",
                 "capture": True,
                 "baselining": True,
                 "progress": alert.get("progress", 0.0),
                 "protocol": alert.get("protocol", "")},
            )
            continue

        # ── Detect tcp_detector readiness transition ───────────────────────────
        # Covers both initial baseline completion and re-baselining after reset.
        now_ready = _od.tcp_detector.is_ready
        if now_ready and not _detector_was_ready:
            loop.call_soon_threadsafe(
                alert_queue.put_nowait,
                {"type": "status", "capture": True,
                 "models": True, "baselining": False},
            )
        _detector_was_ready = now_ready

        log.info("Alert: proto=%s label=%s src=%s:%s dst=%s:%s",
                 alert["proto"], alert["verdict"]["label"],
                 alert["src_ip"], alert["src_port"],
                 alert["dst_ip"], alert["dst_port"])
        storage.insert_flow(alert)
        loop.call_soon_threadsafe(alert_queue.put_nowait, alert)

        # Broadcast OIF health metrics every 10 flows so the dashboard
        # Model Health panel updates in near-real-time without flooding the socket.
        _stats_counter += 1
        if _stats_counter % 10 == 0:
            loop.call_soon_threadsafe(
                alert_queue.put_nowait,
                {"type": "stats",
                 "tcp": _od.tcp_detector.metrics() | {"ready": _od.tcp_detector.is_ready},
                 "udp": _od.udp_detector.metrics() | {"ready": _od.udp_detector.is_ready}},
            )


async def _broadcast_worker(alert_queue: asyncio.Queue) -> None:
    """Drain the asyncio alert_queue and broadcast each item to all WS clients.

    Status messages (baselining progress) are already fully-formed dicts with
    a 'type' key and are broadcast as-is. Alert dicts are wrapped in the
    standard {'type': 'alert', 'data': ...} envelope.
    """
    while True:
        item = await alert_queue.get()
        if item.get("type") in ("status", "stats"):
            await manager.broadcast(item)
        else:
            # Stamp WebSocket send time, then strip timing from the nested dict
            # so it travels as a flat block inside the alert envelope.
            timing = item.pop("_timing", None)
            if timing:
                timing["t_ws_ns"] = time.time_ns()
                item["timing"] = timing
            await manager.broadcast({"type": "alert", "data": item})


async def _run(args: argparse.Namespace) -> None:
    loop = asyncio.get_running_loop()

    # Unbounded queue — Thread 1 (socket reader) must never block on put().
    # A size limit causes blocking which backs up the Unix socket buffer and
    # then the C ring buffer, creating a latency cascade under flood load.
    # Memory cost is negligible: ~500 bytes × worst-case 50k queued flows ≈ 25 MB.
    flow_queue: queue.Queue = queue.Queue()
    alert_queue: asyncio.Queue = asyncio.Queue()

    storage.init_db()

    classifier = Classifier(anomaly_only=args.anomaly_only)
    if args.anomaly_only:
        log.warning("Running in anomaly-only mode — classification models not loaded")

    configure(alert_queue, llm)

    # Thread 1 — Unix socket server
    t_socket = threading.Thread(
        target=run_socket_server,
        args=(flow_queue,),
        daemon=True,
        name="socket-reader",
    )
    t_socket.start()

    # Thread 2 — inference worker
    t_infer = threading.Thread(
        target=_inference_worker,
        args=(flow_queue, alert_queue, loop, classifier),
        daemon=True,
        name="inference-worker",
    )
    t_infer.start()

    # Asyncio task — broadcast worker
    asyncio.create_task(_broadcast_worker(alert_queue))

    # Thread 3 — uvicorn (runs inside the asyncio loop)
    config = uvicorn.Config(
        app,
        host="0.0.0.0",
        port=8765,
        log_level="warning",   # uvicorn access logs are noisy; use our own
    )
    server = uvicorn.Server(config)
    await server.serve()


def main() -> None:
    parser = argparse.ArgumentParser(description="Corvus IDS inference engine")
    parser.add_argument(
        "--anomaly-only",
        action="store_true",
        help=(
            "Run without classification models — anomaly detection only. "
            "Use when pkl files are not yet available."
        ),
    )
    args = parser.parse_args()
    asyncio.run(_run(args))


if __name__ == "__main__":
    main()
