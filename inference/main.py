# main.py — starts all threads and runs uvicorn.
#
# Thread layout:
#   Thread 1 (daemon): Unix socket server  — socket_reader.run_socket_server()
#   Thread 2 (daemon): flow router         — dispatches flow_queue → tcp_queue / udp_queue
#   Thread 3 (daemon): TCP inference worker — reads tcp_queue, runs classifier
#   Thread 4 (daemon): UDP inference worker — reads udp_queue, runs classifier
#   Thread 5 (main):   uvicorn asyncio event loop — FastAPI + WebSocket
#
# Protocol split rationale: tcp_detector and udp_detector have zero shared
# state — splitting them onto separate threads gives true parallel inference
# without any locking. During a SYN flood (TCP-only), the UDP worker is
# unaffected. Each worker accesses only its own detector, so the OIF arrays
# are never accessed from two threads simultaneously.
#
# Stats broadcasting: each protocol worker broadcasts combined tcp+udp stats
# every 20 flows processed by that worker. Messages are read-only accesses to
# both detectors via the module reference, which is safe under the GIL.

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

# ── First-flow synchronisation ─────────────────────────────────────────────────
# Either protocol worker may see the first flow. Use a threading.Event so the
# "capture is up" signal fires exactly once regardless of which worker fires first.
_capture_event = threading.Event()


def _router(
    flow_queue: queue.Queue,
    tcp_queue:  queue.Queue,
    udp_queue:  queue.Queue,
) -> None:
    """Dispatch flows from the shared socket queue to protocol-specific queues.

    Other protocols are dropped here — process_flow already filters them, but
    routing keeps the per-protocol workers clean and removes any dict lookup
    from their hot path.
    """
    while True:
        try:
            flow = flow_queue.get(timeout=1.0)
        except queue.Empty:
            continue
        proto = flow.get("protocol")
        if proto == 6:
            tcp_queue.put(flow)
        elif proto == 17:
            udp_queue.put(flow)


def _protocol_worker(
    proto_queue:      queue.Queue,
    alert_queue:      asyncio.Queue,
    loop:             asyncio.AbstractEventLoop,
    classifier:       Classifier,
    proto_name:       str,   # "TCP" or "UDP"
) -> None:
    """Inference worker for a single protocol.

    Accesses only the detector for its own protocol via classifier.predict(),
    which internally routes to tcp_detector or udp_detector based on the flow's
    protocol field. No shared mutable state with the other protocol worker.
    """
    _detector_was_ready = False
    _stats_counter      = 0

    while True:
        try:
            flow = proto_queue.get(timeout=1.0)
        except queue.Empty:
            continue

        # ── Signal capture-engine liveness on the first flow (any protocol) ───
        if not _capture_event.is_set():
            _capture_event.set()
            notify_capture_up()
            loop.call_soon_threadsafe(
                alert_queue.put_nowait,
                {"type": "status", "capture": True,
                 "models": _od.tcp_detector.is_ready},
            )

        try:
            alert = classifier.predict(flow)
        except Exception as exc:
            log.error("[%s] Classifier error: %s", proto_name, exc)
            continue

        if alert is None:
            continue

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

        # ── Detect tcp_detector readiness transition ──────────────────────────
        # Both workers check tcp_detector.is_ready because the dashboard "Models"
        # indicator is keyed on TCP (the primary detector). UDP readiness is
        # surfaced through the stats message.
        now_ready = _od.tcp_detector.is_ready
        if now_ready and not _detector_was_ready:
            loop.call_soon_threadsafe(
                alert_queue.put_nowait,
                {"type": "status", "capture": True,
                 "models": True, "baselining": False},
            )
        _detector_was_ready = now_ready

        log.info("[%s] Alert: label=%s src=%s:%s dst=%s:%s",
                 proto_name, alert["verdict"]["label"],
                 alert["src_ip"], alert["src_port"],
                 alert["dst_ip"], alert["dst_port"])
        storage.insert_flow(alert)
        loop.call_soon_threadsafe(alert_queue.put_nowait, alert)

        # Broadcast OIF health metrics every 20 flows.
        # Both workers broadcast combined tcp+udp stats — the dashboard
        # always gets a fresh view regardless of which protocol is active.
        _stats_counter += 1
        if _stats_counter % 20 == 0:
            loop.call_soon_threadsafe(
                alert_queue.put_nowait,
                {"type": "stats",
                 "tcp": _od.tcp_detector.metrics() | {"ready": _od.tcp_detector.is_ready},
                 "udp": _od.udp_detector.metrics() | {"ready": _od.udp_detector.is_ready}},
            )


async def _broadcast_worker(alert_queue: asyncio.Queue) -> None:
    """Drain the asyncio alert_queue and broadcast each item to all WS clients."""
    while True:
        item = await alert_queue.get()
        if item.get("type") in ("status", "stats"):
            await manager.broadcast(item)
        else:
            timing = item.pop("_timing", None)
            if timing:
                timing["t_ws_ns"] = time.time_ns()
                item["timing"] = timing
            await manager.broadcast({"type": "alert", "data": item})


async def _run(args: argparse.Namespace) -> None:
    loop = asyncio.get_running_loop()

    # Unbounded queues — socket reader and router must never block on put().
    flow_queue: queue.Queue = queue.Queue()
    tcp_queue:  queue.Queue = queue.Queue()
    udp_queue:  queue.Queue = queue.Queue()
    alert_queue: asyncio.Queue = asyncio.Queue()

    storage.init_db()

    classifier = Classifier(anomaly_only=args.anomaly_only)
    if args.anomaly_only:
        log.warning("Running in anomaly-only mode — classification models not loaded")

    configure(alert_queue, llm)

    # Thread 1 — Unix socket server
    threading.Thread(
        target=run_socket_server,
        args=(flow_queue,),
        daemon=True,
        name="socket-reader",
    ).start()

    # Thread 2 — router
    threading.Thread(
        target=_router,
        args=(flow_queue, tcp_queue, udp_queue),
        daemon=True,
        name="flow-router",
    ).start()

    # Thread 3 — TCP inference worker
    threading.Thread(
        target=_protocol_worker,
        args=(tcp_queue, alert_queue, loop, classifier, "TCP"),
        daemon=True,
        name="tcp-worker",
    ).start()

    # Thread 4 — UDP inference worker
    threading.Thread(
        target=_protocol_worker,
        args=(udp_queue, alert_queue, loop, classifier, "UDP"),
        daemon=True,
        name="udp-worker",
    ).start()

    # Asyncio task — broadcast worker
    asyncio.create_task(_broadcast_worker(alert_queue))

    # Thread 5 — uvicorn (runs inside the asyncio loop)
    config = uvicorn.Config(
        app,
        host="0.0.0.0",
        port=8765,
        log_level="warning",
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
