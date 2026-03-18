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
import storage
from classifier import Classifier
from server import app, configure
from socket_reader import run_socket_server
from ws_handler import manager

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
    """Drain flow_queue, run inference, push alerts onto the asyncio alert_queue."""
    while True:
        try:
            flow = flow_queue.get(timeout=1.0)
        except queue.Empty:
            continue

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
                 "baselining": True,
                 "progress": alert.get("progress", 0.0),
                 "protocol": alert.get("protocol", "")},
            )
            continue

        log.info("Alert: proto=%s label=%s src=%s:%s dst=%s:%s",
                 alert["proto"], alert["verdict"]["label"],
                 alert["src_ip"], alert["src_port"],
                 alert["dst_ip"], alert["dst_port"])
        storage.insert_flow(alert)
        # Thread-safe put into the asyncio queue via the event loop
        loop.call_soon_threadsafe(alert_queue.put_nowait, alert)


async def _broadcast_worker(alert_queue: asyncio.Queue) -> None:
    """Drain the asyncio alert_queue and broadcast each item to all WS clients.

    Status messages (baselining progress) are already fully-formed dicts with
    a 'type' key and are broadcast as-is. Alert dicts are wrapped in the
    standard {'type': 'alert', 'data': ...} envelope.
    """
    while True:
        item = await alert_queue.get()
        if item.get("type") == "status":
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

    flow_queue: queue.Queue = queue.Queue(maxsize=4096)
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
