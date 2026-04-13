# socket_reader.py - Unix socket server that receives flow_record_t structs
# from the C capture engine and puts parsed dicts onto a queue.
#
# The C engine is the client; we own the socket file. Wire format:
#   [uint32_t payload_len = sizeof(flow_record_t)][flow_record_t bytes]
#
# The ctypes struct must match the C layout exactly; sizeof must equal 6352.
# If it doesn't, startup fails loudly rather than silently producing wrong features.

import ctypes
import logging
import os
import queue
import socket
import struct
import threading
import time
from typing import Any

log = logging.getLogger(__name__)

SOCKET_PATH = "/tmp/ids_ipc/flows.sock"
EXPECTED_SIZEOF = 6352


# ctypes mirror of flow_key_t

class FlowKey(ctypes.Structure):
    _fields_ = [
        ("src_ip",    ctypes.c_uint32),
        ("dst_ip",    ctypes.c_uint32),
        ("src_port",  ctypes.c_uint16),
        ("dst_port",  ctypes.c_uint16),
        ("protocol",  ctypes.c_uint8),
        ("_pad",      ctypes.c_uint8 * 3),
    ]


# ctypes mirror of flow_record_t
# Field order and types must match flow_types.h exactly.
# Padding fields (_padN) are inserted wherever GCC inserts implicit padding
# to satisfy alignment requirements.

class FlowRecord(ctypes.Structure):
    _fields_ = [
        # identity
        ("key",               FlowKey),
        ("first_pkt_ns",      ctypes.c_uint64),
        ("last_pkt_ns",       ctypes.c_uint64),
        ("flow_duration_s",   ctypes.c_float),

        # TCP feature set
        ("init_fwd_win_bytes", ctypes.c_uint16),
        ("_pad1",              ctypes.c_uint8 * 2),   # align rst_flag_cnt to 4
        ("rst_flag_cnt",       ctypes.c_uint32),
        ("bwd_pkts_per_sec",   ctypes.c_float),
        ("bwd_pkt_len_max",    ctypes.c_uint16),
        ("_pad2",              ctypes.c_uint8 * 2),   # align tot_fwd_pkts to 4
        ("tot_fwd_pkts",       ctypes.c_uint32),
        ("pkt_len_mean",       ctypes.c_float),
        ("ack_flag_cnt",       ctypes.c_uint32),
        ("psh_flag_cnt",       ctypes.c_uint32),
        ("pkt_len_std",        ctypes.c_float),
        ("bwd_pkt_len_std",    ctypes.c_float),
        ("fwd_seg_size_min",   ctypes.c_uint32),
        ("fwd_act_data_pkts",  ctypes.c_uint32),

        # UDP feature set
        # fwd_act_data_pkts ends at offset 84; uint64 needs 8-byte alignment → pad 4
        ("_pad3",              ctypes.c_uint8 * 4),
        ("tot_fwd_bytes",      ctypes.c_uint64),
        ("tot_bwd_bytes",      ctypes.c_uint64),
        ("fwd_pkt_len_max",    ctypes.c_uint16),
        ("_pad4",              ctypes.c_uint8 * 2),   # align flow_iat_mean to 4
        ("flow_iat_mean",      ctypes.c_float),
        ("fwd_iat_std",        ctypes.c_float),

        # shared counters
        ("tot_bwd_pkts",       ctypes.c_uint32),
        ("tot_pkts",           ctypes.c_uint32),
        ("syn_flag_cnt",       ctypes.c_uint32),
        ("fin_flag_cnt",       ctypes.c_uint32),
        ("urg_flag_cnt",       ctypes.c_uint32),
        ("bwd_pkt_len_mean",   ctypes.c_float),

        # derived features - computed at finalisation, used by IsolationForest models
        ("fwd_pkts_per_sec",   ctypes.c_float),
        ("syn_flag_ratio",     ctypes.c_float),
        ("psh_flag_ratio",     ctypes.c_float),

        # accumulation buffers (internal - not used for inference)
        ("pkt_len_buf",            ctypes.c_uint16 * 512),
        ("pkt_len_buf_count",      ctypes.c_uint32),
        ("bwd_pkt_len_buf",        ctypes.c_uint16 * 512),
        ("bwd_pkt_len_buf_count",  ctypes.c_uint32),
        # bwd_pkt_len_buf_count ends at offset 2208 (8-byte aligned) after the 3
        # float fields were added; no padding needed before fwd_iat_buf.
        ("fwd_iat_buf",            ctypes.c_uint64 * 256),
        ("fwd_iat_buf_count",      ctypes.c_uint32),
        # fwd_iat_buf_count ends at offset 4252; uint64 needs 8-byte align → pad 4
        ("_pad6",                  ctypes.c_uint8 * 4),
        ("all_iat_buf",            ctypes.c_uint64 * 256),
        ("all_iat_buf_count",      ctypes.c_uint32),
        # all_iat_buf_count ends at offset 6308; uint64 needs 8-byte align → pad 4
        ("_pad7",                  ctypes.c_uint8 * 4),
        ("last_pkt_ns_for_iat",    ctypes.c_uint64),
        ("last_fwd_pkt_ns",        ctypes.c_uint64),

        # pipeline timing - set by ipc_writer_enqueue() on the ring slot copy,
        # NOT at flow creation. t_socket_ns - t_enqueue_ns = true IPC transfer time.
        ("t_enqueue_ns",       ctypes.c_uint64),

        # state
        ("complete",           ctypes.c_uint8),
        ("fwd_is_lower_ip",    ctypes.c_uint8),
        ("init_win_captured",  ctypes.c_uint8),
        ("_pad8",              ctypes.c_uint8 * 1),   # reduced 9→1: 8 bytes moved to t_enqueue_ns
    ]


def _check_struct_size() -> None:
    actual = ctypes.sizeof(FlowRecord)
    if actual != EXPECTED_SIZEOF:
        raise RuntimeError(
            f"FlowRecord ctypes size mismatch: got {actual}, expected {EXPECTED_SIZEOF}. "
            "flow_types.h and socket_reader.py are out of sync."
        )


def _ip_to_str(ip: int) -> str:
    return socket.inet_ntoa(struct.pack(">I", ip))


def _record_to_dict(r: FlowRecord) -> dict[str, Any]:
    """Convert a FlowRecord to a plain dict for the inference queue."""
    return {
        "src_ip":            _ip_to_str(r.key.src_ip),
        "dst_ip":            _ip_to_str(r.key.dst_ip),
        "src_port":          r.key.src_port,
        "dst_port":          r.key.dst_port,
        "protocol":          r.key.protocol,
        "flow_duration_s":   r.flow_duration_s,
        "init_fwd_win_bytes": r.init_fwd_win_bytes,
        "rst_flag_cnt":      r.rst_flag_cnt,
        "bwd_pkts_per_sec":  r.bwd_pkts_per_sec,
        "bwd_pkt_len_max":   r.bwd_pkt_len_max,
        "tot_fwd_pkts":      r.tot_fwd_pkts,
        "pkt_len_mean":      r.pkt_len_mean,
        "ack_flag_cnt":      r.ack_flag_cnt,
        "psh_flag_cnt":      r.psh_flag_cnt,
        "pkt_len_std":       r.pkt_len_std,
        "bwd_pkt_len_std":   r.bwd_pkt_len_std,
        "fwd_seg_size_min":  r.fwd_seg_size_min,
        "fwd_act_data_pkts": r.fwd_act_data_pkts,
        "tot_fwd_bytes":     r.tot_fwd_bytes,
        "tot_bwd_bytes":     r.tot_bwd_bytes,
        "fwd_pkt_len_max":   r.fwd_pkt_len_max,
        "flow_iat_mean":     r.flow_iat_mean,
        "fwd_iat_std":       r.fwd_iat_std,
        "tot_bwd_pkts":      r.tot_bwd_pkts,
        "tot_pkts":          r.tot_pkts,
        "syn_flag_cnt":      r.syn_flag_cnt,
        "fin_flag_cnt":      r.fin_flag_cnt,
        "urg_flag_cnt":      r.urg_flag_cnt,
        "bwd_pkt_len_mean":  r.bwd_pkt_len_mean,
        # derived fields computed at finalisation in features_finalise()
        "fwd_pkts_per_sec":  r.fwd_pkts_per_sec,
        "syn_flag_ratio":    r.syn_flag_ratio,
        "psh_flag_ratio":    r.psh_flag_ratio,
        # capture timestamps - nanoseconds since Unix epoch (C CLOCK_REALTIME)
        "first_pkt_ns":      r.first_pkt_ns,
        "last_pkt_ns":       r.last_pkt_ns,
        # IPC ring enqueue time - set by ipc_writer_enqueue() after copying the
        # flow into the ring buffer. t_socket_ns - t_enqueue_ns = true IPC latency.
        "t_enqueue_ns":      r.t_enqueue_ns,
    }


def _read_exactly(conn: socket.socket, n: int) -> bytes | None:
    """Read exactly n bytes; returns None on EOF or error."""
    buf = bytearray(n)
    view = memoryview(buf)
    received = 0
    while received < n:
        chunk = conn.recv_into(view[received:], n - received)
        if chunk == 0:
            return None
        received += chunk
    return bytes(buf)


def _handle_client(conn: socket.socket, out_queue: queue.Queue) -> None:
    record = FlowRecord()
    record_size = ctypes.sizeof(FlowRecord)

    while True:
        # Read 4-byte length prefix
        header = _read_exactly(conn, 4)
        if header is None:
            break

        payload_len = struct.unpack("<I", header)[0]

        if payload_len != record_size:
            log.error(
                "Unexpected payload_len=%d expected=%d - discarding",
                payload_len, record_size,
            )
            # Drain the bytes to stay in sync
            remaining = payload_len
            while remaining > 0:
                chunk = _read_exactly(conn, min(remaining, 4096))
                if chunk is None:
                    return
                remaining -= len(chunk)
            continue

        data = _read_exactly(conn, record_size)
        if data is None:
            break

        ctypes.memmove(ctypes.addressof(record), data, record_size)
        d = _record_to_dict(record)
        # stamp arrival time right after decode; measures IPC transport + ctypes cost
        d["t_socket_ns"] = time.time_ns()
        log.info("Flow received: proto=%d src=%s:%d dst=%s:%d pkts=%d",
                 d["protocol"], d["src_ip"], d["src_port"],
                 d["dst_ip"], d["dst_port"], d["tot_pkts"])

        out_queue.put(d)

    log.debug("Capture engine disconnected")


def run_socket_server(out_queue: queue.Queue) -> None:
    """Bind the Unix socket, accept connections, push flow dicts onto out_queue.

    Runs forever in the calling thread. Designed to be the target of a daemon thread.
    """
    _check_struct_size()
    log.info("FlowRecord sizeof = %d bytes ✓", ctypes.sizeof(FlowRecord))

    os.makedirs(os.path.dirname(SOCKET_PATH), exist_ok=True)
    try:
        os.unlink(SOCKET_PATH)
    except FileNotFoundError:
        pass

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(SOCKET_PATH)
    server.listen(4)
    log.info("Listening on %s", SOCKET_PATH)

    while True:
        conn, _ = server.accept()
        log.info("Capture engine connected")
        # each client gets its own thread; in practice only one capture engine
        # connects at a time, but this keeps the accept loop non-blocking
        t = threading.Thread(target=_handle_client_safe, args=(conn, out_queue), daemon=True)
        t.start()


def _handle_client_safe(conn: socket.socket, out_queue: queue.Queue) -> None:
    """Wrapper that logs any unhandled exception from _handle_client."""
    try:
        _handle_client(conn, out_queue)
    except Exception:
        log.exception("_handle_client crashed unexpectedly")
    finally:
        conn.close()
