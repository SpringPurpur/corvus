# storage.py — SQLite flow persistence.
#
# One row per completed alert. Scalar fields are indexed columns; structured
# data (attribution, shap) is stored as JSON text — too nested to query inside,
# just needs to round-trip faithfully.
#
# WAL mode allows the FastAPI thread to read concurrently while the inference
# worker thread writes. A threading.Lock guards the single write path.

import json
import logging
import sqlite3
import threading
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

DB_PATH = Path("/app/data/flows.db")

_conn: sqlite3.Connection | None = None
_write_lock = threading.Lock()


def init_db() -> None:
    """Open (or create) the database and apply the schema."""
    global _conn
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    _conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)

    # WAL allows concurrent reads from the FastAPI thread while the inference
    # worker writes. NORMAL sync is safe with WAL and avoids an fsync per commit.
    _conn.execute("PRAGMA journal_mode=WAL")
    _conn.execute("PRAGMA synchronous=NORMAL")

    _conn.executescript("""
        CREATE TABLE IF NOT EXISTS flows (
            id           INTEGER PRIMARY KEY,
            flow_id      TEXT    NOT NULL,
            ts           REAL    NOT NULL,
            src_ip       TEXT    NOT NULL,
            dst_ip       TEXT    NOT NULL,
            src_port     INTEGER NOT NULL,
            dst_port     INTEGER NOT NULL,
            proto        TEXT    NOT NULL,
            duration     REAL    NOT NULL,
            fwd_pkts     INTEGER NOT NULL,
            label        TEXT    NOT NULL,
            severity     TEXT    NOT NULL,
            confidence   REAL    NOT NULL,
            score_fast   REAL,
            score_medium REAL,
            score_slow   REAL,
            score_comp   REAL,
            score_oor    REAL,
            attribution  TEXT,
            shap         TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_ts     ON flows(ts);
        CREATE INDEX IF NOT EXISTS idx_src_ip ON flows(src_ip);
        CREATE INDEX IF NOT EXISTS idx_proto  ON flows(proto);
        CREATE INDEX IF NOT EXISTS idx_label  ON flows(label);
    """)
    # Schema migration: add score_oor if upgrading an existing DB that predates it.
    cols = {row[1] for row in _conn.execute("PRAGMA table_info(flows)").fetchall()}
    if "score_oor" not in cols:
        _conn.execute("ALTER TABLE flows ADD COLUMN score_oor REAL")
        log.info("Migrated flows table: added score_oor column")
    _conn.commit()
    log.info("SQLite DB ready at %s", DB_PATH)


def insert_flow(alert: dict) -> None:
    """Persist a completed alert dict. Called from the inference worker thread."""
    if _conn is None:
        return

    v = alert.get("verdict", {})
    s = alert.get("scores", {})

    with _write_lock:
        try:
            _conn.execute(
                """
                INSERT INTO flows
                    (flow_id, ts, src_ip, dst_ip, src_port, dst_port,
                     proto, duration, fwd_pkts,
                     label, severity, confidence,
                     score_fast, score_medium, score_slow, score_comp, score_oor,
                     attribution, shap)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    alert["flow_id"], alert["ts"],
                    alert["src_ip"], alert["dst_ip"],
                    alert["src_port"], alert["dst_port"],
                    alert["proto"], alert["duration"], alert["fwd_pkts"],
                    v.get("label", ""), v.get("severity", ""), v.get("confidence", 0.0),
                    s.get("fast"), s.get("medium"), s.get("slow"), s.get("composite"),
                    s.get("oor"),
                    json.dumps(alert.get("attribution", [])),
                    json.dumps(alert.get("shap", [])),
                ),
            )
            _conn.commit()
        except Exception:
            log.warning("Failed to insert flow %s", alert.get("flow_id"), exc_info=True)


def query_flows(
    limit: int = 200,
    proto: str | None = None,
    label: str | None = None,
    src_ip: str | None = None,
    ts_from: float | None = None,
    ts_to: float | None = None,
) -> list[dict]:
    """Return flows as alert dicts, newest first.

    All filter params are optional and combinable. ts_from/ts_to are Unix
    timestamps; use them in the scenario runner to bound the query to the
    attack window so the limit doesn't cut off early flows.
    """
    if _conn is None:
        return []

    clauses: list[str] = []
    params: list[Any] = []

    if proto:
        clauses.append("proto = ?")
        params.append(proto.upper())
    if label:
        clauses.append("label = ?")
        params.append(label)
    if src_ip:
        clauses.append("src_ip = ?")
        params.append(src_ip)
    if ts_from is not None:
        clauses.append("ts >= ?")
        params.append(ts_from)
    if ts_to is not None:
        clauses.append("ts <= ?")
        params.append(ts_to)

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(limit)

    rows = _conn.execute(
        f"""
        SELECT flow_id, ts, src_ip, dst_ip, src_port, dst_port,
               proto, duration, fwd_pkts,
               label, severity, confidence,
               score_fast, score_medium, score_slow, score_comp, score_oor,
               attribution, shap
        FROM flows
        {where}
        ORDER BY ts DESC
        LIMIT ?
        """,
        params,
    ).fetchall()

    return [_row_to_alert(r) for r in rows]


def _row_to_alert(row: tuple) -> dict:
    (flow_id, ts, src_ip, dst_ip, src_port, dst_port,
     proto, duration, fwd_pkts,
     label, severity, confidence,
     fast, medium, slow, comp, oor,
     attribution_json, shap_json) = row

    return {
        "flow_id":     flow_id,
        "ts":          ts,
        "src_ip":      src_ip,
        "dst_ip":      dst_ip,
        "src_port":    src_port,
        "dst_port":    dst_port,
        "proto":       proto,
        "duration":    duration,
        "fwd_pkts":    fwd_pkts,
        "verdict": {
            "label":      label,
            "severity":   severity,
            "confidence": confidence,
        },
        "scores": {
            "fast":      fast,
            "medium":    medium,
            "slow":      slow,
            "composite": comp,
            "oor":       oor,
        },
        "attribution": json.loads(attribution_json or "[]"),
    }
