#!/usr/bin/env python3
"""
gen_demo_db.py — generate a synthetic 24-hour flows.db for dashboard demo.

Produces a realistic mix of benign INFO flows and several attack episodes
(SYN flood, SSH brute-force, HTTP GET flood, UDP flood, Slowloris, port scan)
spread across a 24-hour window ending now.

Usage (run from repo root):
  python tools/gen_demo_db.py
  python tools/gen_demo_db.py --out data/flows_demo.db
  python tools/gen_demo_db.py --out data/flows.db   # overwrite live DB
"""
import argparse
import json
import math
import random
import sqlite3
import time
import uuid
from pathlib import Path

random.seed(42)

# ── Network topology ─────────────────────────────────────────────────────────

VICTIM_WEB  = "172.20.0.10"
VICTIM_SSH  = "172.20.0.11"
ATTACKER    = "172.20.0.20"
INFRA_IPS   = {"172.20.0.1", "172.20.0.30", "172.20.0.31"}
CLIENTS     = [f"10.0.{b}.{h}" for b in range(1, 6) for h in range(2, 30)]

# ── Baseline feature statistics (median, iqr) — realistic for the lab ────────

TCP_BASELINE = {
    "fwd_pkts_per_sec":   {"median": 14.2,   "iqr": 9.8},
    "bwd_pkts_per_sec":   {"median": 11.5,   "iqr": 8.2},
    "pkt_len_mean":       {"median": 512.0,  "iqr": 280.0},
    "pkt_len_std":        {"median": 180.0,  "iqr": 120.0},
    "flow_duration_s":    {"median": 1.4,    "iqr": 0.9},
    "flow_iat_mean":      {"median": 45.0,   "iqr": 30.0},
    "fwd_iat_std":        {"median": 22.0,   "iqr": 18.0},
    "init_fwd_win_bytes": {"median": 65535.0,"iqr": 8192.0},
    "syn_flag_ratio":     {"median": 0.08,   "iqr": 0.06},
    "fwd_act_data_ratio": {"median": 0.72,   "iqr": 0.18},
}
UDP_BASELINE = {
    "fwd_pkts_per_sec":  {"median": 25.0,  "iqr": 18.0},
    "bwd_pkts_per_sec":  {"median": 20.0,  "iqr": 15.0},
    "pkt_len_mean":      {"median": 256.0, "iqr": 180.0},
    "pkt_len_std":       {"median": 100.0, "iqr": 80.0},
    "flow_duration_s":   {"median": 2.0,   "iqr": 1.5},
    "flow_iat_mean":     {"median": 30.0,  "iqr": 20.0},
    "fwd_iat_std":       {"median": 15.0,  "iqr": 12.0},
    "down_up_ratio":     {"median": 0.8,   "iqr": 0.4},
    "bwd_pkt_len_max":   {"median": 512.0, "iqr": 256.0},
}

# ── Score helpers ─────────────────────────────────────────────────────────────

def _severity(comp: float) -> str:
    if comp >= 0.80: return "CRITICAL"
    if comp >= 0.60: return "HIGH"
    return "INFO"

def _scores(comp: float, oor: float = 0.0):
    jitter = lambda: random.uniform(-0.03, 0.03)
    fast   = max(0.0, min(1.0, comp * 0.85 + jitter()))
    medium = max(0.0, min(1.0, comp * 0.95 + jitter()))
    slow   = max(0.0, min(1.0, comp          + jitter()))
    return fast, medium, slow, comp, oor

def _timing_ns(ts: float):
    t_enq = int(ts * 1e9)
    t_soc = t_enq + random.randint(200_000, 2_000_000)
    t_deq = t_soc + random.randint(50_000,  500_000)
    t_scr = t_deq + random.randint(100_000, 1_500_000)
    return t_enq, t_soc, t_deq, t_scr

def _attribution(top3: list[tuple[str, float, float]], baseline: dict) -> str:
    """top3 = [(feature_name, value, weight_hint), ...]"""
    total = sum(w for _, _, w in top3)
    out = [
        {
            "feature":  feat,
            "score":    round(w / total, 4),
            "value":    val,
            "baseline": baseline.get(feat, {"median": 0.0, "iqr": 1.0}),
        }
        for feat, val, w in top3
    ]
    return json.dumps(out)

# ── Flow row builder ──────────────────────────────────────────────────────────

def _row(ts, src_ip, dst_ip, src_port, dst_port, proto,
         duration, fwd_pkts, comp, oor=0.0, attr_json="[]"):
    sev = _severity(comp)
    fast, med, slow, comp_, oor_ = _scores(comp, oor)
    t_enq, t_soc, t_deq, t_scr  = _timing_ns(ts)
    return (
        str(uuid.uuid4()), ts,
        src_ip, dst_ip, src_port, dst_port,
        proto, duration, fwd_pkts,
        sev, sev, comp_,
        fast, med, slow, comp_, oor_,
        attr_json, "[]", "{}",
        t_enq, t_soc, t_deq, t_scr,
    )

# ── Traffic generators ────────────────────────────────────────────────────────

def gen_benign_tcp(t0: float, t1: float, n: int):
    """Normal HTTP/HTTPS/SSH background traffic."""
    rows = []
    for _ in range(n):
        ts       = random.uniform(t0, t1)
        client   = random.choice(CLIENTS)
        dst      = random.choice([VICTIM_WEB, VICTIM_SSH])
        dport    = 22 if dst == VICTIM_SSH else random.choice([80, 443])
        sport    = random.randint(1024, 65535)
        duration = max(0.1, random.gauss(1.4, 0.8))
        pkts     = random.randint(4, 60)
        comp     = max(0.0, min(0.58, random.gauss(0.18, 0.08)))
        attr = _attribution([
            ("pkt_len_mean",       random.gauss(512, 100),  0.4),
            ("fwd_pkts_per_sec",   random.gauss(14, 5),     0.35),
            ("flow_duration_s",    duration,                 0.25),
        ], TCP_BASELINE)
        rows.append(_row(ts, client, dst, sport, dport, "TCP",
                         duration, pkts, comp, 0.0, attr))
    return rows


def gen_benign_udp(t0: float, t1: float, n: int):
    """Normal DNS/NTP background traffic."""
    rows = []
    for _ in range(n):
        ts       = random.uniform(t0, t1)
        client   = random.choice(CLIENTS)
        dport    = random.choice([53, 123, 5353])
        sport    = random.randint(1024, 65535)
        duration = max(0.01, random.gauss(2.0, 1.0))
        pkts     = random.randint(1, 8)
        comp     = max(0.0, min(0.58, random.gauss(0.15, 0.07)))
        attr = _attribution([
            ("pkt_len_mean",     random.gauss(256, 80),  0.45),
            ("fwd_pkts_per_sec", random.gauss(25, 8),    0.35),
            ("down_up_ratio",    random.gauss(0.8, 0.2), 0.20),
        ], UDP_BASELINE)
        rows.append(_row(ts, client, VICTIM_WEB, sport, dport, "UDP",
                         duration, pkts, comp, 0.0, attr))
    return rows


def gen_syn_flood(t0: float, duration_s: float = 45.0, rate: int = 80):
    """SYN flood: near-1.0 syn_flag_ratio, tiny packets, very short flows."""
    rows = []
    for i in range(int(duration_s * rate / 10)):
        ts       = t0 + i * (duration_s / (duration_s * rate / 10))
        flow_dur = random.uniform(0.001, 0.005)
        pkts     = random.randint(1, 3)
        comp     = random.uniform(0.82, 0.97)
        oor      = random.uniform(0.0, 0.05)
        attr = _attribution([
            ("syn_flag_ratio",   random.uniform(0.95, 1.0),  0.55),
            ("fwd_pkts_per_sec", random.uniform(800, 2000),  0.30),
            ("flow_duration_s",  flow_dur,                   0.15),
        ], TCP_BASELINE)
        rows.append(_row(ts, ATTACKER, VICTIM_WEB,
                         random.randint(1024, 65535), 80, "TCP",
                         flow_dur, pkts, comp, oor, attr))
    return rows


def gen_ssh_brute(t0: float, duration_s: float = 120.0, rate: int = 12):
    """SSH brute-force: repeated TCP flows to port 22, moderate rate."""
    rows = []
    n = int(duration_s * rate)
    for i in range(n):
        ts       = t0 + i * (duration_s / n)
        flow_dur = random.uniform(0.5, 3.0)
        pkts     = random.randint(6, 20)
        comp     = random.uniform(0.62, 0.88)
        attr = _attribution([
            ("fwd_pkts_per_sec",  random.uniform(8, 25),     0.40),
            ("init_fwd_win_bytes",random.uniform(1024, 8192), 0.35),
            ("fwd_act_data_ratio",random.uniform(0.9, 1.0),  0.25),
        ], TCP_BASELINE)
        rows.append(_row(ts, ATTACKER, VICTIM_SSH,
                         random.randint(1024, 65535), 22, "TCP",
                         flow_dur, pkts, comp, 0.0, attr))
    return rows


def gen_http_get_flood(t0: float, duration_s: float = 60.0, rate: int = 50):
    """HTTP GET flood: detected via OOR (score_oor ≈ score_comp)."""
    rows = []
    n = int(duration_s * rate)
    for i in range(n):
        ts       = t0 + i * (duration_s / n)
        flow_dur = random.uniform(0.01, 0.08)
        pkts     = random.randint(4, 12)
        comp     = random.uniform(0.88, 0.9999)
        oor      = comp - random.uniform(0.0, 1e-4)   # OOR-driven
        attr = _attribution([
            ("fwd_pkts_per_sec",   random.uniform(400, 1200), 0.50),
            ("pkt_len_mean",       random.uniform(200, 400),  0.30),
            ("fwd_act_data_ratio", random.uniform(0.95, 1.0), 0.20),
        ], TCP_BASELINE)
        rows.append(_row(ts, ATTACKER, VICTIM_WEB,
                         random.randint(1024, 65535), 80, "TCP",
                         flow_dur, pkts, comp, oor, attr))
    return rows


def gen_udp_flood(t0: float, duration_s: float = 90.0, rate: int = 60):
    """UDP flood: high fwd rate, near-zero bwd, tiny packets."""
    rows = []
    n = int(duration_s * rate)
    for i in range(n):
        ts       = t0 + i * (duration_s / n)
        flow_dur = random.uniform(0.5, 2.0)
        pkts     = random.randint(10, 40)
        comp     = random.uniform(0.61, 0.82)
        attr = _attribution([
            ("fwd_pkts_per_sec",  random.uniform(500, 3000), 0.50),
            ("down_up_ratio",     random.uniform(0.0, 0.02), 0.30),
            ("pkt_len_mean",      random.uniform(28, 64),    0.20),
        ], UDP_BASELINE)
        rows.append(_row(ts, ATTACKER, VICTIM_WEB,
                         random.randint(1024, 65535),
                         random.choice([53, 80, 443, 8080]), "UDP",
                         flow_dur, pkts, comp, 0.0, attr))
    return rows


def gen_slowloris(t0: float, duration_s: float = 180.0, n_conn: int = 40):
    """Slowloris: very long TCP flows, low rate, many concurrent connections."""
    rows = []
    for i in range(n_conn):
        ts       = t0 + random.uniform(0, 20)
        flow_dur = random.uniform(60, duration_s)
        pkts     = random.randint(4, 15)
        comp     = random.uniform(0.65, 0.84)
        attr = _attribution([
            ("flow_duration_s",   flow_dur,                0.55),
            ("fwd_pkts_per_sec",  random.uniform(0.1, 1.2), 0.25),
            ("fwd_act_data_ratio",random.uniform(0.1, 0.4), 0.20),
        ], TCP_BASELINE)
        rows.append(_row(ts, ATTACKER, VICTIM_WEB,
                         random.randint(1024, 65535), 80, "TCP",
                         flow_dur, pkts, comp, 0.0, attr))
    return rows


def gen_port_scan(t0: float, duration_s: float = 30.0):
    """TCP port scan: short flows, many ports, low packet count."""
    rows = []
    ports = random.sample(range(1, 65535), 300)
    for i, dport in enumerate(ports):
        ts       = t0 + i * (duration_s / len(ports))
        flow_dur = random.uniform(0.001, 0.02)
        pkts     = random.randint(1, 3)
        comp     = random.uniform(0.38, 0.62)
        attr = _attribution([
            ("flow_duration_s",  flow_dur,                0.45),
            ("syn_flag_ratio",   random.uniform(0.5, 1.0), 0.35),
            ("pkt_len_mean",     random.uniform(40, 80),   0.20),
        ], TCP_BASELINE)
        rows.append(_row(ts, ATTACKER, VICTIM_WEB,
                         random.randint(1024, 65535), dport, "TCP",
                         flow_dur, pkts, comp, 0.0, attr))
    return rows


# ── Phase rows ────────────────────────────────────────────────────────────────

def _phase(run_id, scenario, phase, t_start, t_end, attacker_ip=None):
    return (run_id, scenario, phase, t_start, t_end, attacker_ip)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--out", default="data/flows.db",
                   help="Output SQLite path (default: data/flows.db)")
    p.add_argument("--seed", type=int, default=42)
    args = p.parse_args()

    random.seed(args.seed)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.exists():
        out.unlink()
        print(f"Removed existing {out}")

    conn = sqlite3.connect(str(out))
    conn.executescript("""
        CREATE TABLE flows (
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
            shap         TEXT,
            features     TEXT,
            flow_ts_ns    INTEGER,
            t_enqueue_ns  INTEGER,
            t_socket_ns   INTEGER,
            t_infer_ns    INTEGER,
            t_dequeue_ns  INTEGER,
            t_scored_ns   INTEGER
        );
        CREATE TABLE phases (
            id           INTEGER PRIMARY KEY,
            run_id       TEXT    NOT NULL,
            scenario     TEXT    NOT NULL,
            phase        TEXT    NOT NULL,
            t_start      REAL    NOT NULL,
            t_end        REAL,
            attacker_ip  TEXT
        );
        CREATE INDEX idx_ts    ON flows(ts);
        CREATE INDEX idx_src   ON flows(src_ip);
        CREATE INDEX idx_proto ON flows(proto);
        CREATE INDEX idx_label ON flows(label);
    """)

    now = time.time()
    day_ago = now - 86400
    run_id  = "demo-run-001"

    # ── Attack episode schedule (offset from day_ago in seconds) ─────────────
    episodes = [
        # (offset_s, label, generator_fn, kwargs)
        (3_600,  "SYN Flood",        gen_syn_flood,    {"duration_s": 45}),
        (7_200,  "SSH Brute-Force",   gen_ssh_brute,    {"duration_s": 120}),
        (14_400, "HTTP GET Flood",    gen_http_get_flood,{"duration_s": 60}),
        (21_600, "UDP Flood",         gen_udp_flood,    {"duration_s": 90}),
        (32_400, "Slowloris",         gen_slowloris,    {"duration_s": 180}),
        (50_400, "TCP Port Scan",     gen_port_scan,    {"duration_s": 30}),
        (64_800, "SSH Brute-Force",   gen_ssh_brute,    {"duration_s": 90}),
        (75_600, "SYN Flood",         gen_syn_flood,    {"duration_s": 30}),
    ]

    all_rows    = []
    phase_rows  = []

    # ── Benign background — day-of-week traffic curve ─────────────────────────
    print("Generating benign background traffic…")
    for hour in range(24):
        t0 = day_ago + hour * 3600
        t1 = t0 + 3600
        # More traffic during business hours (UTC+2 assumed: peaks 8-18h local)
        hour_local = (hour + 2) % 24
        weight = 0.3 + 0.7 * max(0, math.sin(math.pi * (hour_local - 6) / 12)) \
                 if 6 <= hour_local <= 20 else 0.2
        n_tcp = int(random.gauss(180 * weight, 20))
        n_udp = int(random.gauss(80  * weight, 10))
        all_rows.extend(gen_benign_tcp(t0, t1, max(n_tcp, 10)))
        all_rows.extend(gen_benign_udp(t0, t1, max(n_udp, 5)))

    # ── Attack episodes ───────────────────────────────────────────────────────
    for offset, label, fn, kwargs in episodes:
        t_start = day_ago + offset
        print(f"Generating {label} at +{offset//3600:.1f}h…")
        attack_rows = fn(t_start, **kwargs)
        all_rows.extend(attack_rows)

        dur = kwargs.get("duration_s", 60)
        phase_rows.append(_phase(run_id, label, "attack",
                                 t_start, t_start + dur, ATTACKER))

    # ── Insert ────────────────────────────────────────────────────────────────
    INSERT_SQL = """
        INSERT INTO flows
            (flow_id, ts, src_ip, dst_ip, src_port, dst_port,
             proto, duration, fwd_pkts,
             label, severity, confidence,
             score_fast, score_medium, score_slow, score_comp, score_oor,
             attribution, shap, features,
             t_enqueue_ns, t_socket_ns, t_dequeue_ns, t_scored_ns)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """
    random.shuffle(all_rows)
    conn.executemany(INSERT_SQL, all_rows)

    PHASE_SQL = """
        INSERT INTO phases (run_id, scenario, phase, t_start, t_end, attacker_ip)
        VALUES (?,?,?,?,?,?)
    """
    conn.executemany(PHASE_SQL, phase_rows)
    conn.commit()

    # ── Summary ───────────────────────────────────────────────────────────────
    total     = conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0]
    by_sev    = conn.execute(
        "SELECT severity, COUNT(*) FROM flows GROUP BY severity"
    ).fetchall()
    by_proto  = conn.execute(
        "SELECT proto, COUNT(*) FROM flows GROUP BY proto"
    ).fetchall()
    n_phases  = conn.execute("SELECT COUNT(*) FROM phases").fetchone()[0]
    conn.close()

    print(f"\nWrote {total} flows + {n_phases} phase rows -> {out}")
    print("  Severity:", {s: n for s, n in by_sev})
    print("  Protocol:", {p: n for p, n in by_proto})


if __name__ == "__main__":
    main()
