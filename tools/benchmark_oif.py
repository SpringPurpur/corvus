#!/usr/bin/env python3
"""
benchmark_oif.py — replay stored flows through MultiWindowOIF instances with
different window configurations and compare detection performance.

Reads flows from the SQLite database produced by the inference engine and
replays them in timestamp order through fresh OIF instances. Reports:
  - Time-to-detect (TTD): flows from first attack flow until first CRITICAL alert
  - False positive rate (FPR): CRITICAL alerts during benign segments / total benign flows
  - Recovery time: flows after last attack flow until scores drop below HIGH threshold
  - Training rejection rate during attack segments

Usage:
    python tools/benchmark_oif.py --db data/flows.db --protocol TCP
    python tools/benchmark_oif.py --db data/flows.db --protocol UDP \\
        --windows "128,512,2048" "256,1024,4096" "512,2048,8192"

The default config matches the live system (256/1024/4096, weights 0.20/0.30/0.50).
"""

import argparse
import sqlite3
import sys
import os
from pathlib import Path
from typing import NamedTuple

# Allow importing from inference/ without installing as a package
sys.path.insert(0, str(Path(__file__).parent.parent / "inference"))

from online_detector import MultiWindowOIF  # noqa: E402 (after sys.path fix)

# ── Feature name lists (must match online_detector.py) ────────────────────────

TCP_FEATURE_NAMES = [
    "init_fwd_win_bytes", "rst_flag_cnt", "bwd_pkt_len_std",
    "psh_flag_cnt", "bwd_pkts_per_sec", "pkt_len_mean",
    "fwd_pkts_per_sec", "syn_flag_ratio", "flow_duration_s",
    "fwd_act_data_ratio",
]

UDP_FEATURE_NAMES = [
    "tot_fwd_bytes", "tot_fwd_pkts", "fwd_pkt_len_max",
    "down_up_ratio", "flow_duration_s", "flow_iat_mean",
    "fwd_iat_std", "bwd_pkts_per_sec", "psh_flag_ratio",
]

BENIGN_LABELS = {"Benign", "Unknown", "INFO"}


# ── Data loading ──────────────────────────────────────────────────────────────

def load_flows(db_path: str, protocol: str) -> list[dict]:
    """Load all flows for the given protocol from SQLite, ordered by timestamp."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM flows WHERE proto = ? ORDER BY ts ASC", (protocol,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def flow_to_features(flow: dict, feature_names: list[str]) -> list[float]:
    """Extract OIF feature vector from a stored flow dict."""
    import json
    # Features may be stored as a JSON blob or as individual columns
    feat_json = flow.get("features_json")
    if feat_json:
        feat = json.loads(feat_json)
        return [float(feat.get(n, 0.0)) for n in feature_names]

    # Fall back to direct column access for each feature
    mapping = {
        "init_fwd_win_bytes": "init_fwd_win_bytes",
        "rst_flag_cnt":       "rst_flag_cnt",
        "bwd_pkt_len_std":    "bwd_pkt_len_std",
        "psh_flag_cnt":       "psh_flag_cnt",
        "bwd_pkts_per_sec":   "bwd_pkts_per_sec",
        "pkt_len_mean":       "pkt_len_mean",
        "fwd_pkts_per_sec":   "fwd_pkts_per_sec",
        "syn_flag_ratio":     "syn_flag_ratio",
        "flow_duration_s":    "flow_duration_s",
        "fwd_act_data_ratio": "fwd_act_data_pkts",  # stored as count; ratio computed below
        "tot_fwd_bytes":      "tot_fwd_bytes",
        "tot_fwd_pkts":       "tot_fwd_pkts",
        "fwd_pkt_len_max":    "fwd_pkt_len_max",
        "down_up_ratio":      "down_up_ratio",
        "flow_iat_mean":      "flow_iat_mean",
        "fwd_iat_std":        "fwd_iat_std",
        "psh_flag_ratio":     "psh_flag_ratio",
    }
    return [float(flow.get(mapping.get(n, n), 0.0)) for n in feature_names]


# ── Benchmark run ─────────────────────────────────────────────────────────────

class BenchResult(NamedTuple):
    config:         str
    ttd_flows:      int | None   # None = never detected
    fpr:            float
    recovery_flows: int | None   # None = did not recover within dataset
    rejection_rate: float        # during attack segment


def run_benchmark(
    flows:         list[dict],
    feature_names: list[str],
    protocol:      str,
    windows:       tuple[int, int, int],
    weights:       tuple[float, float, float],
    threshold_high:     float = 0.60,
    threshold_critical: float = 0.75,
) -> BenchResult:
    import numpy as np

    config_label = f"{windows[0]}/{windows[1]}/{windows[2]} ×{weights[0]:.2f}"

    # Patch weights into a temporary subclass so we don't mutate the global
    class _OIF(MultiWindowOIF):
        _WINDOWS = windows
        _WEIGHTS = weights
        TRAIN_THRESHOLD = threshold_high

    detector = _OIF(feature_names, protocol, baseline_flows=windows[1])

    # Identify attack vs benign segments by verdict label
    # label is stored in verdict_label column
    labels = [f.get("verdict_label", "Unknown") for f in flows]
    is_attack = [lbl not in BENIGN_LABELS for lbl in labels]

    first_attack = next((i for i, a in enumerate(is_attack) if a), None)
    last_attack  = next((i for i, a in reversed(list(enumerate(is_attack))) if a), None)

    ttd_flows      = None
    recovery_flows = None
    n_fp           = 0
    n_benign       = 0
    n_rejected_atk = 0
    n_seen_atk     = 0
    in_attack      = first_attack is not None
    detected       = False
    recovered      = False

    for i, flow in enumerate(flows):
        raw = np.array(flow_to_features(flow, feature_names), dtype=np.float32)
        result = detector.process(raw)
        if result is None:
            continue  # still baselining

        scores, _ = result
        composite  = scores.composite

        # TTD — first CRITICAL during attack segment
        if in_attack and first_attack is not None and i >= first_attack and not detected:
            if composite >= threshold_critical:
                ttd_flows = i - first_attack
                detected  = True

        # FPR — CRITICAL alerts during benign flows
        if not is_attack[i]:
            n_benign += 1
            if composite >= threshold_critical:
                n_fp += 1

        # Rejection rate during attack
        if in_attack and first_attack is not None and i >= first_attack:
            if last_attack is not None and i <= last_attack:
                n_seen_atk += 1
                if composite >= threshold_high:
                    n_rejected_atk += 1

        # Recovery — first flow after attack where composite drops below HIGH
        if last_attack is not None and i > last_attack and not recovered:
            if composite < threshold_high:
                recovery_flows = i - last_attack
                recovered = True

    fpr = n_fp / max(n_benign, 1)
    rej = n_rejected_atk / max(n_seen_atk, 1)

    return BenchResult(
        config         = config_label,
        ttd_flows      = ttd_flows,
        fpr            = fpr,
        recovery_flows = recovery_flows,
        rejection_rate = rej,
    )


# ── CLI ───────────────────────────────────────────────────────────────────────

def parse_windows(s: str) -> tuple[int, int, int]:
    parts = [int(x.strip()) for x in s.split(",")]
    if len(parts) != 3:
        raise argparse.ArgumentTypeError("--windows expects three comma-separated integers")
    return tuple(parts)  # type: ignore[return-value]


def parse_weights(s: str) -> tuple[float, float, float]:
    parts = [float(x.strip()) for x in s.split(",")]
    if len(parts) != 3:
        raise argparse.ArgumentTypeError("--weights expects three comma-separated floats")
    total = sum(parts)
    if abs(total - 1.0) > 0.01:
        raise argparse.ArgumentTypeError(f"Weights must sum to 1.0 (got {total:.3f})")
    return tuple(parts)  # type: ignore[return-value]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Benchmark MultiWindowOIF window configurations against stored flows",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--db",       default="data/flows.db",
                        help="Path to flows SQLite database (default: data/flows.db)")
    parser.add_argument("--protocol", choices=["TCP", "UDP"], default="TCP",
                        help="Protocol to benchmark (default: TCP)")
    parser.add_argument("--windows",  nargs="+", type=parse_windows,
                        default=[(256, 1024, 4096)],
                        help='Window configs as "fast,medium,slow" triples '
                             '(default: "256,1024,4096")')
    parser.add_argument("--weights",  type=parse_weights,
                        default=(0.20, 0.30, 0.50),
                        help='Model weights as "w1,w2,w3" (must sum to 1, '
                             'default: "0.20,0.30,0.50")')
    parser.add_argument("--threshold-high",     type=float, default=0.60)
    parser.add_argument("--threshold-critical", type=float, default=0.75)
    args = parser.parse_args()

    db_path = args.db
    if not os.path.exists(db_path):
        print(f"ERROR: database not found at {db_path}", file=sys.stderr)
        print("Run the inference engine first to accumulate flows.", file=sys.stderr)
        sys.exit(1)

    feature_names = TCP_FEATURE_NAMES if args.protocol == "TCP" else UDP_FEATURE_NAMES

    print(f"Loading {args.protocol} flows from {db_path}…")
    flows = load_flows(db_path, args.protocol)
    if not flows:
        print(f"No {args.protocol} flows found in database.", file=sys.stderr)
        sys.exit(1)

    attack_count  = sum(1 for f in flows if f.get("verdict_label", "Unknown") not in BENIGN_LABELS)
    print(f"  {len(flows)} flows total — {attack_count} attack, "
          f"{len(flows) - attack_count} benign\n")

    results: list[BenchResult] = []
    for windows in args.windows:
        print(f"  Running config {windows[0]}/{windows[1]}/{windows[2]}…", end=" ", flush=True)
        r = run_benchmark(
            flows, feature_names, args.protocol,
            windows, args.weights,
            args.threshold_high, args.threshold_critical,
        )
        results.append(r)
        print("done")

    # ── Results table ──────────────────────────────────────────────────────────
    print()
    col_w = max(len(r.config) for r in results) + 2
    header = f"{'Config':<{col_w}}  {'TTD (flows)':>12}  {'FPR':>7}  {'Recovery':>10}  {'Rejection':>10}"
    print(header)
    print("-" * len(header))
    for r in results:
        ttd  = str(r.ttd_flows)      if r.ttd_flows      is not None else "never"
        rec  = str(r.recovery_flows) if r.recovery_flows is not None else "n/a"
        print(
            f"{r.config:<{col_w}}  {ttd:>12}  {r.fpr*100:>6.1f}%  "
            f"{rec:>10}  {r.rejection_rate*100:>9.1f}%"
        )

    print()
    print("TTD        — flows from first attack until first CRITICAL alert")
    print("FPR        — CRITICAL alerts on benign flows / total benign flows")
    print("Recovery   — flows after last attack until scores drop below HIGH threshold")
    print("Rejection  — % of attack-segment flows withheld from training (poisoning defence)")


if __name__ == "__main__":
    main()