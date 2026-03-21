#!/usr/bin/env python3
"""
eval_baseline.py — measure false positive rate on clean benign traffic.

Resets the OIF detectors, waits for rebaselining to complete, observes
benign-only traffic for --duration minutes, then reports:
  - Score distribution (p25/p50/p75/p95/p99/max)
  - FPR at HIGH (≥0.60) and CRITICAL (≥0.75) thresholds
  - Feature attribution breakdown for false-positive flows
    (which features are most often driving the wrong scores)

Usage:
    python tools/eval_baseline.py
    python tools/eval_baseline.py --duration 10
    python tools/eval_baseline.py --api http://localhost:8765 --duration 5 --no-reset
"""

import argparse
import json
import subprocess
import sys

# Force UTF-8 stdout so Unicode characters (em-dashes, block bars, etc.) don't
# crash with UnicodeEncodeError on Windows where the default codec is cp1252.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import time
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime
from pathlib import Path
from statistics import median, stdev

SEP  = "=" * 55
DEFAULT_API = "http://localhost:8765"
DOCKER_CMD  = ["docker", "--context", "default"]


# ── HTTP helpers ──────────────────────────────────────────────────────────────

def _get(url: str) -> dict | list:
    with urllib.request.urlopen(url, timeout=5) as r:
        return json.loads(r.read())


def _post(url: str) -> dict:
    req = urllib.request.Request(url, method="POST", data=b"")
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def _delete(url: str) -> dict:
    # data=b"" forces Content-Length: 0; without it urllib omits the header
    # and uvicorn drops the connection before sending a response.
    # 30s timeout: clear_flows() acquires _write_lock which the inference
    # worker also holds during inserts — contention can delay the response.
    req = urllib.request.Request(url, data=b"", method="DELETE")
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def _get_flows(api: str, ts_from: float | None = None) -> list[dict]:
    url = f"{api}/flows?limit=50000"
    if ts_from is not None:
        url += f"&ts_from={ts_from}"
    return _get(url)  # type: ignore[return-value]


def _get_stats(api: str) -> dict:
    return _get(f"{api}/stats")  # type: ignore[return-value]


# ── Reset ─────────────────────────────────────────────────────────────────────

def reset_and_clear(api: str) -> None:
    print("[reset] Clearing flow DB…")
    try:
        result = _delete(f"{api}/flows")
        print(f"[reset] Deleted {result.get('deleted', 0)} flows.")
    except urllib.error.HTTPError as e:
        if e.code == 405:
            print("ERROR: DELETE /flows returned 405 — the inference container needs a rebuild.\n"
                  "       Run: python launch.py --build", file=sys.stderr)
            sys.exit(1)
        raise

    print("[reset] Resetting OIF detectors (TCP + UDP)…")
    try:
        _post(f"{api}/baseline/reset?protocol=all")
        print("[reset] Detectors reset — re-baselining will begin on next flows.")
    except urllib.error.HTTPError as e:
        if e.code in (404, 405):
            print(f"ERROR: POST /baseline/reset returned {e.code} — the inference container "
                  f"needs a rebuild.\n       Run: python launch.py --build", file=sys.stderr)
            sys.exit(1)
        raise


# ── Baseline traffic ──────────────────────────────────────────────────────────

def trigger_fast_baseline(
    client_a: str = "ids_client_a",
    client_b: str = "ids_client_b",
) -> None:
    print("[baseline] Triggering fast_baseline.sh on client containers…")
    for c in (client_a, client_b):
        try:
            subprocess.Popen(
                DOCKER_CMD + ["exec", c, "bash", "/scripts/fast_baseline.sh"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
        except FileNotFoundError:
            print(f"[baseline] WARNING: docker not found — skipping {c}")


def wait_for_ready(api: str, timeout_s: int = 360) -> dict:
    """Poll /stats until TCP detector reports is_ready=true."""
    deadline = time.time() + timeout_s
    last_prog = -1.0

    print(f"[baseline] Waiting for TCP detector (timeout {timeout_s}s)…")
    while time.time() < deadline:
        try:
            stats = _get_stats(api)
        except Exception:
            time.sleep(3)
            continue

        tcp   = stats.get("tcp", {})
        ready = tcp.get("ready", False)
        # During baselining n_seen=0; use n_baseline for progress instead.
        n_base  = tcp.get("n_baseline", 0)
        n_total = tcp.get("n_baseline_target", 0) or tcp.get("n_seen", 0)
        prog    = n_base if not ready else n_total

        if prog != last_prog:
            last_prog = prog
            if ready:
                status = "READY"
            elif n_total:
                status = f"baselining {n_base}/{n_total}"
            else:
                status = f"{prog} flows"
            print(f"  TCP: {status}")

        if ready:
            print("[baseline] Detector ready.\n")
            return stats

        time.sleep(5)

    print(f"[baseline] WARNING: timed out after {timeout_s}s — proceeding anyway.")
    return _get_stats(api)


# ── Metrics ───────────────────────────────────────────────────────────────────

def _score(flow: dict) -> float:
    return flow.get("score_comp") or (flow.get("scores") or {}).get("composite") or 0.0


def _percentile(data: list[float], pct: float) -> float:
    if not data:
        return 0.0
    s = sorted(data)
    idx = (len(s) - 1) * pct / 100.0
    lo, hi = int(idx), min(int(idx) + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (idx - lo)


def compute_baseline_metrics(
    flows: list[dict],
    threshold_high: float = 0.60,
    threshold_critical: float = 0.75,
) -> dict:
    scores = [_score(f) for f in flows]
    if not scores:
        return {}

    n_total    = len(scores)
    n_high     = sum(1 for s in scores if s >= threshold_high)
    n_critical = sum(1 for s in scores if s >= threshold_critical)

    # Per-protocol split
    tcp_scores = [_score(f) for f in flows if f.get("proto") == "TCP"]
    udp_scores = [_score(f) for f in flows if f.get("proto") == "UDP"]

    # Feature attribution breakdown for false-positive flows.
    # Each false-positive flow has an attribution list; the first entry
    # (highest-scoring feature) most drove the erroneous score.
    fp_flows = [f for f in flows if _score(f) >= threshold_high]
    top_feature_counter: Counter = Counter()
    for f in fp_flows:
        attr = f.get("attribution") or []
        if isinstance(attr, str):
            try:
                attr = json.loads(attr)
            except Exception:
                attr = []
        if attr:
            top_feature_counter[attr[0].get("feature", "unknown")] += 1

    return {
        "n_total":    n_total,
        "n_tcp":      len(tcp_scores),
        "n_udp":      len(udp_scores),
        "n_high":     n_high,
        "n_critical": n_critical,
        "fpr_high":   n_high     / n_total,
        "fpr_crit":   n_critical / n_total,
        "score_p25":  _percentile(scores, 25),
        "score_p50":  _percentile(scores, 50),
        "score_p75":  _percentile(scores, 75),
        "score_p95":  _percentile(scores, 95),
        "score_p99":  _percentile(scores, 99),
        "score_max":  max(scores),
        "score_mean": sum(scores) / n_total,
        "score_std":  stdev(scores) if n_total > 1 else 0.0,
        # Histogram buckets: INFO / borderline / HIGH / CRITICAL
        "hist": {
            "info":       sum(1 for s in scores if s < 0.45),
            "borderline": sum(1 for s in scores if 0.45 <= s < threshold_high),
            "high":       sum(1 for s in scores if threshold_high <= s < threshold_critical),
            "critical":   sum(1 for s in scores if s >= threshold_critical),
        },
        "fp_features": dict(top_feature_counter.most_common(8)),
    }


# ── Report printing ───────────────────────────────────────────────────────────

def print_report(m: dict, duration_min: float, run_at: float, out_path: str) -> None:
    ts = datetime.fromtimestamp(run_at).strftime("%Y-%m-%d %H:%M:%S")
    print(f"\n{SEP}")
    print("  Corvus IDS — Baseline Quality Evaluation")
    print(f"  Duration : {duration_min:.1f} min observation after baselining")
    print(f"  Run at   : {ts}")
    print(SEP)

    if not m:
        print("\n  No flows scored during observation window.\n")
        return

    print(f"\nFlows scored : {m['n_total']}  (TCP: {m['n_tcp']}  UDP: {m['n_udp']})")

    print("\nScore distribution")
    print(f"  p25  : {m['score_p25']:.3f}   p50 : {m['score_p50']:.3f}   "
          f"p75 : {m['score_p75']:.3f}")
    print(f"  p95  : {m['score_p95']:.3f}   p99 : {m['score_p99']:.3f}   "
          f"max : {m['score_max']:.3f}")
    print(f"  mean : {m['score_mean']:.3f}   std : {m['score_std']:.3f}")

    hist = m["hist"]
    print("\nScore histogram")
    total = m["n_total"]
    print(f"  INFO       (<0.45)  : {hist['info']:5d}  ({hist['info']/total*100:5.1f}%)")
    print(f"  Borderline (0.45–0.60): {hist['borderline']:5d}  "
          f"({hist['borderline']/total*100:5.1f}%)")
    print(f"  HIGH       (0.60–0.75): {hist['high']:5d}  "
          f"({hist['high']/total*100:5.1f}%)")
    print(f"  CRITICAL   (≥0.75)  : {hist['critical']:5d}  "
          f"({hist['critical']/total*100:5.1f}%)")

    fpr_h_pct  = m["fpr_high"] * 100
    fpr_c_pct  = m["fpr_crit"] * 100
    h_flag  = "  ← HIGH" if fpr_h_pct > 5 else ""
    c_flag  = "  ← HIGH" if fpr_c_pct > 2 else ""
    print("\nFalse positive rate (all flows are benign)")
    print(f"  FPR HIGH     (≥0.60) : {m['n_high']:5d} / {total}  = {fpr_h_pct:.2f}%{h_flag}")
    print(f"  FPR CRITICAL (≥0.75) : {m['n_critical']:5d} / {total}  = {fpr_c_pct:.2f}%{c_flag}")

    if m["fp_features"]:
        print("\nTop features driving false-positive alerts (≥HIGH flows, leading attribution)")
        total_fp = sum(m["fp_features"].values())
        for feat, cnt in m["fp_features"].items():
            bar = "█" * int(cnt / max(m["fp_features"].values()) * 20)
            print(f"  {feat:<22} : {cnt:4d} / {total_fp}  ({cnt/total_fp*100:5.1f}%)  {bar}")

    print(f"\n{SEP}")
    print(f"  Saved to: {out_path}")
    print(SEP)


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> dict:
    parser = argparse.ArgumentParser(
        description="Evaluate OIF false positive rate on benign-only traffic"
    )
    parser.add_argument("--api",       default=DEFAULT_API)
    parser.add_argument("--duration",  type=float, default=5.0,
                        help="Minutes of benign observation after baselining (default: 5)")
    parser.add_argument("--timeout",   type=int,   default=360,
                        help="Seconds to wait for baselining to complete (default: 360)")
    parser.add_argument("--no-reset",  action="store_true",
                        help="Skip OIF reset — evaluate model in its current state")
    parser.add_argument("--threshold-high",     type=float, default=0.60)
    parser.add_argument("--threshold-critical", type=float, default=0.75)
    parser.add_argument("--client-a",  default="ids_client_a")
    parser.add_argument("--client-b",  default="ids_client_b")
    args = parser.parse_args()

    run_at = time.time()

    if not args.no_reset:
        reset_and_clear(args.api)
        trigger_fast_baseline(args.client_a, args.client_b)
        wait_for_ready(args.api, timeout_s=args.timeout)

    # Record the timestamp at which detection became active.
    # Only flows scored after this point count as baseline-quality observations.
    obs_start = time.time()
    obs_end   = obs_start + args.duration * 60

    print(f"[eval] Observing benign traffic for {args.duration:.1f} min…")
    remaining = obs_end - time.time()
    while remaining > 0:
        mins, secs = divmod(int(remaining), 60)
        print(f"  {mins:02d}:{secs:02d} remaining…", end="\r", flush=True)
        time.sleep(min(10, remaining))
        remaining = obs_end - time.time()
    print()

    print("[eval] Querying flows…")
    flows = _get_flows(args.api, ts_from=obs_start)
    print(f"[eval] {len(flows)} flows retrieved.")

    metrics = compute_baseline_metrics(flows, args.threshold_high, args.threshold_critical)

    results_dir = Path(__file__).parent.parent / "scenarios" / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    ts_str   = datetime.fromtimestamp(run_at).strftime("%Y%m%d_%H%M%S")
    out_path = results_dir / f"baseline_{ts_str}.json"

    result = {
        "type":               "baseline",
        "run_at":             run_at,
        "duration_min":       args.duration,
        "obs_start":          obs_start,
        "thresholds":         {"high": args.threshold_high, "critical": args.threshold_critical},
        "metrics":            metrics,
        "output_path":        str(out_path),
    }
    out_path.write_text(json.dumps(result, indent=2))

    print_report(metrics, args.duration, run_at, str(out_path))
    return result


if __name__ == "__main__":
    main()