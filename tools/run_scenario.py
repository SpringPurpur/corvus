#!/usr/bin/env python3
"""
run_scenario.py — orchestrate a reproducible IDS scenario and produce a
quantified detection report.

Usage:
    python tools/run_scenario.py scenarios/syn_flood.yml
    python tools/run_scenario.py scenarios/mixed.yml --api http://localhost:8765
    python tools/run_scenario.py scenarios/slowloris.yml --no-baseline

The script:
  1. Optionally triggers fast_baseline.sh on both client containers
  2. Polls GET /stats until both OIF detectors are ready
  3. Records attack start time, runs the attack via docker exec (blocking)
  4. Records attack end time, waits for the recovery period
  5. Queries SQLite flows, annotates by source IP + time window
  6. Prints a structured report and saves JSON to scenarios/results/
"""

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime
from pathlib import Path
from statistics import median, stdev

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML is required. Run: pip install pyyaml", file=sys.stderr)
    sys.exit(1)

# ── Defaults ──────────────────────────────────────────────────────────────────

DEFAULT_API     = "http://localhost:8765"
DOCKER_CMD      = ["docker", "--context", "default"]
SEP             = "=" * 55

# ── HTTP helpers ──────────────────────────────────────────────────────────────

def _get(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=30) as r:
        return json.loads(r.read())


def _get_flows(
    api: str,
    src_ip: str | None = None,
    limit: int = 50000,
    ts_from: float | None = None,
    ts_to: float | None = None,
) -> list[dict]:
    url = f"{api}/flows?limit={limit}"
    if src_ip:
        url += f"&src_ip={src_ip}"
    if ts_from is not None:
        url += f"&ts_from={ts_from}"
    if ts_to is not None:
        url += f"&ts_to={ts_to}"
    return _get(url)


def _get_stats(api: str) -> dict:
    return _get(f"{api}/stats")


# ── Baseline waiting ──────────────────────────────────────────────────────────

def wait_for_baseline(api: str, timeout_s: int, needs_udp: bool = False) -> dict:
    """Poll /stats until both required detectors report is_ready=true."""
    deadline = time.time() + timeout_s
    last_tcp = last_udp = 0.0

    print(f"\n[baseline] Waiting for OIF detectors to warm up (timeout {timeout_s}s)…")
    while time.time() < deadline:
        try:
            stats = _get_stats(api)
        except Exception:
            time.sleep(3)
            continue

        tcp_ready = stats["tcp"].get("ready", False)
        udp_ready = stats["udp"].get("ready", False)

        tcp_p = stats["tcp"].get("baseline_progress", stats["tcp"].get("n_seen", 0))
        udp_p = stats["udp"].get("baseline_progress", stats["udp"].get("n_seen", 0))

        if tcp_p != last_tcp or udp_p != last_udp:
            last_tcp, last_udp = tcp_p, udp_p
            tcp_str = "READY" if tcp_ready else f"{tcp_p}"
            udp_str = "READY" if udp_ready else f"{udp_p}"
            print(f"  TCP: {tcp_str}   UDP: {udp_str}")

        ready = tcp_ready and (udp_ready if needs_udp else True)
        if ready:
            print("[baseline] Detectors ready.\n")
            return stats

        time.sleep(5)

    print(f"[baseline] WARNING: timed out after {timeout_s}s — proceeding anyway.")
    return _get_stats(api)


# ── Docker exec helpers ───────────────────────────────────────────────────────

def docker_exec(container: str, cmd: list[str], background: bool = False) -> subprocess.Popen | None:
    full = DOCKER_CMD + ["exec", container] + cmd
    if background:
        return subprocess.Popen(full, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(full, check=False)
    return None


def trigger_fast_baseline(client_a: str = "ids_client_a", client_b: str = "ids_client_b") -> None:
    print("[baseline] Triggering fast_baseline.sh on both clients…")
    docker_exec(client_a, ["bash", "/scripts/fast_baseline.sh"], background=True)
    docker_exec(client_b, ["bash", "/scripts/fast_baseline.sh"], background=True)


# ── Metrics computation ───────────────────────────────────────────────────────

def _score(flow: dict) -> float:
    """Return the composite OIF score from a flow dict.

    Tries the flat alias first (score_comp), then the nested path — handles
    both the current storage format and any older snapshots.
    """
    return (
        flow.get("score_comp")
        or (flow.get("scores") or {}).get("composite")
        or 0.0
    )


def _involves_attacker(flow: dict, attacker_ip: str) -> bool:
    # Flow keys are normalised (lower IP → src_ip), so the attacker can appear
    # in either src_ip or dst_ip depending on which side has the lower address.
    return flow.get("src_ip") == attacker_ip or flow.get("dst_ip") == attacker_ip


def compute_metrics(
    all_flows: list[dict],
    attacker_ip: str,
    t_attack_start: float,
    t_attack_end: float,
    threshold_high: float = 0.60,
    threshold_critical: float = 0.75,
) -> dict:
    attack_flows  = [f for f in all_flows
                     if _involves_attacker(f, attacker_ip)
                     and t_attack_start <= f["ts"] <= t_attack_end]
    benign_flows  = [f for f in all_flows
                     if not (_involves_attacker(f, attacker_ip)
                             and t_attack_start <= f["ts"] <= t_attack_end)]
    post_flows    = [f for f in all_flows if f["ts"] > t_attack_end]

    # TTD — first CRITICAL alert from attacker during attack window
    ttd_s         = None
    ttd_flows_idx = None
    for i, f in enumerate(sorted(attack_flows, key=lambda x: x["ts"])):
        if _score(f) >= threshold_critical:
            ttd_s         = f["ts"] - t_attack_start
            ttd_flows_idx = i + 1
            break

    # Peak score during attack
    attack_scores = [_score(f) for f in attack_flows]
    peak_score    = max(attack_scores) if attack_scores else 0.0

    # Rejection rate proxy: fraction of attack flows scoring >= threshold_high
    # (actual rejection rate is in /stats, this is a post-hoc approximation)
    rejection_approx = (
        sum(1 for s in attack_scores if s >= threshold_high) / max(len(attack_scores), 1)
    )

    # FPR — CRITICAL alerts from non-attacker IPs during the full window
    n_fp      = sum(1 for f in benign_flows if _score(f) >= threshold_critical)
    fpr       = n_fp / max(len(benign_flows), 1)

    # Recovery — flows after attack until last CRITICAL drops below HIGH
    recovery_flows = None
    for i, f in enumerate(sorted(post_flows, key=lambda x: x["ts"])):
        if _score(f) < threshold_high:
            recovery_flows = i + 1
            break

    # Baseline quality — benign flows before the attack
    pre_flows     = [f for f in benign_flows if f["ts"] < t_attack_start]
    pre_scores    = [_score(f) for f in pre_flows]
    pre_median    = median(pre_scores) if pre_scores else 0.0
    pre_std       = stdev(pre_scores)  if len(pre_scores) > 1 else 0.0

    return {
        "attack_flows":      len(attack_flows),
        "benign_flows":      len(benign_flows),
        "ttd_s":             ttd_s,
        "ttd_flows":         ttd_flows_idx,
        "peak_score":        peak_score,
        "rejection_approx":  rejection_approx,
        "n_fp":              n_fp,
        "fpr":               fpr,
        "recovery_flows":    recovery_flows,
        "pre_median":        pre_median,
        "pre_std":           pre_std,
    }


# ── Report printing ───────────────────────────────────────────────────────────

def print_report(scenario: dict, result: dict, stats_before: dict, stats_after: dict,
                 t_attack_start: float, t_attack_end: float) -> None:
    run_at   = datetime.fromtimestamp(t_attack_start).strftime("%Y-%m-%d %H:%M:%S")
    duration = t_attack_end - t_attack_start
    m        = result["metrics"]

    print(f"\n{SEP}")
    print("  Corvus IDS — Scenario Report")
    print(f"  Scenario : {scenario['name']}")
    print(f"  Run at   : {run_at}")
    print(SEP)

    tcp_b = stats_before["tcp"]
    udp_b = stats_before["udp"]
    print(f"\nBaseline")
    print(f"  TCP flows seen       : {tcp_b.get('n_seen', '—')}")
    print(f"  UDP flows seen       : {udp_b.get('n_seen', '—')}")
    print(f"  Baseline score p50   : {m['pre_median']:.3f}  (σ = {m['pre_std']:.3f})")

    print(f"\nAttack  ({scenario['attacker_ip']},  {duration:.1f}s)")
    print(f"  Flows captured       : {m['attack_flows']}")
    if m["ttd_s"] is not None:
        print(f"  First CRITICAL alert : {m['ttd_s']:.1f}s after start  "
              f"(flow #{m['ttd_flows']} of {m['attack_flows']})")
    else:
        print(f"  First CRITICAL alert : NOT DETECTED")
    print(f"  Peak composite score : {m['peak_score']:.3f}")
    print(f"  Rejection rate (est) : {m['rejection_approx']*100:.1f}%  "
          f"(flows scored ≥ HIGH threshold)")

    print(f"\nRecovery")
    if m["recovery_flows"] is not None:
        print(f"  Scores below HIGH    : {m['recovery_flows']} flows after attack ended")
    else:
        print(f"  Scores below HIGH    : Not recovered within monitoring window")

    print(f"\nBenign traffic quality")
    print(f"  Benign flows in window : {m['benign_flows']}")
    print(f"  False positives (CRIT) : {m['n_fp']}")
    fp_pct = m['fpr'] * 100
    print(f"  False positive rate    : {fp_pct:.2f}%")

    tcp_a = stats_after["tcp"]
    print(f"\nModel state after scenario")
    print(f"  TCP flows seen       : {tcp_a.get('n_seen', '—')}")
    print(f"  TCP flows trained    : {tcp_a.get('n_trained', '—')}")
    print(f"  TCP rejection rate   : {tcp_a.get('rejection_rate', 0)*100:.1f}%")

    print(f"\n{SEP}")
    print(f"  Saved to             : {result['output_path']}")
    print(SEP)


# ── Single-phase attack runner ────────────────────────────────────────────────

def run_phase(container: str, script: str, args: list, phase_name: str = "Attack") -> tuple[float, float]:
    print(f"\n[{phase_name.lower()}] Starting: {script} {' '.join(str(a) for a in args)}")
    t_start = time.time()
    docker_exec(container, [script] + [str(a) for a in args])
    t_end = time.time()
    print(f"[{phase_name.lower()}] Completed in {t_end - t_start:.1f}s")
    return t_start, t_end


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Run a Corvus IDS scenario and report detection metrics")
    parser.add_argument("scenario",    help="Path to scenario YAML file")
    parser.add_argument("--api",       default=DEFAULT_API, help=f"Inference engine base URL (default: {DEFAULT_API})")
    parser.add_argument("--no-baseline", action="store_true", help="Skip baselining step (model already warm)")
    parser.add_argument("--threshold-high",     type=float, default=0.60)
    parser.add_argument("--threshold-critical", type=float, default=0.75)
    args = parser.parse_args()

    # ── Load scenario ──────────────────────────────────────────────────────────
    scenario_path = Path(args.scenario)
    if not scenario_path.exists():
        print(f"ERROR: scenario file not found: {scenario_path}", file=sys.stderr)
        sys.exit(1)

    with open(scenario_path) as f:
        scenario = yaml.safe_load(f)

    container    = scenario.get("attacker_container", "ids_attacker")
    attacker_ip  = scenario["attacker_ip"]
    baseline_cfg = scenario.get("baseline", {})
    recovery_cfg = scenario.get("recovery", {})
    monitor_s    = recovery_cfg.get("monitor_s", 60)
    needs_udp    = scenario.get("attack", {}).get("script", "").endswith("udp_flood.sh")

    print(f"\n{SEP}")
    print(f"  Corvus IDS — {scenario['name']}")
    print(SEP)

    # ── Baseline ───────────────────────────────────────────────────────────────
    if not args.no_baseline and baseline_cfg.get("auto_baseline", False):
        trigger_fast_baseline()

    stats_before = {}
    if not args.no_baseline and baseline_cfg.get("wait_for_ready", True):
        timeout = baseline_cfg.get("timeout_s", 300)
        stats_before = wait_for_baseline(args.api, timeout, needs_udp=needs_udp)
    else:
        try:
            stats_before = _get_stats(args.api)
        except Exception:
            stats_before = {"tcp": {}, "udp": {}}

    # ── Run attack(s) ──────────────────────────────────────────────────────────
    phases = scenario.get("phases") or [scenario.get("attack", {})]
    all_phases: list[dict] = []

    for phase in phases:
        if not phase:
            continue
        script = phase["script"]
        pargs  = phase.get("args", [])
        name   = phase.get("name", "Attack")

        t_start, t_end = run_phase(container, script, pargs, phase_name=name)
        all_phases.append({"name": name, "script": script, "t_start": t_start, "t_end": t_end})

        rest = phase.get("rest_s", 0)
        if rest and phase is not phases[-1]:
            print(f"[scenario] Resting {rest}s between phases…")
            time.sleep(rest)

    # Use the outer bounds of all phases for the overall attack window
    t_attack_start = all_phases[0]["t_start"]
    t_attack_end   = all_phases[-1]["t_end"]

    # ── Recovery monitoring ────────────────────────────────────────────────────
    if monitor_s > 0:
        print(f"\n[recovery] Monitoring for {monitor_s}s…")
        time.sleep(monitor_s)

    # ── Wait for ring buffer to drain before querying ──────────────────────────
    # The SYN flood (and any pre-existing ring buffer backlog) causes flows to
    # arrive in Python long after their capture timestamp. Flows are only written
    # to SQLite once processed, so querying immediately after monitoring misses
    # flows still in the queue.
    #
    # Strategy: measure background flow rate (flows/s before the attack), then
    # after monitoring, poll until the processing rate drops back to within 20%
    # of that baseline for 3 consecutive intervals — meaning the burst has drained.
    background_rate = (stats_before["tcp"].get("n_seen", 0) +
                       stats_before["udp"].get("n_seen", 0))

    # Sample rate over a short pre-query window to get flows/s
    time.sleep(5)
    try:
        s_sample = _get_stats(args.api)
        sample_total = s_sample["tcp"].get("n_seen", 0) + s_sample["udp"].get("n_seen", 0)
        background_rate_per_s = (sample_total - background_rate) / (monitor_s + 5)
    except Exception:
        background_rate_per_s = 50   # safe fallback

    background_rate_per_s = max(background_rate_per_s, 1)

    print(f"\n[drain] Background rate: {background_rate_per_s:.1f} flows/s. "
          f"Waiting for queue to drain…")

    prev_seen = sample_total
    stable_count = 0
    poll_interval = 5
    for _ in range(72):   # max 72 × 5s = 6 minutes
        time.sleep(poll_interval)
        try:
            s = _get_stats(args.api)
            cur_seen = s["tcp"].get("n_seen", 0) + s["udp"].get("n_seen", 0)
        except Exception:
            continue
        rate = (cur_seen - prev_seen) / poll_interval
        prev_seen = cur_seen
        print(f"  [drain] current rate: {rate:.1f} flows/s  "
              f"(baseline: {background_rate_per_s:.1f})")
        if rate <= background_rate_per_s * 1.2:
            stable_count += 1
            if stable_count >= 3:
                break
        else:
            stable_count = 0

    print("[drain] Queue stable — proceeding to query.\n")

    stats_after = _get_stats(args.api)

    # ── Query flows ────────────────────────────────────────────────────────────
    window_start = t_attack_start - 120   # include 2min of benign pre-attack context
    window_end   = t_attack_end + monitor_s

    print("[report] Querying flow database…")
    try:
        # Use ts_from/ts_to so the query is bounded to the window — avoids the
        # limit cutting off early flows when high background traffic fills the DB.
        raw = _get_flows(args.api, ts_from=window_start, ts_to=window_end)
        window_flows = raw   # server already filtered by time
    except Exception as e:
        print(f"[report] WARNING: could not query flows: {e}")
        window_flows = []

    # ── Compute metrics ────────────────────────────────────────────────────────
    metrics = compute_metrics(
        window_flows, attacker_ip, t_attack_start, t_attack_end,
        args.threshold_high, args.threshold_critical,
    )

    # ── Save results ───────────────────────────────────────────────────────────
    results_dir = Path(__file__).parent.parent / "scenarios" / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    ts_str   = datetime.fromtimestamp(t_attack_start).strftime("%Y%m%d_%H%M%S")
    stem     = scenario_path.stem
    out_path = results_dir / f"{stem}_{ts_str}.json"

    result = {
        "scenario":       scenario["name"],
        "scenario_file":  str(scenario_path),
        "run_at":         t_attack_start,
        "attacker_ip":    attacker_ip,
        "phases":         all_phases,
        "window_flows":   len(window_flows),
        "metrics":        metrics,
        "stats_before":   stats_before,
        "stats_after":    stats_after,
        "thresholds":     {"high": args.threshold_high, "critical": args.threshold_critical},
        "output_path":    str(out_path),
    }

    out_path.write_text(json.dumps(result, indent=2))

    # ── Print report ───────────────────────────────────────────────────────────
    print_report(scenario, result, stats_before, stats_after, t_attack_start, t_attack_end)


if __name__ == "__main__":
    main()