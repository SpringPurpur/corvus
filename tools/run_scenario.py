#!/usr/bin/env python3
"""
run_scenario.py - orchestrate a reproducible IDS scenario and produce a
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
import csv
import json
import os
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

# Force UTF-8 stdout on Windows where the default codec is cp1252.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
from datetime import datetime
from pathlib import Path
from statistics import median, stdev

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML is required. Run: pip install pyyaml", file=sys.stderr)
    sys.exit(1)

# -- Defaults --

DEFAULT_API     = "http://localhost:8765"
DOCKER_CMD      = ["docker", "--context", "default"]
SEP             = "=" * 55

# -- HTTP helpers --

def _get(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=30) as r:
        return json.loads(r.read())


def _post_json(url: str, body: dict) -> dict:
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read())


def _patch_json(url: str, body: dict) -> dict:
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method="PATCH",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
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


def _delete(url: str) -> dict:
    req = urllib.request.Request(url, data=b"", method="DELETE")
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def _get_stats(api: str) -> dict:
    return _get(f"{api}/stats")


def _get_ts_offset(api: str) -> float:
    """Return (container_time - host_time) in seconds.

    Flow timestamps come from the C engine's CLOCK_REALTIME which runs in the
    Docker container. On Windows with WSL2, the container clock can drift from
    the Windows host clock. This offset is added to host time.time() values
    before comparing with flow ts fields or passing ts_from/ts_to to /flows.
    """
    try:
        t_before = time.time()
        server_ts = _get(f"{api}/time")["ts"]
        t_after = time.time()
        host_mid = (t_before + t_after) / 2.0
        offset = server_ts - host_mid
        if abs(offset) > 1.0:
            print(f"[ts] Clock offset: container is {offset:+.1f}s vs host "
                  f"(WSL2 drift)")
        return offset
    except Exception:
        return 0.0


# -- Baseline waiting --

def wait_for_queue_empty(api: str, timeout_s: int = 60, label: str = "pre-attack") -> None:
    """Block until the inference queue depth is zero (or timeout).

    Used twice:
      1. After baseline completes but BEFORE attack starts - ensures no overflow
         baseline flows are in the queue when the attack begins.
      2. After attack + monitor_s - ensures all attack flows are processed before
         we query the DB for metrics.
    """
    deadline = time.time() + timeout_s
    print(f"\n[queue] Waiting for inference queue to drain ({label})...")
    prev_depth = None
    while time.time() < deadline:
        try:
            stats = _get_stats(api)
            depth = stats.get("queue_depth", {}).get("total", None)
        except Exception:
            time.sleep(1)
            continue
        if depth is None:
            # Old inference without queue_depth - skip drain wait
            print("[queue] queue_depth not available in /stats - skipping drain wait")
            return
        if depth != prev_depth:
            print(f"  [queue] depth={depth}")
            prev_depth = depth
        if depth == 0:
            print(f"[queue] Queue empty ({label}).\n")
            return
        time.sleep(1)
    print(f"[queue] WARNING: queue did not drain within {timeout_s}s - proceeding anyway.")


def open_phase(api: str, run_id: str, scenario: str, phase: str,
               t_start: float, attacker_ip: str | None = None) -> int:
    """POST /phases - record phase start, return phase_id."""
    try:
        body = {"run_id": run_id, "scenario": scenario, "phase": phase,
                "t_start": t_start, "attacker_ip": attacker_ip}
        resp = _post_json(f"{api}/phases", body)
        return resp.get("phase_id", -1)
    except Exception as e:
        print(f"[phase] WARNING: could not record phase start: {e}")
        return -1


def close_phase(api: str, phase_id: int, t_end: float) -> None:
    """PATCH /phases/{id} - set t_end."""
    if phase_id < 0:
        return
    try:
        _patch_json(f"{api}/phases/{phase_id}", {"t_end": t_end})
    except Exception as e:
        print(f"[phase] WARNING: could not close phase {phase_id}: {e}")


def wait_for_baseline(api: str, timeout_s: int, needs_udp: bool = False) -> dict:
    """Poll /stats until both required detectors report is_ready=true."""
    deadline = time.time() + timeout_s
    last_tcp = last_udp = 0.0

    print(f"\n[baseline] Waiting for OIF detectors to warm up (timeout {timeout_s}s)...")
    while time.time() < deadline:
        try:
            stats = _get_stats(api)
        except Exception:
            time.sleep(3)
            continue

        tcp_ready = stats["tcp"].get("ready", False)
        udp_ready = stats["udp"].get("ready", False)

        tcp_p    = stats["tcp"].get("n_baseline", stats["tcp"].get("n_seen", 0))
        udp_p    = stats["udp"].get("n_baseline", stats["udp"].get("n_seen", 0))
        tcp_tgt  = stats["tcp"].get("n_baseline_target", 4096)
        udp_tgt  = stats["udp"].get("n_baseline_target", 1024)

        if tcp_p != last_tcp or udp_p != last_udp:
            last_tcp, last_udp = tcp_p, udp_p
            tcp_str = "READY" if tcp_ready else f"{tcp_p}/{tcp_tgt}"
            udp_str = "READY" if udp_ready else f"{udp_p}/{udp_tgt}"
            print(f"  TCP: {tcp_str}   UDP: {udp_str}")

        ready = tcp_ready and (udp_ready if needs_udp else True)
        if ready:
            if not needs_udp and not udp_ready:
                print(f"[baseline] TCP ready - UDP still filling in background "
                      f"({udp_p}/{udp_tgt}, not required for this scenario).\n")
            else:
                print("[baseline] Detectors ready.\n")
            return stats

        time.sleep(5)

    print(f"[baseline] WARNING: timed out after {timeout_s}s -- proceeding anyway.")
    return _get_stats(api)


# -- Docker exec helpers --

def docker_exec(container: str, cmd: list[str], background: bool = False) -> subprocess.Popen | None:
    full = DOCKER_CMD + ["exec", container] + cmd
    if background:
        return subprocess.Popen(full, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(full, check=False)
    return None


_BASELINE_NODES = ["ids_node_1", "ids_node_2", "ids_node_3", "ids_node_4", "ids_node_5"]

def trigger_fast_baseline() -> None:
    print("[baseline] Triggering fast_baseline.sh on client containers...")
    for node in _BASELINE_NODES:
        docker_exec(node, ["bash", "/scripts/fast_baseline.sh"], background=True)


# -- Metrics computation --

def _score(flow: dict) -> float:
    """Return the composite OIF score from a flow dict.

    Tries the flat alias first (score_comp), then the nested path - handles
    both the current storage format and any older snapshots.
    """
    return (
        flow.get("score_comp")
        or (flow.get("scores") or {}).get("composite")
        or 0.0
    )


def _involves_attacker(flow: dict, attacker_ip: str) -> bool:
    # Flow keys are normalised (lower IP -> src_ip), so the attacker can appear
    # in either src_ip or dst_ip depending on which side has the lower address.
    return flow.get("src_ip") == attacker_ip or flow.get("dst_ip") == attacker_ip


def compute_metrics(
    all_flows: list[dict],
    attacker_ip: str,
    t_attack_start: float,
    t_attack_end: float,
    threshold_high: float = 0.60,
    threshold_critical: float = 0.80,
    attacker_port: int | None = None,
) -> dict:
    # attack_flows: all attacker-IP flows in the query window.
    # The outer query (ts_from=window_start, ts_to=window_end) already bounds the
    # window. We intentionally do NOT further filter by [c_attack_start, c_attack_end]
    # here because fast attacks (SYN flood ~1.2s, UDP flood ~0.6s) have windows
    # narrower than the docker-exec overhead + first-packet latency, causing flows
    # whose pcap timestamp lands just outside the narrow window to be missed entirely.
    attack_flows  = [f for f in all_flows if _involves_attacker(f, attacker_ip)]
    # Optional port filter: narrows burst-attack flows to a specific target port.
    # Flows are IP-normalised (lower IP → src), so the victim's port may appear
    # in either src_port or dst_port depending on which side has the lower address.
    if attacker_port is not None:
        attack_flows = [f for f in attack_flows
                        if f.get("src_port") == attacker_port
                        or f.get("dst_port") == attacker_port]
    benign_flows  = [f for f in all_flows if not _involves_attacker(f, attacker_ip)]
    post_flows    = [f for f in all_flows if f["ts"] > t_attack_end]

    # TTD - first CRITICAL alert from attacker. Floor negative TTD to 0 so
    # attacks whose first packet arrives fractionally before the start stamp
    # (clock drift) don't produce a confusing negative time-to-detect.
    ttd_s         = None
    ttd_flows_idx = None
    for i, f in enumerate(sorted(attack_flows, key=lambda x: x["ts"])):
        if _score(f) >= threshold_critical:
            ttd_s         = max(f["ts"] - t_attack_start, 0.0)
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

    # FPR - CRITICAL alerts from non-attacker IPs during the full window
    n_fp      = sum(1 for f in benign_flows if _score(f) >= threshold_critical)
    fpr       = n_fp / max(len(benign_flows), 1)

    # Recovery - flows after attack until last CRITICAL drops below HIGH
    recovery_flows = None
    for i, f in enumerate(sorted(post_flows, key=lambda x: x["ts"])):
        if _score(f) < threshold_high:
            recovery_flows = i + 1
            break

    # Baseline quality - benign flows before the attack
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


# -- Report printing --

def print_report(scenario: dict, result: dict, stats_before: dict, stats_after: dict,
                 t_attack_start: float, t_attack_end: float) -> None:
    run_at   = datetime.fromtimestamp(t_attack_start).strftime("%Y-%m-%d %H:%M:%S")
    duration = t_attack_end - t_attack_start
    m        = result["metrics"]

    print(f"\n{SEP}")
    print("  Corvus IDS - Scenario Report")
    print(f"  Scenario : {scenario['name']}")
    print(f"  Run at   : {run_at}")
    print(SEP)

    tcp_b = stats_before["tcp"]
    udp_b = stats_before["udp"]
    print(f"\nBaseline")
    print(f"  TCP flows seen       : {tcp_b.get('n_seen', '-')}")
    print(f"  UDP flows seen       : {udp_b.get('n_seen', '-')}")
    print(f"  Baseline score p50   : {m['pre_median']:.3f}  (std = {m['pre_std']:.3f})")

    print(f"\nAttack  ({scenario['attacker_ip']},  {duration:.1f}s)")
    print(f"  Flows captured       : {m['attack_flows']}")
    if m["ttd_s"] is not None:
        print(f"  First CRITICAL alert : {m['ttd_s']:.1f}s after start  "
              f"(flow #{m['ttd_flows']} of {m['attack_flows']})")
    else:
        print(f"  First CRITICAL alert : NOT DETECTED")
    print(f"  Peak composite score : {m['peak_score']:.3f}")
    print(f"  Rejection rate (est) : {m['rejection_approx']*100:.1f}%  "
          f"(flows scored >= HIGH threshold)")

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
    print(f"  TCP flows seen       : {tcp_a.get('n_seen', '-')}")
    print(f"  TCP flows trained    : {tcp_a.get('n_trained', '-')}")
    print(f"  TCP rejection rate   : {tcp_a.get('rejection_rate', 0)*100:.1f}%")

    print(f"\n{SEP}")
    print(f"  Saved to             : {result['output_path']}")
    print(SEP)


# -- Resource monitoring --

def _parse_pct(s: str) -> float:
    try:
        return float(s.strip().rstrip("%"))
    except ValueError:
        return 0.0


def _parse_size_mb(s: str) -> float:
    """Parse docker stats size strings ('123.4MiB', '1.5GiB', '500kB') to MB."""
    s = s.strip()
    for suffix, factor in [("gib", 1024.0), ("gb", 1024.0),
                           ("mib", 1.0),   ("mb", 1.0),
                           ("kib", 1/1024), ("kb", 1/1024),
                           ("b",   1/(1024*1024))]:
        if s.lower().endswith(suffix):
            try:
                return float(s[:-len(suffix)]) * factor
            except ValueError:
                return 0.0
    try:
        return float(s) / (1024 * 1024)
    except ValueError:
        return 0.0


class ResourceMonitor:
    """Poll 'docker stats --no-stream' every poll_s seconds in a background thread.

    Captures CPU%, memory MB, and net I/O for all running containers.
    Call start() before the attack, stop() after recovery, then save_csv().
    """

    _FIELDS = ["ts", "container", "cpu_pct", "mem_mb", "mem_pct",
               "net_rx_mb", "net_tx_mb"]

    def __init__(self, poll_s: float = 2.0):
        self._poll_s = poll_s
        self._rows: list[dict] = []
        self._stop   = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self._stop.clear()
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=15)

    def _run(self) -> None:
        while not self._stop.wait(self._poll_s):
            try:
                self._sample()
            except Exception:
                pass

    def _sample(self) -> None:
        proc = subprocess.run(
            DOCKER_CMD + ["stats", "--no-stream", "--format", "{{json .}}"],
            capture_output=True, text=True, timeout=10,
        )
        ts = time.time()
        for line in proc.stdout.strip().splitlines():
            if not line.strip():
                continue
            try:
                d    = json.loads(line)
                name = d.get("Name") or d.get("Container", "?")
                net  = d.get("NetIO", "0B / 0B")
                rx_s, tx_s = (net.split("/") + ["0B"])[:2]
                self._rows.append({
                    "ts":        round(ts, 3),
                    "container": name,
                    "cpu_pct":   _parse_pct(d.get("CPUPerc", "0%")),
                    "mem_mb":    _parse_size_mb(d.get("MemUsage", "0B / 0B").split("/")[0]),
                    "mem_pct":   _parse_pct(d.get("MemPerc", "0%")),
                    "net_rx_mb": _parse_size_mb(rx_s),
                    "net_tx_mb": _parse_size_mb(tx_s),
                })
            except Exception:
                pass

    def save_csv(self, path: str) -> int:
        """Write collected rows to CSV. Returns row count."""
        if not self._rows:
            return 0
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=self._FIELDS)
            w.writeheader()
            w.writerows(self._rows)
        return len(self._rows)


# -- Single-phase attack runner --

def run_phase(container: str, script: str, args: list, phase_name: str = "Attack") -> tuple[float, float]:
    print(f"\n[{phase_name.lower()}] Starting: {script} {' '.join(str(a) for a in args)}")
    t_start = time.time()
    docker_exec(container, [script] + [str(a) for a in args])
    t_end = time.time()
    print(f"[{phase_name.lower()}] Completed in {t_end - t_start:.1f}s")
    return t_start, t_end


# -- Main --

def main() -> None:
    parser = argparse.ArgumentParser(description="Run a Corvus IDS scenario and report detection metrics")
    parser.add_argument("scenario",    help="Path to scenario YAML file")
    parser.add_argument("--api",       default=DEFAULT_API, help=f"Inference engine base URL (default: {DEFAULT_API})")
    parser.add_argument("--no-baseline", action="store_true", help="Skip baselining step (model already warm)")
    parser.add_argument("--threshold-high",     type=float, default=0.60)
    parser.add_argument("--threshold-critical", type=float, default=0.80)
    parser.add_argument("--results-dir", default=None,
                        help="Output directory for result JSON (default: scenarios/results/)")
    args = parser.parse_args()

    # -- Load scenario --
    scenario_path = Path(args.scenario)
    if not scenario_path.exists():
        print(f"ERROR: scenario file not found: {scenario_path}", file=sys.stderr)
        sys.exit(1)

    with open(scenario_path) as f:
        scenario = yaml.safe_load(f)

    container    = scenario.get("attacker_container", "ids_attacker")
    attacker_ip  = scenario["attacker_ip"]
    attacker_port = scenario.get("attacker_port")  # optional: tighten burst-attack flow filter
    baseline_cfg = scenario.get("baseline", {})
    recovery_cfg = scenario.get("recovery", {})
    monitor_s    = recovery_cfg.get("monitor_s", 60)
    needs_udp    = scenario.get("attack", {}).get("script", "").endswith("udp_flood.sh")

    print(f"\n{SEP}")
    print(f"  Corvus IDS - {scenario['name']}")
    print(SEP)

    # Measure host-to-container clock offset once before the attack.
    # Flow ts values come from the C engine's CLOCK_REALTIME in the Docker
    # container; on Windows/WSL2 this can diverge from host time.time().
    ts_offset = _get_ts_offset(args.api)

    # run_id ties all phase records for this scenario run together.
    run_id = datetime.now().strftime("%Y%m%d_%H%M%S") + "_" + scenario_path.stem

    # -- Baseline --
    baseline_phase_id = -1
    if not args.no_baseline and baseline_cfg.get("auto_baseline", False):
        baseline_phase_id = open_phase(
            args.api, run_id, scenario["name"], "baseline",
            t_start=time.time(), attacker_ip=None,
        )
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

    # Close baseline phase record now that OIF is ready.
    close_phase(args.api, baseline_phase_id, t_end=time.time())

    # After baseline is ready, atomically clear the inference queue before the
    # attack starts. This is faster and more reliable than polling for drain;
    # DELETE /queue discards all pending flows instantly so the attack window
    # starts with a clean slate. Any baseline overflow flows that were in the
    # queue are intentionally discarded here; only attack-window flows matter.
    try:
        qd = _delete(f"{args.api}/queue")
        dropped = qd.get("dropped", {})
        total_dropped = sum(dropped.values()) if isinstance(dropped, dict) else 0
        if total_dropped:
            print(f"[queue] Cleared inference queue: {total_dropped} pre-attack flows discarded.")
        else:
            print("[queue] Inference queue already empty - clean start.")
    except Exception as e:
        print(f"[queue] WARNING: could not clear queue: {e}")

    # -- Run attack(s) --
    phases = scenario.get("phases") or [scenario.get("attack", {})]
    all_phases: list[dict] = []

    resource_monitor = ResourceMonitor(poll_s=2.0)
    resource_monitor.start()

    for phase in phases:
        if not phase:
            continue
        script = phase["script"]
        pargs  = phase.get("args", [])
        name   = phase.get("name", "Attack")

        attack_phase_id = open_phase(
            args.api, run_id, scenario["name"], "attack",
            t_start=time.time(), attacker_ip=attacker_ip,
        )
        t_start, t_end = run_phase(container, script, pargs, phase_name=name)
        close_phase(args.api, attack_phase_id, t_end=t_end)
        all_phases.append({"name": name, "script": script,
                           "t_start": t_start, "t_end": t_end,
                           "phase_id": attack_phase_id})

        rest = phase.get("rest_s", 0)
        if rest and phase is not phases[-1]:
            print(f"[scenario] Resting {rest}s between phases...")
            time.sleep(rest)

    # Use the outer bounds of all phases for the overall attack window
    t_attack_start = all_phases[0]["t_start"]
    t_attack_end   = all_phases[-1]["t_end"]

    # -- Post-attack wait then queue drain --
    # monitor_s: time to wait for attack effects to play out before querying.
    # Used by scenarios where the C engine needs time to finalize flows, e.g.:
    #   - SYN flood (hping3 --syn -k): single flow with 120s idle timeout.
    #     monitor_s=150 ensures the flow is finalized and in the IPC ring before
    #     we drain the queue.
    # After the wait, poll queue_depth until zero - all flows scored and in DB.
    recovery_phase_id = open_phase(
        args.api, run_id, scenario["name"], "recovery",
        t_start=t_attack_end, attacker_ip=None,
    )
    if monitor_s > 0:
        print(f"\n[recovery] Waiting {monitor_s}s for flows to finalize and reach queue...")
        time.sleep(monitor_s)
    close_phase(args.api, recovery_phase_id, t_end=time.time())

    wait_for_queue_empty(args.api, timeout_s=180, label="post-attack drain")

    resource_monitor.stop()
    stats_after = _get_stats(args.api)

    # -- Query flows --
    # Apply ts_offset so the window aligns with flow timestamps from the C engine.
    # ts_offset = container_time - host_time (positive if container is ahead).
    c_attack_start = t_attack_start + ts_offset
    c_attack_end   = t_attack_end   + ts_offset
    window_start   = c_attack_start - 120   # 2min pre-attack benign context
    window_end     = c_attack_end   + monitor_s

    print(f"[report] Querying flows ts=[{window_start:.0f}, {window_end:.0f}] "
          f"(offset={ts_offset:+.1f}s)...")
    try:
        # First get total DB count to distinguish "window mismatch" from "empty DB"
        db_all = _get_flows(args.api, limit=50000)
        db_ts_vals = [f["ts"] for f in db_all] if db_all else []
        if db_ts_vals:
            print(f"[report] DB total: {len(db_all)} flows, "
                  f"ts range [{min(db_ts_vals):.0f}, {max(db_ts_vals):.0f}]")
        else:
            print("[report] DB total: 0 flows")

        raw = _get_flows(args.api, ts_from=window_start, ts_to=window_end)
        window_flows = raw

        # Diagnostic: show attacker flow count and src_ip distribution in window
        attacker_in_window = [f for f in window_flows if _involves_attacker(f, attacker_ip)]
        if attacker_in_window:
            print(f"[report] Attacker flows in window: {len(attacker_in_window)}")
            if attacker_port is not None:
                port_match = [f for f in attacker_in_window
                              if f.get("src_port") == attacker_port
                              or f.get("dst_port") == attacker_port]
                print(f"[report]   With port={attacker_port} filter: {len(port_match)}")
        else:
            # No attacker flows in window - check unconstrained DB for attacker flows
            attacker_all = [f for f in db_all if _involves_attacker(f, attacker_ip)]
            if attacker_all:
                ts_vals = [f["ts"] for f in attacker_all]
                print(f"[report] WARNING: 0 attacker flows in window "
                      f"[{window_start:.0f}, {window_end:.0f}].")
                print(f"[report]   Attacker flows in full DB: {len(attacker_all)}  "
                      f"ts=[{min(ts_vals):.3f}, {max(ts_vals):.3f}]")
                print(f"[report]   Sample: src_ip={attacker_all[0].get('src_ip')}  "
                      f"dst_ip={attacker_all[0].get('dst_ip')}  "
                      f"src_port={attacker_all[0].get('src_port')}  "
                      f"dst_port={attacker_all[0].get('dst_port')}")
            else:
                print(f"[report] WARNING: attacker IP {attacker_ip} not found in DB at all "
                      f"(DB has {len(db_all)} flows total). "
                      f"Flow may still be in C engine ring - check monitor_s.")
    except Exception as e:
        print(f"[report] WARNING: could not query flows: {e}")
        window_flows = []

    print(f"[report] {len(window_flows)} flows in window.")

    # -- Compute metrics --
    # Pass container-aligned attack times so ts comparisons inside are correct.
    metrics = compute_metrics(
        window_flows, attacker_ip, c_attack_start, c_attack_end,
        args.threshold_high, args.threshold_critical,
        attacker_port=attacker_port,
    )

    # -- Save results --
    if args.results_dir:
        results_dir = Path(args.results_dir)
    else:
        results_dir = Path(__file__).parent.parent / "scenarios" / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    ts_str   = datetime.fromtimestamp(t_attack_start).strftime("%Y%m%d_%H%M%S")
    stem     = scenario_path.stem
    out_path = results_dir / f"{stem}_{ts_str}.json"

    # Enrich: top-5 attack flows by score (key fields only, not the full dict)
    def _score(f: dict) -> float:
        return f.get("score_comp") or (f.get("scores") or {}).get("composite") or 0.0

    attack_window = [
        f for f in window_flows
        if _involves_attacker(f, attacker_ip)
    ]
    top_flows = sorted(attack_window, key=_score, reverse=True)[:5]
    top_flows_slim = [
        {
            "flow_id":   f.get("flow_id"),
            "ts":        f.get("ts"),
            "src_ip":    f.get("src_ip"),
            "src_port":  f.get("src_port"),
            "dst_ip":    f.get("dst_ip"),
            "dst_port":  f.get("dst_port"),
            "proto":     f.get("proto"),
            "score":     _score(f),
            "verdict":   (f.get("verdict") or {}).get("label"),
            "attribution": f.get("attribution", [])[:3],
        }
        for f in top_flows
    ]

    # Latency percentiles from flows that have timing data.
    # t_enqueue_ns is set by ipc_writer_enqueue() - the correct IPC start time.
    # Falls back to flow_ts_ns (legacy) if t_enqueue_ns is absent or zero.
    def _has(*keys):
        return lambda f: (f.get("timing") and
                          all(f["timing"].get(k, 0) > 0 for k in keys))

    # t_enqueue_ns is only valid if it looks like a real nanosecond timestamp
    # (> 1e15 ns = year 2001+). Old monitor binaries write flag bytes there
    # (values 1, 257, 65537), which pass the > 0 guard but produce garbage IPC ms.
    _NS_PLAUSIBLE = 1_000_000_000_000_000  # 1e15 ns = ~year 2001

    def _ipc_start(f: dict) -> int:
        t = f.get("timing", {})
        enqueue = t.get("t_enqueue_ns", 0) or 0
        if enqueue > _NS_PLAUSIBLE:
            return enqueue
        flow_ts = t.get("flow_ts_ns", 0) or 0
        return flow_ts if flow_ts > _NS_PLAUSIBLE else 0

    ipc_vals   = [(f["timing"]["t_socket_ns"] - _ipc_start(f)) / 1e6
                  for f in window_flows
                  if f.get("timing") and f["timing"].get("t_socket_ns", 0) > 0
                  and _ipc_start(f) > 0]
    queue_vals = [(f["timing"]["t_dequeue_ns"] - f["timing"]["t_socket_ns"]) / 1e6
                  for f in window_flows if _has("t_dequeue_ns", "t_socket_ns")(f)]
    oif_vals   = [(f["timing"]["t_scored_ns"]  - f["timing"]["t_dequeue_ns"])/ 1e6
                  for f in window_flows if _has("t_scored_ns",  "t_dequeue_ns")(f)]

    def _pcts(vals: list) -> dict:
        if not vals:
            return {}
        arr = sorted(vals)
        n   = len(arr)
        return {
            "mean":  sum(arr) / n,
            "p50":   arr[n // 2],
            "p95":   arr[min(int(n * 0.95), n - 1)],
            "p99":   arr[min(int(n * 0.99), n - 1)],
            "count": n,
        }

    result = {
        "type":              "scenario",
        "run_id":            run_id,
        "scenario":          scenario["name"],
        "scenario_file":     str(scenario_path),
        "run_at":            t_attack_start,
        "run_at_human":      datetime.fromtimestamp(t_attack_start).strftime("%Y-%m-%d %H:%M:%S"),
        "attacker_ip":       attacker_ip,
        "attacker_port":     attacker_port,
        "ts_offset_s":       ts_offset,
        "phases":            all_phases,
        "window_flows":      len(window_flows),
        "metrics":           metrics,
        "top_attack_flows":  top_flows_slim,
        "latency_ms": {
            # ipc_decode: t_enqueue_ns (C ring) → t_socket_ns (Python decode).
            # True wire+decode latency - microseconds, not flow lifetime.
            "ipc_decode":  _pcts(ipc_vals),
            # queue_wait:  t_socket_ns -> t_dequeue_ns - pure asyncio queue depth.
            "queue_wait":  _pcts(queue_vals),
            # oif_score:   t_dequeue_ns -> t_scored_ns - Isolation Forest scoring.
            "oif_score":   _pcts(oif_vals),
        },
        "stats_before":      stats_before,
        "stats_after":       stats_after,
        "thresholds":        {"high": args.threshold_high, "critical": args.threshold_critical},
        "output_path":       str(out_path),
    }

    res_path = results_dir / f"resources_{stem}_{ts_str}.csv"
    n_samples = resource_monitor.save_csv(str(res_path))
    result["resources_path"] = str(res_path) if n_samples else None
    if n_samples:
        print(f"[resources] {n_samples} samples saved to {res_path.name}")
    else:
        print("[resources] WARNING: no resource samples collected (docker stats unavailable?)")

    out_path.write_text(json.dumps(result, indent=2))

    # -- Print report --
    print_report(scenario, result, stats_before, stats_after, t_attack_start, t_attack_end)


if __name__ == "__main__":
    main()
