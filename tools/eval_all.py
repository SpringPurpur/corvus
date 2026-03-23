#!/usr/bin/env python3
"""
eval_all.py - run every scenario with OIF resets between each, then
print a side-by-side comparison table.

Workflow per scenario:
  1. DELETE /flows        - clean DB so each scenario starts from zero
  2. POST /baseline/reset - fresh OIF state (deletes pkl, re-baselines)
  3. python tools/run_scenario.py <yml>  - baselines + runs attack
  4. Collect the result JSON from scenarios/results/

After all scenarios, print a comparison table and save a summary JSON.

Usage:
    python tools/eval_all.py
    python tools/eval_all.py --skip-baseline
    python tools/eval_all.py --scenarios scenarios/syn_flood.yml scenarios/slowloris.yml
    python tools/eval_all.py --api http://localhost:8765
"""

import argparse
import json
import subprocess
import sys
import time
import urllib.request

# Force UTF-8 stdout on Windows where the default codec is cp1252.
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
from datetime import datetime
from pathlib import Path

SEP        = "=" * 79
DEFAULT_API = "http://localhost:8765"

# Order matters for two reasons:
#   1. High-volume scenarios (http_flood, ~13K flows) can overflow the C engine's
#      IPC ring buffer. Port scan (~1000 micro-flows) and syn_flood (single long-
#      lived flow) must run before these, or their flows get dropped mid-capture.
#   2. syn_flood uses hping3 --syn with a fixed source port, so it creates one
#      flow per target that stays in the C engine's table until the 120 s idle
#      timeout. Running it after http_flood means the flow table may still be
#      partially drained, causing the syn_flood flow to arrive at the wrong time.
DEFAULT_SCENARIO_ORDER = [
    "slowloris",
    "slow_body",
    "slow_read",
    "ssh_bruteforce",
    "port_scan",          # ~1000 micro-flows — must precede high-volume scenarios
    "syn_flood",          # single long-lived flow; needs table headroom to be recorded
    "http_flood",
    "goldeneye",
    "http2_rapid_reset",
    "udp_flood",
    "mixed",
]


# -- HTTP helpers --

def _post(url: str) -> dict:
    req = urllib.request.Request(url, method="POST", data=b"")
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def _delete(url: str) -> dict:
    # data=b"" forces Content-Length: 0; without it urllib omits the header
    # and uvicorn drops the connection before sending a response.
    # 30s timeout: clear_flows() acquires _write_lock; under active flow
    # ingestion the inference worker may hold it for several seconds.
    req = urllib.request.Request(url, data=b"", method="DELETE")
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


# -- Reset between scenarios --

def reset(api: str) -> None:
    """Clear DB and reset OIF detectors to fresh-baselining state."""
    try:
        result = _delete(f"{api}/flows")
        print(f"  [reset] Deleted {result.get('deleted', 0)} flows from DB.")
    except urllib.error.HTTPError as e:
        if e.code == 405:
            print(f"  [reset] ERROR: DELETE /flows returned 405 - inference container "
                  f"needs a rebuild.\n         Run: python launch.py --build", file=sys.stderr)
            sys.exit(1)
        raise

    try:
        _post(f"{api}/baseline/reset?protocol=all")
        print("  [reset] OIF detectors reset - will re-baseline on next flows.")
    except urllib.error.HTTPError as e:
        if e.code in (404, 405):
            print(f"  [reset] ERROR: POST /baseline/reset returned {e.code} - inference "
                  f"container needs a rebuild.\n         Run: python launch.py --build",
                  file=sys.stderr)
            sys.exit(1)
        raise


# -- Run a single scenario via subprocess --

def run_scenario(yml_path: Path, api: str) -> Path | None:
    """Run run_scenario.py for yml_path. Returns the result JSON path, or None on failure."""
    cmd = [
        sys.executable,
        str(Path(__file__).parent / "run_scenario.py"),
        str(yml_path),
        "--api", api,
    ]
    print(f"\n  Running: {' '.join(cmd)}")
    t_start = time.time()

    proc = subprocess.run(cmd, capture_output=False)

    elapsed = time.time() - t_start
    if proc.returncode != 0:
        print(f"  [scenario] FAILED (exit {proc.returncode}) after {elapsed:.0f}s")
        return None

    # Find the newest result file matching this scenario stem.
    stem        = yml_path.stem
    results_dir = Path(__file__).parent.parent / "scenarios" / "results"
    candidates  = sorted(results_dir.glob(f"{stem}_*.json"), key=lambda p: p.stat().st_mtime)
    if not candidates:
        print(f"  [scenario] WARNING: no result file found for {stem}")
        return None

    return candidates[-1]


# -- Comparison table --

def _fmt(val, fmt: str = ".3f", missing: str = "N/A") -> str:
    return missing if val is None else format(val, fmt)


def print_comparison(
    baseline_result: dict | None,
    scenario_results: list[dict],
) -> None:
    print(f"\n{SEP}")
    print("  Corvus IDS - Full Scenario Evaluation Summary")
    if baseline_result:
        bm = baseline_result.get("metrics", {})
        print(f"  Baseline FPR (benign-only, no attacks): "
              f"HIGH {bm.get('fpr_high', 0)*100:.2f}%  "
              f"CRITICAL {bm.get('fpr_crit', 0)*100:.2f}%")
    print(SEP)

    # Columns:
    #   Detected? - YES/NO/PARTIAL/NO FLOWS
    #   TTD (s)   - seconds from attack start to first CRITICAL alert
    #   Peak      - highest composite score seen during attack
    #   Det%      - rejection_approx: % of attack flows scoring >= HIGH
    #   FPR CRIT  - fpr: benign flows scoring >= CRITICAL / all benign flows
    #   Recovery  - flows after attack until score drops below HIGH
    col = "{:<22}  {:>9}  {:>7}  {:>6}  {:>6}  {:>9}  {:>10}"
    print(col.format(
        "Scenario", "Detected?", "TTD (s)", "Peak", "Det%", "FPR CRIT", "Recovery",
    ))
    print("-" * 79)

    for r in scenario_results:
        name = r.get("scenario", r.get("scenario_file", "?"))[:22]

        m        = r.get("metrics", {})
        ttd      = m.get("ttd_s")
        peak     = m.get("peak_score", 0.0)
        det_rate = m.get("rejection_approx")   # fraction of attack flows >= HIGH
        fpr_crit = m.get("fpr")                # benign CRITICAL rate
        recovery = m.get("recovery_flows")

        if m.get("attack_flows", 0) == 0 and ttd is None:
            detected = "NO FLOWS"
        elif ttd is not None:
            detected = "YES"
        elif peak is not None and peak >= 0.75:
            detected = "YES"
        elif peak is not None and peak >= 0.60:
            detected = "PARTIAL"
        else:
            detected = "NO"

        rec_str     = f"{recovery} fl" if recovery is not None else "N/A"
        det_pct_str = f"{det_rate*100:.0f}%" if det_rate is not None else "N/A"
        fpr_str     = f"{fpr_crit*100:.2f}%" if fpr_crit is not None else "N/A"

        print(col.format(
            name,
            detected,
            _fmt(ttd,  ".1f"),
            _fmt(peak, ".3f"),
            det_pct_str,
            fpr_str,
            rec_str,
        ))

    print(SEP)


# -- Main --

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run all scenarios with OIF resets and produce a comparison table"
    )
    parser.add_argument("--api",            default=DEFAULT_API)
    parser.add_argument("--scenarios",      nargs="*",
                        help="Specific scenario YAML paths. Default: all in scenarios/")
    parser.add_argument("--skip-baseline",  action="store_true",
                        help="Skip the standalone baseline quality check")
    parser.add_argument("--baseline-duration", type=float, default=5.0,
                        help="Minutes of benign observation for baseline check (default: 5)")
    args = parser.parse_args()

    root = Path(__file__).parent.parent

    # -- Resolve scenario list --
    if args.scenarios:
        yml_paths = [Path(p) for p in args.scenarios]
    else:
        scenarios_dir = root / "scenarios"
        # Sort by preferred order, then alphabetically for anything not in the list
        all_ymls = {p.stem: p for p in scenarios_dir.glob("*.yml")}
        yml_paths = []
        for stem in DEFAULT_SCENARIO_ORDER:
            if stem in all_ymls:
                yml_paths.append(all_ymls.pop(stem))
        yml_paths.extend(sorted(all_ymls.values()))  # any remaining in alpha order

    if not yml_paths:
        print("ERROR: no scenario YAML files found.", file=sys.stderr)
        sys.exit(1)

    print(f"\n{SEP}")
    print("  Corvus IDS - Full Scenario Evaluation")
    print(f"  Scenarios  : {len(yml_paths)}")
    print(f"  API        : {args.api}")
    print(SEP)

    run_at = time.time()

    # -- Optional baseline quality check --
    baseline_result: dict | None = None
    if not args.skip_baseline:
        print("\n[eval_all] Step 0: baseline quality check")
        baseline_cmd = [
            sys.executable,
            str(Path(__file__).parent / "eval_baseline.py"),
            "--api", args.api,
            "--duration", str(args.baseline_duration),
        ]
        subprocess.run(baseline_cmd, capture_output=False)

        # Find the newest baseline result
        results_dir = root / "scenarios" / "results"
        candidates  = sorted(results_dir.glob("baseline_*.json"),
                              key=lambda p: p.stat().st_mtime)
        if candidates:
            baseline_result = json.loads(candidates[-1].read_text())

    # -- Run each scenario --
    scenario_results: list[dict] = []

    for i, yml_path in enumerate(yml_paths, start=1):
        print(f"\n{SEP}")
        print(f"  Scenario {i}/{len(yml_paths)}: {yml_path.name}")
        print(SEP)

        print("\n[eval_all] Resetting OIF state...")
        reset(args.api)

        result_path = run_scenario(yml_path, args.api)

        if result_path and result_path.exists():
            result = json.loads(result_path.read_text())
            scenario_results.append(result)
            print(f"\n[eval_all] Result saved: {result_path.name}")
        else:
            # Record a failure entry so the table shows something
            scenario_results.append({
                "scenario":      yml_path.stem,
                "scenario_file": str(yml_path),
                "metrics": {},
            })
            print(f"[eval_all] WARNING: no result collected for {yml_path.name}")

    # -- Summary --
    print_comparison(baseline_result, scenario_results)

    # Save summary
    results_dir = root / "scenarios" / "results"
    ts_str      = datetime.fromtimestamp(run_at).strftime("%Y%m%d_%H%M%S")
    out_path    = results_dir / f"eval_all_{ts_str}.json"
    summary = {
        "type":             "eval_all",
        "run_at":           run_at,
        "api":              args.api,
        "baseline":         baseline_result,
        "scenarios":        scenario_results,
        "output_path":      str(out_path),
    }
    out_path.write_text(json.dumps(summary, indent=2))
    print(f"\n  Full summary saved to: {out_path}\n")


if __name__ == "__main__":
    main()
