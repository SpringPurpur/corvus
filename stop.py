#!/usr/bin/env python3
"""stop.py — tear down the Corvus IDS stack.

Flags:
  --testbed  Also tear down the evaluation testbed overlay (victim nodes,
             attacker, DNS, NTP). Must match how the stack was started.
"""

import argparse
import os
import subprocess

ROOT            = os.path.dirname(__file__)
COMPOSE         = os.path.join(ROOT, "docker-compose.yml")
COMPOSE_TESTBED = os.path.join(ROOT, "docker-compose.testbed.yml")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Stop the Corvus IDS stack.")
    parser.add_argument(
        "--testbed", action="store_true",
        help="Also stop the evaluation testbed overlay.",
    )
    args = parser.parse_args()

    compose_cmd = ["docker", "--context", "default", "compose", "-f", COMPOSE]
    if args.testbed:
        compose_cmd += ["-f", COMPOSE_TESTBED]
    compose_cmd.append("down")

    mode = "IDS + testbed" if args.testbed else "IDS core"
    print(f"[stop] Stopping Corvus {mode}...")
    subprocess.run(compose_cmd, check=True)
    print("[stop] Stack stopped.")

    # Remove dangling images and build cache left behind by docker compose.
    # This prevents the WSL2 virtual disk (ext4.vhdx) from growing unboundedly
    # across repeated launch/stop cycles. Named volumes and bind mounts are
    # not touched — models and SQLite data are preserved.
    subprocess.run(
        ["docker", "--context", "default", "system", "prune", "-f"],
        check=False,   # non-fatal if prune finds nothing to remove
    )
    print("[stop] Docker build cache and dangling images pruned.")
