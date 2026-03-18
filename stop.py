#!/usr/bin/env python3
"""stop.py — tear down the Corvus IDS stack."""

import os
import subprocess

COMPOSE = os.path.join(os.path.dirname(__file__), "docker-compose.yml")

if __name__ == "__main__":
    subprocess.run(
        ["docker", "--context", "default", "compose", "-f", COMPOSE, "down"],
        check=True,
    )
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
