#!/usr/bin/env python3
"""stop.py — tear down the Corvus IDS stack."""

import os
import subprocess

COMPOSE = os.path.join(os.path.dirname(__file__), "docker-compose.yml")

if __name__ == "__main__":
    subprocess.run(
        ["docker-compose", "-f", COMPOSE, "down"],
        check=True,
    )
    print("[stop] Stack stopped.")
