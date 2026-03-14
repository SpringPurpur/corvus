#!/usr/bin/env python3
"""
launch.py — start the full Corvus IDS stack and open the dashboard.

Runs docker-compose up -d, waits for the inference engine to become healthy,
then opens the dashboard in Chrome app mode (or the default browser as fallback).
"""

import os
import subprocess
import sys
import time
import urllib.request

COMPOSE = os.path.join(os.path.dirname(__file__), "docker-compose.yml")
URL     = "http://localhost:8765"
HEALTH  = "http://localhost:8765/health"

# Chrome executable paths to try, in preference order
CHROME_CANDIDATES = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "google-chrome",
    "chromium-browser",
    "chromium",
]


def wait_healthy(url: str, timeout: int = 60) -> bool:
    """Poll the health endpoint until it returns 200 or timeout expires."""
    for _ in range(timeout):
        try:
            urllib.request.urlopen(url, timeout=2)
            return True
        except Exception:
            time.sleep(1)
    return False


def open_dashboard(url: str) -> None:
    """Try to open Chrome in app mode; fall back to the default browser."""
    import webbrowser
    for chrome in CHROME_CANDIDATES:
        try:
            subprocess.Popen([chrome, f"--app={url}"])
            return
        except (FileNotFoundError, OSError):
            continue
    webbrowser.open(url)


if __name__ == "__main__":
    print("[launch] Starting Corvus IDS stack...")
    subprocess.run(
        ["docker-compose", "-f", COMPOSE, "up", "-d",
         "--build",          # rebuild images if source changed
         "--remove-orphans"],
        check=True,
    )

    print("[launch] Waiting for inference engine to become healthy...")
    if not wait_healthy(HEALTH):
        print("[launch] ERROR: inference engine did not become healthy within 60s")
        print("[launch] Check logs with:  docker logs ids_inference")
        sys.exit(1)

    print(f"[launch] Stack ready — opening {URL}")
    open_dashboard(URL)
    print("[launch] Running. Press Ctrl+C or run stop.py to shut down.")
