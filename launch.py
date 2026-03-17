#!/usr/bin/env python3
"""
launch.py — start the full Corvus IDS stack and open the dashboard.

Build order:
  1. npm install + npm run build  (host, skipped if dist/ is up to date)
  2. docker compose up -d          (starts inference, monitor, targets, attacker)
  3. wait for /health             (inference engine ready)
  4. open dashboard in browser
"""

import os
import platform
import subprocess
import sys
import time
import urllib.request

# On Windows, npm/npx are batch scripts (.cmd) — not directly executable
NPM = "npm.cmd" if platform.system() == "Windows" else "npm"

ROOT       = os.path.dirname(__file__)
COMPOSE    = os.path.join(ROOT, "docker-compose.yml")
DASHBOARD  = os.path.join(ROOT, "dashboard")
URL        = "http://localhost:8765"
HEALTH     = "http://localhost:8765/health"

CHROME_CANDIDATES = [
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "google-chrome",
    "chromium-browser",
    "chromium",
]


def build_dashboard() -> None:
    """Run npm install (if needed) then npm run build on the host.

    Skips the build entirely if dist/ is newer than all source files,
    so repeated launches are fast.
    """
    dist = os.path.join(DASHBOARD, "dist", "index.html")
    src  = os.path.join(DASHBOARD, "src")

    if os.path.exists(dist):
        dist_mtime = os.path.getmtime(dist)
        # Check if any source file is newer than the last build
        stale = any(
            os.path.getmtime(os.path.join(dp, f)) > dist_mtime
            for dp, _, files in os.walk(src)
            for f in files
        )
        pkg_mtime = os.path.getmtime(os.path.join(DASHBOARD, "package.json"))
        if not stale and pkg_mtime < dist_mtime:
            print("[launch] Dashboard dist/ is up to date — skipping build.")
            return

    print("[launch] Building dashboard...")
    # Check for vite binary, not just the directory — empty node_modules dir
    # is created by git and would falsely skip install
    vite_bin = os.path.join(DASHBOARD, "node_modules", ".bin", "vite")
    vite_cmd = vite_bin + ".cmd" if platform.system() == "Windows" else vite_bin
    if not os.path.exists(vite_cmd):
        subprocess.run([NPM, "install"], cwd=DASHBOARD, check=True)
    subprocess.run([NPM, "run", "build"], cwd=DASHBOARD, check=True)
    print("[launch] Dashboard built.")


def wait_healthy(url: str, timeout: int = 60) -> bool:
    for _ in range(timeout):
        try:
            urllib.request.urlopen(url, timeout=2)
            return True
        except Exception:
            time.sleep(1)
    return False


def open_dashboard(url: str) -> None:
    import webbrowser
    for chrome in CHROME_CANDIDATES:
        try:
            subprocess.Popen([chrome, f"--app={url}"])
            return
        except (FileNotFoundError, OSError):
            continue
    webbrowser.open(url)


if __name__ == "__main__":
    build_dashboard()

    print("[launch] Starting Corvus IDS stack...")
    subprocess.run(
        ["docker", "--context", "default", "compose", "-f", COMPOSE, "up", "-d",
         "--build",
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
