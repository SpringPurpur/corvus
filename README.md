# Corvus IDS

A real-time network intrusion detection system using online machine learning and LLM-assisted alert explanation. Captures live traffic via libpcap, classifies flows with a multi-window Online Isolation Forest, and displays results in a browser dashboard — all in a single Docker Compose stack.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Quick Start](#quick-start)
3. [Configuration](#configuration)
4. [Running Attack Scenarios](#running-attack-scenarios)
5. [Dashboard Guide](#dashboard-guide)
6. [Building from Source](#building-from-source)
7. [Stopping the Stack](#stopping-the-stack)
8. [Physical Deployment (Port Mirroring)](#physical-deployment-port-mirroring)
9. [Project Structure](#project-structure)

---

## Prerequisites

| Requirement | Version |
|---|---|
| Docker Desktop | 4.x or later (with Linux containers) |
| Python (host) | 3.11+ |
| Node.js (host) | 20+ |
| CPU | x86-64 with AVX2 (Intel Haswell 2013+ / AMD Ryzen 2017+) |

**Python host packages** (installed once, not in Docker):

```bash
pip install msgpack
```

**Docker Desktop must be running** before executing any command.

---

## Quick Start

```bash
git clone <repo>
cd Corvus

# Create environment file
cp .env.example .env
# Edit .env and set ANTHROPIC_API_KEY=sk-ant-... (required for LLM features)

# Launch full stack — builds dashboard, starts all containers, opens browser
python launch.py
```

`launch.py` will:
1. Build the React dashboard (`npm ci && npm run build` in `dashboard/`)
2. Run `docker compose up -d` for all services
3. Wait for the inference engine health check to pass
4. Open `http://localhost:8765` (Chrome app mode if available, otherwise default browser)

The first run takes 2–5 minutes to pull images and build the C capture engine inside the container.

---

## Configuration

All configuration lives in two places: `.env` (secrets and deployment) and the **Settings panel** inside the dashboard (operational thresholds).

### `.env` file (repo root)

```env
# Required for LLM alert explanation. Leave empty to disable LLM features.
ANTHROPIC_API_KEY=sk-ant-...

# Network capture — leave empty for automatic detection (Docker bridge).
# For SPAN/TAP port deployments, set to the physical NIC name, e.g. ens3.
CAPTURE_INTERFACE=

# Optional BPF filter applied at capture time.
# Example: exclude management traffic from a specific host.
CAPTURE_FILTER=
```

### Dashboard Settings (⚙ button, top-right)

| Setting | Default | Description |
|---|---|---|
| HIGH threshold | 0.60 | OIF composite score above which an alert is flagged HIGH |
| CRITICAL threshold | 0.80 | OIF composite score above which an alert is flagged CRITICAL |
| TCP baseline flows | 4096 | Flows required before TCP anomaly detection activates |
| UDP baseline flows | 1024 | Flows required before UDP anomaly detection activates |

Settings take effect **immediately** on save — no restart required. They are persisted to `inference/config.json` and survive container rebuilds.

**Reset Baseline** discards the trained OIF models and re-baselines on the next N flows of live traffic. Use this after clearing an attack so that attack flows do not pollute the model's definition of normal.

### Environment variables reference

| Variable | Default | Description |
|---|---|---|
| `ANTHROPIC_API_KEY` | — | Anthropic API key for LLM features |
| `CAPTURE_INTERFACE` | *(auto)* | Network interface to capture on |
| `CAPTURE_FILTER` | *(none)* | BPF filter expression |

---

## Running Attack Scenarios

There are two ways to run attacks: the **scenario runner** (automated, reproducible, produces a metrics report) and **manual execution** (ad-hoc, useful during development).

### Prerequisites

Install the one extra host-side dependency:

```bash
pip install pyyaml
```

`msgpack` should already be installed from Quick Start. No other packages are needed — the runner uses only the Python standard library plus PyYAML.

### Step 1 — Start the stack

```bash
python launch.py
```

Wait for the browser to open and the status bar to show the capture and models indicators as green dots.

### Step 2 — Wait for baselining to complete

The anomaly detectors must build a statistical baseline before detection activates. The dashboard shows a pulsing **Baselining X%** indicator in the status bar while this is running. By default:
- TCP: 4096 flows required
- UDP: 1024 flows required

The `client_a` and `client_b` containers generate continuous background HTTP, DNS, and NTP traffic to fill this automatically. On a typical run baselining completes in 3–5 minutes.

To accelerate baselining manually:

```bash
docker exec ids_client_a bash /scripts/fast_baseline.sh
docker exec ids_client_b bash /scripts/fast_baseline.sh
```

The indicator disappears when both TCP and UDP detectors are ready.

### Step 3 — Run a scenario with the orchestrator

The scenario runner handles baselining, timing, ground-truth annotation, and metrics calculation automatically:

```bash
# From the repo root
python tools/run_scenario.py scenarios/syn_flood.yml
```

The runner will:
1. Trigger `fast_baseline.sh` on both client containers (unless `--no-baseline` is passed)
2. Poll `GET /stats` every 5 seconds and print a live progress bar until both OIF detectors report `ready: true`
3. Record the attack start time, run the attack script via `docker exec` (blocking until the script exits)
4. Record the attack end time, then wait for the configured recovery window (default 120s) while monitoring scores
5. Query `GET /flows` from the inference engine, annotate each flow as attack or benign based on source IP and time window
6. Print a structured report to stdout and save the full results as JSON to `scenarios/results/`

### Available scenarios

| File | Attack type | Tool | Expected severity |
|---|---|---|---|
| `scenarios/syn_flood.yml` | TCP SYN flood | hping3 | CRITICAL |
| `scenarios/udp_flood.yml` | UDP packet flood | hping3 | CRITICAL |
| `scenarios/ssh_bruteforce.yml` | SSH credential brute-force | hydra | HIGH |
| `scenarios/port_scan.yml` | TCP SYN port scan | nmap | HIGH |
| `scenarios/http_flood.yml` | HTTP GET flood | ab | HIGH/CRITICAL |
| `scenarios/slowloris.yml` | Slowloris connection exhaustion | slowhttptest | HIGH |
| `scenarios/mixed.yml` | SYN flood → SSH brute-force (sequential) | hping3 + hydra | 2× CRITICAL events |

### Reading the report

```
═══════════════════════════════════════════════════════
  Corvus IDS — Scenario Report
  Scenario : TCP SYN Flood
  Run at   : 2025-03-19 14:32:07
═══════════════════════════════════════════════════════

Baseline
  TCP flows seen       : 4312        ← flows seen before attack started
  Baseline score p50   : 0.183       ← typical benign score (low = normal)

Attack  (172.20.0.20,  8.3s)
  Flows captured       : 1
  First CRITICAL alert : 0.4s        ← time-to-detect from attack start
  Peak composite score : 0.971       ← max OIF score during attack (0–1)
  Rejection rate (est) : 100.0%      ← OIF refused to train on attack flows

Recovery
  Scores below HIGH    : 38 flows    ← flows until model returned to normal

Benign traffic quality
  False positive rate  : 0.24%       ← CRITICAL alerts on non-attacker IPs
```

**Key metrics:**
- **First CRITICAL alert** — time-to-detect (TTD). Lower is better.
- **Rejection rate** — fraction of attack flows the OIF refused to incorporate into its baseline. 100% means the poisoning defence was fully engaged.
- **Recovery** — how quickly scores dropped after the attack ended. Reflects the forgetting speed of the fast window (256 flows).
- **False positive rate** — CRITICAL alerts on benign flows during the same window. Should stay below 1–2%.

Results JSON is saved to `scenarios/results/<scenario_name>_<timestamp>.json` for cross-run comparison.

### CLI options

```bash
python tools/run_scenario.py scenarios/syn_flood.yml
    --api http://localhost:8765    # inference engine URL (default: localhost:8765)
    --no-baseline                  # skip fast_baseline.sh (use if already baselining)
```

### Manual attacks (ad-hoc)

To run attacks interactively without the orchestrator, open a shell on the attacker container:

```bash
docker exec -it ids_attacker bash
```

Or run a specific script directly:

```bash
# Attack scripts: arg1=target, arg2=port, arg3=packet count
docker exec ids_attacker bash /attacks/syn_flood.sh 172.20.0.10 80 5000
docker exec ids_attacker bash /attacks/udp_flood.sh 172.20.0.10 53 5000
docker exec ids_attacker bash /attacks/ssh_bruteforce.sh
docker exec ids_attacker bash /attacks/port_scan.sh 172.20.0.10 1-1000 500
docker exec ids_attacker bash /attacks/http_flood.sh http://172.20.0.10/ 10000 50
docker exec ids_attacker bash /attacks/slowloris.sh http://172.20.0.10 200 60

# Raw commands
hping3 --syn --count 5000 -p 80 172.20.0.10
hping3 --udp --count 5000 -p 53 172.20.0.10
hydra -l testuser -P /usr/share/wordlists/rockyou.txt ssh://172.20.0.11:2222 -t 4
nmap -sS -p 1-1000 --max-rate 500 172.20.0.10
ab -n 10000 -c 50 http://172.20.0.10/
slowhttptest -c 200 -H -i 10 -r 50 -t GET -u http://172.20.0.10 -x 24 -p 60
```

Alerts appear in the dashboard in real time. Click any row to see the OIF window scores, path attribution, and LLM explanation.

### Resetting after an attack

If attack flows contaminated the baseline (scores remain elevated after the attack ends), reset the detectors from the Settings panel (⚙ button → Reset Baseline) or via the API:

```bash
curl -X POST http://localhost:8765/baseline/reset?protocol=TCP
curl -X POST http://localhost:8765/baseline/reset?protocol=UDP
curl -X POST http://localhost:8765/baseline/reset?protocol=all
```

This discards the trained OIF models and restarts baselining from zero.

---

## Dashboard Guide

### Status Bar (top)

| Indicator | Meaning |
|---|---|
| **WebSocket** dot | Connection to inference engine |
| **Capture** dot | C engine is running and sending flows |
| **Models** dot | Anomaly detectors are loaded |
| **Baselining X%** | Warmup phase — not yet detecting |
| **TCP / UDP alert counts** | Total alerts in current session |
| **⚙** | Open detection settings panel |

### Alert Feed (left panel)

Scrollable table of flow alerts, colour-coded by severity:
- **Grey** — INFO (below HIGH threshold)
- **Amber** — HIGH
- **Red** — CRITICAL

Click any row to open the detail panel.

### Detail Panel (right, top half)

When an alert is selected:
- Flow metadata: IP, ports, protocol, duration, packet count
- **Anomaly score** with colour-coded severity badge
- **Window scores**: fast (256-flow), medium (1024-flow), slow (4096-flow) with weighted bars
- **Path attribution**: top-3 features that most contributed to the anomaly score, with raw flow value vs baseline median ± IQR

### LLM Panel (right, bottom half)

- **AI Explanation**: auto-requested on alert selection — 2–3 sentence analyst-facing summary referencing the top attributed features
- **Dismiss as false positive**: records analyst feedback
- **Ask Claude**: free-text question about the selected alert; Claude has access to the full alert dict including scores and attribution

### Protocol Tabs

Switch between TCP and UDP alert feeds using the tab bar. Each protocol has its own trained detector and independent alert history.

---

## Building from Source

### Dashboard only

```bash
cd dashboard
npm ci
npm run build      # output in dashboard/dist/
```

### C capture engine only (inside monitor container)

```bash
docker exec -it ids_monitor bash
cd /app/capture && mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_FLAGS="-march=native"
make -j$(nproc)

# Run unit tests (AVX2 functions)
./test_features     # all tests must PASS before using the engine

# Debug tool — prints incoming flows as JSON
./inspect_ipc &
./capture_engine -i <interface>
```

### Full stack rebuild

By default `launch.py` reuses existing Docker images for a fast startup. Pass `--build` to force a rebuild after changing source files:

```bash
python launch.py           # fast — reuses existing images
python launch.py --build   # rebuilds images (needed after changes to capture/, inference/, or attacker/)
```

The dashboard build step has its own staleness check and only reruns when source files in `dashboard/src/` are newer than the last `dist/` output — it is unaffected by `--build`.

To force a full image rebuild without the cache:

```bash
docker --context default compose down
docker --context default compose build --no-cache
python launch.py
```

---

## Stopping the Stack

```bash
python stop.py
```

Or manually:

```bash
docker --context default compose down
```

This stops all containers but preserves:
- `inference/models/tcp_oif.pkl`, `udp_oif.pkl` — trained OIF models (no re-baselining on next start)
- `inference/config.json` — saved threshold settings
- `data/flows.db` — SQLite alert history

To reset everything including trained models:

```bash
python stop.py
rm -f inference/models/*.pkl inference/config.json data/flows.db
```

---

## Physical Deployment (Port Mirroring)

For a real deployment where the host machine receives mirrored traffic from a managed switch SPAN port:

1. Connect the physical NIC to the SPAN port. The NIC will receive a copy of all switch traffic in promiscuous mode.

2. Find the interface name:
   ```bash
   ip link show
   ```

3. Set `CAPTURE_INTERFACE` in `.env`:
   ```env
   CAPTURE_INTERFACE=ens3
   ```

4. Optionally restrict capture scope:
   ```env
   CAPTURE_FILTER=ip and not host 192.168.1.1
   ```

5. Launch normally:
   ```bash
   python launch.py
   ```

The monitor container uses `network_mode: host`, so all host NICs are visible inside the container. No additional Docker configuration is needed.

---

## Project Structure

```
Corvus/
├── capture/                    C capture engine
│   ├── src/
│   │   ├── main.c             libpcap loop and flow lifecycle
│   │   ├── flow_table.c/.h    FNV-1a hash table, 65536 slots
│   │   ├── packet_parser.c/.h zero-copy Ethernet/IP/TCP/UDP parser
│   │   ├── flow_features.c/.h per-packet accumulation, AVX2 finalisation
│   │   └── ipc_writer.c/.h    Unix socket client, ring buffer
│   ├── asm/
│   │   └── features_avx2.asm  NASM AVX2: mean/std + flag counting
│   ├── tests/
│   │   ├── test_features.c    AVX2 unit tests
│   │   └── inspect_ipc.c      debug: print flows as JSON
│   ├── CMakeLists.txt
│   └── Dockerfile
├── inference/                  Python inference engine
│   ├── main.py                thread orchestration, uvicorn entry
│   ├── socket_reader.py       Unix socket server, ctypes unmarshalling
│   ├── feature_extractor.py   flow dict → numpy feature vector
│   ├── online_detector.py     Online Isolation Forest (Leveni et al. 2024)
│   ├── classifier.py          inference entry point
│   ├── server.py              FastAPI: /ws /health /flows /config
│   ├── ws_handler.py          WebSocket manager, MessagePack framing
│   ├── llm.py                 Anthropic SDK wrappers
│   ├── storage.py             SQLite flow persistence
│   ├── config.py              runtime configuration, analyst thresholds
│   ├── models/                OIF pkl files (gitignored, generated at runtime)
│   └── Dockerfile
├── dashboard/                  React frontend
│   ├── src/
│   │   ├── App.tsx
│   │   ├── components/
│   │   │   ├── AlertFeed.tsx
│   │   │   ├── AlertDetail.tsx
│   │   │   ├── LLMPanel.tsx
│   │   │   ├── StatusBar.tsx
│   │   │   ├── StatsBar.tsx
│   │   │   └── SettingsPanel.tsx
│   │   ├── hooks/
│   │   │   ├── useWebSocket.ts
│   │   │   └── useAlerts.ts
│   │   └── types.ts
│   ├── vite.config.ts
│   └── package.json
├── attacker/                   Kali-based attacker container
│   └── attacks/               pre-written attack scripts
├── clients/                    Normal traffic generators (baseline fill)
│   └── scripts/
├── victim_web/                 nginx target with varied content files
├── dns/                        dnsmasq internal DNS (UDP traffic)
├── ntp/                        chrony NTP server (UDP traffic)
├── data/                       SQLite DB (gitignored, generated at runtime)
├── docker-compose.yml
├── launch.py                   host-side one-command launcher
├── stop.py                     host-side shutdown
└── .env                        secrets (gitignored)
```

---

## Network Layout

```
ids_net: 172.20.0.0/24

172.20.0.10   victim_web    nginx:alpine (HTTP target)
172.20.0.11   victim_ssh    OpenSSH server (SSH target)
172.20.0.20   attacker      Kali Linux (hping3, hydra, nmap)
172.20.0.30   monitor       Ubuntu 24.04 (C capture engine, host network)
172.20.0.31   inference     Python 3.11 (inference + WebSocket + dashboard)
172.20.0.40   client_a      Alpine (normal traffic generator)
172.20.0.41   client_b      Alpine (normal traffic generator)
172.20.0.50   dns           dnsmasq (internal DNS, UDP flows)
172.20.0.51   ntp           chrony (NTP server, UDP flows)
```