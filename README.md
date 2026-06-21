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
| Docker | 24+ (Linux native or Docker Desktop) |
| Python (host) | 3.11+ |
| Node.js (host) | 20+ |
| CPU | x86-64 with AVX2 (Intel Haswell 2013+ / AMD Ryzen 2017+) |

**Python host packages** (installed once, not in Docker):

```bash
pip install msgpack
```

---

## Quick Start

```bash
git clone <repo>
cd Corvus

# Create environment file
cp .env.example .env
# Edit .env and set ANTHROPIC_API_KEY=sk-ant-... (required for LLM features)

# Launch core IDS only (capture + inference + dashboard)
python launch.py

# Launch with full evaluation testbed (5 victim nodes + attacker + DNS + NTP)
python launch.py --testbed
```

`launch.py` will:
1. Build the React dashboard (`npm ci && npm run build` in `dashboard/`)
2. Run `docker compose up -d` for the selected profile
3. Wait for the inference engine health check to pass
4. Open `http://localhost:8765` in the browser

The first run takes 2–5 minutes to pull images and build the C capture engine inside the container.

---

## Configuration

All configuration lives in two places: `.env` (secrets and deployment) and the **Settings panel** inside the dashboard (operational thresholds).

### `.env` file (repo root)

```env
# Required for LLM alert explanation. Leave empty to disable LLM features.
ANTHROPIC_API_KEY=sk-ant-...

# Network capture - leave empty for automatic detection (Docker bridge).
# For SPAN/TAP port deployments, set to the physical NIC name, e.g. ens3.
CAPTURE_INTERFACE=

# Optional BPF filter applied at capture time.
CAPTURE_FILTER=

# Optional API key to protect the dashboard and REST API.
CORVUS_API_KEY=

# Dashboard port (default: 8765)
CORVUS_PORT=8765
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
| `ANTHROPIC_API_KEY` | *(none)* | Anthropic API key for LLM features |
| `CAPTURE_INTERFACE` | *(auto)* | Network interface to capture on |
| `CAPTURE_FILTER` | *(none)* | BPF filter expression |
| `CORVUS_API_KEY` | *(none)* | Protect dashboard with X-API-Key header |
| `CORVUS_PORT` | `8765` | Host port for the dashboard and REST API |

---

## Running Attack Scenarios

### Step 1 — Start the stack with testbed

```bash
python launch.py --testbed
```

### Step 2 — Wait for baselining to complete

The anomaly detectors build a statistical baseline before detection activates. The dashboard shows a pulsing **Baselining X%** indicator in the status bar while this is running. By default:
- TCP: 4096 flows required
- UDP: 1024 flows required

The 5 victim nodes generate continuous inter-node HTTP, SSH, DNS, and NTP traffic to fill the baseline automatically. On a typical run baselining completes in 3–5 minutes.

To accelerate baselining manually via the API:

```bash
curl -X POST http://localhost:8765/dev/fast-baseline
```

### Step 3 — Run a scenario

```bash
python tools/run_scenario.py scenarios/syn_flood.yml
```

The runner will:
1. Poll `GET /stats` until both OIF detectors report `ready: true`
2. Record the attack start time and exec the attack script on `ids_attacker`
3. Record the attack end time, then wait for the recovery window (default 120s)
4. Query `GET /flows`, annotate flows as attack/benign by IP and time window
5. Print a structured report and save JSON to `scenarios/results/`

### Available scenarios

| File | Attack type | Tool | Expected severity |
|---|---|---|---|
| `scenarios/syn_flood.yml` | TCP SYN flood | hping3 | CRITICAL |
| `scenarios/udp_flood.yml` | UDP packet flood | hping3 | CRITICAL |
| `scenarios/ssh_bruteforce.yml` | SSH credential brute-force | hydra | HIGH |
| `scenarios/port_scan.yml` | TCP SYN port scan | nmap | HIGH |
| `scenarios/http_flood.yml` | HTTP GET flood | ab | HIGH/CRITICAL |
| `scenarios/slowloris.yml` | Slowloris connection exhaustion | slowhttptest | HIGH |
| `scenarios/mixed.yml` | SYN flood → SSH brute-force (sequential) | hping3 + hydra | 2× CRITICAL |

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
- **First CRITICAL alert**: time-to-detect (TTD). Lower is better.
- **Rejection rate**: fraction of attack flows the OIF refused to incorporate into its baseline. 100% means the poisoning defence was fully engaged.
- **Recovery**: how quickly scores dropped after the attack ended. Reflects the forgetting speed of the fast window (256 flows).
- **False positive rate**: CRITICAL alerts on benign flows during the same window. Should stay below 1–2%.

### CLI options

```bash
python tools/run_scenario.py scenarios/syn_flood.yml
    --api http://localhost:8765    # inference engine URL (default: localhost:8765)
    --no-baseline                  # skip baselining wait (use if already ready)
```

### Manual attacks (ad-hoc)

Open a shell on the attacker container:

```bash
docker exec -it ids_attacker bash
```

Then run tools directly:

```bash
hping3 --syn --count 5000 -p 80 172.20.0.10
hping3 --udp --count 5000 -p 53 172.20.0.10
hydra -l testuser -P /usr/share/wordlists/rockyou.txt ssh://172.20.0.10:22 -t 4
nmap -sS -p 1-1000 --max-rate 500 172.20.0.10
ab -n 10000 -c 50 http://172.20.0.10/
slowhttptest -c 200 -H -i 10 -r 50 -t GET -u http://172.20.0.10 -x 24 -p 60
```

Alerts appear in the dashboard in real time.

### Resetting after an attack

```bash
curl -X POST http://localhost:8765/baseline/reset?protocol=TCP
curl -X POST http://localhost:8765/baseline/reset?protocol=UDP
curl -X POST http://localhost:8765/baseline/reset?protocol=all
```

Or use **Reset Baseline** in the Settings panel.

---

## Dashboard Guide

The dashboard is a drag-and-drop grid of independent modules. Each module can be resized, reordered, and hidden. Layout is persisted to `localStorage`.

### Status Bar (top)

| Indicator | Meaning |
|---|---|
| **WebSocket** dot | Connection to inference engine |
| **Capture** dot | C engine is running and sending flows |
| **Models** dot | Anomaly detectors are loaded |
| **Baselining X%** | Warmup phase — not yet detecting |
| **⚙** | Open detection settings panel |

### Modules

| Module | Description |
|---|---|
| **At-a-glance** | Live counters: flows, HIGH/CRITICAL alerts, queue depth |
| **Network Pulse** | OIF composite score over the last 10 minutes, per-alert severity dots |
| **Model Health** | Per-window IsolationForest training progress and score distribution |
| **Entities** | Ranked source IPs by peak score with 8-sample score sparkbars |
| **Alert Stream** | Scrollable real-time alert feed with pause, filter by severity and protocol |
| **Alert Detail** | Flow metadata, anomaly score, window scores, feature attribution radar |
| **LLM Explanation** | AI-generated explanation of the selected alert; free-text analyst Q&A |
| **Timeline** | Hourly alert histogram split by TCP/UDP |
| **Port Heatmap** | Port × time heat grid; hover for source IP breakdown |
| **Window Consensus** | Three-window score heatmap and divergence sparkline |
| **Topology** | Force-directed graph of alert flows between IPs |

Click any row in **Alert Stream** to populate **Alert Detail** and **LLM Explanation**. Click any IP in **Entities** to filter the stream to that source.

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

```bash
python launch.py           # fast — reuses existing images
python launch.py --build   # rebuilds images after changes to capture/ or inference/
```

To force a full image rebuild without cache:

```bash
docker compose down
docker compose build --no-cache
python launch.py
```

---

## Stopping the Stack

```bash
python stop.py
```

This stops all containers but preserves:
- `inference/models/*.pkl` — trained OIF models (no re-baselining on next start)
- `inference/config.json` — saved threshold settings
- `data/flows.db` — SQLite alert history

To reset everything including trained models:

```bash
python stop.py
rm -f inference/models/*.pkl inference/config.json data/flows.db
```

---

## Physical Deployment (Port Mirroring)

For a real deployment where the host receives mirrored traffic from a managed switch SPAN port:

1. Connect the physical NIC to the SPAN port.

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

5. Launch without testbed (no victim nodes needed):
   ```bash
   python launch.py
   ```

The monitor container uses `network_mode: host`, so all host NICs are visible inside the container.

---

## Project Structure

```
Corvus/
├── capture/                    C capture engine
│   ├── src/
│   │   ├── main.c             libpcap loop and flow lifecycle
│   │   ├── flow_table.c/.h    FNV-1a hash table, 65 536 slots
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
│   ├── online_detector.py     Online Isolation Forest (3 windows per protocol)
│   ├── online_learner.py      incremental IsolationForest fit
│   ├── server.py              FastAPI: /ws /health /flows /stats /config
│   ├── ws_handler.py          WebSocket manager, MessagePack framing
│   ├── llm.py                 Anthropic SDK wrappers
│   ├── storage.py             SQLite flow persistence and window history
│   ├── config.py              runtime configuration, analyst thresholds
│   ├── _array_tree.pyx        Cython extension for fast tree traversal
│   ├── models/                OIF pkl files (gitignored, generated at runtime)
│   └── Dockerfile
├── dashboard/                  React + TypeScript frontend
│   ├── src/
│   │   ├── App.tsx            root: grid layout, WebSocket, alert state
│   │   ├── components/
│   │   │   ├── grid/          drag-and-drop module grid infrastructure
│   │   │   │   ├── GridContainer.tsx
│   │   │   │   ├── Module.tsx
│   │   │   │   └── g3.ts      shared design tokens and colour helpers
│   │   │   └── modules/       individual dashboard modules
│   │   │       ├── ModKPI.tsx
│   │   │       ├── ModPulse.tsx
│   │   │       ├── ModHealth.tsx
│   │   │       ├── ModEntities.tsx
│   │   │       ├── ModStream.tsx
│   │   │       ├── ModDetail.tsx
│   │   │       ├── ModLLM.tsx
│   │   │       ├── ModTimeline.tsx
│   │   │       ├── ModHeatmap.tsx
│   │   │       ├── ModConsensus.tsx
│   │   │       └── ModTopology.tsx
│   │   ├── hooks/
│   │   │   ├── useWebSocket.ts
│   │   │   └── useAlerts.ts   ring buffer (5 000/proto), 150 ms flush
│   │   └── types.ts
│   ├── vite.config.ts
│   └── package.json
├── attacker/                   Kali-based attacker container (testbed only)
├── victim_node/                nginx + sshd + traffic generator (testbed only)
├── dns/                        dnsmasq internal DNS (testbed only)
├── ntp/                        chrony NTP server (testbed only)
├── tools/
│   ├── run_scenario.py         scenario orchestrator with metrics report
│   ├── eval_all.py             batch scenario evaluator
│   └── gen_demo_db.py          generate a populated SQLite DB for offline demo
├── scenarios/                  YAML scenario definitions
├── data/                       SQLite DB (gitignored, generated at runtime)
├── docker-compose.yml          core IDS (monitor + inference)
├── docker-compose.testbed.yml  testbed overlay (victim nodes + attacker)
├── launch.py                   host-side one-command launcher
├── stop.py                     host-side shutdown
└── .env                        secrets (gitignored)
```

---

## Network Layout

### Core IDS (always running)

```
ids_monitor    host network    C capture engine (sees all host interfaces)
ids_inference  host:8765       Python inference + dashboard + REST API
```

### Testbed overlay (`--testbed`)

```
ids_net: 172.20.0.0/24

172.20.0.10–14   ids_node_1–5   victim nodes (nginx + sshd + traffic generator)
172.20.0.20      ids_attacker   Kali Linux (hping3, hydra, nmap, ab)
172.20.0.31      ids_inference  inference engine (also on ids_net in testbed)
172.20.0.50      ids_dns        dnsmasq internal DNS
172.20.0.51      ids_ntp        chrony NTP server
```
