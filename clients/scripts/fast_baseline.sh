#!/bin/bash
# fast_baseline.sh - aggressive benign traffic to fill both OIF baselines quickly.
#
# Runs from all 5 victim nodes simultaneously via run_scenario.py:
#   docker exec ids_node_N /traffic.sh (already running continuously)
#
# This script is invoked by run_scenario.py on each node container to generate
# a burst of HTTP and DNS flows that fill the 4096-flow TCP baseline quickly.
# Nodes generate their own ongoing traffic via traffic.sh, so this script just
# accelerates the initial fill before a scenario starts.
#
# TCP baseline (4096 flows): HTTP at ~10 req/s × 5 nodes → ~1.5 minutes
# UDP baseline (1024 flows): DNS at ~3 queries/s × 5 nodes → ~1 minute

NODES="172.20.0.10 172.20.0.11 172.20.0.12 172.20.0.13 172.20.0.14"
DNS=172.20.0.50
NTP=172.20.0.51

# Exclude self: packets to a container's own IP are delivered via loopback,
# not through the veth pair on the bridge, so the monitor never captures them.
# With shuf picking from all 5 nodes, 1/5 of flows were invisible regardless
# of TCP_COUNT - this was the main cause of the ~3700/4096 shortfall.
MY_IP=$(hostname -I | awk '{print $1}')
TARGETS=$(echo "$NODES" | tr ' ' '\n' | grep -vF "${MY_IP}" | paste -sd ' ')
[ -z "$TARGETS" ] && TARGETS="$NODES"   # fallback if hostname -I fails

TCP_COUNT=${1:-820}    # 820 flows per node × 5 nodes = 4100 through-bridge flows;
                       # ~5-10% filtered by tot_pkts<4 → ~3900-4000 reach OIF.
                       # Slightly under the 4096 target so we don't overshoot into
                       # the attack window. normal_traffic.sh supplies the last ~100.
UDP_COUNT=${2:-250}    # ~250 flows per node × 5 nodes > 1024 UDP baseline
SSH_COUNT=${3:-20}     # 20 SSH sessions per node × 5 nodes = 100 SSH flows in the
                       # initial training set. Without this, the first 4096 flows
                       # are 100% HTTP, SSH flow_duration_s and init_fwd_win_bytes
                       # fall outside the scaler bounding box and trigger OOR=1.0.

# File-size mix targets (sum to 10, RANDOM % 10 used for selection):
#   0-4 (50%) medium.bin   100 KB  - moderate duration, mid bwd_pkts_per_sec
#   5-8 (40%) index.html   ~200 B  - very short, high bwd_pkts_per_sec per second
#   9   (10%) large.bin    1 MB    - longer duration, lower bwd_pkts_per_sec
#
# Previously used medium.bin exclusively: the scaler's IQR for bwd_pkts_per_sec
# was anchored to a single tight cluster, making every small-file HTTP response
# (50% of normal_traffic.sh flows) look anomalous (FPR_HIGH ~63%). Mixing all
# three file sizes aligns the baseline distribution with operational traffic.

log() { echo "[$(date '+%H:%M:%S')] [fast-baseline] $*"; }

dns_query() {
    # Use only internally-resolvable names - dnsmasq answers from its local
    # address table in <1 ms. External names (google.com etc.) require a
    # forward to 8.8.8.8 which may be unavailable inside the isolated bridge
    # network, causing 3x2 s = 6 s stalls that collapse the UDP fill rate.
    # +retry=0 limits to a single attempt; dnsmasq always responds (<1 ms),
    # so retries only cause delays on misconfiguration.
    local names=("ids-node-1.ids" "ids-node-2.ids" "ids-node-3.ids"
                 "ids-node-4.ids" "ids-node-5.ids" "dns.ids")
    local name=${names[$(( RANDOM % ${#names[@]} ))]}
    dig +short +time=2 +retry=0 "@$DNS" "$name" A >/dev/null 2>&1 || true
}

log "Starting - TCP: $TCP_COUNT HTTP, SSH: $SSH_COUNT, UDP: $UDP_COUNT DNS (per node)"

# TCP: burst HTTP requests to random nodes - no sleep for maximum fill rate.
# Each request picks a random file size to produce a diverse bwd_pkts_per_sec
# distribution in the baseline corpus.
(
    i=0
    while (( i < TCP_COUNT )); do
        i=$(( i + 1 ))
        TARGET=$(echo "$TARGETS" | tr ' ' '\n' | shuf -n1)
        r=$(( RANDOM % 10 ))
        if (( r < 5 )); then
            curl -s -o /dev/null -H "Connection: close" "http://$TARGET/medium.bin" 2>/dev/null
        elif (( r < 9 )); then
            curl -s -o /dev/null -H "Connection: close" "http://$TARGET/" 2>/dev/null
        else
            curl -s -o /dev/null -H "Connection: close" "http://$TARGET/large.bin" 2>/dev/null
        fi
        if (( i % 100 == 0 )); then log "TCP: $i / $TCP_COUNT"; fi
    done
    log "TCP done - $TCP_COUNT flows sent."
) &

(
    i=0
    while (( i < UDP_COUNT )); do
        i=$(( i + 1 ))
        dns_query
        if (( i % 10 == 0 )); then
            busybox ntpd -q -p "$NTP" >/dev/null 2>&1 || true
        fi
        if (( i % 50 == 0 )); then log "UDP: $i / $UDP_COUNT"; fi
        sleep 0.1   # ~10 DNS queries/s - don't overwhelm dnsmasq
    done
    log "UDP done - $UDP_COUNT flows sent."
) &

# SSH: sequential sessions (~1-2s each), runs in parallel with TCP/UDP loops.
# 20 sessions × 5 nodes = 100 SSH flows seeded into the training set so the
# OIF learns SSH flow_duration_s (~1-3s) and init_fwd_win_bytes before it
# switches to detection mode. Without this, fresh-start baselines produce
# OOR=1.0 for every SSH flow, driving FPR_CRIT up to ~6%.
(
    i=0
    while (( i < SSH_COUNT )); do
        i=$(( i + 1 ))
        TARGET=$(echo "$TARGETS" | tr ' ' '\n' | shuf -n1)
        sshpass -p testpass ssh \
            -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null \
            -o ConnectTimeout=5 \
            testuser@"$TARGET" "echo done" 2>/dev/null || true
        if (( i % 5 == 0 )); then log "SSH: $i / $SSH_COUNT"; fi
    done
    log "SSH done - $SSH_COUNT sessions sent."
) &

wait
log "Fast baseline complete."
