#!/bin/bash
# fast_baseline.sh — aggressive benign traffic to fill both OIF baselines quickly.
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

TCP_COUNT=${1:-900}    # ~900 flows per node × 5 nodes > 4096 TCP baseline
UDP_COUNT=${2:-250}    # ~250 flows per node × 5 nodes > 1024 UDP baseline

log() { echo "[$(date '+%H:%M:%S')] [fast-baseline] $*"; }

dns_query() {
    local names=("ids-node-1.ids" "ids-node-2.ids" "google.com" "github.com" "cloudflare.com")
    local name=${names[$(( RANDOM % ${#names[@]} ))]}
    dig +short +time=2 "@$DNS" "$name" A >/dev/null 2>&1 || true
}

log "Starting — TCP: $TCP_COUNT HTTP flows x5 nodes, UDP: $UDP_COUNT DNS flows"

# TCP: burst HTTP requests to random nodes — no sleep for maximum fill rate
(
    i=0
    while (( i < TCP_COUNT )); do
        i=$(( i + 1 ))
        # Pick a random target node each request for flow diversity (varied dst_ip)
        TARGET=$(echo "$NODES" | tr ' ' '\n' | shuf -n1)
        if (( i % 3 == 0 )); then
            curl -s -o /dev/null -H "Connection: close" "http://$TARGET/medium.bin" 2>/dev/null
        else
            curl -s -o /dev/null -H "Connection: close" "http://$TARGET/" 2>/dev/null
        fi
        if (( i % 100 == 0 )); then log "TCP: $i / $TCP_COUNT"; fi
        # No sleep — back-to-back curls fill the 4096-flow baseline quickly,
        # keeping infrastructure contamination to < 0.1% of the corpus.
    done
    log "TCP done — $TCP_COUNT flows sent."
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
        sleep 0.1   # ~10 DNS queries/s — don't overwhelm dnsmasq
    done
    log "UDP done — $UDP_COUNT flows sent."
) &

wait
log "Fast baseline complete."
