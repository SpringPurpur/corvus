#!/bin/bash
# fast_baseline.sh — aggressive benign traffic to fill both IF baselines quickly.
#
# Run from both clients simultaneously:
#   docker exec ids_client_a /scripts/fast_baseline.sh &
#   docker exec ids_client_b /scripts/fast_baseline.sh &
#
# TCP baseline (4096 flows): HTTP at ~10 req/s × 2 clients → ~3.5 minutes
# UDP baseline (1024 flows): DNS at ~3 queries/s × 2 clients → ~3 minutes
# Both complete roughly simultaneously.

WEB=172.20.0.10
SSH_HOST=172.20.0.11
SSH_PORT=2222
SSH_USER=testuser
SSH_PASS=testpass
DNS=172.20.0.50
NTP=172.20.0.51

TCP_COUNT=${1:-2200}   # slightly over half of 4096
UDP_COUNT=${2:-600}    # slightly over half of 1024

log() { echo "[$(date '+%H:%M:%S')] [fast-baseline / client-${CLIENT_ID:-?}] $*"; }

ssh_session() {
    sshpass -p "$SSH_PASS" ssh \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=5 \
        -p "$SSH_PORT" \
        "$SSH_USER@$SSH_HOST" \
        "uptime" 2>/dev/null || true
}

dns_query() {
    local names=("victim-web.ids" "victim-ssh.ids" "google.com" "github.com" "cloudflare.com")
    local name=${names[$(( RANDOM % ${#names[@]} ))]}
    dig +short +time=2 "@$DNS" "$name" A >/dev/null 2>&1 || true
}

log "Starting — TCP: $TCP_COUNT HTTP flows, UDP: $UDP_COUNT DNS flows"

# Run TCP and UDP baselining in parallel
(
    i=0
    while (( i < TCP_COUNT )); do
        i=$(( i + 1 ))
        if (( i % 3 == 0 )); then
            curl -s -o /dev/null -H "Connection: close" "http://$WEB/medium.bin" 2>/dev/null
        else
            curl -s -o /dev/null -H "Connection: close" "http://$WEB/" 2>/dev/null
        fi
        if (( i % 50 == 0 )); then
            log "TCP: $i / $TCP_COUNT"
            ssh_session
        fi
        # No sleep — back-to-back curls fill the 4096-flow baseline in ~20s,
        # keeping infrastructure contamination to < 0.1% of the corpus.
    done
    log "TCP done — $TCP_COUNT flows sent."
) &

(
    i=0
    while (( i < UDP_COUNT )); do
        i=$(( i + 1 ))
        dns_query
        # NTP every 10 queries for flow-type diversity
        if (( i % 10 == 0 )); then
            busybox ntpd -q -p "$NTP" >/dev/null 2>&1 || true
        fi
        if (( i % 100 == 0 )); then log "UDP: $i / $UDP_COUNT"; fi
        sleep 0.1   # ~10 DNS queries/s — don't overwhelm dnsmasq
    done
    log "UDP done — $UDP_COUNT flows sent."
) &

wait
log "Fast baseline complete. Check dashboard for baselining indicators."
