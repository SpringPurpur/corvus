#!/bin/bash
# traffic.sh — mesh traffic generator for victim nodes.
#
# Each node reads NODE_IP (its own address) and PEERS (comma-separated list
# of all node IPs) from environment variables. It excludes itself from the
# peer list and generates HTTP, SSH, DNS, and NTP traffic to random peers.
#
# CLIENT_ID (1-5) shifts the startup sleep offset so all nodes are not in
# lockstep — they produce interleaved flows rather than synchronised bursts.

DNS=172.20.0.50
NTP=172.20.0.51

log() { echo "[$(date '+%H:%M:%S')] [node-${NODE_IP##*.}] $*"; }

# Build peer list by excluding own IP
build_peers() {
    echo "${PEERS}" | tr ',' '\n' | grep -v "^${NODE_IP}$"
}

random_peer() {
    build_peers | shuf -n1
}

http_small() {
    local peer; peer=$(random_peer)
    # Connection: close forces one TCP flow per request so each request
    # appears as a distinct flow in the capture engine — critical for baseline diversity.
    curl -s -o /dev/null -H "Connection: close" "http://$peer/" 2>/dev/null
}

http_medium() {
    local peer; peer=$(random_peer)
    curl -s -o /dev/null -H "Connection: close" "http://$peer/medium.bin" 2>/dev/null
}

http_large() {
    local peer; peer=$(random_peer)
    wget -q -O /dev/null "http://$peer/large.bin" 2>/dev/null
}

ssh_session() {
    local peer; peer=$(random_peer)
    # Legitimate interactive-style SSH: connect, run a command, disconnect.
    # Produces: low fwd_pkts_per_sec, balanced asymmetry, long flow_iat_mean.
    sshpass -p testpass ssh \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=5 \
        testuser@"$peer" \
        "uptime && echo done" 2>/dev/null || true
}

dns_query() {
    # Mix internal names (instant cache hits) and external names (forwarded to
    # 8.8.8.8 for cache-miss diversity). +retry=0 prevents the default 3-retry
    # loop that stalls 6 s when the upstream DNS is unreachable (isolated bridge).
    local names=("ids-node-1.ids" "ids-node-2.ids" "ids-node-3.ids"
                 "ids-node-4.ids" "ids-node-5.ids"
                 "google.com" "github.com" "cloudflare.com")
    local name=${names[$(( RANDOM % ${#names[@]} ))]}
    dig +short +time=2 +retry=0 "@$DNS" "$name" A >/dev/null 2>&1 || true
}

ntp_sync() {
    # Tiny fixed-size UDP exchange (48 bytes each direction).
    ntpdate -q "$NTP" >/dev/null 2>&1 || \
        busybox ntpd -q -p "$NTP" >/dev/null 2>&1 || true
}

rand_sleep() {
    local min=$1 max=$2
    sleep $(( min + RANDOM % (max - min + 1) ))
}

# Stagger startup by CLIENT_ID seconds so nodes don't generate synchronised
# traffic bursts — each node gets a distinct IAT pattern in the baseline.
if [[ -n "${CLIENT_ID}" && "${CLIENT_ID}" -gt 1 ]]; then
    sleep $(( CLIENT_ID - 1 ))
fi

log "Starting mesh traffic loop (peers: $(build_peers | tr '\n' ' '))"

i=0
while true; do
    i=$(( i + 1 ))

    http_small
    rand_sleep 1 3

    # Every 3 cycles: DNS query — keeps UDP baseline filling steadily
    if (( i % 3 == 0 )); then
        dns_query
    fi

    # Every 4 cycles: medium file download
    if (( i % 4 == 0 )); then
        http_medium
        rand_sleep 2 4
    fi

    # Every 8 cycles: NTP sync
    if (( i % 8 == 0 )); then
        ntp_sync
    fi

    # Every 15 cycles: large file download
    if (( i % 15 == 0 )); then
        log "Large download"
        http_large
        rand_sleep 3 6
    fi

    # Every 10 cycles: SSH session to a random peer
    if (( i % 10 == 0 )); then
        log "SSH session"
        ssh_session
        rand_sleep 4 8
    fi
done
