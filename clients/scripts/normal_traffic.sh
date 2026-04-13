#!/bin/bash
# normal_traffic.sh - continuous realistic benign traffic generator.
#
# Runs indefinitely as the container's main process. CLIENT_ID (a|b)
# shifts timing and emphasis so the two clients produce distinct flow
# distributions even though they hit the same targets.
#
# Flow characteristics produced:
#   HTTP small  → short duration, low pkt_len_mean, high down/up ratio
#   HTTP medium → moderate duration, mid pkt_len_mean
#   HTTP large  → longer duration, high pkt_len_mean, very high down/up ratio
#   SSH session → low fwd_pkts_per_sec, balanced down/up, long IAT
#   DNS query   → short UDP flow, varied response sizes (cache miss vs hit)
#   NTP sync    → tiny fixed-size UDP flow, very short duration

WEB=172.20.0.10
SSH_HOST=172.20.0.11
SSH_PORT=2222
SSH_USER=testuser
SSH_PASS=testpass
DNS=172.20.0.50
NTP=172.20.0.51

log() { echo "[$(date '+%H:%M:%S')] [client-${CLIENT_ID:-?}] $*"; }

http_small() {
    # Connection: close forces one TCP flow per request - critical for baseline diversity.
    # Without it curl reuses the connection and multiple requests become one flow.
    curl -s -o /dev/null -H "Connection: close" "http://$WEB/" 2>/dev/null
}

http_medium() {
    curl -s -o /dev/null -H "Connection: close" "http://$WEB/medium.bin" 2>/dev/null
}

http_large() {
    wget -q -O /dev/null "http://$WEB/large.bin" 2>/dev/null
}

ssh_session() {
    # Legitimate interactive-style SSH: connect, run a command, disconnect.
    # Produces low fwd_pkts_per_sec, balanced asymmetry, long flow_iat_mean.
    sshpass -p "$SSH_PASS" ssh \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=5 \
        -p "$SSH_PORT" \
        "$SSH_USER@$SSH_HOST" \
        "uptime && echo done" 2>/dev/null || true
}

dns_query() {
    # Alternates between internal names (cache hits, small response) and
    # external names forwarded to 8.8.8.8 (cache misses, larger response).
    # Produces varied pkt_len_mean and down/up ratio across UDP flows.
    local names=("victim-web.ids" "victim-ssh.ids" "dns.ids"
                 "google.com" "github.com" "cloudflare.com")
    local name=${names[$(( RANDOM % ${#names[@]} ))]}
    dig +short +time=2 "@$DNS" "$name" A >/dev/null 2>&1 || true
}

ntp_sync() {
    # NTP query - fixed-size UDP exchange (48 bytes each way).
    # Adds a distinct short-duration, symmetric UDP flow type to the baseline.
    ntpdate -q "$NTP" >/dev/null 2>&1 || \
        busybox ntpd -q -p "$NTP" >/dev/null 2>&1 || true
}

rand_sleep() {
    local min=$1 max=$2
    sleep $(( min + RANDOM % (max - min + 1) ))
}

# client_b shifts its cycle phase so the two clients are not in lockstep,
# producing different IAT patterns at the capture engine.
if [[ "${CLIENT_ID}" == "b" ]]; then
    sleep 7
fi

log "Starting - normal traffic loop"
i=0
while true; do
    i=$(( i + 1 ))

    http_small
    rand_sleep 1 3

    # Every 3 cycles: DNS query - keeps UDP baseline filling steadily
    if (( i % 3 == 0 )); then
        dns_query
    fi

    # Every 4 cycles: medium file
    if (( i % 4 == 0 )); then
        http_medium
        rand_sleep 2 4
    fi

    # Every 8 cycles: NTP sync - short symmetric UDP, different from DNS
    if (( i % 8 == 0 )); then
        ntp_sync
    fi

    # Every 15 cycles: large file download
    if (( i % 15 == 0 )); then
        log "Large download"
        http_large
        rand_sleep 3 6
    fi

    # Every 12 cycles (client_a) or 8 cycles (client_b): SSH session
    if [[ "${CLIENT_ID}" == "b" ]]; then
        ssh_every=8
    else
        ssh_every=12
    fi
    if (( i % ssh_every == 0 )); then
        log "SSH session"
        ssh_session
        rand_sleep 4 8
    fi
done
