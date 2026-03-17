#!/bin/bash
# fast_baseline.sh — aggressive benign traffic to fill the IF baseline quickly.
#
# Run this from both clients simultaneously for fastest baseline completion:
#   docker exec ids_client_a /scripts/fast_baseline.sh &
#   docker exec ids_client_b /scripts/fast_baseline.sh &
#
# Each client sends COUNT requests. Two clients in parallel reach the 4096-flow
# baseline in roughly: 4096 / (2 × rate) seconds.
# At 8 req/s per client → ~4 minutes. At 15 req/s → ~2.5 minutes.
#
# Uses Connection: close to force one TCP flow per request so every request
# increments the baseline counter rather than reusing a single connection.

WEB=172.20.0.10
SSH_HOST=172.20.0.11
SSH_PORT=2222
SSH_USER=testuser
SSH_PASS=testpass

COUNT=${1:-2200}   # slightly over half of 4096 — both clients together exceed the threshold

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

log "Starting — $COUNT requests (mix of small/medium + SSH every 50)"
i=0
while (( i < COUNT )); do
    i=$(( i + 1 ))

    # 2-in-3 small, 1-in-3 medium — produces varied pkt_len_mean in baseline
    if (( i % 3 == 0 )); then
        curl -s -o /dev/null -H "Connection: close" "http://$WEB/medium.bin" 2>/dev/null
    else
        curl -s -o /dev/null -H "Connection: close" "http://$WEB/" 2>/dev/null
    fi

    # SSH every 50 requests for flow-type diversity
    if (( i % 50 == 0 )); then
        log "SSH session ($i / $COUNT)"
        ssh_session
    fi

    # Brief pause every 20 requests to vary IAT and avoid overwhelming the capture engine
    if (( i % 20 == 0 )); then
        sleep 0.2
    fi
done

log "Done — $COUNT flows sent. Check dashboard for baseline completion."
