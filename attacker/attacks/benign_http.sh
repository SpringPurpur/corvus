#!/bin/sh
# benign_http.sh - normal HTTP traffic to victim_web (172.20.0.10)
# Generates benign flows for baselining: ack_flag_ratio > 0, psh_flag_ratio moderate.
TARGET=${1:-172.20.0.10}
COUNT=${2:-100}
DELAY=${3:-0.5}
echo "[benign] HTTP GET × $COUNT → http://$TARGET/  (${DELAY}s interval)"
i=0
while [ "$i" -lt "$COUNT" ]; do
    curl -s -o /dev/null "http://$TARGET/"
    i=$((i + 1))
    sleep "$DELAY"
done
echo "[benign] Done."
