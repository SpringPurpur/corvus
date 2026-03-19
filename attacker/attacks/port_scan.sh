#!/bin/sh
# port_scan.sh — TCP SYN port scan against victim_web.
# Generates many micro-flows: 2-3 packets each, high rst_flag_cnt,
# very short flow_duration_s. Signature is opposite of floods:
# breadth (many destinations/ports) vs depth (one flow, many packets).
TARGET=${1:-172.20.0.10}
PORTS=${2:-1-1000}
RATE=${3:-200}
echo "[attack] TCP SYN scan → $TARGET  ports $PORTS  rate $RATE pkt/s"
nmap -sS -p "$PORTS" --max-rate "$RATE" --open "$TARGET"