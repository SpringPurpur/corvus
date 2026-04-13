#!/bin/sh
# port_scan.sh - TCP SYN port scan against victim_web.
# Generates many micro-flows: 2-3 packets each, high rst_flag_cnt,
# very short flow_duration_s. Signature is opposite of floods:
# breadth (many destinations/ports) vs depth (one flow, many packets).
PORTS=${1:-1-1000}
RATE=${2:-200}

VICTIMS="172.20.0.10 172.20.0.11 172.20.0.12 172.20.0.13 172.20.0.14"

echo "[attack] TCP SYN scan -> all nodes  ports $PORTS  rate $RATE pkt/s"
for ip in $VICTIMS; do
    nmap -sS -p "$PORTS" --max-rate "$RATE" --open "$ip" &
done
wait