#!/bin/sh
# start.sh — launch nginx and sshd, then hand off to the traffic generator.
# traffic.sh becomes PID 1 (via exec) so Docker tracks its lifetime.

# nginx reads /etc/nginx/sites-available/default via sites-enabled symlink
nginx

# sshd requires /run/sshd to exist
mkdir -p /run/sshd
/usr/sbin/sshd

exec /traffic.sh
