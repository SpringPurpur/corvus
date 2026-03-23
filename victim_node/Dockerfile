FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        nginx openssh-server curl wget sshpass dnsutils ntpdate iputils-ping openssl \
    && rm -rf /var/lib/apt/lists/*

# SSH: create user, enable password auth, generate host keys
RUN useradd -m -s /bin/bash testuser \
    && echo "testuser:testpass" | chpasswd \
    && mkdir -p /run/sshd \
    && sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config \
    && ssh-keygen -A

# Nginx content — varied sizes so OIF baseline learns a realistic pkt_len distribution
RUN dd if=/dev/urandom of=/var/www/html/medium.bin bs=1024 count=100  2>/dev/null \
 && dd if=/dev/urandom of=/var/www/html/large.bin  bs=1024 count=1024 2>/dev/null \
 && printf '<html><body><h1>Corvus IDS node</h1></body></html>\n' \
        > /var/www/html/index.html

# Self-signed cert for HTTP/2 Rapid Reset scenario (CVE-2023-44487)
RUN mkdir -p /etc/nginx/ssl \
 && openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout /etc/nginx/ssl/self.key \
        -out    /etc/nginx/ssl/self.crt \
        -subj   "/CN=ids-victim-node" 2>/dev/null

COPY victim_node/nginx.conf  /etc/nginx/sites-available/default
COPY victim_node/start.sh   /start.sh
COPY victim_node/traffic.sh /traffic.sh
# fast_baseline.sh is invoked by run_scenario.py at /scripts/fast_baseline.sh
RUN mkdir -p /scripts
COPY clients/scripts/fast_baseline.sh /scripts/fast_baseline.sh
RUN chmod +x /start.sh /traffic.sh /scripts/fast_baseline.sh

CMD ["/start.sh"]
