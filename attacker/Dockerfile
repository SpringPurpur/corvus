FROM kalilinux/kali-rolling

RUN apt-get update -q && apt-get install -y --no-install-recommends \
        hping3 \
        hydra \
        nmap \
        curl \
        wget \
        iputils-ping \
        wordlists \
        apache2-utils \
        slowhttptest \
        nghttp2-client \
        python3-pip \
    && gunzip -f /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true \
    && pip3 install --break-system-packages h2 \
    && rm -rf /var/lib/apt/lists/*

COPY attacks/ /attacks/
RUN chmod +x /attacks/*.sh

CMD ["sleep", "infinity"]
