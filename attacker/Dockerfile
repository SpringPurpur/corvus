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
    && gunzip -f /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true \
    && rm -rf /var/lib/apt/lists/*

COPY attacks/ /attacks/
RUN chmod +x /attacks/*.sh

CMD ["sleep", "infinity"]
