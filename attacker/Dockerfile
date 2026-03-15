FROM kalilinux/kali-rolling

RUN apt-get update -q && apt-get install -y --no-install-recommends \
        hping3 \
        hydra \
        nmap \
        curl \
        wget \
        iputils-ping \
        wordlists \
    && gunzip -f /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true \
    && rm -rf /var/lib/apt/lists/*

CMD ["sleep", "infinity"]
