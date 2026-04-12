FROM ubuntu:24.04

# Avoid interactive prompts during apt
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    make \
    cmake \
    nasm \
    libpcap-dev \
    libpcap0.8 \
    gdb \
    valgrind \
    curl \
    iproute2 \
    procps \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app/capture

# start.sh is bind-mounted alongside the source at /app/capture/start.sh.
# It builds the engine on first run (if no binary exists) then starts capture.
CMD ["/bin/bash", "/app/capture/start.sh"]
