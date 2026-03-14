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
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app/capture

# Source is bind-mounted by docker-compose at /app/capture.
# Build manually inside the container:
#   cd /app/capture && mkdir -p build && cd build && cmake .. && make -j$(nproc)
CMD ["sleep", "infinity"]
