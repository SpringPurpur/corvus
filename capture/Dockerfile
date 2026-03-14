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
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app/capture

# Copy source into image — in docker-compose the source is bind-mounted,
# so this layer is only used for standalone image builds
COPY . .

RUN mkdir -p build && cd build && \
    cmake .. -DCMAKE_BUILD_TYPE=Debug && \
    make -j$(nproc)

CMD ["./build/capture_engine", "-i", "eth0"]
