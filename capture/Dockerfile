FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        make \
        cmake \
        nasm \
        libpcap-dev \
        libpcap0.8 \
        curl \
        iproute2 \
        procps \
        tcpdump \
        jq

WORKDIR /app/capture

CMD ["/bin/bash", "/app/capture/start.sh"]
