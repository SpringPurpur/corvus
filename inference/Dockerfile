FROM debian:bookworm-slim AS python-builder

ARG PYTHON_VERSION=3.13.3

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential wget ca-certificates libssl-dev libbz2-dev \
        libffi-dev zlib1g-dev libsqlite3-dev libreadline-dev \
    && rm -rf /var/lib/apt/lists/*

RUN wget -q https://www.python.org/ftp/python/${PYTHON_VERSION}/Python-${PYTHON_VERSION}.tgz \
    && tar xzf Python-${PYTHON_VERSION}.tgz \
    && cd Python-${PYTHON_VERSION} \
    && ./configure --disable-gil --prefix=/opt/python \
    && make -j$(nproc) \
    && make install \
    && cd .. && rm -rf Python-${PYTHON_VERSION} Python-${PYTHON_VERSION}.tgz

# ── runtime image ─────────────────────────────────────────────────────────────
FROM debian:bookworm-slim

# ca-certificates needed for Rust/cargo to reach crates.io when building
# packages without pre-built wheels (pydantic-core, cryptography)
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential curl ca-certificates \
        libssl3 libbz2-1.0 libffi8 zlib1g libsqlite3-0 \
    && rm -rf /var/lib/apt/lists/*

# Rust needed for pydantic-core and cryptography source builds
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --profile minimal
ENV PATH="/root/.cargo/bin:/opt/python/bin:$PATH"

COPY --from=python-builder /opt/python /opt/python

WORKDIR /app

COPY requirements-base.txt .
RUN --mount=type=cache,target=/root/.cache/pip \
    python3 -m pip install -r requirements-base.txt

COPY requirements.txt .
RUN --mount=type=cache,target=/root/.cache/pip \
    python3 -m pip install -r requirements.txt

COPY . .

# Compile _array_tree.pyx → _array_tree.cpython-313t-*.so
RUN python3 setup_ext.py build_ext --inplace \
    && rm -rf build/ _array_tree.c

HEALTHCHECK --interval=5s --timeout=3s --start-period=30s --retries=5 \
    CMD curl -f http://localhost:8765/health || exit 1

CMD ["python3", "-Xgil=0", "main.py", "--anomaly-only"]