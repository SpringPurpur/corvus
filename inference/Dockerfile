FROM python:3.11-slim

WORKDIR /app

# build-essential (gcc + libc headers) required for Cython compilation; curl for healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Compile _array_tree.pyx → _array_tree.cpython-311-*.so
# Replaces the pure-Python hot paths in _ArrayTree.score_one /
# attribute_path with ~200-300x faster C-level loop implementations.
RUN python setup_ext.py build_ext --inplace \
    && rm -rf build/ _array_tree.c

HEALTHCHECK --interval=5s --timeout=3s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8765/health || exit 1

CMD ["python", "main.py", "--anomaly-only"]
